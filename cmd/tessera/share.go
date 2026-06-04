package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/emmayusufu/tessera/internal/agent"
	"github.com/emmayusufu/tessera/internal/certs"
	"github.com/emmayusufu/tessera/internal/netutil"
	"github.com/emmayusufu/tessera/internal/proto"
)

type shareRequest struct {
	CAcert             string         `json:"ca_cert"`
	GuestCert          string         `json:"guest_cert"`
	GuestKey           string         `json:"guest_key"`
	CoordAddr          string         `json:"coord_addr"`
	ServerName         string         `json:"server_name"`
	AgentName          string         `json:"agent_name"`
	ShareID            string         `json:"share_id"`
	Services           []shareService `json:"services"`
	ExpectedName       string         `json:"expected_name"`
	Reason             string         `json:"reason"`
	TTLSeconds         int            `json:"ttl_seconds"`
	IdleTimeoutSeconds int            `json:"idle_timeout_seconds"`
}

type shareService struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	ExecHint string `json:"exec_hint,omitempty"`
}

// flagSlice collects repeated string flags so callers can pass -service multiple times.
type flagSlice []string

func (f *flagSlice) String() string     { return strings.Join(*f, ",") }
func (f *flagSlice) Set(v string) error { *f = append(*f, v); return nil }

// parseServiceFlag splits a "name=host:port" value. Whitespace around the name
// and target is trimmed; the host:port is validated.
func parseServiceFlag(raw string) (shareService, error) {
	eq := strings.IndexByte(raw, '=')
	if eq <= 0 {
		return shareService{}, fmt.Errorf("service %q must be name=host:port", raw)
	}
	name := strings.TrimSpace(raw[:eq])
	target := strings.TrimSpace(raw[eq+1:])
	if name == "" || target == "" {
		return shareService{}, fmt.Errorf("service %q must be name=host:port", raw)
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return shareService{}, fmt.Errorf("service %q: bad target: %w", raw, err)
	}
	return shareService{Name: name, Target: target}, nil
}

// deriveExecHint guesses a sensible guest-side command from a host:port target
// so the guest does not have to remember the protocol. The returned string may
// contain "{port}" which the guest substitutes with its local forwarded port.
func deriveExecHint(target string) string {
	_, p, err := net.SplitHostPort(target)
	if err != nil {
		return ""
	}
	switch p {
	case "22":
		user := os.Getenv("USER")
		if user == "" {
			user = "root"
		}
		return "ssh " + user + "@127.0.0.1 -p {port}"
	case "5432":
		return "psql -h 127.0.0.1 -p {port}"
	case "3306":
		return "mysql -h 127.0.0.1 -P {port} -u root"
	case "6379":
		return "redis-cli -p {port}"
	case "27017":
		return "mongosh mongodb://127.0.0.1:{port}"
	case "80", "443", "3000", "8000", "8080":
		return "open http://127.0.0.1:{port}"
	}
	return ""
}

func cmdShare(args []string) {
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	port := fs.Int("port", 0, "local port to forward; sets target to 127.0.0.1:<port>")
	target := fs.String("target", "", "host:port the guest will reach (alternative to -port)")
	var services flagSlice
	fs.Var(&services, "service", "named service to share, repeatable: -service name=host:port")
	reason := fs.String("reason", "", "reason shown to the host")
	expectedName := fs.String("expected-name", os.Getenv("USER"), "the name you expect the guest to be")
	coordAddr := fs.String("coordinator", "", "coordinator mTLS address host:port (required)")
	serverName := fs.String("server-name", "", "coordinator certificate name (defaults to host part of -coordinator)")
	configDir := fs.String("config-dir", "", "config directory (defaults to $XDG_CONFIG_HOME/tessera)")
	ttl := fs.Duration("ttl", 90*time.Second, "share code TTL")
	maxDuration := fs.Duration("max-duration", 0, "kill the share session after this wall-clock duration regardless of activity (0 disables)")
	idleTimeout := fs.Duration("idle-timeout", 30*time.Minute, "close a stream after this much idle time (clamped to [1m, 24h] by the coordinator)")
	execHint := fs.String("exec-hint", "", "command the guest should run after connecting; {port} is replaced with the guest's local port. Single-service only; for -service use the port-based default. If empty, derived from the target port.")
	_ = fs.Parse(args)

	dir := *configDir
	if dir == "" {
		dir = defaultConfigDir()
	}
	if *coordAddr == "" {
		if c, _ := loadCoordinator(dir); c != nil {
			*coordAddr = c.MtlsAddr
		}
	}
	if *coordAddr == "" {
		fmt.Fprintln(os.Stderr, "share: -coordinator is required (run `tessera link` once to save it)")
		os.Exit(2)
	}
	var svcList []shareService
	switch {
	case len(services) > 0:
		if *port != 0 || *target != "" {
			fmt.Fprintln(os.Stderr, "share: -service cannot be combined with -port or -target")
			os.Exit(2)
		}
		for _, raw := range services {
			s, err := parseServiceFlag(raw)
			if err != nil {
				fmt.Fprintln(os.Stderr, "share:", err)
				os.Exit(2)
			}
			s.ExecHint = deriveExecHint(s.Target)
			svcList = append(svcList, s)
		}
		if len(svcList) > 1 && *execHint != "" {
			fmt.Fprintln(os.Stderr, "share: -exec-hint is only supported with a single service")
			os.Exit(2)
		}
		if len(svcList) == 1 && *execHint != "" {
			svcList[0].ExecHint = *execHint
		}
	default:
		resolvedTarget := *target
		if resolvedTarget == "" {
			if *port == 0 {
				fmt.Fprintln(os.Stderr, "share: pass -port, -target, or -service")
				os.Exit(2)
			}
			resolvedTarget = fmt.Sprintf("127.0.0.1:%d", *port)
		}
		hint := *execHint
		if hint == "" {
			hint = deriveExecHint(resolvedTarget)
		}
		svcList = []shareService{{Name: "default", Target: resolvedTarget, ExecHint: hint}}
	}
	allowed := make([]string, 0, len(svcList))
	for _, s := range svcList {
		allowed = append(allowed, s.Target)
	}
	name := *serverName
	if name == "" {
		host, _, err := net.SplitHostPort(*coordAddr)
		check(err)
		name = host
	}

	hostID, ca, err := certs.LoadPair(
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "agent.crt"),
		filepath.Join(dir, "agent.key"),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, normalizeErr(err, "", filepath.Join(dir, "agent.crt")))
		os.Exit(1)
	}
	caID, err := certs.Load(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	check(err)

	shareID := "share-" + randomTag(6)
	agentName := "agent-" + randomTag(6)
	guestName := "guest-" + randomTag(6)

	agentID, err := certs.Issue(caID, agentName, agentName)
	check(err)
	guestID, err := certs.Issue(caID, guestName, guestName)
	check(err)

	// The host's own cert anchors both the agent registration and the share
	// upload so the coordinator can pin the share-id to a single identity.
	outer, err := certs.ClientTLS(hostID, ca, name)
	check(err)
	inner, err := certs.ServerTLS(agentID, ca)
	check(err)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dial := netutil.Dialer(func() (net.Conn, error) { return tls.Dial("tcp", *coordAddr, outer) })
	ag := &agent.Agent{
		ShareID: shareID,
		Dial:    dial,
		Allowed: allowed,
		Inner:   inner,
		Logger:  log,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		for ctx.Err() == nil {
			if err := ag.Run(ctx); err != nil && ctx.Err() == nil {
				time.Sleep(2 * time.Second)
			}
		}
	}()

	ttlSecs := int(ttl.Seconds())
	if ttlSecs < 10 {
		ttlSecs = 10
	}
	if ttlSecs > 600 {
		ttlSecs = 600
	}

	body, err := json.Marshal(shareRequest{
		CAcert:             string(ca.Cert),
		GuestCert:          string(guestID.Cert),
		GuestKey:           string(guestID.Key),
		CoordAddr:          *coordAddr,
		ServerName:         name,
		AgentName:          agentName,
		ShareID:            shareID,
		Services:           svcList,
		ExpectedName:       *expectedName,
		Reason:             *reason,
		TTLSeconds:         ttlSecs,
		IdleTimeoutSeconds: int(idleTimeout.Seconds()),
	})
	check(err)

	code, err := uploadShare(ctx, *coordAddr, outer, string(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	printCodeBox(code, ttlSecs)

	approveLoop(ctx, *coordAddr, name, shareID, *expectedName, svcList, hostID, ca, time.Duration(ttlSecs)*time.Second, *maxDuration)
}

// uploadShare opens a fresh mTLS connection to the coordinator and sends one
// KindShareUpload frame, retrying briefly so the share-id pin lands on the same
// cert as the agent's registration (which races on a separate goroutine).
func uploadShare(ctx context.Context, coordAddr string, outer *tls.Config, body string) (string, error) {
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		code, err := uploadShareOnce(coordAddr, outer, body)
		if err == nil {
			return code, nil
		}
		lastErr = err
		if time.Now().After(deadline) || attempt > 20 {
			return "", fmt.Errorf("share upload failed: %w", lastErr)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func uploadShareOnce(coordAddr string, outer *tls.Config, body string) (string, error) {
	conn, err := tls.Dial("tcp", coordAddr, outer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := proto.WriteMsg(conn, proto.Msg{Kind: proto.KindShareUpload, Detail: body}); err != nil {
		return "", err
	}
	resp, err := proto.ReadMsg(conn)
	if err != nil {
		return "", err
	}
	if resp.Kind != proto.KindShareResponse {
		return "", fmt.Errorf("unexpected response kind %q", resp.Kind)
	}
	if resp.Detail != "" {
		return "", fmt.Errorf("%s", resp.Detail)
	}
	if resp.Code == "" {
		return "", fmt.Errorf("empty share code")
	}
	return resp.Code, nil
}

func printCodeBox(code string, ttlSecs int) {
	inner := fmt.Sprintf("     %s     ", code)
	border := strings.Repeat("─", len(inner))
	pad := strings.Repeat(" ", len(inner))
	fmt.Println()
	fmt.Printf("   ┌%s┐\n", border)
	fmt.Printf("   │%s│\n", pad)
	fmt.Printf("   │%s│\n", inner)
	fmt.Printf("   │%s│\n", pad)
	fmt.Printf("   └%s┘\n", border)
	fmt.Println()
	fmt.Println("Share this code with your guest (any channel: phone, chat, in person).")
	fmt.Printf("Code expires in %d seconds.\n", ttlSecs)
	fmt.Println()
	fmt.Println("Waiting for the guest to connect...")
}

// formatServices renders the bundle's services for the host's approval prompt.
// Names and targets are host-provided, but sanitize anyway for symmetry.
func formatServices(list []shareService) string {
	parts := make([]string, 0, len(list))
	for _, s := range list {
		parts = append(parts, fmt.Sprintf("%s (%s)", sanitize(s.Name), sanitize(s.Target)))
	}
	return strings.Join(parts, ", ")
}

// sanitize strips ASCII control bytes and caps length, so a guest can't
// smuggle ANSI escapes into the host's terminal prompt.
func sanitize(s string) string {
	const max = 200
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
		if b.Len() >= max {
			b.WriteString("...")
			break
		}
	}
	return b.String()
}

func approveLoop(ctx context.Context, coordAddr, serverName, shareID, expectedName string, svcList []shareService, hostID, ca certs.Identity, ttl, maxDuration time.Duration) {
	cfg, err := certs.ClientTLS(hostID, ca, serverName)
	check(err)

	conn, err := tls.Dial("tcp", coordAddr, cfg)
	check(err)
	defer conn.Close()

	check(proto.WriteMsg(conn, proto.Msg{Kind: proto.KindApprovalSubscribe, ShareID: shareID}))

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	msgs := make(chan proto.Msg, 16)
	go func() {
		defer close(msgs)
		for {
			m, err := proto.ReadMsg(conn)
			if err != nil {
				return
			}
			switch m.Kind {
			case proto.KindApprovalPrompt, proto.KindSessionEnded:
				msgs <- m
			}
		}
	}()

	timer := time.NewTimer(ttl)
	defer timer.Stop()

	var maxC <-chan time.Time
	if maxDuration > 0 {
		maxT := time.NewTimer(maxDuration)
		defer maxT.Stop()
		maxC = maxT.C
	}

	var firstSeen bool

	in := bufio.NewReader(os.Stdin)
	for {
		select {
		case m, ok := <-msgs:
			if !ok {
				return
			}
			switch m.Kind {
			case proto.KindApprovalPrompt:
				if !firstSeen {
					firstSeen = true
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
				}
				warn := ""
				if !strings.EqualFold(strings.TrimSpace(m.Who), strings.TrimSpace(expectedName)) {
					warn = "WARNING: name mismatch. "
				}
				fmt.Printf("\n%s%s (expected: %s) wants access to share %s services: %s. Reason: %s. approve? [y/N] ",
					warn, sanitize(m.Who), sanitize(expectedName), sanitize(shareID), formatServices(svcList), sanitize(m.Reason))
				line, err := in.ReadString('\n')
				if err != nil {
					return
				}
				approved := strings.EqualFold(strings.TrimSpace(line), "y")
				out := proto.Msg{Kind: proto.KindApprovalDecision, RequestID: m.RequestID, Approved: approved}
				if !approved {
					out.Detail = "denied by host"
				}
				if err := proto.WriteMsg(conn, out); err != nil {
					fmt.Fprintln(os.Stderr, err)
					return
				}
			case proto.KindSessionEnded:
				if firstSeen {
					fmt.Fprintln(os.Stderr, "session ended; tessera share exiting")
					return
				}
			}
		case <-timer.C:
			if !firstSeen {
				fmt.Fprintf(os.Stderr, "share code expired; no guest joined within %ds\n", int(ttl.Seconds()))
				return
			}
		case <-maxC:
			fmt.Fprintln(os.Stderr, "max duration reached; tessera share exiting")
			return
		}
	}
}

const tagAlphabet = "23456789abcdefghjkmnpqrstvwxyz"

func randomTag(n int) string {
	out := make([]byte, n)
	bound := big.NewInt(int64(len(tagAlphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, bound)
		check(err)
		out[i] = tagAlphabet[v.Int64()]
	}
	return string(out)
}
