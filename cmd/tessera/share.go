package main

import (
	"bufio"
	"bytes"
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
	"net/http"
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
	CAcert       string `json:"ca_cert"`
	GuestCert    string `json:"guest_cert"`
	GuestKey     string `json:"guest_key"`
	CoordAddr    string `json:"coord_addr"`
	ServerName   string `json:"server_name"`
	AgentName    string `json:"agent_name"`
	ShareID      string `json:"share_id"`
	Target       string `json:"target"`
	ExpectedName string `json:"expected_name"`
	Reason       string `json:"reason"`
	TTLSeconds   int    `json:"ttl_seconds"`
}

type shareResponse struct {
	Code      string `json:"code"`
	ExpiresAt string `json:"expires_at"`
}

func cmdShare(args []string) {
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	port := fs.Int("port", 0, "local port to forward; sets target to 127.0.0.1:<port>")
	target := fs.String("target", "", "host:port the guest will reach (alternative to -port)")
	reason := fs.String("reason", "", "reason shown to the host")
	expectedName := fs.String("expected-name", os.Getenv("USER"), "the name you expect the guest to be")
	coordAddr := fs.String("coordinator", "", "coordinator mTLS address host:port (required)")
	serverName := fs.String("server-name", "", "coordinator certificate name (defaults to host part of -coordinator)")
	coordBase := fs.String("coord-base-url", "", "HTTP(S) base URL for /share + /redeem (required)")
	configDir := fs.String("config-dir", "", "config directory (defaults to $XDG_CONFIG_HOME/tessera)")
	operatorToken := fs.String("operator-token", "", "operator token for /share (falls back to TESSERA_OPERATOR_TOKEN, then <config-dir>/operator-token)")
	ttl := fs.Duration("ttl", 90*time.Second, "share code TTL")
	_ = fs.Parse(args)

	dir := *configDir
	if dir == "" {
		dir = defaultConfigDir()
	}
	if *coordAddr == "" || *coordBase == "" {
		if c, _ := loadCoordinator(dir); c != nil {
			if *coordAddr == "" {
				*coordAddr = c.MtlsAddr
			}
			if *coordBase == "" {
				*coordBase = c.BaseURL
			}
		}
	}
	if *coordAddr == "" || *coordBase == "" {
		fmt.Fprintln(os.Stderr, "share: -coordinator and -coord-base-url are required (run `tessera link` once to save them)")
		os.Exit(2)
	}
	resolvedTarget := *target
	if resolvedTarget == "" {
		if *port == 0 {
			fmt.Fprintln(os.Stderr, "share: pass -port or -target")
			os.Exit(2)
		}
		resolvedTarget = fmt.Sprintf("127.0.0.1:%d", *port)
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

	outer, err := certs.ClientTLS(agentID, ca, name)
	check(err)
	inner, err := certs.ServerTLS(agentID, ca)
	check(err)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dial := netutil.Dialer(func() (net.Conn, error) { return tls.Dial("tcp", *coordAddr, outer) })
	ag := &agent.Agent{
		ShareID: shareID,
		Dial:    dial,
		Allowed: []string{resolvedTarget},
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
	time.Sleep(500 * time.Millisecond)

	ttlSecs := int(ttl.Seconds())
	if ttlSecs < 10 {
		ttlSecs = 10
	}
	if ttlSecs > 600 {
		ttlSecs = 600
	}

	body, err := json.Marshal(shareRequest{
		CAcert:       string(ca.Cert),
		GuestCert:    string(guestID.Cert),
		GuestKey:     string(guestID.Key),
		CoordAddr:    *coordAddr,
		ServerName:   name,
		AgentName:    agentName,
		ShareID:      shareID,
		Target:       resolvedTarget,
		ExpectedName: *expectedName,
		Reason:       *reason,
		TTLSeconds:   ttlSecs,
	})
	check(err)

	httpTLS, err := certs.ClientTLS(hostID, ca, name)
	check(err)
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: httpTLS},
	}
	opToken, err := resolveOperatorToken(*operatorToken, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	shareURL := strings.TrimRight(*coordBase, "/") + "/share"
	httpReq, err := http.NewRequest(http.MethodPost, shareURL, bytes.NewReader(body))
	check(err)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+opToken)
	resp, err := client.Do(httpReq)
	check(err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "share upload failed: %s: %s\n", resp.Status, strings.TrimSpace(string(errBody)))
		os.Exit(1)
	}
	var sr shareResponse
	check(json.NewDecoder(resp.Body).Decode(&sr))

	printCodeBox(sr.Code, ttlSecs)

	approveLoop(ctx, *coordAddr, name, shareID, *expectedName, hostID, ca)
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

func approveLoop(ctx context.Context, coordAddr, serverName, shareID, expectedName string, hostID, ca certs.Identity) {
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

	prompts := make(chan proto.Msg, 16)
	go func() {
		defer close(prompts)
		for {
			m, err := proto.ReadMsg(conn)
			if err != nil {
				return
			}
			if m.Kind == proto.KindApprovalPrompt {
				prompts <- m
			}
		}
	}()

	in := bufio.NewReader(os.Stdin)
	for m := range prompts {
		warn := ""
		if !strings.EqualFold(strings.TrimSpace(m.Who), strings.TrimSpace(expectedName)) {
			warn = "WARNING: name mismatch. "
		}
		fmt.Printf("\n%s%s (expected: %s) wants access to %s. Reason: %s. approve? [y/N] ",
			warn, m.Who, expectedName, m.Target, m.Reason)
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
	}
}

func resolveOperatorToken(flagVal, configDir string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if t := strings.TrimSpace(os.Getenv("TESSERA_OPERATOR_TOKEN")); t != "" {
		return t, nil
	}
	p := filepath.Join(configDir, "operator-token")
	if b, err := os.ReadFile(p); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf("operator token required. Provide one of: -operator-token <hex>, TESSERA_OPERATOR_TOKEN env, or write the token to %s (mode 0600 recommended)", p)
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
