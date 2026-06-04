package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/emmayusufu/tessera/internal/certs"
	"github.com/emmayusufu/tessera/internal/client"
	"github.com/emmayusufu/tessera/internal/netutil"
	"github.com/emmayusufu/tessera/internal/proto"
)

type redeemService struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	ExecHint string `json:"exec_hint,omitempty"`
}

type redeemResponse struct {
	CAcert       string          `json:"ca_cert"`
	GuestCert    string          `json:"guest_cert"`
	GuestKey     string          `json:"guest_key"`
	CoordAddr    string          `json:"coord_addr"`
	ServerName   string          `json:"server_name"`
	AgentName    string          `json:"agent_name"`
	ShareID      string          `json:"share_id"`
	Services     []redeemService `json:"services"`
	ExpectedName string          `json:"expected_name"`
	Reason       string          `json:"reason"`
}

type peekResponse struct {
	ExpectedName string   `json:"expected_name"`
	Reason       string   `json:"reason"`
	ServiceNames []string `json:"service_names"`
	ExpiresAt    string   `json:"expires_at"`
}

var codeAlphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"

func cmdJoin(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	baseURL := fs.String("coord-base-url", "", "HTTP(S) base URL of the coordinator's /redeem endpoint (required)")
	coordAddr := fs.String("coordinator", "", "coordinator mTLS host:port (defaults to base URL host + :8443)")
	local := fs.String("local", "127.0.0.1:13000", "local address to forward from")
	execCmd := fs.String("exec", "", "shell command to run after the tunnel opens; {port} is replaced with the local port. When the command exits, the tunnel closes.")
	serviceName := fs.String("service", "", "service name to connect to (required when the share offers more than one)")
	_ = fs.Parse(args)

	if *baseURL == "" || *coordAddr == "" {
		if c, _ := loadCoordinator(defaultConfigDir()); c != nil {
			if *baseURL == "" {
				*baseURL = c.BaseURL
			}
			if *coordAddr == "" {
				*coordAddr = c.MtlsAddr
			}
		}
	}
	if *baseURL == "" {
		fmt.Fprintln(os.Stderr, "join: -coord-base-url is required (run `tessera link` once to save it)")
		os.Exit(2)
	}

	in := bufio.NewReader(os.Stdin)
	var code string
	if fs.NArg() > 0 {
		code = fs.Arg(0)
	} else {
		fmt.Print("code: ")
		line, err := in.ReadString('\n')
		check(err)
		code = line
	}
	normalized, err := normalizeCode(code)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	dialAddr, err := deriveCoordAddr(*baseURL, *coordAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	peek, err := peekCode(*baseURL, normalized)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(peek.ServiceNames) == 0 {
		fmt.Fprintln(os.Stderr, "join: share has no services")
		os.Exit(1)
	}

	chosen, err := pickService(in, peek.ServiceNames, *serviceName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	bundle, err := redeem(*baseURL, normalized)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	svc, ok := findService(bundle.Services, chosen)
	if !ok {
		fmt.Fprintf(os.Stderr, "join: service %q not in bundle (got %v)\n", chosen, serviceNames(bundle.Services))
		os.Exit(1)
	}

	tmp, err := os.MkdirTemp("", "tessera-join-")
	check(err)
	defer os.RemoveAll(tmp)

	caPath := filepath.Join(tmp, "ca.crt")
	certPath := filepath.Join(tmp, "guest.crt")
	keyPath := filepath.Join(tmp, "guest.key")
	check(os.WriteFile(caPath, []byte(bundle.CAcert), 0o644))
	check(os.WriteFile(certPath, []byte(bundle.GuestCert), 0o644))
	check(os.WriteFile(keyPath, []byte(bundle.GuestKey), 0o600))

	defaultWho := os.Getenv("USER")
	if defaultWho == "" {
		defaultWho = "guest"
	}
	fmt.Printf("Your name [the host will see this] (%s): ", defaultWho)
	line, err := in.ReadString('\n')
	check(err)
	who := strings.TrimSpace(line)
	if who == "" {
		who = defaultWho
	}

	id, ca, err := certs.LoadPair(caPath, certPath, keyPath)
	check(err)
	outer, err := certs.ClientTLS(id, ca, bundle.ServerName)
	check(err)
	inner, err := certs.ClientTLS(id, ca, bundle.AgentName)
	check(err)

	dial := netutil.Dialer(func() (net.Conn, error) { return tls.Dial("tcp", dialAddr, outer) })

	fmt.Printf("Connecting to %s's machine for: %s...\n", cyan(bundle.ExpectedName), dim(bundle.Reason))
	sessionID, ctl, err := client.Request(dial, who, bundle.ShareID, svc.Target, bundle.Reason)
	if err != nil {
		fmt.Fprintln(os.Stderr, joinDialError(err, dialAddr))
		os.Exit(1)
	}
	defer ctl.Close()

	if svc.Target == "shell" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		fmt.Printf("approved. attaching shell [%s] (Ctrl-D or exit to end)\n", svc.Name)
		if err := runShellSession(ctx, dial, ctl, sessionID, inner); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("session ended.")
		return
	}

	ln, err := net.Listen("tcp", *local)
	check(err)
	fmt.Printf("approved. forwarding %s -> %s [%s] (Ctrl-C to end)\n", *local, svc.Target, svc.Name)

	localPort, portErr := extractPort(*local, ln)
	if *execCmd == "" && svc.ExecHint != "" {
		*execCmd = svc.ExecHint
	}
	if *execCmd == "" && portErr == nil && strings.HasSuffix(svc.Target, ":22") {
		fmt.Printf("Hint: ssh user@127.0.0.1 -p %s\n", localPort)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *execCmd != "" {
		if portErr != nil {
			fmt.Fprintln(os.Stderr, portErr)
			os.Exit(1)
		}
		forwardErrCh := make(chan error, 1)
		go func() {
			forwardErrCh <- client.Forward(ctx, dial, ctl, sessionID, ln, inner, slog.Default())
		}()

		time.Sleep(200 * time.Millisecond)

		subst := strings.ReplaceAll(*execCmd, "{port}", localPort)
		fmt.Printf("running: %s\n", subst)
		cmd := exec.CommandContext(ctx, "sh", "-c", subst)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		runErr := cmd.Run()
		stop()
		<-forwardErrCh

		fmt.Println("session ended.")
		if runErr != nil {
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintln(os.Stderr, runErr)
			os.Exit(1)
		}
		return
	}

	if err := client.Forward(ctx, dial, ctl, sessionID, ln, inner, slog.Default()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("session ended.")
}

func extractPort(local string, ln net.Listener) (string, error) {
	if _, p, err := net.SplitHostPort(local); err == nil && p != "" && p != "0" {
		return p, nil
	}
	if addr, ok := ln.Addr().(*net.TCPAddr); ok {
		return fmt.Sprintf("%d", addr.Port), nil
	}
	return "", fmt.Errorf("could not determine local port from %q", local)
}

func normalizeCode(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 8 {
		return "", fmt.Errorf("code must be 8 characters (got %d)", len(s))
	}
	for _, r := range s {
		if !strings.ContainsRune(codeAlphabet, r) {
			return "", fmt.Errorf("code contains invalid character %q", r)
		}
	}
	return s, nil
}

func deriveCoordAddr(baseURL, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid -coord-base-url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("invalid -coord-base-url: missing host")
	}
	return net.JoinHostPort(host, "8443"), nil
}

func pickService(in *bufio.Reader, names []string, requested string) (string, error) {
	if requested != "" {
		for _, n := range names {
			if n == requested {
				return n, nil
			}
		}
		return "", fmt.Errorf("service %q not offered; available: %s", requested, strings.Join(names, ", "))
	}
	if len(names) == 1 {
		return names[0], nil
	}
	fmt.Printf("Services: %s\n", strings.Join(names, ", "))
	fmt.Printf("Pick one [%s]: ", strings.Join(names, "/"))
	line, err := in.ReadString('\n')
	if err != nil {
		return "", err
	}
	pick := strings.TrimSpace(line)
	for _, n := range names {
		if n == pick {
			return n, nil
		}
	}
	return "", fmt.Errorf("unknown service %q; available: %s", pick, strings.Join(names, ", "))
}

func findService(list []redeemService, name string) (redeemService, bool) {
	for _, s := range list {
		if s.Name == name {
			return s, true
		}
	}
	return redeemService{}, false
}

func serviceNames(list []redeemService) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.Name)
	}
	return out
}

func peekCode(baseURL, code string) (*peekResponse, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/peek/" + code
	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Get(endpoint)
	if err != nil {
		return nil, redeemDialError(err, baseURL)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errors.New(red("code not recognized; ask the host to re-run `tessera share`"))
	case http.StatusGone:
		return nil, errors.New(red("code already used or expired; ask the host for a new one"))
	case http.StatusLocked:
		return nil, errors.New(red("too many wrong attempts; try again in a few minutes"))
	case http.StatusTooManyRequests:
		return nil, errors.New(red("rate limited; wait a moment"))
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("peek failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var out peekResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding peek response: %w", err)
	}
	return &out, nil
}

func redeem(baseURL, code string) (*redeemResponse, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/redeem/" + code
	httpClient := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, redeemDialError(err, baseURL)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errors.New(red("code not recognized; ask the host to re-run `tessera share`"))
	case http.StatusGone:
		return nil, errors.New(red("code already used; ask the host for a new one"))
	case http.StatusLocked:
		return nil, errors.New(red("too many wrong attempts; try again in a few minutes"))
	case http.StatusTooManyRequests:
		return nil, errors.New(red("rate limited; wait a moment"))
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("redeem failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var out redeemResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding redeem response: %w", err)
	}
	return &out, nil
}

func redeemDialError(err error, baseURL string) error {
	s := err.Error()
	if strings.Contains(s, "timeout") || strings.Contains(s, "deadline") || strings.Contains(s, "refused") || strings.Contains(s, "no such host") {
		return fmt.Errorf("could not reach the coordinator at %s; check your internet connection", baseURL)
	}
	return err
}

func joinDialError(err error, addr string) string {
	s := err.Error()
	if strings.Contains(s, "refused") || strings.Contains(s, "timeout") || strings.Contains(s, "no such host") {
		return fmt.Sprintf("could not reach the coordinator at %s; check your internet connection", addr)
	}
	return s
}

// runShellSession opens one inner-TLS data stream, sends the initial terminal
// size as an 8-byte header (rows, cols big-endian uint32), then pipes the
// local terminal in raw mode against the remote PTY. Mid-session resize is
// not propagated; quit and reopen if the window changes.
func runShellSession(ctx context.Context, dial netutil.Dialer, ctl net.Conn, sessionID string, inner *tls.Config) error {
	if inner == nil {
		return fmt.Errorf("shell: inner TLS config is required")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		for {
			if _, err := proto.ReadMsg(ctl); err != nil {
				cancel()
				return
			}
		}
	}()

	data, err := dial()
	if err != nil {
		return fmt.Errorf("shell dial: %w", err)
	}
	defer data.Close()

	if err := proto.WriteMsg(data, proto.Msg{Kind: proto.KindDataHello, Role: "guest", SessionID: sessionID}); err != nil {
		return fmt.Errorf("shell hello: %w", err)
	}

	ic := tls.Client(data, inner)
	hsCtx, hsCancel := context.WithTimeout(ctx, 15*time.Second)
	err = ic.HandshakeContext(hsCtx)
	hsCancel()
	if err != nil {
		return fmt.Errorf("shell inner TLS handshake: %w", err)
	}
	defer ic.Close()

	rows, cols := terminalSize()
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(rows))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(cols))
	if _, err := ic.Write(hdr[:]); err != nil {
		return fmt.Errorf("shell size header: %w", err)
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Fprintln(os.Stderr, yellow("warning: stdin is not a terminal; shell mode requires an interactive session"))
		return fmt.Errorf("shell: stdin is not a terminal")
	}
	st, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintln(os.Stderr, yellow(fmt.Sprintf("warning: could not set raw mode: %v; output may show duplicated keystrokes", err)))
	} else {
		defer func() { _ = term.Restore(fd, st) }()
	}

	go func() {
		<-ctx.Done()
		ic.Close()
	}()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(ic, os.Stdin)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, ic)
		done <- struct{}{}
	}()
	<-done
	return nil
}

func terminalSize() (rows, cols int) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		w, h, err := term.GetSize(fd)
		if err == nil {
			return h, w
		}
	}
	return 24, 80
}
