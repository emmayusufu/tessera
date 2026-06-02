// Command tessera is the guest CLI: generate certs and request a forwarded session.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/emmayusufu/tessera/internal/certs"
	"github.com/emmayusufu/tessera/internal/client"
	"github.com/emmayusufu/tessera/internal/netutil"
	"github.com/emmayusufu/tessera/internal/proto"
	"github.com/emmayusufu/tessera/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		cmdInteractive(nil)
		return
	}
	switch os.Args[1] {
	case "ca":
		cmdCA(os.Args[2:])
	case "issue":
		cmdIssue(os.Args[2:])
	case "quickstart":
		cmdQuickstart(os.Args[2:])
	case "renew":
		cmdRenew(os.Args[2:])
	case "connect":
		cmdConnect(os.Args[2:])
	case "approve":
		cmdApprove(os.Args[2:])
	case "join":
		cmdJoin(os.Args[2:])
	case "share":
		cmdShare(os.Args[2:])
	case "token":
		cmdToken(os.Args[2:])
	case "link":
		cmdLink(os.Args[2:])
	case "interactive":
		cmdInteractive(os.Args[2:])
	case "version":
		fmt.Println(version.Version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tessera <ca|issue|quickstart|renew|connect|approve|share|join|token|link|interactive|version> [flags]")
	os.Exit(2)
}

func cmdCA(args []string) {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	host := fs.String("coordinator-name", "localhost", "DNS name on the coordinator certificate")
	agentName := fs.String("agent-name", "agent", "name on the agent certificate")
	guestName := fs.String("guest-name", "guest", "name on the guest certificate")
	dir := fs.String("out", ".", "directory to write certs into")
	_ = fs.Parse(args)

	ca, err := certs.NewCA()
	check(err)
	check(ca.Save(path(*dir, "ca.crt"), path(*dir, "ca.key")))

	for _, c := range []struct{ file, name string }{
		{"coordinator", *host},
		{"agent", *agentName},
		{"guest", *guestName},
	} {
		id, err := certs.Issue(ca, c.name, c.name)
		check(err)
		check(id.Save(path(*dir, c.file+".crt"), path(*dir, c.file+".key")))
	}
	fmt.Printf("wrote ca, coordinator, agent, guest certs to %s\n", *dir)
}

func cmdIssue(args []string) {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	name := fs.String("name", "", "name on the certificate, also the output file prefix (required)")
	caCert := fs.String("ca", "ca.crt", "CA certificate")
	caKey := fs.String("ca-key", "ca.key", "CA private key")
	dir := fs.String("out", ".", "directory to write the cert into")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "issue: -name is required")
		os.Exit(2)
	}
	ca, err := certs.Load(*caCert, *caKey)
	check(err)
	id, err := certs.Issue(ca, *name, *name)
	check(err)
	check(id.Save(path(*dir, *name+".crt"), path(*dir, *name+".key")))
	fmt.Printf("wrote %s.crt and %s.key to %s\n", *name, *name, *dir)
}

func cmdConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	coordAddr := fs.String("coordinator", "", "coordinator mTLS address host:port (required)")
	serverName := fs.String("server-name", "", "coordinator certificate name (defaults to host part of -coordinator)")
	shareID := fs.String("share-id", "", "share-id to request access from (required)")
	target := fs.String("target", "", "internal host:port to reach (required)")
	reason := fs.String("reason", "", "reason shown to the approver")
	who := fs.String("who", "guest", "your identity, shown to the approver")
	local := fs.String("local", "127.0.0.1:15432", "local address to forward from")
	agentName := fs.String("agent-name", "agent", "name on the agent's certificate (for end-to-end TLS)")
	caFile := fs.String("ca", "ca.crt", "CA certificate")
	certFile := fs.String("cert", "guest.crt", "guest certificate")
	keyFile := fs.String("key", "guest.key", "guest private key")
	_ = fs.Parse(args)

	if *coordAddr == "" {
		if c, _ := loadCoordinator(defaultConfigDir()); c != nil {
			*coordAddr = c.MtlsAddr
		}
	}
	if *coordAddr == "" || *shareID == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "connect: -coordinator, -share-id and -target are required")
		os.Exit(2)
	}
	name := *serverName
	if name == "" {
		host, _, err := net.SplitHostPort(*coordAddr)
		check(err)
		name = host
	}

	id, ca, err := certs.LoadPair(*caFile, *certFile, *keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, normalizeErr(err, *shareID, *caFile))
		os.Exit(1)
	}
	outer, err := certs.ClientTLS(id, ca, name)
	check(err)
	inner, err := certs.ClientTLS(id, ca, *agentName)
	check(err)

	dial := netutil.Dialer(func() (net.Conn, error) { return tls.Dial("tcp", *coordAddr, outer) })

	fmt.Printf("requesting access to %s at %s, waiting for approval...\n", *target, *shareID)
	sessionID, ctl, err := client.Request(dial, *who, *shareID, *target, *reason)
	if err != nil {
		fmt.Fprintln(os.Stderr, normalizeErr(err, *shareID, *caFile))
		os.Exit(1)
	}
	defer ctl.Close()

	ln, err := net.Listen("tcp", *local)
	check(err)
	fmt.Printf("approved. forwarding %s -> %s (Ctrl-C to end)\n", *local, *target)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := client.Forward(ctx, dial, ctl, sessionID, ln, inner, slog.Default()); err != nil {
		fmt.Fprintln(os.Stderr, normalizeErr(err, *shareID, *caFile))
		os.Exit(1)
	}
	fmt.Println("session ended.")
}

func cmdQuickstart(args []string) {
	fs := flag.NewFlagSet("quickstart", flag.ExitOnError)
	out := fs.String("out", "", "directory to write certs into (defaults to $XDG_CONFIG_HOME/tessera)")
	_ = fs.Parse(args)

	dir := *out
	if dir == "" {
		dir = defaultConfigDir()
	}
	check(os.MkdirAll(dir, 0o700))

	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")

	var ca certs.Identity
	if _, err := os.Stat(caCert); errors.Is(err, os.ErrNotExist) {
		fresh, err := certs.NewCA()
		check(err)
		check(fresh.Save(caCert, caKey))
		ca = fresh
	} else {
		check(err)
		loaded, err := certs.Load(caCert, caKey)
		check(err)
		ca = loaded
	}

	for _, c := range []struct{ file, name string }{
		{"coordinator", "localhost"},
		{"agent", "agent"},
		{"guest", "guest"},
	} {
		id, err := certs.Issue(ca, c.name, c.name)
		check(err)
		check(id.Save(filepath.Join(dir, c.file+".crt"), filepath.Join(dir, c.file+".key")))
	}

	fmt.Printf("wrote certs to %s\n", dir)
	fmt.Println("share-id: demo")
	fmt.Println("next step:")
	fmt.Printf("  ./coordinator -listen :8443 -http :8080 -base-url http://localhost:8080 \\\n"+
		"    -ca %s/ca.crt -cert %s/coordinator.crt -key %s/coordinator.key\n", dir, dir, dir)
	fmt.Printf("  ./agent -coordinator localhost:8443 -share-id demo \\\n"+
		"    -allow 127.0.0.1:5432 -ca %s/ca.crt -cert %s/agent.crt -key %s/agent.key\n", dir, dir, dir)
	fmt.Printf("  ./tessera connect -coordinator localhost:8443 -share-id demo \\\n"+
		"    -target 127.0.0.1:5432 -reason \"test\" \\\n"+
		"    -ca %s/ca.crt -cert %s/guest.crt -key %s/guest.key\n", dir, dir, dir)
}

func cmdRenew(args []string) {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	dir := fs.String("ca-dir", "", "directory holding ca.crt/ca.key (defaults to $XDG_CONFIG_HOME/tessera)")
	caCert := fs.String("ca", "", "CA certificate path (overrides -ca-dir)")
	caKey := fs.String("ca-key", "", "CA private key path (overrides -ca-dir)")
	_ = fs.Parse(args)

	resolved := *dir
	if resolved == "" {
		resolved = defaultConfigDir()
	}
	certPath := *caCert
	keyPath := *caKey
	if certPath == "" {
		certPath = filepath.Join(resolved, "ca.crt")
	}
	if keyPath == "" {
		keyPath = filepath.Join(resolved, "ca.key")
	}

	ca, err := certs.Load(certPath, keyPath)
	check(err)

	for _, c := range []struct{ file, name string }{
		{"coordinator", "localhost"},
		{"agent", "agent"},
		{"guest", "guest"},
	} {
		id, err := certs.Issue(ca, c.name, c.name)
		check(err)
		check(id.Save(filepath.Join(resolved, c.file+".crt"), filepath.Join(resolved, c.file+".key")))
	}
	fmt.Printf("renewed coordinator, agent, guest certs in %s\n", resolved)
}

func cmdApprove(args []string) {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	coordAddr := fs.String("coordinator", "", "coordinator mTLS address host:port (required)")
	serverName := fs.String("server-name", "", "coordinator certificate name (defaults to host part of -coordinator)")
	shareID := fs.String("share-id", "", "share-id to receive approval prompts for")
	caFile := fs.String("ca", "ca.crt", "CA certificate")
	certFile := fs.String("cert", "agent.crt", "host certificate (same as the agent)")
	keyFile := fs.String("key", "agent.key", "host private key")
	_ = fs.Parse(args)

	if *coordAddr == "" {
		if c, _ := loadCoordinator(defaultConfigDir()); c != nil {
			*coordAddr = c.MtlsAddr
		}
	}
	if *coordAddr == "" {
		fmt.Fprintln(os.Stderr, "approve: -coordinator is required")
		os.Exit(2)
	}
	name := *serverName
	if name == "" {
		host, _, err := net.SplitHostPort(*coordAddr)
		check(err)
		name = host
	}

	id, ca, err := certs.LoadPair(*caFile, *certFile, *keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, normalizeErr(err, *shareID, *caFile))
		os.Exit(1)
	}
	cfg, err := certs.ClientTLS(id, ca, name)
	check(err)

	conn, err := tls.Dial("tcp", *coordAddr, cfg)
	check(err)
	defer conn.Close()

	check(proto.WriteMsg(conn, proto.Msg{Kind: proto.KindApprovalSubscribe, ShareID: *shareID}))
	fmt.Printf("subscribed to approval requests for share-id %s; press y to approve, n to deny, Ctrl-C to quit\n", *shareID)

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
		fmt.Printf("request %s: %s wants access to %s. reason: %s. approve? [y/N] ", m.RequestID, m.Who, m.Target, m.Reason)
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

func defaultConfigDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "tessera")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "tessera")
}

func normalizeErr(err error, shareID, certPath string) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such file"):
		return fmt.Sprintf("cert files not found at %s; did you run `tessera quickstart`?", certPath)
	case strings.Contains(s, "no agent online"):
		return fmt.Sprintf("no agent online for share-id %s; ask the host to run `tessera agent`", shareID)
	case strings.Contains(s, "certificate is valid for"):
		return "TLS hostname mismatch; pass -server-name to match the coordinator certificate"
	}
	return s
}

func path(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return dir + "/" + name
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
