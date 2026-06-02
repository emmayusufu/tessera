// Command agent runs on the host's side and dials out to the coordinator.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/emmayusufu/tessera/internal/agent"
	"github.com/emmayusufu/tessera/internal/certs"
	"github.com/emmayusufu/tessera/internal/netutil"
	"github.com/emmayusufu/tessera/internal/version"
)

func main() {
	coordAddr := flag.String("coordinator", "", "coordinator mTLS address host:port (required)")
	serverName := flag.String("server-name", "", "coordinator certificate name (defaults to host part of -coordinator)")
	shareID := flag.String("share-id", "", "share-id this agent serves (required)")
	allowed := flag.String("allow", "", "comma-separated host:port targets the agent may reach (required)")
	caFile := flag.String("ca", "ca.crt", "CA certificate")
	certFile := flag.String("cert", "agent.crt", "agent certificate")
	keyFile := flag.String("key", "agent.key", "agent private key")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Version)
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	if *coordAddr == "" || *shareID == "" {
		log.Error("-coordinator and -share-id are required")
		os.Exit(2)
	}
	if strings.TrimSpace(*allowed) == "" {
		log.Error("-allow is required: list the host:port targets this agent may reach")
		os.Exit(2)
	}
	allowList := strings.Split(*allowed, ",")
	for i := range allowList {
		allowList[i] = strings.TrimSpace(allowList[i])
	}

	name := *serverName
	if name == "" {
		host, _, err := net.SplitHostPort(*coordAddr)
		if err != nil {
			log.Error("parse -coordinator", "err", err)
			os.Exit(2)
		}
		name = host
	}

	id, ca, err := certs.LoadPair(*caFile, *certFile, *keyFile)
	if err != nil {
		log.Error("load certificates", "err", normalizeErr(err, *coordAddr))
		os.Exit(1)
	}
	outer, err := certs.ClientTLS(id, ca, name)
	if err != nil {
		log.Error("client TLS", "err", err)
		os.Exit(1)
	}
	inner, err := certs.ServerTLS(id, ca)
	if err != nil {
		log.Error("inner TLS", "err", err)
		os.Exit(1)
	}

	dial := netutil.Dialer(func() (net.Conn, error) { return tls.Dial("tcp", *coordAddr, outer) })
	ag := &agent.Agent{ShareID: *shareID, Dial: dial, Allowed: allowList, Inner: inner, Logger: log}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for ctx.Err() == nil {
		if err := ag.Run(ctx); err != nil && ctx.Err() == nil {
			log.Warn("disconnected, retrying", "err", normalizeErr(err, *coordAddr))
			select {
			case <-time.After(3 * time.Second):
			case <-ctx.Done():
			}
		}
	}
}

func normalizeErr(err error, coordAddr string) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such file or directory"):
		return "cert files not found; run `tessera quickstart` on the host machine"
	case strings.Contains(s, "connection refused"):
		return fmt.Sprintf("coordinator unreachable at %s; check it is running", coordAddr)
	}
	return s
}
