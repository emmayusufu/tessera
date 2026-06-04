// Command coordinator runs tessera's broker on a host with a public address.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/emmayusufu/tessera/internal/audit"
	"github.com/emmayusufu/tessera/internal/certs"
	"github.com/emmayusufu/tessera/internal/coordinator"
	"github.com/emmayusufu/tessera/internal/version"
)

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "coordinator: tessera broker. Accepts agent and guest mTLS connections and serves")
		fmt.Fprintln(out, "the bootstrap redeem/peek endpoints over HTTP. Relays approved sessions as opaque")
		fmt.Fprintln(out, "ciphertext (inner TLS terminates at the endpoints, not here).")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Usage: coordinator [-listen :8443] [-http :8080] [flags]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Flags:")
		flag.PrintDefaults()
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Environment:")
		fmt.Fprintln(out, "  TESSERA_OPERATOR_TOKEN   when set, enables the operator revoke endpoint")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Example:")
		fmt.Fprintln(out, "  coordinator -listen :8443 -http :8080 \\")
		fmt.Fprintln(out, "    -ca ca.crt -cert coordinator.crt -key coordinator.key \\")
		fmt.Fprintln(out, "    -http-cert fullchain.pem -http-key privkey.pem")
	}
	listenAddr := flag.String("listen", ":8443", "mTLS address for agents and guests")
	httpAddr := flag.String("http", ":8080", "address for the bootstrap redeem/peek and operator revoke endpoints")
	caFile := flag.String("ca", "ca.crt", "CA certificate")
	certFile := flag.String("cert", "coordinator.crt", "coordinator certificate")
	keyFile := flag.String("key", "coordinator.key", "coordinator private key")
	httpCert := flag.String("http-cert", "", "TLS certificate for the HTTP endpoints (enables HTTPS)")
	httpKey := flag.String("http-key", "", "TLS key for the HTTP endpoints")
	auditFile := flag.String("audit", "tessera-audit.jsonl", "append-only audit log path")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Version)
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	id, ca, err := certs.LoadPair(*caFile, *certFile, *keyFile)
	if err != nil {
		log.Error("load certificates", "err", err)
		os.Exit(1)
	}
	tlsConf, err := certs.ServerTLS(id, ca)
	if err != nil {
		log.Error("server TLS", "err", err)
		os.Exit(1)
	}

	auditLog, err := audit.Open(*auditFile)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			log.Error(fmt.Sprintf("audit log path %s is not writable; pass --audit /path/you/own", *auditFile), "err", err)
		} else {
			log.Error("open audit log", "err", err)
		}
		os.Exit(1)
	}
	defer auditLog.Close()

	listen := func() (net.Listener, error) { return tls.Listen("tcp", *listenAddr, tlsConf) }
	coord := coordinator.New(auditLog, listen)

	if opToken := os.Getenv("TESSERA_OPERATOR_TOKEN"); opToken != "" {
		coord.SetOperatorToken(opToken)
		log.Info("operator endpoints (revoke) require the operator token")
	} else {
		log.Info("operator endpoints (revoke) are disabled; set TESSERA_OPERATOR_TOKEN to enable")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("coordinator starting", "listen", *listenAddr, "http", *httpAddr, "https", *httpCert != "", "version", version.Version)
	if err := coord.Serve(ctx, *httpAddr, *httpCert, *httpKey); err != nil {
		log.Error("coordinator exited", "err", err)
		os.Exit(1)
	}
}
