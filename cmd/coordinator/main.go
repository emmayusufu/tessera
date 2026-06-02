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
	listenAddr := flag.String("listen", ":8443", "mTLS address for agents and guests")
	httpAddr := flag.String("http", ":8080", "address for the approval web page")
	baseURL := flag.String("base-url", "http://localhost:8080", "public URL prefix used in approval links")
	caFile := flag.String("ca", "ca.crt", "CA certificate")
	certFile := flag.String("cert", "coordinator.crt", "coordinator certificate")
	keyFile := flag.String("key", "coordinator.key", "coordinator private key")
	httpCert := flag.String("http-cert", "", "TLS certificate for the approval page (enables HTTPS)")
	httpKey := flag.String("http-key", "", "TLS key for the approval page")
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
	coord := coordinator.New(auditLog, *baseURL, listen)

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
