// Package agent runs on the host's side and serves approved streams to allowed local targets.
package agent

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/emmayusufu/tessera/internal/netutil"
	"github.com/emmayusufu/tessera/internal/proto"
)

const handshakeTimeout = 15 * time.Second

type Agent struct {
	ShareID string
	Dial    netutil.Dialer
	Allowed []string
	Inner   *tls.Config
	Logger  *slog.Logger
}

func (a *Agent) Run(ctx context.Context) error {
	log := a.Logger
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctl, err := a.Dial()
	if err != nil {
		return err
	}
	defer ctl.Close()

	if err := proto.WriteMsg(ctl, proto.Msg{Kind: proto.KindRegister, ShareID: a.ShareID}); err != nil {
		return err
	}
	log.Info("registered with coordinator", "share_id", a.ShareID)

	go func() {
		<-ctx.Done()
		ctl.Close()
	}()

	for {
		m, err := proto.ReadMsg(ctl)
		if err != nil {
			return err
		}
		if m.Kind == proto.KindOpenData {
			go a.serveStream(ctx, m, log)
		}
	}
}

func (a *Agent) serveStream(ctx context.Context, m proto.Msg, log *slog.Logger) {
	if !slices.Contains(a.Allowed, m.Target) {
		log.Warn("refused target not on allowlist", "target", m.Target)
		return
	}
	if a.Inner == nil {
		log.Error("no inner TLS config; refusing to serve unencrypted stream")
		return
	}

	data, err := a.Dial()
	if err != nil {
		log.Error("data dial to coordinator failed", "err", err)
		return
	}
	if err := proto.WriteMsg(data, proto.Msg{Kind: proto.KindDataHello, Role: "agent", ConnID: m.ConnID}); err != nil {
		data.Close()
		return
	}

	hsCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	inner := tls.Server(data, a.Inner)
	if err := inner.HandshakeContext(hsCtx); err != nil {
		log.Error("inner TLS handshake failed", "err", err)
		inner.Close()
		return
	}

	target, err := net.Dial("tcp", m.Target)
	if err != nil {
		log.Error("dial target failed", "target", m.Target, "err", err)
		inner.Close()
		return
	}
	log.Info("stream open", "target", m.Target)
	netutil.Pipe(inner, target)
	log.Info("stream closed", "target", m.Target)
}
