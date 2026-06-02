// Package client is the guest side: request access, then forward a local port through the coordinator.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/emmayusufu/tessera/internal/netutil"
	"github.com/emmayusufu/tessera/internal/proto"
)

const handshakeTimeout = 15 * time.Second

func Request(dial netutil.Dialer, who, shareID, target, reason string) (sessionID string, ctl net.Conn, err error) {
	ctl, err = dial()
	if err != nil {
		return "", nil, err
	}
	req := proto.Msg{Kind: proto.KindRequest, ShareID: shareID, Target: target, Reason: reason, Who: who}
	if err := proto.WriteMsg(ctl, req); err != nil {
		ctl.Close()
		return "", nil, err
	}
	d, err := proto.ReadMsg(ctl)
	if err != nil {
		ctl.Close()
		return "", nil, err
	}
	if d.Kind != proto.KindDecision || !d.Approved {
		ctl.Close()
		return "", nil, fmt.Errorf("access denied: %s", d.Detail)
	}
	return d.SessionID, ctl, nil
}

func Forward(ctx context.Context, dial netutil.Dialer, ctl net.Conn, sessionID string, ln net.Listener, inner *tls.Config, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if inner == nil {
		return fmt.Errorf("forward: inner TLS config is required for end-to-end encryption")
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
	go func() {
		<-ctx.Done()
		ln.Close()
		ctl.Close()
	}()

	log.Info("forwarding", "local", ln.Addr().String(), "session", sessionID)
	for {
		local, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go func() {
			data, err := dial()
			if err != nil {
				local.Close()
				return
			}
			if err := proto.WriteMsg(data, proto.Msg{Kind: proto.KindDataHello, Role: "guest", SessionID: sessionID}); err != nil {
				data.Close()
				local.Close()
				return
			}
			hsCtx, hcancel := context.WithTimeout(ctx, handshakeTimeout)
			ic := tls.Client(data, inner)
			err = ic.HandshakeContext(hsCtx)
			hcancel()
			if err != nil {
				log.Error("inner TLS handshake failed", "err", err)
				ic.Close()
				local.Close()
				return
			}
			netutil.Pipe(local, ic)
		}()
	}
}
