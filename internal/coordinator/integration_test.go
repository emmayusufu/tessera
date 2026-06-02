package coordinator_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/emmayusufu/tessera/internal/agent"
	"github.com/emmayusufu/tessera/internal/audit"
	"github.com/emmayusufu/tessera/internal/certs"
	"github.com/emmayusufu/tessera/internal/client"
	"github.com/emmayusufu/tessera/internal/coordinator"
	"github.com/emmayusufu/tessera/internal/netutil"
	"github.com/emmayusufu/tessera/internal/proto"
)

func writeHello(conn net.Conn, sessionID string) error {
	return proto.WriteMsg(conn, proto.Msg{Kind: proto.KindDataHello, Role: "guest", SessionID: sessionID})
}

type env struct {
	coord       *coordinator.Coordinator
	addr        string
	ca          certs.Identity
	guestDial   netutil.Dialer
	agentDial   netutil.Dialer
	innerServer *tls.Config
	innerClient *tls.Config
}

func tlsDial(addr string, conf *tls.Config) netutil.Dialer {
	return func() (net.Conn, error) { return tls.Dial("tcp", addr, conf) }
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ca, err := certs.NewCA()
	must(t, err)
	coordID, err := certs.Issue(ca, "coordinator", "localhost")
	must(t, err)
	agentID, err := certs.Issue(ca, "agent", "agent")
	must(t, err)
	guestID, err := certs.Issue(ca, "guest", "guest")
	must(t, err)

	tcpln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	srvConf, err := certs.ServerTLS(coordID, ca)
	must(t, err)
	tlsln := tls.NewListener(tcpln, srvConf)

	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	must(t, err)
	t.Cleanup(func() { log.Close() })

	coord := coordinator.New(log, "http://test", func() (net.Listener, error) { return tlsln, nil })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go coord.Serve(ctx, "127.0.0.1:0", "", "")

	guestOuter, err := certs.ClientTLS(guestID, ca, "localhost")
	must(t, err)
	agentOuter, err := certs.ClientTLS(agentID, ca, "localhost")
	must(t, err)
	innerServer, err := certs.ServerTLS(agentID, ca)
	must(t, err)
	innerClient, err := certs.ClientTLS(guestID, ca, "agent")
	must(t, err)

	return &env{
		coord:       coord,
		addr:        tcpln.Addr().String(),
		ca:          ca,
		guestDial:   tlsDial(tcpln.Addr().String(), guestOuter),
		agentDial:   tlsDial(tcpln.Addr().String(), agentOuter),
		innerServer: innerServer,
		innerClient: innerClient,
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func echoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func runAgent(t *testing.T, e *env, ctx context.Context, allowed string) {
	t.Helper()
	ag := &agent.Agent{ShareID: "demo", Dial: e.agentDial, Allowed: []string{allowed}, Inner: e.innerServer}
	go func() { _ = ag.Run(ctx) }()
	waitFor(t, "agent registration", func() bool { return e.coord.AgentOnline("demo") })
}

func approveAndConnect(t *testing.T, e *env, target string) (sessionID string, ctl net.Conn) {
	t.Helper()
	type res struct {
		sid string
		ctl net.Conn
		err error
	}
	done := make(chan res, 1)
	go func() {
		sid, ctl, err := client.Request(e.guestDial, "emma", "demo", target, "troubleshoot")
		done <- res{sid, ctl, err}
	}()
	waitFor(t, "pending request", func() bool { return len(e.coord.PendingIDs()) == 1 })
	if !e.coord.Approve(e.coord.PendingIDs()[0]) {
		t.Fatal("approve failed")
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("request: %v", r.err)
		}
		return r.sid, r.ctl
	case <-time.After(3 * time.Second):
		t.Fatal("request never returned")
		return "", nil
	}
}

type recordConn struct {
	net.Conn
	mu  *sync.Mutex
	rec *bytes.Buffer
}

func (c recordConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		c.rec.Write(b[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c recordConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.rec.Write(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func TestEndToEndEncryptedForward(t *testing.T) {
	e := newEnv(t)
	echoAddr, stopEcho := echoServer(t)
	defer stopEcho()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runAgent(t, e, ctx, echoAddr)

	sid, ctl := approveAndConnect(t, e, echoAddr)
	defer ctl.Close()

	var mu sync.Mutex
	var seen bytes.Buffer
	recDial := func() (net.Conn, error) {
		c, err := e.guestDial()
		if err != nil {
			return nil, err
		}
		return recordConn{Conn: c, mu: &mu, rec: &seen}, nil
	}

	local, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	go func() { _ = client.Forward(ctx, recDial, ctl, sid, local, e.innerClient, nil) }()

	conn, err := net.Dial("tcp", local.Addr().String())
	must(t, err)
	defer conn.Close()

	secret := []byte("PLAINTEXT-MARKER-do-not-leak-9f3a2c")
	_, err = conn.Write(secret)
	must(t, err)
	got := make([]byte, len(secret))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("echo = %q, want %q", got, secret)
	}

	mu.Lock()
	captured := append([]byte(nil), seen.Bytes()...)
	mu.Unlock()
	if len(captured) == 0 {
		t.Fatal("recorded no bytes on the relay path")
	}
	if bytes.Contains(captured, secret) {
		t.Fatal("plaintext leaked through the relay: end-to-end encryption is not working")
	}
}

func TestSessionHijackRejected(t *testing.T) {
	e := newEnv(t)
	echoAddr, stopEcho := echoServer(t)
	defer stopEcho()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runAgent(t, e, ctx, echoAddr)

	sid, ctl := approveAndConnect(t, e, echoAddr)
	defer ctl.Close()

	attackerID, err := certs.Issue(e.ca, "attacker", "attacker")
	must(t, err)
	attackerOuter, err := certs.ClientTLS(attackerID, e.ca, "localhost")
	must(t, err)

	conn, err := tls.Dial("tcp", e.addr, attackerOuter)
	must(t, err)
	defer conn.Close()
	if err := writeHello(conn, sid); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, rerr := conn.Read(buf)
	if rerr == nil {
		t.Fatal("hijack attempt was not rejected: connection stayed open")
	}
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatal("hijack attempt was not rejected: connection neither relayed nor closed")
	}
}

func TestRevokeClosesLiveStream(t *testing.T) {
	e := newEnv(t)
	echoAddr, stopEcho := echoServer(t)
	defer stopEcho()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runAgent(t, e, ctx, echoAddr)

	sid, ctl := approveAndConnect(t, e, echoAddr)
	defer ctl.Close()

	local, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	go func() { _ = client.Forward(ctx, e.guestDial, ctl, sid, local, e.innerClient, nil) }()

	conn, err := net.Dial("tcp", local.Addr().String())
	must(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	must(t, err)
	got := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("stream not live before revoke: %v", err)
	}

	if !e.coord.Revoke(sid) {
		t.Fatal("revoke returned false for a live session")
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, rerr := conn.Read(got)
	if rerr == nil {
		t.Fatal("stream still open after revoke")
	}
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatal("revoke did not close the in-flight stream (timed out waiting for close)")
	}
}

func TestRequestDenied(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runAgent(t, e, ctx, "127.0.0.1:1")

	errc := make(chan error, 1)
	go func() {
		_, _, err := client.Request(e.guestDial, "emma", "demo", "127.0.0.1:1", "nope")
		errc <- err
	}()
	waitFor(t, "pending request", func() bool { return len(e.coord.PendingIDs()) == 1 })
	e.coord.Deny(e.coord.PendingIDs()[0], "not allowed")

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected denial error, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request never returned")
	}
}

func TestRequestNoAgent(t *testing.T) {
	e := newEnv(t)
	if _, _, err := client.Request(e.guestDial, "emma", "ghost", "127.0.0.1:1", "x"); err == nil {
		t.Fatal("expected error when no agent is online")
	}
}
