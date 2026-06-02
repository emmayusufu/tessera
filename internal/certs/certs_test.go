package certs

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestMutualTLSHandshake(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Issue(ca, "coordinator", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := Issue(ca, "agent", "agent")
	if err != nil {
		t.Fatal(err)
	}

	sc, err := ServerTLS(server, ca)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := ClientTLS(clientID, ca, "localhost")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tln := tls.NewListener(ln, sc)
	go func() {
		c, err := tln.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), cc)
	if err != nil {
		t.Fatalf("mutual TLS dial failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("authenticated")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q", got)
	}
}

func TestRejectsUntrustedClient(t *testing.T) {
	ca, _ := NewCA()
	other, _ := NewCA()

	server, _ := Issue(ca, "coordinator", "localhost")
	rogue, _ := Issue(other, "rogue", "rogue")

	sc, _ := ServerTLS(server, ca)
	cc, _ := ClientTLS(rogue, other, "localhost")

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	tln := tls.NewListener(ln, sc)
	go func() {
		if c, err := tln.Accept(); err == nil {
			c.Close()
		}
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), cc)
	if err == nil {
		conn.Close()
		t.Fatal("expected handshake to fail for client signed by an untrusted CA")
	}
}
