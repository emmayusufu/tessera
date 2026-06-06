package coordinator

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmayusufu/tessera/internal/audit"
)

func newTestCoordinator(t *testing.T) *Coordinator {
	t.Helper()
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	return New(log, func() (net.Listener, error) { return nil, nil })
}

func TestHealthzOK(t *testing.T) {
	c := newTestCoordinator(t)
	srv := httptest.NewServer(c.httpMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "ok ") {
		t.Fatalf("healthz body = %q, want prefix \"ok \"", string(body))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("healthz content-type = %q, want text/plain; charset=utf-8", ct)
	}
}

func TestRevokeRequiresOperatorToken(t *testing.T) {
	c := newTestCoordinator(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c.sessions["sid"] = &session{id: "sid", shareID: "demo", ctl: a, streams: map[net.Conn]struct{}{}}
	c.SetOperatorToken("op-secret")
	srv := httptest.NewServer(c.httpMux())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/s/sid/revoke", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("revoke without auth = %d, want 403", resp.StatusCode)
	}
	c.mu.Lock()
	_, still := c.sessions["sid"]
	c.mu.Unlock()
	if !still {
		t.Fatal("session removed without operator auth")
	}

	r, _ := http.NewRequest(http.MethodPost, srv.URL+"/s/sid/revoke", nil)
	r.Header.Set("Authorization", "Bearer op-secret")
	resp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke with auth = %d, want 200", resp.StatusCode)
	}
	c.mu.Lock()
	_, still = c.sessions["sid"]
	c.mu.Unlock()
	if still {
		t.Fatal("session not revoked with valid operator auth")
	}
}
