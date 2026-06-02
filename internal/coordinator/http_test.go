package coordinator

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
	return New(log, "http://test", func() (net.Listener, error) { return nil, nil })
}

func TestApproveRequiresToken(t *testing.T) {
	c := newTestCoordinator(t)
	req := &request{id: "rid", token: "secret-token", shareID: "demo", target: "t", who: "w", decided: make(chan decision, 1)}
	c.requests[req.id] = req
	srv := httptest.NewServer(c.httpMux())
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/a/rid/approve", url.Values{"t": {"wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong token = %d, want 403", resp.StatusCode)
	}
	select {
	case <-req.decided:
		t.Fatal("approved with the wrong token")
	default:
	}

	resp, err = http.PostForm(srv.URL+"/a/rid/approve", url.Values{"t": {"secret-token"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("correct token = %d, want 200", resp.StatusCode)
	}
	select {
	case d := <-req.decided:
		if !d.approved {
			t.Fatal("expected an approved decision")
		}
	default:
		t.Fatal("expected a decision")
	}
}

func TestApprovalPageRendersOnlyForKnownID(t *testing.T) {
	c := newTestCoordinator(t)
	c.requests["rid"] = &request{id: "rid", token: "tok", decided: make(chan decision, 1)}
	srv := httptest.NewServer(c.httpMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/a/unknown-id")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/a/rid")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("known id = %d, want 200", resp.StatusCode)
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
