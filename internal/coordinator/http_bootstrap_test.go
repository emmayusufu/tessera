package coordinator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRedeemRoute(t *testing.T) {
	c := newTestCoordinator(t)
	code, _, _, err := c.bootstrap.Put(sampleBundle(), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.httpMux())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/redeem/"+code, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first redeem = %d, want 200", resp.StatusCode)
	}
	var got redeemResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ShareID != "demo" || got.Target != "127.0.0.1:22" {
		t.Fatalf("bundle fields wrong: %+v", got)
	}

	resp2, err := http.Post(srv.URL+"/redeem/"+code, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusGone {
		t.Fatalf("second redeem = %d, want 410", resp2.StatusCode)
	}
}

func TestRedeemRouteNotFound(t *testing.T) {
	c := newTestCoordinator(t)
	srv := httptest.NewServer(c.httpMux())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/redeem/UNKNOWN1", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown code = %d, want 404", resp.StatusCode)
	}
}

func TestRedeemRouteLockout(t *testing.T) {
	c := newTestCoordinator(t)
	srv := httptest.NewServer(c.httpMux())
	defer srv.Close()

	// Drive the per-code lockout directly; the IP rate limiter would otherwise
	// answer 429 before the lookup ran enough times to lock the id.
	normalized := normalizeCode("UNKNOWN1")
	for i := 0; i < idMaxFails; i++ {
		c.rl.idFail(normalized)
	}

	resp, err := http.Post(srv.URL+"/redeem/UNKNOWN1", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("locked code = %d, want 423", resp.StatusCode)
	}
}
