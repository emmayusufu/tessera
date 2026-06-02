package coordinator

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

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

func TestShareRouteRequiresOperatorToken(t *testing.T) {
	c := newTestCoordinator(t)
	srv := httptest.NewServer(c.httpMux())
	defer srv.Close()

	body := mustJSON(t, shareRequestBody{ShareID: "demo", Target: "127.0.0.1:22", TTLSeconds: 60})
	resp, err := http.Post(srv.URL+"/share", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("share without token configured = %d, want 503", resp.StatusCode)
	}

	c.SetOperatorToken("op-secret")
	resp, err = http.Post(srv.URL+"/share", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("share without auth header = %d, want 403", resp.StatusCode)
	}
}

func TestShareRouteRoundTrip(t *testing.T) {
	c := newTestCoordinator(t)
	c.SetOperatorToken("op-secret")
	srv := httptest.NewServer(c.httpMux())
	defer srv.Close()

	in := shareRequestBody{
		CAcert:       "ca-pem",
		GuestCert:    "guest-pem",
		GuestKey:     "guest-key-pem",
		CoordAddr:    "host:8443",
		ServerName:   "host.sslip.io",
		AgentName:    "agent",
		ShareID:      "demo",
		Target:       "127.0.0.1:22",
		ExpectedName: "host",
		Reason:       "ssh",
		TTLSeconds:   60,
	}
	body := mustJSON(t, in)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/share", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer op-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("share = %d, want 200 (body=%s)", resp.StatusCode, raw)
	}
	var sr shareResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		t.Fatalf("decode share resp: %v", err)
	}
	if len(sr.Code) != 9 || sr.Code[4] != '-' {
		t.Fatalf("code %q not canonical XXXX-XXXX", sr.Code)
	}
	if sr.Code != strings.ToUpper(sr.Code) {
		t.Fatalf("code %q not uppercase", sr.Code)
	}

	resp2, err := http.Post(srv.URL+"/redeem/"+sr.Code, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("redeem = %d, want 200", resp2.StatusCode)
	}
	var out redeemResponseBody
	if err := json.NewDecoder(resp2.Body).Decode(&out); err != nil {
		t.Fatalf("decode redeem: %v", err)
	}
	want := redeemResponseBody{
		CAcert:       in.CAcert,
		GuestCert:    in.GuestCert,
		GuestKey:     in.GuestKey,
		CoordAddr:    in.CoordAddr,
		ServerName:   in.ServerName,
		AgentName:    in.AgentName,
		ShareID:      in.ShareID,
		Target:       in.Target,
		ExpectedName: in.ExpectedName,
		Reason:       in.Reason,
	}
	if out != want {
		t.Fatalf("redeem body mismatch:\n got %+v\nwant %+v", out, want)
	}
}
