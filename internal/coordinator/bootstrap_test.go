package coordinator

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emmayusufu/tessera/internal/audit"
)

func newTestStore(t *testing.T) (*bootstrapStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	return newBootstrapStore(log, nil), path
}

func TestBootstrapCodeFormat(t *testing.T) {
	allowed := bootstrapAlphabet + "-"
	for i := 0; i < 1000; i++ {
		code, err := newCode()
		if err != nil {
			t.Fatalf("newCode: %v", err)
		}
		if len(code) != 9 {
			t.Fatalf("code %q length = %d, want 9", code, len(code))
		}
		if code[4] != '-' {
			t.Fatalf("code %q missing hyphen at position 4", code)
		}
		if code != strings.ToUpper(code) {
			t.Fatalf("code %q is not uppercase", code)
		}
		for _, r := range code {
			if !strings.ContainsRune(allowed, r) {
				t.Fatalf("code %q has invalid char %q", code, r)
			}
		}
	}
}

func sampleBundle() *bootstrapBundle {
	return &bootstrapBundle{
		CAcert:       "ca",
		GuestCert:    "gc",
		GuestKey:     "gk",
		CoordAddr:    "coord:8443",
		ServerName:   "host.sslip.io",
		AgentName:    "agent",
		ShareID:      "demo",
		Target:       "127.0.0.1:22",
		ExpectedName: "host",
		Reason:       "ssh in",
	}
}

func TestBootstrapPutRedeem(t *testing.T) {
	s, _ := newTestStore(t)
	code, _, _, err := s.Put(sampleBundle(), 60*time.Second)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	b, found, used := s.Redeem(code)
	if !found || used {
		t.Fatalf("first redeem: found=%v used=%v, want true,false", found, used)
	}
	if b.ShareID != "demo" || b.Target != "127.0.0.1:22" || b.CAcert != "ca" {
		t.Fatalf("bundle fields wrong: %+v", b)
	}

	_, found, used = s.Redeem(code)
	if !found || !used {
		t.Fatalf("second redeem: found=%v used=%v, want true,true", found, used)
	}
}

func TestBootstrapRedeemUnknown(t *testing.T) {
	s, _ := newTestStore(t)
	_, found, _ := s.Redeem("ZZZZ-ZZZZ")
	if found {
		t.Fatal("Redeem of unknown code returned found=true")
	}
}

func TestBootstrapExpired(t *testing.T) {
	s, _ := newTestStore(t)
	code, _, _, err := s.Put(sampleBundle(), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	// Bundles stay in the map until the janitor sweeps them, so an expired
	// code that has never been redeemed surfaces as found=true, used=true.
	_, found, used := s.Redeem(code)
	if !found {
		return
	}
	if !used {
		t.Fatalf("expired redeem: found=true used=false, want used=true")
	}
}

func TestBootstrapNormalize(t *testing.T) {
	s, _ := newTestStore(t)
	code, canonical, _, err := s.Put(sampleBundle(), 60*time.Second)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	stripped := strings.ReplaceAll(code, "-", "")
	lowered := strings.ToLower(code)

	forms := []string{code, stripped, lowered}
	for i, form := range forms {
		n := normalizeCode(form)
		if n != canonical {
			t.Fatalf("form %d (%q) normalized to %q, want %q", i, form, n, canonical)
		}
	}

	if _, found, used := s.Redeem(code); !found || used {
		t.Fatalf("hyphenated upper: found=%v used=%v", found, used)
	}

	s2, _ := newTestStore(t)
	code2, _, _, err := s2.Put(sampleBundle(), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, used := s2.Redeem(strings.ReplaceAll(code2, "-", "")); !found || used {
		t.Fatalf("unhyphenated upper: found=%v used=%v", found, used)
	}

	s3, _ := newTestStore(t)
	code3, _, _, err := s3.Put(sampleBundle(), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, used := s3.Redeem(strings.ToLower(code3)); !found || used {
		t.Fatalf("hyphenated lower: found=%v used=%v", found, used)
	}
}

func readAuditKinds(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var kinds []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		var e audit.Event
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatalf("audit decode: %v", err)
		}
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

func TestBootstrapJanitorWritesExpired(t *testing.T) {
	s, path := newTestStore(t)
	if _, _, _, err := s.Put(sampleBundle(), 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.Put(sampleBundle(), 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	s.sweep()

	kinds := readAuditKinds(t, path)
	var expired int
	for _, k := range kinds {
		if k == "bootstrap_expired" {
			expired++
		}
	}
	if expired != 2 {
		t.Fatalf("bootstrap_expired events = %d, want 2 (kinds=%v)", expired, kinds)
	}
}
