package coordinator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/emmayusufu/tessera/internal/audit"
)

const bootstrapAlphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"

type bundleService struct {
	Name   string
	Target string
	Kind   string
}

type bootstrapBundle struct {
	CAcert             string
	GuestCert          string
	GuestKey           string
	CoordAddr          string
	ServerName         string
	AgentName          string
	ShareID            string
	Services           []bundleService
	ExpectedName       string
	HostName           string
	Reason             string
	IdleTimeoutSeconds int

	expiresAt time.Time
	consumed  bool
}

func (b *bootstrapBundle) targetSummary() string {
	if len(b.Services) == 0 {
		return ""
	}
	if len(b.Services) == 1 {
		return b.Services[0].Target
	}
	parts := make([]string, 0, len(b.Services))
	for _, s := range b.Services {
		parts = append(parts, s.Name+"="+s.Target)
	}
	return strings.Join(parts, ",")
}

type bootstrapStore struct {
	mu      sync.Mutex
	bundles map[string]*bootstrapBundle
	audit   *audit.Log
	logger  *slog.Logger
}

func newBootstrapStore(a *audit.Log, l *slog.Logger) *bootstrapStore {
	return &bootstrapStore{bundles: map[string]*bootstrapBundle{}, audit: a, logger: l}
}

func (s *bootstrapStore) Put(b *bootstrapBundle, ttl time.Duration) (string, string, time.Time, error) {
	b.expiresAt = time.Now().Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()

	var code, canonical string
	for i := 0; i < 3; i++ {
		c, err := newCode()
		if err != nil {
			return "", "", time.Time{}, err
		}
		n := normalizeCode(c)
		if _, exists := s.bundles[n]; exists {
			continue
		}
		code, canonical = c, n
		break
	}
	if canonical == "" {
		return "", "", time.Time{}, errors.New("bootstrap: code allocation failed")
	}

	s.bundles[canonical] = b
	_ = s.audit.Write(audit.Event{
		Kind:    "bootstrap_minted",
		ShareID: b.ShareID,
		Target:  b.targetSummary(),
		Reason:  b.Reason,
		Token:   hashCode(canonical),
	})
	return code, canonical, b.expiresAt, nil
}

// peekView is the metadata subset returned by Peek. It deliberately omits
// the CA cert, the guest cert, the guest private key, and the coordinator
// address: those are only handed out at Redeem time, against a one-shot
// code, so a caller polling Peek can never extract a guest credential.
type peekView struct {
	ShareID      string
	ExpectedName string
	HostName     string
	Reason       string
	Services     []bundleService
	ExpiresAt    time.Time
}

// Peek returns metadata without consuming the code. Used by the guest CLI
// to fetch the services list before the user commits to redeeming. The
// return shape excludes secrets so a future caller cannot accidentally
// expose them by reading the bundle pointer.
func (s *bootstrapStore) Peek(code string) (peekView, bool, bool) {
	n := normalizeCode(code)

	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bundles[n]
	if !ok {
		return peekView{}, false, false
	}
	if b.consumed || !time.Now().Before(b.expiresAt) {
		return peekView{}, true, true
	}
	return peekView{
		ShareID:      b.ShareID,
		ExpectedName: b.ExpectedName,
		HostName:     b.HostName,
		Reason:       b.Reason,
		Services:     append([]bundleService(nil), b.Services...),
		ExpiresAt:    b.expiresAt,
	}, true, false
}

// Redeem returns (bundle, found, alreadyUsed). found=false means the code has
// never been seen. found=true with alreadyUsed=true means it was consumed or
// expired. Only a successful redemption emits a bootstrap_redeemed event.
func (s *bootstrapStore) Redeem(code string) (*bootstrapBundle, bool, bool) {
	n := normalizeCode(code)

	s.mu.Lock()
	b, ok := s.bundles[n]
	if !ok {
		s.mu.Unlock()
		return nil, false, false
	}
	if b.consumed || !time.Now().Before(b.expiresAt) {
		s.mu.Unlock()
		return nil, true, true
	}
	b.consumed = true
	s.mu.Unlock()

	_ = s.audit.Write(audit.Event{
		Kind:    "bootstrap_redeemed",
		ShareID: b.ShareID,
		Target:  b.targetSummary(),
		Reason:  b.Reason,
		Token:   hashCode(n),
	})
	return b, true, false
}

func (s *bootstrapStore) RunJanitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep()
		}
	}
}

func (s *bootstrapStore) sweep() {
	now := time.Now()
	type expired struct {
		canonical string
		shareID   string
		target    string
		reason    string
	}
	var drop []expired

	s.mu.Lock()
	for k, b := range s.bundles {
		if !now.Before(b.expiresAt) {
			drop = append(drop, expired{k, b.ShareID, b.targetSummary(), b.Reason})
			delete(s.bundles, k)
		}
	}
	s.mu.Unlock()

	for _, e := range drop {
		_ = s.audit.Write(audit.Event{
			Kind:    "bootstrap_expired",
			ShareID: e.shareID,
			Target:  e.target,
			Reason:  e.reason,
			Token:   hashCode(e.canonical),
		})
	}
}

func newCode() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, r := range raw {
		out = append(out, bootstrapAlphabet[int(r)%len(bootstrapAlphabet)])
		if i == 3 {
			out = append(out, '-')
		}
	}
	return string(out), nil
}

func normalizeCode(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", ""))
}

func hashCode(canonical string) string {
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}
