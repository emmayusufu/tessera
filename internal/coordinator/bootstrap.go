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

type bootstrapBundle struct {
	CAcert             string
	GuestCert          string
	GuestKey           string
	CoordAddr          string
	ServerName         string
	AgentName          string
	ShareID            string
	Target             string
	ExpectedName       string
	Reason             string
	IdleTimeoutSeconds int

	expiresAt time.Time
	consumed  bool
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
		Target:  b.Target,
		Reason:  b.Reason,
		Token:   hashCode(canonical),
	})
	return code, canonical, b.expiresAt, nil
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
		Target:  b.Target,
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
			drop = append(drop, expired{k, b.ShareID, b.Target, b.Reason})
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
