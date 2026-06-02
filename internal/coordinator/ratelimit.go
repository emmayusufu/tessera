package coordinator

import (
	"sync"
	"time"
)

const (
	ipWindow     = time.Minute
	ipMaxHits    = 5
	idMaxFails   = 10
	idLockoutFor = 5 * time.Minute
)

type rateLimiter struct {
	mu      sync.Mutex
	ipHits  map[string][]time.Time
	idFails map[string]int
	idLock  map[string]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		ipHits:  map[string][]time.Time{},
		idFails: map[string]int{},
		idLock:  map[string]time.Time{},
	}
}

func (r *rateLimiter) ipAllow(addr string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	hits := r.ipHits[addr]
	cutoff := now.Add(-ipWindow)
	kept := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= ipMaxHits {
		r.ipHits[addr] = kept
		return false
	}
	kept = append(kept, now)
	r.ipHits[addr] = kept
	return true
}

func (r *rateLimiter) idLocked(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.idLock[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(r.idLock, id)
		delete(r.idFails, id)
		return false
	}
	return true
}

func (r *rateLimiter) idFail(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.idFails[id]++
	if r.idFails[id] >= idMaxFails {
		r.idLock[id] = time.Now().Add(idLockoutFor)
	}
}
