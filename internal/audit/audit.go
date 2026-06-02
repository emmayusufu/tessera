// Package audit writes an append-only record of every access event as JSON lines.
// Bootstrap events ("bootstrap_minted", "bootstrap_redeemed", "bootstrap_expired") store
// hex(sha256(canonical-code)) in the Token field; never the raw code.
package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Event struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	RequestID string    `json:"request_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	ShareID   string    `json:"share_id,omitempty"`
	Who       string    `json:"who,omitempty"`
	Target    string    `json:"target,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Token     string    `json:"token,omitempty"`
	HMAC      string    `json:"hmac,omitempty"`
}

type Log struct {
	mu       sync.Mutex
	f        *os.File
	now      func() time.Time
	key      []byte
	lastHMAC string
}

func Open(path string) (*Log, error) {
	return OpenWithHMAC(path, nil)
}

func OpenWithHMAC(path string, key []byte) (*Log, error) {
	var last string
	if key != nil {
		if rf, err := os.Open(path); err == nil {
			s := bufio.NewScanner(rf)
			s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for s.Scan() {
				var e Event
				if json.Unmarshal(s.Bytes(), &e) == nil && e.HMAC != "" {
					last = e.HMAC
				}
			}
			rf.Close()
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f, now: time.Now, key: key, lastHMAC: last}, nil
}

func (l *Log) Write(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Time = l.now()
	if l.key != nil {
		e.HMAC = ""
		body, err := json.Marshal(e)
		if err != nil {
			return err
		}
		mac := hmac.New(sha256.New, l.key)
		mac.Write([]byte(l.lastHMAC))
		mac.Write(body)
		e.HMAC = hex.EncodeToString(mac.Sum(nil))
		l.lastHMAC = e.HMAC
	}
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(body, '\n')); err != nil {
		return err
	}
	return l.f.Sync()
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
