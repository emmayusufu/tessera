package coordinator

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/emmayusufu/tessera/internal/audit"
)

func (c *Coordinator) httpMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /s/{id}/revoke", c.handleRevoke)
	mux.HandleFunc("POST /redeem/{code}", c.handleRedeem)
	mux.HandleFunc("GET /peek/{code}", c.handlePeek)
	return mux
}

func (c *Coordinator) operatorOK(r *http.Request) bool {
	if c.operatorToken == "" {
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.operatorToken)) == 1
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rlGate enforces both the per-IP rate limit and the per-ID lockout in one
// call. On denial it writes a rate_limit_trip audit entry naming the handler,
// the limit that fired, and the requesting IP, then sends the appropriate
// HTTP status and returns false. Handlers should early-return on false.
func (c *Coordinator) rlGate(w http.ResponseWriter, r *http.Request, id, handler string) bool {
	ip := clientIP(r)
	if !c.rl.ipAllow(ip) {
		_ = c.auditLog.Write(audit.Event{
			Kind:   "rate_limit_trip",
			Detail: handler + ":ip:" + ip,
		})
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return false
	}
	if c.rl.idLocked(id) {
		_ = c.auditLog.Write(audit.Event{
			Kind:   "rate_limit_trip",
			Detail: handler + ":id_locked:" + ip,
		})
		http.Error(w, "locked: too many attempts", http.StatusLocked)
		return false
	}
	return true
}

func (c *Coordinator) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !c.rlGate(w, r, id, "revoke") {
		return
	}
	if !c.operatorOK(r) {
		c.rl.idFail(id)
		_ = c.auditLog.Write(audit.Event{
			Kind:      "operator_auth_failed",
			SessionID: id,
			Detail:    "revoke:" + clientIP(r),
		})
		http.Error(w, "operator authentication required", http.StatusForbidden)
		return
	}
	if c.Revoke(id) {
		page(w, r, "Revoked", "The session has been ended.")
		return
	}
	page(w, r, "Not found", "No such active session.")
}

type redeemServiceView struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	Kind   string `json:"kind,omitempty"`
}

type redeemResponseBody struct {
	CAcert       string              `json:"ca_cert"`
	GuestCert    string              `json:"guest_cert"`
	GuestKey     string              `json:"guest_key"`
	CoordAddr    string              `json:"coord_addr"`
	ServerName   string              `json:"server_name"`
	AgentName    string              `json:"agent_name"`
	ShareID      string              `json:"share_id"`
	Services     []redeemServiceView `json:"services"`
	ExpectedName string              `json:"expected_name"`
	HostName     string              `json:"host_name"`
	Reason       string              `json:"reason"`
}

type peekResponseBody struct {
	ExpectedName string   `json:"expected_name"`
	HostName     string   `json:"host_name"`
	Reason       string   `json:"reason"`
	ServiceNames []string `json:"service_names"`
	ExpiresAt    string   `json:"expires_at"`
}

// handleRedeem exchanges a bootstrap code for a one-shot guest bundle.
// 404 means the code never existed; 410 means it was already consumed or
// expired. The code space is ~30^8 so the oracle distinction is moot.
func (c *Coordinator) handleRedeem(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	normalized := normalizeCode(code)
	if !c.rlGate(w, r, normalized, "redeem") {
		return
	}
	b, found, used := c.bootstrap.Redeem(normalized)
	if !found {
		c.rl.idFail(normalized)
		http.Error(w, "unknown code", http.StatusNotFound)
		return
	}
	if used {
		http.Error(w, "code already used or expired", http.StatusGone)
		return
	}
	services := make([]redeemServiceView, 0, len(b.Services))
	for _, s := range b.Services {
		services = append(services, redeemServiceView(s))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(redeemResponseBody{
		CAcert:       b.CAcert,
		GuestCert:    b.GuestCert,
		GuestKey:     b.GuestKey,
		CoordAddr:    b.CoordAddr,
		ServerName:   b.ServerName,
		AgentName:    b.AgentName,
		ShareID:      b.ShareID,
		Services:     services,
		ExpectedName: b.ExpectedName,
		HostName:     b.HostName,
		Reason:       b.Reason,
	})
}

// handlePeek returns just enough metadata for the guest to choose a service
// without consuming the one-shot code. It deliberately omits certs and targets
// since the guest hasn't proven intent yet.
func (c *Coordinator) handlePeek(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	normalized := normalizeCode(code)
	if !c.rlGate(w, r, normalized, "peek") {
		return
	}
	b, found, used := c.bootstrap.Peek(normalized)
	if !found {
		c.rl.idFail(normalized)
		http.Error(w, "unknown code", http.StatusNotFound)
		return
	}
	if used {
		http.Error(w, "code already used or expired", http.StatusGone)
		return
	}
	names := make([]string, 0, len(b.Services))
	for _, s := range b.Services {
		names = append(names, s.Name)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(peekResponseBody{
		ExpectedName: b.ExpectedName,
		HostName:     b.HostName,
		Reason:       b.Reason,
		ServiceNames: names,
		ExpiresAt:    b.expiresAt.UTC().Format(time.RFC3339),
	})
}

func (c *Coordinator) Revoke(sessionID string) bool {
	c.mu.Lock()
	sess, ok := c.sessions[sessionID]
	c.mu.Unlock()
	if !ok {
		return false
	}
	c.endSession(sessionID, "revoked by operator")
	if sess.ctl != nil {
		sess.ctl.Close()
	}
	return true
}

func page(w http.ResponseWriter, r *http.Request, title, body string) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if r != nil && r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><title>%s</title><body style='font-family:system-ui;max-width:30rem;margin:3rem auto;padding:0 1rem'><h2>%s</h2><p>%s</p>", title, title, body)
}
