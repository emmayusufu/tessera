package coordinator

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"strings"
)

func (c *Coordinator) httpMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /a/{id}", c.handleApprovalPage)
	mux.HandleFunc("POST /a/{id}/approve", c.handleApprove)
	mux.HandleFunc("POST /a/{id}/deny", c.handleDeny)
	mux.HandleFunc("POST /s/{id}/revoke", c.handleRevoke)
	mux.HandleFunc("POST /redeem/{code}", c.handleRedeem)
	return mux
}

func (c *Coordinator) requestInfo(id string) (*request, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.requests[id]
	return r, ok
}

func tokenOK(req *request, token string) bool {
	return req.token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(req.token)) == 1
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

func (c *Coordinator) handleApprovalPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := c.requestInfo(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	noLeak(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, approvalPage,
		html.EscapeString(req.who),
		html.EscapeString(req.shareID),
		html.EscapeString(req.target),
		html.EscapeString(req.reason),
		html.EscapeString(id),
		html.EscapeString(id),
	)
}

func (c *Coordinator) handleApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !c.rl.ipAllow(clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if c.rl.idLocked(id) {
		http.Error(w, "locked: too many attempts", http.StatusLocked)
		return
	}
	req, ok := c.requestInfo(id)
	if !ok {
		page(w, r, "Expired", "This request is no longer pending.")
		return
	}
	token := r.PostFormValue("t")
	if token == "" || !tokenOK(req, token) {
		c.rl.idFail(id)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	c.Approve(id)
	page(w, r, "Approved", "Access granted. You can close this page.")
}

func (c *Coordinator) handleDeny(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !c.rl.ipAllow(clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if c.rl.idLocked(id) {
		http.Error(w, "locked: too many attempts", http.StatusLocked)
		return
	}
	req, ok := c.requestInfo(id)
	if !ok {
		page(w, r, "Expired", "This request is no longer pending.")
		return
	}
	token := r.PostFormValue("t")
	if token == "" || !tokenOK(req, token) {
		c.rl.idFail(id)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	c.Deny(id, "denied by host")
	page(w, r, "Denied", "Access was denied.")
}

func (c *Coordinator) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !c.rl.ipAllow(clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if c.rl.idLocked(id) {
		http.Error(w, "locked: too many attempts", http.StatusLocked)
		return
	}
	if !c.operatorOK(r) {
		c.rl.idFail(id)
		http.Error(w, "operator authentication required", http.StatusForbidden)
		return
	}
	if c.Revoke(id) {
		page(w, r, "Revoked", "The session has been ended.")
		return
	}
	page(w, r, "Not found", "No such active session.")
}

type redeemResponseBody struct {
	CAcert       string `json:"ca_cert"`
	GuestCert    string `json:"guest_cert"`
	GuestKey     string `json:"guest_key"`
	CoordAddr    string `json:"coord_addr"`
	ServerName   string `json:"server_name"`
	AgentName    string `json:"agent_name"`
	ShareID      string `json:"share_id"`
	Target       string `json:"target"`
	ExpectedName string `json:"expected_name"`
	Reason       string `json:"reason"`
}

// handleRedeem exchanges a bootstrap code for a one-shot guest bundle.
// 404 means the code never existed; 410 means it was already consumed or
// expired. The code space is ~30^8 so the oracle distinction is moot.
func (c *Coordinator) handleRedeem(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	normalized := normalizeCode(code)
	if !c.rl.ipAllow(clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if c.rl.idLocked(normalized) {
		http.Error(w, "locked: too many attempts", http.StatusLocked)
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(redeemResponseBody{
		CAcert:       b.CAcert,
		GuestCert:    b.GuestCert,
		GuestKey:     b.GuestKey,
		CoordAddr:    b.CoordAddr,
		ServerName:   b.ServerName,
		AgentName:    b.AgentName,
		ShareID:      b.ShareID,
		Target:       b.Target,
		ExpectedName: b.ExpectedName,
		Reason:       b.Reason,
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

func noLeak(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if r != nil && r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
}

func page(w http.ResponseWriter, r *http.Request, title, body string) {
	noLeak(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><title>%s</title><body style='font-family:system-ui;max-width:30rem;margin:3rem auto;padding:0 1rem'><h2>%s</h2><p>%s</p>", title, title, body)
}

const approvalPage = `<!doctype html>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Access request</title>
<body style="font-family:system-ui;max-width:30rem;margin:2.5rem auto;padding:0 1rem">
<h2>Access request</h2>
<p><b>%s</b> is requesting access on behalf of <b>%s</b>.</p>
<p>Resource: <code>%s</code></p>
<p>Reason: %s</p>
<form method="post" action="/a/%s/approve" style="display:inline">
  <button style="padding:.8rem 1.6rem;font-size:1.1rem;background:#138a36;color:#fff;border:0;border-radius:.5rem">Approve</button>
</form>
<form method="post" action="/a/%s/deny" style="display:inline;margin-left:.5rem">
  <button style="padding:.8rem 1.6rem;font-size:1.1rem;background:#b3261e;color:#fff;border:0;border-radius:.5rem">Deny</button>
</form>
<script>
(function(){
  var h = window.location.hash;
  if (!h || h.length < 3) {
    document.body.innerHTML = '<h2>Bad approval link</h2><p>Missing token.</p>';
    return;
  }
  var t = h.substring(1).split('&').find(function(kv){ return kv.indexOf('t=') === 0; });
  if (!t) {
    document.body.innerHTML = '<h2>Bad approval link</h2><p>Missing token.</p>';
    return;
  }
  var tok = t.substring(2);
  document.querySelectorAll('form').forEach(function(f){
    var i = document.createElement('input');
    i.type = 'hidden'; i.name = 't'; i.value = tok;
    f.appendChild(i);
  });
})();
</script>
`
