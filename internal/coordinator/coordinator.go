// Package coordinator is tessera's broker: it pairs an approved guest stream with its agent.
package coordinator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/emmayusufu/tessera/internal/audit"
	"github.com/emmayusufu/tessera/internal/proto"
)

const (
	idleTimeout = 30 * time.Minute
	pairTimeout = 15 * time.Second
)

type agentConn struct {
	conn net.Conn
	wmu  sync.Mutex
}

func (a *agentConn) send(m proto.Msg) error {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	return proto.WriteMsg(a.conn, m)
}

type approverConn struct {
	conn net.Conn
	wmu  sync.Mutex
}

func (a *approverConn) send(m proto.Msg) error {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	return proto.WriteMsg(a.conn, m)
}

type decision struct {
	approved bool
	detail   string
}

type request struct {
	id      string
	token   string
	shareID string
	target  string
	reason  string
	who     string
	peer    string
	created time.Time
	decided chan decision
}

type session struct {
	id      string
	shareID string
	target  string
	who     string
	guest   string
	ctl     net.Conn

	smu     sync.Mutex
	streams map[net.Conn]struct{}
	ended   bool
}

func (s *session) addStream(c net.Conn) bool {
	s.smu.Lock()
	defer s.smu.Unlock()
	if s.ended {
		return false
	}
	s.streams[c] = struct{}{}
	return true
}

func (s *session) removeStream(c net.Conn) {
	s.smu.Lock()
	delete(s.streams, c)
	s.smu.Unlock()
}

func (s *session) end() []net.Conn {
	s.smu.Lock()
	defer s.smu.Unlock()
	s.ended = true
	conns := make([]net.Conn, 0, len(s.streams))
	for c := range s.streams {
		conns = append(conns, c)
	}
	s.streams = nil
	return conns
}

type Coordinator struct {
	auditLog      *audit.Log
	logger        *slog.Logger
	baseURL       string
	listen        func() (net.Listener, error)
	operatorToken string

	mu        sync.Mutex
	agents    map[string]*agentConn
	requests  map[string]*request
	sessions  map[string]*session
	pending   map[string]chan net.Conn
	approvers map[string][]*approverConn
	sharePins map[string]string
	rl        *rateLimiter
	bootstrap *bootstrapStore
}

func New(log *audit.Log, baseURL string, listen func() (net.Listener, error)) *Coordinator {
	c := &Coordinator{
		auditLog:  log,
		logger:    slog.Default(),
		baseURL:   baseURL,
		listen:    listen,
		agents:    map[string]*agentConn{},
		requests:  map[string]*request{},
		sessions:  map[string]*session{},
		pending:   map[string]chan net.Conn{},
		approvers: map[string][]*approverConn{},
		sharePins: map[string]string{},
		rl:        newRateLimiter(),
	}
	c.bootstrap = newBootstrapStore(c.auditLog, c.logger)
	return c
}

// SetOperatorToken sets the bearer required for operator endpoints. If unset, they are disabled.
func (c *Coordinator) SetOperatorToken(t string) { c.operatorToken = t }

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func peerFingerprint(conn net.Conn) string {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return ""
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:])
}

func hashFingerprint(fp string) string {
	if fp == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(sum[:])
}

// checkOrPinShare pins the share-id to fp on first use, or verifies a later
// caller presents the same cert. Caller must hold c.mu.
func (c *Coordinator) checkOrPinShare(shareID, fp string) bool {
	if fp == "" || shareID == "" {
		return false
	}
	pinned, ok := c.sharePins[shareID]
	if !ok {
		c.sharePins[shareID] = fp
		return true
	}
	return pinned == fp
}

// Serve accepts agent and guest connections and serves the approval API on
// httpAddr. If certFile and keyFile are set, the approval API is served over
// HTTPS. It blocks until ctx is cancelled.
func (c *Coordinator) Serve(ctx context.Context, httpAddr, certFile, keyFile string) error {
	ln, err := c.listen()
	if err != nil {
		return err
	}
	defer ln.Close()

	httpSrv := &http.Server{Addr: httpAddr, Handler: c.httpMux()}
	go func() {
		<-ctx.Done()
		ln.Close()
		_ = httpSrv.Close()
	}()
	go func() {
		var err error
		if certFile != "" && keyFile != "" {
			err = httpSrv.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			c.logger.Error("approval http server", "err", err)
		}
	}()
	go c.bootstrap.RunJanitor(ctx)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go c.handleConn(conn)
	}
}

func (c *Coordinator) handleConn(conn net.Conn) {
	m, err := proto.ReadMsg(conn)
	if err != nil {
		conn.Close()
		return
	}
	switch m.Kind {
	case proto.KindRegister:
		defer conn.Close()
		c.handleAgent(conn, m)
	case proto.KindRequest:
		defer conn.Close()
		c.handleRequest(conn, m)
	case proto.KindDataHello:
		if m.Role == "agent" {
			c.handleAgentData(conn, m)
		} else {
			c.handleGuestData(conn, m)
		}
	case proto.KindApprovalSubscribe:
		defer conn.Close()
		c.handleApprovalSubscribe(conn, m)
	case proto.KindShareUpload:
		defer conn.Close()
		c.handleShareUpload(conn, m)
	default:
		conn.Close()
	}
}

func (c *Coordinator) handleAgent(conn net.Conn, m proto.Msg) {
	fp := peerFingerprint(conn)
	ac := &agentConn{conn: conn}
	c.mu.Lock()
	if !c.checkOrPinShare(m.ShareID, fp) {
		c.mu.Unlock()
		_ = c.auditLog.Write(audit.Event{Kind: "register_denied", ShareID: m.ShareID, Token: hashFingerprint(fp), Detail: "share-id owned by a different cert"})
		c.logger.Warn("agent register denied", "share_id", m.ShareID)
		return
	}
	c.agents[m.ShareID] = ac
	c.mu.Unlock()
	c.logger.Info("agent registered", "share_id", m.ShareID)

	for {
		if _, err := proto.ReadMsg(conn); err != nil {
			break
		}
	}
	c.mu.Lock()
	if c.agents[m.ShareID] == ac {
		delete(c.agents, m.ShareID)
	}
	c.mu.Unlock()
	c.logger.Info("agent disconnected", "share_id", m.ShareID)
}

func (c *Coordinator) handleRequest(conn net.Conn, m proto.Msg) {
	fp := peerFingerprint(conn)
	if fp == "" {
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindDecision, Detail: "client certificate required"})
		return
	}

	c.mu.Lock()
	_, online := c.agents[m.ShareID]
	c.mu.Unlock()
	if !online {
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindDecision, Detail: "no agent online for share-id"})
		return
	}

	req := &request{
		id:      newID(),
		token:   newID(),
		shareID: m.ShareID,
		target:  m.Target,
		reason:  m.Reason,
		who:     m.Who,
		peer:    fp,
		created: time.Now(),
		decided: make(chan decision, 1),
	}
	c.mu.Lock()
	c.requests[req.id] = req
	c.mu.Unlock()

	approveURL := fmt.Sprintf("%s/a/%s#t=%s", c.baseURL, req.id, req.token)
	_ = c.auditLog.Write(audit.Event{Kind: "request", RequestID: req.id, ShareID: req.shareID, Who: req.who, Target: req.target, Reason: req.reason, Token: req.token})
	c.logger.Info("access requested",
		"request", req.id, "share_id", req.shareID, "who", req.who, "target", req.target, "approve_url", approveURL)
	c.fanoutPrompt(req)

	var d decision
	select {
	case d = <-req.decided:
	case <-time.After(5 * time.Minute):
		d = decision{detail: "request timed out"}
	}

	c.mu.Lock()
	delete(c.requests, req.id)
	c.mu.Unlock()

	if !d.approved {
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindDecision, Detail: d.detail})
		return
	}

	sess := &session{
		id:      newID(),
		shareID: req.shareID,
		target:  req.target,
		who:     req.who,
		guest:   req.peer,
		ctl:     conn,
		streams: map[net.Conn]struct{}{},
	}
	c.mu.Lock()
	c.sessions[sess.id] = sess
	c.mu.Unlock()
	_ = c.auditLog.Write(audit.Event{Kind: "session_open", RequestID: req.id, SessionID: sess.id, ShareID: sess.shareID, Who: sess.who, Target: sess.target})
	c.logger.Info("session opened", "session", sess.id, "share_id", sess.shareID, "target", sess.target)

	if err := proto.WriteMsg(conn, proto.Msg{Kind: proto.KindDecision, Approved: true, SessionID: sess.id, Target: sess.target}); err != nil {
		c.endSession(sess.id, "guest send failed")
		return
	}

	for {
		if _, err := proto.ReadMsg(conn); err != nil {
			break
		}
	}
	c.endSession(sess.id, "guest disconnected")
}

func (c *Coordinator) endSession(sessionID, reason string) {
	c.mu.Lock()
	sess, ok := c.sessions[sessionID]
	if !ok {
		c.mu.Unlock()
		return
	}
	delete(c.sessions, sessionID)
	subs := append([]*approverConn(nil), c.approvers[sess.shareID]...)
	c.mu.Unlock()

	for _, conn := range sess.end() {
		conn.Close()
	}
	_ = c.auditLog.Write(audit.Event{Kind: "session_close", SessionID: sess.id, ShareID: sess.shareID, Who: sess.who, Target: sess.target, Detail: reason})
	c.logger.Info("session closed", "session", sess.id, "reason", reason)

	notice := proto.Msg{Kind: proto.KindSessionEnded, SessionID: sess.id, ShareID: sess.shareID}
	for _, a := range subs {
		_ = a.send(notice)
	}
}

func (c *Coordinator) Approve(requestID string) bool {
	return c.resolve(requestID, decision{approved: true})
}

func (c *Coordinator) Deny(requestID, reason string) bool {
	return c.resolve(requestID, decision{detail: reason})
}

func (c *Coordinator) fanoutPrompt(req *request) {
	prompt := proto.Msg{
		Kind:      proto.KindApprovalPrompt,
		RequestID: req.id,
		ShareID:   req.shareID,
		Who:       req.who,
		Target:    req.target,
		Reason:    req.reason,
	}
	c.mu.Lock()
	subs := c.approvers[req.shareID]
	c.mu.Unlock()

	var dead []*approverConn
	for _, a := range subs {
		if err := a.send(prompt); err != nil {
			dead = append(dead, a)
		}
	}
	if len(dead) == 0 {
		return
	}
	c.mu.Lock()
	c.approvers[req.shareID] = removeApprovers(c.approvers[req.shareID], dead)
	c.mu.Unlock()
	for _, a := range dead {
		a.conn.Close()
	}
}

func removeApprovers(in []*approverConn, drop []*approverConn) []*approverConn {
	out := in[:0]
	for _, a := range in {
		keep := true
		for _, d := range drop {
			if a == d {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, a)
		}
	}
	return out
}

func (c *Coordinator) handleApprovalSubscribe(conn net.Conn, m proto.Msg) {
	fp := peerFingerprint(conn)
	if fp == "" {
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindDecision, Detail: "client certificate required"})
		return
	}
	ac := &approverConn{conn: conn}
	c.mu.Lock()
	if !c.checkOrPinShare(m.ShareID, fp) {
		c.mu.Unlock()
		_ = c.auditLog.Write(audit.Event{Kind: "subscribe_denied", ShareID: m.ShareID, Token: hashFingerprint(fp), Detail: "share-id owned by a different cert"})
		c.logger.Warn("approver subscribe denied", "share_id", m.ShareID)
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindDecision, Detail: "share-id is owned by a different cert"})
		return
	}
	c.approvers[m.ShareID] = append(c.approvers[m.ShareID], ac)
	pending := make([]*request, 0)
	for _, r := range c.requests {
		if r.shareID == m.ShareID {
			pending = append(pending, r)
		}
	}
	c.mu.Unlock()
	c.logger.Info("approver subscribed", "share_id", m.ShareID)

	for _, r := range pending {
		_ = ac.send(proto.Msg{
			Kind:      proto.KindApprovalPrompt,
			RequestID: r.id,
			ShareID:   r.shareID,
			Who:       r.who,
			Target:    r.target,
			Reason:    r.reason,
		})
	}

	for {
		msg, err := proto.ReadMsg(conn)
		if err != nil {
			break
		}
		if msg.Kind != proto.KindApprovalDecision {
			continue
		}
		if msg.Approved {
			c.Approve(msg.RequestID)
		} else {
			c.Deny(msg.RequestID, msg.Detail)
		}
	}

	c.mu.Lock()
	c.approvers[m.ShareID] = removeApprovers(c.approvers[m.ShareID], []*approverConn{ac})
	c.mu.Unlock()
	c.logger.Info("approver disconnected", "share_id", m.ShareID)
}

func (c *Coordinator) pendingIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.requests))
	for k := range c.requests {
		ids = append(ids, k)
	}
	return ids
}

func (c *Coordinator) agentOnline(shareID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.agents[shareID]
	return ok
}

func (c *Coordinator) resolve(requestID string, d decision) bool {
	c.mu.Lock()
	req, ok := c.requests[requestID]
	c.mu.Unlock()
	if !ok {
		return false
	}
	kind := "deny"
	if d.approved {
		kind = "approve"
	}
	_ = c.auditLog.Write(audit.Event{Kind: kind, RequestID: requestID, ShareID: req.shareID, Who: req.who, Target: req.target, Detail: d.detail})
	select {
	case req.decided <- d:
		return true
	default:
		return false
	}
}
