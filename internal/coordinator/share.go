package coordinator

import (
	"encoding/json"
	"net"
	"time"

	"github.com/emmayusufu/tessera/internal/audit"
	"github.com/emmayusufu/tessera/internal/proto"
)

// shareUploadRequest is the JSON body the host sends inside a KindShareUpload
// frame. It mirrors the redeem response so the guest sees a matching bundle.
type shareUploadRequest struct {
	CAcert             string `json:"ca_cert"`
	GuestCert          string `json:"guest_cert"`
	GuestKey           string `json:"guest_key"`
	CoordAddr          string `json:"coord_addr"`
	ServerName         string `json:"server_name"`
	AgentName          string `json:"agent_name"`
	ShareID            string `json:"share_id"`
	Target             string `json:"target"`
	ExpectedName       string `json:"expected_name"`
	Reason             string `json:"reason"`
	TTLSeconds         int    `json:"ttl_seconds"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
}

func (c *Coordinator) handleShareUpload(conn net.Conn, m proto.Msg) {
	fp := peerFingerprint(conn)
	if fp == "" {
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindShareResponse, Detail: "client certificate required"})
		return
	}

	var req shareUploadRequest
	if err := json.Unmarshal([]byte(m.Detail), &req); err != nil {
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindShareResponse, Detail: "bad json"})
		return
	}
	if req.ShareID == "" {
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindShareResponse, Detail: "share_id required"})
		return
	}

	c.mu.Lock()
	pinOK := c.checkOrPinShare(req.ShareID, fp)
	c.mu.Unlock()
	if !pinOK {
		_ = c.auditLog.Write(audit.Event{Kind: "share_denied", ShareID: req.ShareID, Token: hashFingerprint(fp), Detail: "share-id owned by a different cert"})
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindShareResponse, Detail: "share-id is owned by a different cert"})
		return
	}

	ttl := req.TTLSeconds
	if ttl < 10 {
		ttl = 10
	}
	if ttl > 600 {
		ttl = 600
	}

	idle := req.IdleTimeoutSeconds
	if idle == 0 {
		idle = int(defaultIdleTimeout / time.Second)
	}
	if idle < 60 {
		idle = 60
	}
	if idle > 86400 {
		idle = 86400
	}

	b := &bootstrapBundle{
		CAcert:             req.CAcert,
		GuestCert:          req.GuestCert,
		GuestKey:           req.GuestKey,
		CoordAddr:          req.CoordAddr,
		ServerName:         req.ServerName,
		AgentName:          req.AgentName,
		ShareID:            req.ShareID,
		Target:             req.Target,
		ExpectedName:       req.ExpectedName,
		Reason:             req.Reason,
		IdleTimeoutSeconds: idle,
	}
	code, _, _, err := c.bootstrap.Put(b, time.Duration(ttl)*time.Second)
	if err != nil {
		_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindShareResponse, Detail: "could not mint code"})
		return
	}

	c.mu.Lock()
	c.sessionTimeouts[req.ShareID] = time.Duration(idle) * time.Second
	c.mu.Unlock()

	_ = proto.WriteMsg(conn, proto.Msg{Kind: proto.KindShareResponse, Code: code})
}
