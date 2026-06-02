package coordinator

import (
	"net"
	"time"

	"github.com/emmayusufu/tessera/internal/audit"
	"github.com/emmayusufu/tessera/internal/netutil"
	"github.com/emmayusufu/tessera/internal/proto"
)

func (c *Coordinator) handleGuestData(conn net.Conn, m proto.Msg) {
	c.mu.Lock()
	sess, ok := c.sessions[m.SessionID]
	var ac *agentConn
	if ok {
		ac = c.agents[sess.shareID]
	}
	c.mu.Unlock()
	if !ok || ac == nil {
		conn.Close()
		return
	}

	if fp := peerFingerprint(conn); fp == "" || fp != sess.guest {
		_ = c.auditLog.Write(audit.Event{Kind: "stream_denied", SessionID: sess.id, ShareID: sess.shareID, Target: sess.target, Detail: "guest identity mismatch"})
		conn.Close()
		return
	}

	connID := newID()
	wait := make(chan net.Conn, 1)
	c.mu.Lock()
	c.pending[connID] = wait
	c.mu.Unlock()

	if err := ac.send(proto.Msg{Kind: proto.KindOpenData, ConnID: connID, Target: sess.target}); err != nil {
		c.mu.Lock()
		delete(c.pending, connID)
		c.mu.Unlock()
		conn.Close()
		return
	}

	select {
	case agentSide := <-wait:
		if !sess.addStream(conn) {
			conn.Close()
			agentSide.Close()
			return
		}
		netutil.PipeIdle(conn, agentSide, idleTimeout)
		sess.removeStream(conn)
	case <-time.After(pairTimeout):
		c.mu.Lock()
		_, stillPending := c.pending[connID]
		delete(c.pending, connID)
		c.mu.Unlock()
		conn.Close()
		// If the agent claimed connID under the lock just before we gave up, it
		// will still deliver its conn on wait; receive and close it so it cannot leak.
		if !stillPending {
			(<-wait).Close()
		}
	}
}

func (c *Coordinator) handleAgentData(conn net.Conn, m proto.Msg) {
	c.mu.Lock()
	wait, ok := c.pending[m.ConnID]
	if ok {
		delete(c.pending, m.ConnID)
	}
	c.mu.Unlock()
	if !ok {
		conn.Close()
		return
	}
	wait <- conn
}
