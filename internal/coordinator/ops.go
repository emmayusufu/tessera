package coordinator

import (
	"github.com/emmayusufu/tessera/internal/audit"
)

type RequestView struct {
	ID      string
	ShareID string
	Who     string
	Target  string
	Reason  string
}

func (c *Coordinator) Online(shareID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.agents[shareID]
	return ok
}

func (c *Coordinator) PendingRequests() []RequestView {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]RequestView, 0, len(c.requests))
	for _, r := range c.requests {
		out = append(out, RequestView{ID: r.id, ShareID: r.shareID, Who: r.who, Target: r.target, Reason: r.reason})
	}
	return out
}

// Restore is a stub; replaying pending requests requires reading the audit file
// back, which is out of scope for v1 since live ctl conns cannot be restored anyway.
func (c *Coordinator) Restore(log *audit.Log) {
	if log == nil {
		c.logger.Warn("restore called with nil audit log")
	}
}
