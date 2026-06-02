package coordinator

func (c *Coordinator) PendingIDs() []string      { return c.pendingIDs() }
func (c *Coordinator) AgentOnline(s string) bool { return c.agentOnline(s) }
