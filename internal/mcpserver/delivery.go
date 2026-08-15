package mcpserver

import (
	"sync"
	"time"
)

// deliveryTracker enforces the tool-layer half of invariant I4:
// credentials cross the MCP boundary exactly once per grant unless the
// operator enables credential_redelivery. The broker is the durable
// authority on delivery; this tracker is the boundary's own guarantee,
// so even a broker that keeps offering a secret cannot make the MCP
// layer repeat it.
//
// Entries are timestamped and swept after retention: once a grant's
// credentials have expired (max session 12 h), remembering the delivery
// no longer changes anything, so a 24 h retention keeps the map bounded
// without ever enabling redelivery inside a credential lifetime.
type deliveryTracker struct {
	mu        sync.Mutex
	delivered map[string]time.Time
	now       func() time.Time
	retention time.Duration
	lastSweep time.Time
}

func newDeliveryTracker() *deliveryTracker {
	return &deliveryTracker{
		delivered: make(map[string]time.Time),
		now:       time.Now,
		retention: 24 * time.Hour,
	}
}

// FirstDelivery reports whether this call is the first delivery for
// grantID, and records it. Only the first call per grant returns true.
func (t *deliveryTracker) FirstDelivery(grantID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.sweepLocked(now)
	if _, seen := t.delivered[grantID]; seen {
		return false
	}
	t.delivered[grantID] = now
	return true
}

// sweepLocked drops entries past retention. Called with t.mu held.
func (t *deliveryTracker) sweepLocked(now time.Time) {
	if now.Sub(t.lastSweep) < time.Hour {
		return
	}
	t.lastSweep = now
	for id, at := range t.delivered {
		if now.Sub(at) > t.retention {
			delete(t.delivered, id)
		}
	}
}
