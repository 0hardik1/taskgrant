package broker

import (
	"context"
	"errors"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/revoke"
)

// Sweep cadences.
const (
	sweepInterval = 2 * time.Second
	gcInterval    = 10 * time.Minute
)

// Run drives the broker's periodic work until ctx ends: pending
// approvals past their TTL become expired_pending (deterministically,
// including across restarts), active grants past credential expiry
// become expired, stale idempotency keys are dropped, and expired
// revocation deny statements are garbage-collected.
func (b *Broker) Run(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	gcTicker := time.NewTicker(gcInterval)
	defer gcTicker.Stop()

	// One immediate sweep so pending rows that crossed their deadline
	// while the broker was down expire promptly (section 11 step 5).
	b.SweepOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.SweepOnce(ctx)
		case <-gcTicker.C:
			b.gcOnce(ctx)
		}
	}
}

// SweepOnce runs one expiry pass. Exported so tests and the serve loop
// can drive it deterministically.
func (b *Broker) SweepOnce(ctx context.Context) {
	now := b.now()

	// Pending -> expired_pending. The queue rows the manager flips are
	// returned to its caller through the waiter channels; the broker
	// additionally appends the approval-expiry record for rows it owns.
	expiredRows := b.sweepPending(ctx)
	for _, grantID := range expiredRows {
		if e, ok := b.entry(grantID); ok {
			b.finalizeExpiredPending(ctx, e)
		}
	}

	// Active -> expired, and registry retention.
	b.mu.Lock()
	for id, e := range b.grants {
		if (e.grant.State == domain.StateActive || e.grant.State == domain.StateMinted) &&
			!e.grant.ExpiresAt.IsZero() && now.After(e.grant.ExpiresAt) {
			b.setStateLocked(e, domain.StateExpired)
			e.delivery = nil
			e.markTerminal(now)
			b.incOutcome("expired")
		}
		if !e.terminalAt.IsZero() && now.Sub(e.terminalAt) > entryRetention {
			delete(b.grants, id)
		}
	}
	b.mu.Unlock()
}

// sweepPending expires overdue queue rows and returns their grant ids.
func (b *Broker) sweepPending(ctx context.Context) []string {
	// The manager's SweepOnce wakes waiters; collecting the ids needs
	// the row list, so ask the queue directly afterwards.
	if _, err := b.approvals.SweepOnce(ctx); err != nil {
		b.logger.Error("broker: approval sweep failed", "err", err)
	}
	rows, err := b.approvals.List(ctx, "")
	if err != nil {
		return nil
	}
	var out []string
	for _, row := range rows {
		if row.Status != "expired_pending" {
			continue
		}
		if e, ok := b.entry(row.GrantID); ok && e.grant.State == domain.StatePendingApproval {
			out = append(out, row.GrantID)
		}
	}
	return out
}

// gcOnce drops expired idempotency keys and garbage-collects expired
// revocation deny statements on every profile role (section 8.5).
func (b *Broker) gcOnce(ctx context.Context) {
	if _, err := b.log.DeleteExpiredIdempotencyKeys(ctx, b.now()); err != nil {
		b.logger.Error("broker: idempotency key gc failed", "err", err)
	}
	if b.revoker == nil {
		return
	}
	for _, name := range b.cfg.ProfileNames() {
		roleName, err := roleNameFromARN(b.cfg.Profiles[name].RoleARN)
		if err != nil {
			continue
		}
		if _, err := b.revoker.GC(ctx, roleName); err != nil &&
			!errors.Is(err, revoke.ErrNoSuchPolicy) {
			b.logger.Warn("broker: revocation gc failed", "role", roleName, "err", err)
		}
	}
}
