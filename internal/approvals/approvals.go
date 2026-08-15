// Package approvals is the durable human-approval gate (architecture
// section 11): a pending queue persisted in the store database, a
// deterministic TTL sweeper, and wait channels that let one MCP call
// block until a human decides. No STS call has happened when a grant
// parks here, so a stale approval can never leak already-minted
// credentials; the pending TTL bounds staleness.
package approvals

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/0hardik1/taskgrant/internal/store"
)

// Backend is the persistence surface the manager needs. *store.Store
// implements it; tests may inject a fake.
type Backend interface {
	CreatePendingApproval(ctx context.Context, p store.PendingApproval) error
	GetPendingApproval(ctx context.Context, grantID string) (store.PendingApproval, error)
	ListPendingApprovals(ctx context.Context, status store.PendingStatus) ([]store.PendingApproval, error)
	DecidePendingApproval(ctx context.Context, grantID string, status store.PendingStatus, approver, method, note string, decidedAt time.Time) (store.PendingApproval, error)
	ExpirePendingApprovals(ctx context.Context, ttl time.Duration, now time.Time) ([]store.PendingApproval, error)
	MarkFirstUse(ctx context.Context, agent, capability string, now time.Time, approved bool) error
}

var _ Backend = (*store.Store)(nil)

// ErrNotPending marks an approve or deny attempt on a grant that is not
// waiting for a decision.
var ErrNotPending = errors.New("approvals: grant is not pending")

// Approval methods recorded on decisions (section 11).
const (
	MethodCLI = "cli"
	MethodAPI = "api"
)

// Identity is the verified approver identity: the OS peer of the admin
// socket, or the bearer-authenticated admin API user.
type Identity struct {
	Approver string
	Method   string // MethodCLI or MethodAPI
}

// Decision is the outcome delivered to waiters and callers.
type Decision struct {
	GrantID   string
	Status    store.PendingStatus // approved, denied, or expired_pending
	Approver  string
	Method    string
	Note      string
	DecidedAt time.Time
}

func decisionFrom(p store.PendingApproval) Decision {
	return Decision{
		GrantID:   p.GrantID,
		Status:    p.Status,
		Approver:  p.Approver,
		Method:    p.Method,
		Note:      p.Note,
		DecidedAt: p.DecidedAt,
	}
}

// Options tunes a Manager.
type Options struct {
	// SweepInterval is the cadence of the expiry sweeper in Run.
	// Defaults to 1 second.
	SweepInterval time.Duration
	// Clock overrides time.Now for tests.
	Clock func() time.Time
	// Logger receives operational messages. Defaults to slog.Default().
	Logger *slog.Logger
}

// Manager owns the pending-approval queue: submission, waiting,
// deciding, and TTL expiry. Safe for concurrent use.
type Manager struct {
	backend Backend
	ttl     time.Duration
	sweep   time.Duration
	clock   func() time.Time
	logger  *slog.Logger

	mu      sync.Mutex
	waiters map[string][]chan Decision
}

// New builds a Manager over the backend with the configured pending TTL
// (approvals.pending_ttl_seconds).
func New(backend Backend, ttl time.Duration, opts Options) (*Manager, error) {
	if backend == nil {
		return nil, errors.New("approvals: backend is required")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("approvals: ttl must be positive, got %v", ttl)
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = time.Second
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Manager{
		backend: backend,
		ttl:     ttl,
		sweep:   opts.SweepInterval,
		clock:   opts.Clock,
		logger:  opts.Logger,
		waiters: map[string][]chan Decision{},
	}, nil
}

// TTL returns the configured pending TTL.
func (m *Manager) TTL() time.Duration { return m.ttl }

// Submit parks one grant as pending_approval, durably. ReceivedAt
// defaults to the current clock; ExpiresAt is always derived from
// ReceivedAt plus the TTL, so expiry stays deterministic across
// restarts.
func (m *Manager) Submit(ctx context.Context, p store.PendingApproval) (store.PendingApproval, error) {
	if p.GrantID == "" || p.AgentID == "" {
		return store.PendingApproval{}, errors.New("approvals: submit requires grant id and agent id")
	}
	if p.ReceivedAt.IsZero() {
		p.ReceivedAt = m.clock().UTC()
	} else {
		p.ReceivedAt = p.ReceivedAt.UTC()
	}
	p.Status = store.StatusPending
	p.ExpiresAt = p.ReceivedAt.Add(m.ttl)
	p.DecidedAt = time.Time{}
	p.Approver, p.Method, p.Note = "", "", ""
	if err := m.backend.CreatePendingApproval(ctx, p); err != nil {
		return store.PendingApproval{}, err
	}
	return p, nil
}

// Get returns the current queue row for one grant.
func (m *Manager) Get(ctx context.Context, grantID string) (store.PendingApproval, error) {
	return m.backend.GetPendingApproval(ctx, grantID)
}

// List returns queue rows, oldest first. Empty status lists all.
func (m *Manager) List(ctx context.Context, status store.PendingStatus) ([]store.PendingApproval, error) {
	return m.backend.ListPendingApprovals(ctx, status)
}

// WaitDecision blocks until the grant is approved, denied, or expired,
// or until ctx is done. A grant already decided returns immediately.
// The TTL deadline is armed locally from the stored received_at, so a
// waiter learns about expiry even between sweeper ticks.
func (m *Manager) WaitDecision(ctx context.Context, grantID string) (Decision, error) {
	p, err := m.backend.GetPendingApproval(ctx, grantID)
	if err != nil {
		return Decision{}, err
	}
	if p.Status != store.StatusPending {
		return decisionFrom(p), nil
	}

	ch := make(chan Decision, 1)
	m.mu.Lock()
	m.waiters[grantID] = append(m.waiters[grantID], ch)
	m.mu.Unlock()
	defer m.removeWaiter(grantID, ch)

	// Re-check after registration: a decision may have landed between
	// the first read and the waiter registration.
	p, err = m.backend.GetPendingApproval(ctx, grantID)
	if err != nil {
		return Decision{}, err
	}
	if p.Status != store.StatusPending {
		return decisionFrom(p), nil
	}

	deadline := p.ReceivedAt.Add(m.ttl)
	wait := deadline.Sub(m.clock())
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return Decision{}, ctx.Err()
	case d := <-ch:
		return d, nil
	case <-timer.C:
		return m.expireOne(ctx, grantID)
	}
}

// expireOne expires a single grant at its deadline. A concurrent human
// decision wins the race; the stored row is authoritative either way.
func (m *Manager) expireOne(ctx context.Context, grantID string) (Decision, error) {
	now := m.clock().UTC()
	p, err := m.backend.DecidePendingApproval(ctx, grantID, store.StatusExpiredPending, "", "", "", now)
	if errors.Is(err, store.ErrAlreadyDecided) {
		return decisionFrom(p), nil
	}
	if err != nil {
		return Decision{}, err
	}
	d := decisionFrom(p)
	m.notify(grantID, d)
	return d, nil
}

// Approve records a human approval, marks first-use bookkeeping for
// every capability on the grant, and wakes waiters. The broker mints at
// this moment (section 11); the caller drives the mint after Approve
// returns.
func (m *Manager) Approve(ctx context.Context, grantID string, by Identity, note string) (Decision, error) {
	return m.decide(ctx, grantID, store.StatusApproved, by, note)
}

// Deny records a human denial and wakes waiters. First-use pairs on the
// grant are recorded as seen but not approved.
func (m *Manager) Deny(ctx context.Context, grantID string, by Identity, note string) (Decision, error) {
	return m.decide(ctx, grantID, store.StatusDenied, by, note)
}

func (m *Manager) decide(ctx context.Context, grantID string, status store.PendingStatus, by Identity, note string) (Decision, error) {
	if by.Approver == "" {
		return Decision{}, errors.New("approvals: approver identity is required")
	}
	if by.Method != MethodCLI && by.Method != MethodAPI {
		return Decision{}, fmt.Errorf("approvals: method must be %q or %q, got %q", MethodCLI, MethodAPI, by.Method)
	}
	now := m.clock().UTC()
	p, err := m.backend.DecidePendingApproval(ctx, grantID, status, by.Approver, by.Method, note, now)
	if errors.Is(err, store.ErrAlreadyDecided) {
		return decisionFrom(p), fmt.Errorf("%w: grant %s is already %s", ErrNotPending, grantID, p.Status)
	}
	if err != nil {
		return Decision{}, err
	}

	// First-use bookkeeping (section 5.5): an approval satisfies the
	// first-use gate for each (agent, capability) pair on the grant; a
	// denial records the pair as seen but not approved.
	approved := status == store.StatusApproved
	for _, capability := range p.Capabilities {
		if err := m.backend.MarkFirstUse(ctx, p.AgentID, capability, now, approved); err != nil {
			m.logger.Error("approvals: first-use bookkeeping failed",
				"grant_id", grantID, "capability", capability, "error", err)
		}
	}

	d := decisionFrom(p)
	m.notify(grantID, d)
	return d, nil
}

// Run drives the expiry sweeper until ctx is done. Restart safety:
// expiry derives from stored received_at, so pending rows that crossed
// their deadline while the broker was down expire on the first sweep.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.sweep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := m.SweepOnce(ctx); err != nil {
				m.logger.Error("approvals: sweep failed", "error", err)
			}
		}
	}
}

// SweepOnce expires every pending row past its deadline and wakes their
// waiters. It returns the number of rows expired.
func (m *Manager) SweepOnce(ctx context.Context) (int, error) {
	expired, err := m.backend.ExpirePendingApprovals(ctx, m.ttl, m.clock().UTC())
	for _, p := range expired {
		m.notify(p.GrantID, decisionFrom(p))
	}
	return len(expired), err
}

// notify delivers a decision to every waiter of grantID.
func (m *Manager) notify(grantID string, d Decision) {
	m.mu.Lock()
	chans := m.waiters[grantID]
	delete(m.waiters, grantID)
	m.mu.Unlock()
	for _, ch := range chans {
		select {
		case ch <- d:
		default:
		}
	}
}

func (m *Manager) removeWaiter(grantID string, ch chan Decision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	chans := m.waiters[grantID]
	for i, c := range chans {
		if c == ch {
			chans = append(chans[:i], chans[i+1:]...)
			break
		}
	}
	if len(chans) == 0 {
		delete(m.waiters, grantID)
	} else {
		m.waiters[grantID] = chans
	}
}
