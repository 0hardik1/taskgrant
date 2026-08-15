package approvals

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/0hardik1/taskgrant/internal/store"
)

// fakeClock is a settable test clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func openBackend(t *testing.T, path string) *store.Store {
	t.Helper()
	if path == "" {
		path = filepath.Join(t.TempDir(), "approvals.db")
	}
	s, err := store.Open(store.Options{Path: path})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newManager(t *testing.T, backend Backend, ttl time.Duration, clock *fakeClock) *Manager {
	t.Helper()
	m, err := New(backend, ttl, Options{Clock: clock.Now, SweepInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func pendingFixture(grantID string) store.PendingApproval {
	return store.PendingApproval{
		GrantID:      grantID,
		AgentID:      "invoice-bot",
		Profile:      "s3-archiver",
		Task:         "archive invoices",
		Capabilities: []string{"s3.read-prefix", "s3.write-prefix"},
		RequiredBy:   "first_use",
	}
}

const grantA = "01K2G3H4J5K6M7N8P9Q0R1S2T3"
const grantB = "01K2G3H4J5K6M7N8P9Q0R1S2T4"

func TestApproveWakesWaiter(t *testing.T) {
	backend := openBackend(t, "")
	clock := &fakeClock{now: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	m := newManager(t, backend, 15*time.Minute, clock)
	ctx := context.Background()

	if _, err := m.Submit(ctx, pendingFixture(grantA)); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	type waitResult struct {
		d   Decision
		err error
	}
	resCh := make(chan waitResult, 1)
	go func() {
		d, err := m.WaitDecision(ctx, grantA)
		resCh <- waitResult{d, err}
	}()

	// Give the waiter time to register, then approve.
	time.Sleep(50 * time.Millisecond)
	d, err := m.Approve(ctx, grantA, Identity{Approver: "ops-alice", Method: MethodCLI}, "lgtm")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if d.Status != store.StatusApproved || d.Approver != "ops-alice" || d.Method != MethodCLI {
		t.Fatalf("decision: %+v", d)
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("WaitDecision: %v", res.err)
		}
		if res.d.Status != store.StatusApproved || res.d.Approver != "ops-alice" {
			t.Fatalf("waiter decision: %+v", res.d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not wake")
	}

	// First-use bookkeeping: both capabilities are approved.
	for _, capability := range []string{"s3.read-prefix", "s3.write-prefix"} {
		seen, approved, err := backend.FirstUseSeen(ctx, "invoice-bot", capability)
		if err != nil || !seen || !approved {
			t.Fatalf("first use %s: seen=%v approved=%v err=%v", capability, seen, approved, err)
		}
	}
}

func TestDenyRecordsFirstUseUnapproved(t *testing.T) {
	backend := openBackend(t, "")
	clock := &fakeClock{now: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	m := newManager(t, backend, 15*time.Minute, clock)
	ctx := context.Background()

	if _, err := m.Submit(ctx, pendingFixture(grantA)); err != nil {
		t.Fatal(err)
	}
	d, err := m.Deny(ctx, grantA, Identity{Approver: "ops-bob", Method: MethodAPI}, "not now")
	if err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if d.Status != store.StatusDenied || d.Note != "not now" {
		t.Fatalf("decision: %+v", d)
	}
	seen, approved, err := backend.FirstUseSeen(ctx, "invoice-bot", "s3.read-prefix")
	if err != nil || !seen || approved {
		t.Fatalf("first use after deny: seen=%v approved=%v err=%v", seen, approved, err)
	}
	// Waiting on a decided grant returns immediately.
	got, err := m.WaitDecision(ctx, grantA)
	if err != nil || got.Status != store.StatusDenied {
		t.Fatalf("wait on decided: %+v err=%v", got, err)
	}
}

func TestDecideValidatesInput(t *testing.T) {
	backend := openBackend(t, "")
	clock := &fakeClock{now: time.Now().UTC()}
	m := newManager(t, backend, time.Minute, clock)
	ctx := context.Background()
	if _, err := m.Submit(ctx, pendingFixture(grantA)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Approve(ctx, grantA, Identity{Method: MethodCLI}, ""); err == nil {
		t.Fatal("accepted empty approver")
	}
	if _, err := m.Approve(ctx, grantA, Identity{Approver: "x", Method: "slack"}, ""); err == nil {
		t.Fatal("accepted unknown method")
	}
	// Double decision fails with ErrNotPending.
	if _, err := m.Approve(ctx, grantA, Identity{Approver: "a", Method: MethodCLI}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Deny(ctx, grantA, Identity{Approver: "b", Method: MethodCLI}, ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("double decision: %v, want ErrNotPending", err)
	}
	// Unknown grant.
	if _, err := m.WaitDecision(ctx, "01K2G3H4J5K6M7N8P9Q0R1S2T9"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown grant: %v, want ErrNotFound", err)
	}
}

func TestTTLExpiryAcrossSimulatedRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.db")
	clock := &fakeClock{now: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	ttl := 15 * time.Minute
	ctx := context.Background()

	// First broker lifetime: submit and stop without deciding.
	backend := openBackend(t, path)
	m := newManager(t, backend, ttl, clock)
	if _, err := m.Submit(ctx, pendingFixture(grantA)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Submit(ctx, pendingFixture(grantB)); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}

	// Downtime crosses grantA's deadline only after restart; both rows
	// stayed pending on disk.
	clock.Advance(16 * time.Minute)

	backend2 := openBackend(t, path)
	m2 := newManager(t, backend2, ttl, clock)
	n, err := m2.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if n != 2 {
		t.Fatalf("swept %d, want 2 (expiry derives from stored received_at)", n)
	}
	for _, id := range []string{grantA, grantB} {
		p, err := m2.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != store.StatusExpiredPending {
			t.Fatalf("grant %s status %s, want expired_pending", id, p.Status)
		}
	}
	// Waiting on an expired grant returns immediately.
	d, err := m2.WaitDecision(ctx, grantA)
	if err != nil || d.Status != store.StatusExpiredPending {
		t.Fatalf("wait on expired: %+v err=%v", d, err)
	}
	// Deciding an expired grant fails.
	if _, err := m2.Approve(ctx, grantA, Identity{Approver: "late", Method: MethodCLI}, ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("approve after expiry: %v, want ErrNotPending", err)
	}
}

func TestWaiterLearnsExpiryFromLocalDeadline(t *testing.T) {
	backend := openBackend(t, "")
	// Real clock here: the waiter arms a real timer from received_at.
	m, err := New(backend, 100*time.Millisecond, Options{SweepInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := m.Submit(ctx, pendingFixture(grantA)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	d, err := m.WaitDecision(ctx, grantA)
	if err != nil {
		t.Fatalf("WaitDecision: %v", err)
	}
	if d.Status != store.StatusExpiredPending {
		t.Fatalf("status %s, want expired_pending", d.Status)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("expiry took %v; the local deadline did not fire", elapsed)
	}
	p, err := m.Get(ctx, grantA)
	if err != nil || p.Status != store.StatusExpiredPending {
		t.Fatalf("stored status: %+v err=%v", p, err)
	}
}

func TestWaitDecisionHonorsContext(t *testing.T) {
	backend := openBackend(t, "")
	clock := &fakeClock{now: time.Now().UTC()}
	m := newManager(t, backend, time.Hour, clock)
	if _, err := m.Submit(context.Background(), pendingFixture(grantA)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := m.WaitDecision(ctx, grantA)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v, want context.DeadlineExceeded", err)
	}
}

func TestRunSweeperWakesWaiters(t *testing.T) {
	backend := openBackend(t, "")
	m, err := New(backend, 80*time.Millisecond, Options{SweepInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	if _, err := m.Submit(ctx, pendingFixture(grantA)); err != nil {
		t.Fatal(err)
	}
	d, err := m.WaitDecision(ctx, grantA)
	if err != nil {
		t.Fatalf("WaitDecision: %v", err)
	}
	if d.Status != store.StatusExpiredPending {
		t.Fatalf("status %s, want expired_pending", d.Status)
	}
}
