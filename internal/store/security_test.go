package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestTakeTokenPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	ctx := context.Background()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

	s := openTestStore(t, Options{Path: path})
	// Burst 2, rate 1 per hour: two takes pass, the third is denied.
	for i := 0; i < 2; i++ {
		ok, err := s.TakeToken(ctx, "invoice-bot", "s3.read-prefix", 1, 2, now)
		if err != nil || !ok {
			t.Fatalf("take %d: ok=%v err=%v", i, ok, err)
		}
	}
	ok, err := s.TakeToken(ctx, "invoice-bot", "s3.read-prefix", 1, 2, now)
	if err != nil {
		t.Fatalf("take 3: %v", err)
	}
	if ok {
		t.Fatal("bucket did not exhaust")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Restart: the ledger must persist (I5). Still denied right away.
	s2 := openTestStore(t, Options{Path: path})
	ok, err = s2.TakeToken(ctx, "invoice-bot", "s3.read-prefix", 1, 2, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("post-restart take: %v", err)
	}
	if ok {
		t.Fatal("restart reset the rate ledger")
	}
	// One hour later one token has refilled.
	ok, err = s2.TakeToken(ctx, "invoice-bot", "s3.read-prefix", 1, 2, now.Add(time.Hour+time.Minute))
	if err != nil || !ok {
		t.Fatalf("refill take: ok=%v err=%v", ok, err)
	}
}

func TestTakeTokenCapsAtBurst(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	if _, err := s.TakeToken(ctx, "a", "c", 30, 2, now); err != nil {
		t.Fatal(err)
	}
	// A week of refill must not exceed the burst.
	later := now.Add(7 * 24 * time.Hour)
	for i := 0; i < 2; i++ {
		ok, err := s.TakeToken(ctx, "a", "c", 30, 2, later)
		if err != nil || !ok {
			t.Fatalf("take %d after refill: ok=%v err=%v", i, ok, err)
		}
	}
	ok, err := s.TakeToken(ctx, "a", "c", 30, 2, later)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("bucket exceeded burst after long idle")
	}
}

func TestTakeTokenValidatesInput(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	now := time.Now()
	if _, err := s.TakeToken(ctx, "", "c", 1, 1, now); err == nil {
		t.Fatal("accepted empty agent")
	}
	if _, err := s.TakeToken(ctx, "a", "c", 0, 1, now); err == nil {
		t.Fatal("accepted zero rate")
	}
}

func TestDistinctCapabilities24h(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

	uses := []struct {
		capability string
		at         time.Time
	}{
		{"s3.read-prefix", now.Add(-1 * time.Hour)},
		{"s3.read-prefix", now.Add(-2 * time.Hour)}, // duplicate capability
		{"sqs.consume", now.Add(-23 * time.Hour)},
		{"logs.read", now.Add(-25 * time.Hour)}, // outside the window
	}
	for _, u := range uses {
		if err := s.RecordCapabilityUse(ctx, "invoice-bot", u.capability, u.at); err != nil {
			t.Fatalf("RecordCapabilityUse: %v", err)
		}
	}
	n, err := s.DistinctCapabilities24h(ctx, "invoice-bot", now)
	if err != nil {
		t.Fatalf("DistinctCapabilities24h: %v", err)
	}
	if n != 2 {
		t.Fatalf("distinct capabilities: %d, want 2", n)
	}
	// Another agent's ledger is separate.
	n, err = s.DistinctCapabilities24h(ctx, "other-bot", now)
	if err != nil || n != 0 {
		t.Fatalf("other agent: n=%d err=%v, want 0", n, err)
	}
}

func TestFirstUseSet(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	now := time.Now().UTC()

	seen, approved, err := s.FirstUseSeen(ctx, "invoice-bot", "s3.read-prefix")
	if err != nil || seen || approved {
		t.Fatalf("fresh pair: seen=%v approved=%v err=%v", seen, approved, err)
	}
	if err := s.MarkFirstUse(ctx, "invoice-bot", "s3.read-prefix", now, false); err != nil {
		t.Fatalf("MarkFirstUse: %v", err)
	}
	seen, approved, err = s.FirstUseSeen(ctx, "invoice-bot", "s3.read-prefix")
	if err != nil || !seen || approved {
		t.Fatalf("marked pair: seen=%v approved=%v err=%v", seen, approved, err)
	}
	// Approval only moves forward.
	if err := s.MarkFirstUse(ctx, "invoice-bot", "s3.read-prefix", now, true); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkFirstUse(ctx, "invoice-bot", "s3.read-prefix", now, false); err != nil {
		t.Fatal(err)
	}
	_, approved, err = s.FirstUseSeen(ctx, "invoice-bot", "s3.read-prefix")
	if err != nil || !approved {
		t.Fatalf("approval regressed: approved=%v err=%v", approved, err)
	}
}

func TestIdempotencyWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	s := openTestStore(t, Options{Path: path})
	ctx := context.Background()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	expires := now.Add(10 * time.Minute)

	stored, created, err := s.PutIdempotencyKey(ctx, "invoice-bot", "run-4412-step-3", "GRANT1", now, expires)
	if err != nil || !created || stored != "GRANT1" {
		t.Fatalf("first put: stored=%q created=%v err=%v", stored, created, err)
	}
	// A repeat inside the window returns the stored grant.
	stored, created, err = s.PutIdempotencyKey(ctx, "invoice-bot", "run-4412-step-3", "GRANT2", now.Add(time.Minute), expires)
	if err != nil || created || stored != "GRANT1" {
		t.Fatalf("repeat put: stored=%q created=%v err=%v", stored, created, err)
	}
	got, ok, err := s.LookupIdempotencyKey(ctx, "invoice-bot", "run-4412-step-3", now.Add(time.Minute))
	if err != nil || !ok || got != "GRANT1" {
		t.Fatalf("lookup: got=%q ok=%v err=%v", got, ok, err)
	}
	// The window is per agent.
	_, ok, err = s.LookupIdempotencyKey(ctx, "other-bot", "run-4412-step-3", now.Add(time.Minute))
	if err != nil || ok {
		t.Fatalf("cross-agent lookup: ok=%v err=%v", ok, err)
	}

	// Survives restart.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := openTestStore(t, Options{Path: path})
	got, ok, err = s2.LookupIdempotencyKey(ctx, "invoice-bot", "run-4412-step-3", now.Add(2*time.Minute))
	if err != nil || !ok || got != "GRANT1" {
		t.Fatalf("post-restart lookup: got=%q ok=%v err=%v", got, ok, err)
	}

	// After expiry the key is gone and a new grant may claim it.
	after := expires.Add(time.Second)
	_, ok, err = s2.LookupIdempotencyKey(ctx, "invoice-bot", "run-4412-step-3", after)
	if err != nil || ok {
		t.Fatalf("expired lookup: ok=%v err=%v", ok, err)
	}
	stored, created, err = s2.PutIdempotencyKey(ctx, "invoice-bot", "run-4412-step-3", "GRANT3", after, after.Add(10*time.Minute))
	if err != nil || !created || stored != "GRANT3" {
		t.Fatalf("post-expiry put: stored=%q created=%v err=%v", stored, created, err)
	}
	n, err := s2.DeleteExpiredIdempotencyKeys(ctx, after.Add(11*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("gc: n=%d err=%v", n, err)
	}
}

func TestPendingApprovalLifecycle(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

	p := PendingApproval{
		GrantID:      "01K2G3H4J5K6M7N8P9Q0R1S2T3",
		AgentID:      "invoice-bot",
		Profile:      "s3-archiver",
		Task:         "archive invoices",
		Capabilities: []string{"s3.read-prefix"},
		RequiredBy:   "first_use",
		ReceivedAt:   now,
		ExpiresAt:    now.Add(15 * time.Minute),
	}
	if err := s.CreatePendingApproval(ctx, p); err != nil {
		t.Fatalf("CreatePendingApproval: %v", err)
	}
	got, err := s.GetPendingApproval(ctx, p.GrantID)
	if err != nil {
		t.Fatalf("GetPendingApproval: %v", err)
	}
	if got.Status != StatusPending || got.AgentID != "invoice-bot" || len(got.Capabilities) != 1 {
		t.Fatalf("row mismatch: %+v", got)
	}
	if !got.ReceivedAt.Equal(now) {
		t.Fatalf("received_at %v, want %v", got.ReceivedAt, now)
	}

	list, err := s.ListPendingApprovals(ctx, StatusPending)
	if err != nil || len(list) != 1 {
		t.Fatalf("list pending: n=%d err=%v", len(list), err)
	}

	decided, err := s.DecidePendingApproval(ctx, p.GrantID, StatusApproved, "ops-alice", "cli", "lgtm", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("DecidePendingApproval: %v", err)
	}
	if decided.Status != StatusApproved || decided.Approver != "ops-alice" {
		t.Fatalf("decision mismatch: %+v", decided)
	}
	// A second decision reports the conflict and keeps the first.
	again, err := s.DecidePendingApproval(ctx, p.GrantID, StatusDenied, "ops-bob", "cli", "no", now.Add(2*time.Minute))
	if !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("second decision: err=%v, want ErrAlreadyDecided", err)
	}
	if again.Status != StatusApproved {
		t.Fatalf("second decision clobbered the first: %+v", again)
	}
}

func TestExpirePendingApprovalsDeterministic(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	ttl := 15 * time.Minute

	old := PendingApproval{GrantID: "01K2G3H4J5K6M7N8P9Q0R1S2T4", AgentID: "a1",
		ReceivedAt: now.Add(-16 * time.Minute)}
	fresh := PendingApproval{GrantID: "01K2G3H4J5K6M7N8P9Q0R1S2T5", AgentID: "a1",
		ReceivedAt: now.Add(-time.Minute)}
	for _, p := range []PendingApproval{old, fresh} {
		if err := s.CreatePendingApproval(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	expired, err := s.ExpirePendingApprovals(ctx, ttl, now)
	if err != nil {
		t.Fatalf("ExpirePendingApprovals: %v", err)
	}
	if len(expired) != 1 || expired[0].GrantID != old.GrantID {
		t.Fatalf("expired %v, want only %s", expired, old.GrantID)
	}
	got, err := s.GetPendingApproval(ctx, fresh.GrantID)
	if err != nil || got.Status != StatusPending {
		t.Fatalf("fresh row: %+v err=%v", got, err)
	}
}
