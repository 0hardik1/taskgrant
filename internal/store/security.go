package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// GuardrailState is the durable security state surface the guardrail
// evaluator consumes (G8 and invariant I5). The store implements it
// directly so wiring is one assignment. The guardrails package defines
// its own consumer-side interface; this declaration documents and
// compile-checks the store's side of the contract.
type GuardrailState interface {
	TakeToken(ctx context.Context, agent, capability string, ratePerHour, burst float64, now time.Time) (bool, error)
	DistinctCapabilities24h(ctx context.Context, agent string, now time.Time) (int, error)
	RecordCapabilityUse(ctx context.Context, agent, capability string, now time.Time) error
	FirstUseSeen(ctx context.Context, agent, capability string) (seen, approved bool, err error)
	MarkFirstUse(ctx context.Context, agent, capability string, now time.Time, approved bool) error
}

var _ GuardrailState = (*Store)(nil)

// TakeToken takes one token from the durable (agent, capability) bucket
// and reports whether the caller may proceed. The bucket starts full at
// burst tokens and refills at ratePerHour, capped at burst. State
// persists across restarts, so an induced restart never resets the rate
// ledger (I5).
func (s *Store) TakeToken(ctx context.Context, agent, capability string, ratePerHour, burst float64, now time.Time) (bool, error) {
	if agent == "" || capability == "" {
		return false, errors.New("store: TakeToken requires agent and capability")
	}
	if ratePerHour <= 0 || burst <= 0 {
		return false, fmt.Errorf("store: TakeToken requires positive rate and burst, got %v/%v", ratePerHour, burst)
	}
	now = now.UTC()

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store: rate begin: %w", err)
	}
	defer tx.Rollback()

	var tokens float64
	var updatedNanos int64
	row := tx.QueryRowContext(ctx,
		`SELECT tokens, updated_at FROM rate_buckets WHERE agent = ? AND capability = ?`,
		agent, capability)
	switch err := row.Scan(&tokens, &updatedNanos); {
	case errors.Is(err, sql.ErrNoRows):
		tokens = burst
	case err != nil:
		return false, fmt.Errorf("store: rate read: %w", err)
	default:
		elapsed := now.Sub(nanosToTime(updatedNanos))
		if elapsed > 0 {
			tokens += elapsed.Hours() * ratePerHour
		}
		if tokens > burst {
			tokens = burst
		}
	}

	allowed := tokens >= 1
	if allowed {
		tokens--
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO rate_buckets (agent, capability, tokens, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(agent, capability) DO UPDATE SET tokens = excluded.tokens, updated_at = excluded.updated_at`,
		agent, capability, tokens, timeToNanos(now)); err != nil {
		return false, fmt.Errorf("store: rate write: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: rate commit: %w", err)
	}
	return allowed, nil
}

// DistinctCapabilities24h counts the distinct capabilities the agent
// used in the 24 hours before now (the anti-creep ledger of G8).
func (s *Store) DistinctCapabilities24h(ctx context.Context, agent string, now time.Time) (int, error) {
	since := timeToNanos(now.Add(-24 * time.Hour))
	row := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT capability) FROM capability_uses WHERE agent = ? AND used_at > ?`,
		agent, since)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, fmt.Errorf("store: distinct capabilities: %w", err)
	}
	return n, nil
}

// RecordCapabilityUse appends one use of (agent, capability) to the
// rolling ledger and drops entries older than 48 hours.
func (s *Store) RecordCapabilityUse(ctx context.Context, agent, capability string, now time.Time) error {
	if agent == "" || capability == "" {
		return errors.New("store: RecordCapabilityUse requires agent and capability")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: capability use begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO capability_uses (agent, capability, used_at) VALUES (?, ?, ?)`,
		agent, capability, timeToNanos(now)); err != nil {
		return fmt.Errorf("store: capability use insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM capability_uses WHERE used_at < ?`,
		timeToNanos(now.Add(-48*time.Hour))); err != nil {
		return fmt.Errorf("store: capability use gc: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: capability use commit: %w", err)
	}
	return nil
}

// FirstUseSeen reports whether (agent, capability) is in the durable
// first-use set and whether that first use was approved.
func (s *Store) FirstUseSeen(ctx context.Context, agent, capability string) (seen, approved bool, err error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT approved FROM first_use WHERE agent = ? AND capability = ?`,
		agent, capability)
	var a int
	switch err := row.Scan(&a); {
	case errors.Is(err, sql.ErrNoRows):
		return false, false, nil
	case err != nil:
		return false, false, fmt.Errorf("store: first use read: %w", err)
	}
	return true, a != 0, nil
}

// MarkFirstUse records (agent, capability) in the first-use set. The
// earliest first_used_at wins; approved only ever moves from false to
// true.
func (s *Store) MarkFirstUse(ctx context.Context, agent, capability string, now time.Time, approved bool) error {
	if agent == "" || capability == "" {
		return errors.New("store: MarkFirstUse requires agent and capability")
	}
	a := 0
	if approved {
		a = 1
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO first_use (agent, capability, first_used_at, approved)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(agent, capability) DO UPDATE SET approved = MAX(first_use.approved, excluded.approved)`,
		agent, capability, timeToNanos(now), a); err != nil {
		return fmt.Errorf("store: first use write: %w", err)
	}
	return nil
}

// PutIdempotencyKey stores (agent, key) -> grantID until expiresAt. A
// repeat of a live key returns the stored grant id and false, so the
// caller replays the existing grant instead of minting again. An
// expired row is replaced.
func (s *Store) PutIdempotencyKey(ctx context.Context, agent, key, grantID string, now, expiresAt time.Time) (storedGrantID string, created bool, err error) {
	if agent == "" || key == "" || grantID == "" {
		return "", false, errors.New("store: idempotency key requires agent, key, and grant id")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("store: idempotency begin: %w", err)
	}
	defer tx.Rollback()

	var existing string
	var expNanos int64
	row := tx.QueryRowContext(ctx,
		`SELECT grant_id, expires_at FROM idempotency_keys WHERE agent = ? AND key = ?`,
		agent, key)
	switch err := row.Scan(&existing, &expNanos); {
	case errors.Is(err, sql.ErrNoRows):
		// New key.
	case err != nil:
		return "", false, fmt.Errorf("store: idempotency read: %w", err)
	default:
		if nanosToTime(expNanos).After(now) {
			return existing, false, nil
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO idempotency_keys (agent, key, grant_id, expires_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(agent, key) DO UPDATE SET grant_id = excluded.grant_id, expires_at = excluded.expires_at`,
		agent, key, grantID, timeToNanos(expiresAt)); err != nil {
		return "", false, fmt.Errorf("store: idempotency write: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("store: idempotency commit: %w", err)
	}
	return grantID, true, nil
}

// LookupIdempotencyKey returns the grant id stored for (agent, key)
// when the key is still inside its window.
func (s *Store) LookupIdempotencyKey(ctx context.Context, agent, key string, now time.Time) (grantID string, ok bool, err error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT grant_id, expires_at FROM idempotency_keys WHERE agent = ? AND key = ?`,
		agent, key)
	var g string
	var expNanos int64
	switch err := row.Scan(&g, &expNanos); {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("store: idempotency lookup: %w", err)
	}
	if !nanosToTime(expNanos).After(now) {
		return "", false, nil
	}
	return g, true, nil
}

// DeleteExpiredIdempotencyKeys removes keys whose window closed.
func (s *Store) DeleteExpiredIdempotencyKeys(ctx context.Context, now time.Time) (int64, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM idempotency_keys WHERE expires_at <= ?`, timeToNanos(now))
	if err != nil {
		return 0, fmt.Errorf("store: idempotency gc: %w", err)
	}
	return res.RowsAffected()
}

// PendingStatus is the lifecycle state of one pending approval row.
type PendingStatus string

const (
	StatusPending        PendingStatus = "pending"
	StatusApproved       PendingStatus = "approved"
	StatusDenied         PendingStatus = "denied"
	StatusExpiredPending PendingStatus = "expired_pending"
)

// Valid reports whether p is a known pending status.
func (p PendingStatus) Valid() bool {
	switch p {
	case StatusPending, StatusApproved, StatusDenied, StatusExpiredPending:
		return true
	}
	return false
}

// PendingApproval is one durable pending-approval queue row (I5,
// section 11). Task and Reason hold raw agent bytes; sanitize on every
// human-facing render.
type PendingApproval struct {
	GrantID      string
	AgentID      string
	Profile      string
	Task         string
	Reason       string
	PolicyJSON   string
	Capabilities []string
	RequiredBy   string // why approval is required: rule, first_use, guardrail
	Status       PendingStatus
	ReceivedAt   time.Time
	ExpiresAt    time.Time
	DecidedAt    time.Time
	Approver     string
	Method       string
	Note         string
}

// CreatePendingApproval inserts one pending row. The grant id must be
// unique in the queue.
func (s *Store) CreatePendingApproval(ctx context.Context, p PendingApproval) error {
	if p.GrantID == "" || p.AgentID == "" {
		return errors.New("store: pending approval requires grant id and agent id")
	}
	if p.Status == "" {
		p.Status = StatusPending
	}
	if !p.Status.Valid() {
		return fmt.Errorf("store: invalid pending status %q", string(p.Status))
	}
	caps, err := json.Marshal(p.Capabilities)
	if err != nil {
		return fmt.Errorf("store: pending capabilities: %w", err)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO pending_approvals (grant_id, agent_id, profile, task, reason,
			policy_json, capabilities, required_by, status, received_at, expires_at,
			decided_at, approver, method, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.GrantID, p.AgentID, p.Profile, p.Task, p.Reason,
		p.PolicyJSON, string(caps), p.RequiredBy, string(p.Status),
		timeToNanos(p.ReceivedAt), timeToNanos(p.ExpiresAt),
		timeToNanos(p.DecidedAt), p.Approver, p.Method, p.Note); err != nil {
		return fmt.Errorf("store: create pending approval: %w", err)
	}
	return nil
}

const pendingColumns = `grant_id, agent_id, profile, task, reason, policy_json,
	capabilities, required_by, status, received_at, expires_at, decided_at,
	approver, method, note`

func scanPending(sc rowScanner) (PendingApproval, error) {
	var p PendingApproval
	var caps, status string
	var received, expires, decided int64
	err := sc.Scan(&p.GrantID, &p.AgentID, &p.Profile, &p.Task, &p.Reason,
		&p.PolicyJSON, &caps, &p.RequiredBy, &status, &received, &expires,
		&decided, &p.Approver, &p.Method, &p.Note)
	if err != nil {
		return PendingApproval{}, err
	}
	p.Status = PendingStatus(status)
	p.ReceivedAt = nanosToTime(received)
	p.ExpiresAt = nanosToTime(expires)
	p.DecidedAt = nanosToTime(decided)
	if caps != "" {
		if err := json.Unmarshal([]byte(caps), &p.Capabilities); err != nil {
			return PendingApproval{}, fmt.Errorf("store: pending capabilities decode: %w", err)
		}
	}
	return p, nil
}

// GetPendingApproval returns one queue row by grant id.
func (s *Store) GetPendingApproval(ctx context.Context, grantID string) (PendingApproval, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+pendingColumns+` FROM pending_approvals WHERE grant_id = ?`, grantID)
	p, err := scanPending(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PendingApproval{}, ErrNotFound
	}
	if err != nil {
		return PendingApproval{}, fmt.Errorf("store: get pending approval: %w", err)
	}
	return p, nil
}

// ListPendingApprovals returns queue rows, oldest first. An empty
// status lists every row.
func (s *Store) ListPendingApprovals(ctx context.Context, status PendingStatus) ([]PendingApproval, error) {
	q := `SELECT ` + pendingColumns + ` FROM pending_approvals`
	var args []any
	if status != "" {
		if !status.Valid() {
			return nil, fmt.Errorf("store: invalid pending status %q", string(status))
		}
		q += ` WHERE status = ?`
		args = append(args, string(status))
	}
	q += ` ORDER BY received_at ASC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list pending approvals: %w", err)
	}
	defer rows.Close()
	var out []PendingApproval
	for rows.Next() {
		p, err := scanPending(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan pending approval: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: pending approval rows: %w", err)
	}
	return out, nil
}

// DecidePendingApproval moves one row from pending to the given
// terminal status. The update is atomic: it applies only when the row
// is still pending. When the row exists but is already decided the
// current row returns together with ErrAlreadyDecided.
func (s *Store) DecidePendingApproval(ctx context.Context, grantID string, status PendingStatus, approver, method, note string, decidedAt time.Time) (PendingApproval, error) {
	switch status {
	case StatusApproved, StatusDenied, StatusExpiredPending:
	default:
		return PendingApproval{}, fmt.Errorf("store: %q is not a terminal pending status", string(status))
	}
	s.writeMu.Lock()
	res, err := s.db.ExecContext(ctx, `
		UPDATE pending_approvals
		SET status = ?, approver = ?, method = ?, note = ?, decided_at = ?
		WHERE grant_id = ? AND status = ?`,
		string(status), approver, method, note, timeToNanos(decidedAt),
		grantID, string(StatusPending))
	s.writeMu.Unlock()
	if err != nil {
		return PendingApproval{}, fmt.Errorf("store: decide pending approval: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return PendingApproval{}, fmt.Errorf("store: decide pending approval: %w", err)
	}
	p, getErr := s.GetPendingApproval(ctx, grantID)
	if getErr != nil {
		return PendingApproval{}, getErr
	}
	if n == 0 {
		return p, ErrAlreadyDecided
	}
	return p, nil
}

// ExpirePendingApprovals marks every pending row whose received_at is
// at or before now minus ttl as expired_pending and returns the rows it
// expired. Expiry derives from the stored received_at, so it is
// deterministic across restarts (section 11).
func (s *Store) ExpirePendingApprovals(ctx context.Context, ttl time.Duration, now time.Time) ([]PendingApproval, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("store: expire requires a positive ttl, got %v", ttl)
	}
	deadline := timeToNanos(now.Add(-ttl))

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+pendingColumns+` FROM pending_approvals WHERE status = ? AND received_at <= ?`,
		string(StatusPending), deadline)
	if err != nil {
		return nil, fmt.Errorf("store: expire select: %w", err)
	}
	var doomed []PendingApproval
	for rows.Next() {
		p, err := scanPending(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: expire scan: %w", err)
		}
		doomed = append(doomed, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store: expire rows: %w", err)
	}
	rows.Close()

	var expired []PendingApproval
	for _, p := range doomed {
		got, err := s.DecidePendingApproval(ctx, p.GrantID, StatusExpiredPending, "", "", "", now)
		if errors.Is(err, ErrAlreadyDecided) {
			continue // a human decision won the race
		}
		if err != nil {
			return expired, err
		}
		expired = append(expired, got)
	}
	return expired, nil
}
