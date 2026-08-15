package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// DefaultListLimit bounds List and Search result sizes when the filter
// does not set one.
const DefaultListLimit = 1000

// ListFilter selects records for List and ExportJSONL. Zero fields
// match everything.
type ListFilter struct {
	Agent   string
	Outcome string
	Profile string
	GrantID string
	Kind    domain.RecordKind
	// ResourcePattern is a SQLite GLOB over the record_resources side
	// table, for example "arn:aws:s3:::acme-invoices-prod*".
	ResourcePattern string
	Since           time.Time
	Until           time.Time
	Limit           int
}

func (f ListFilter) build() (where string, args []any, limit int) {
	var conds []string
	if f.Agent != "" {
		conds = append(conds, "r.agent_id = ?")
		args = append(args, f.Agent)
	}
	if f.Outcome != "" {
		conds = append(conds, "r.outcome = ?")
		args = append(args, f.Outcome)
	}
	if f.Profile != "" {
		conds = append(conds, "r.profile = ?")
		args = append(args, f.Profile)
	}
	if f.GrantID != "" {
		conds = append(conds, "r.grant_id = ?")
		args = append(args, f.GrantID)
	}
	if f.Kind != "" {
		conds = append(conds, "r.kind = ?")
		args = append(args, string(f.Kind))
	}
	if !f.Since.IsZero() {
		conds = append(conds, "r.ts >= ?")
		args = append(args, timeToNanos(f.Since))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "r.ts < ?")
		args = append(args, timeToNanos(f.Until))
	}
	if f.ResourcePattern != "" {
		conds = append(conds, `r.record_id IN
			(SELECT record_id FROM record_resources WHERE resource GLOB ?)`)
		args = append(args, f.ResourcePattern)
	}
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	limit = f.Limit
	if limit <= 0 {
		limit = DefaultListLimit
	}
	return where, args, limit
}

// List returns records matching the filter in chain (seq) order.
func (s *Store) List(ctx context.Context, f ListFilter) ([]Record, error) {
	where, args, limit := f.build()
	q := `SELECT ` + recordColumns + ` FROM records r` + where + ` ORDER BY r.seq ASC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list scan: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list rows: %w", err)
	}
	if err := s.loadResources(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GrantChain returns every record of one grant in chain order: the full
// negotiation and decision history behind "taskgrant audit show".
func (s *Store) GrantChain(ctx context.Context, grantID string) ([]Record, error) {
	return s.List(ctx, ListFilter{GrantID: grantID, Limit: DefaultListLimit})
}

// Search runs full-text search over task, reason, and explanation. With
// FTS5 unavailable it falls back to LIKE substring matching over the
// same columns. The query is hostile input; FTS syntax is neutralized
// by quoting every token.
func (s *Store) Search(ctx context.Context, query string, limit int) ([]Record, error) {
	if limit <= 0 {
		limit = DefaultListLimit
	}
	if s.ftsEnabled {
		match := ftsQuery(query)
		if match == "" {
			return nil, nil
		}
		rows, err := s.db.QueryContext(ctx, `
			SELECT `+recordColumnsQualified+`
			FROM records_fts f JOIN records r ON r.seq = f.rowid
			WHERE records_fts MATCH ? ORDER BY rank LIMIT ?`, match, limit)
		if err == nil {
			defer rows.Close()
			var out []Record
			for rows.Next() {
				rec, err := scanRecord(rows)
				if err != nil {
					return nil, fmt.Errorf("store: search scan: %w", err)
				}
				out = append(out, rec)
			}
			if err := rows.Err(); err != nil {
				return nil, fmt.Errorf("store: search rows: %w", err)
			}
			if err := s.loadResources(ctx, out); err != nil {
				return nil, err
			}
			return out, nil
		}
		s.logger.Warn("store: FTS query failed, falling back to LIKE", "error", err)
	}
	return s.searchLike(ctx, query, limit)
}

// ftsQuery converts hostile free text into a safe FTS5 match string:
// every whitespace token becomes a quoted phrase, joined by implicit
// AND.
func ftsQuery(query string) string {
	fields := strings.Fields(query)
	if len(fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fields))
	for _, tok := range fields {
		parts = append(parts, `"`+strings.ReplaceAll(tok, `"`, `""`)+`"`)
	}
	return strings.Join(parts, " ")
}

// searchLike is the FTS fallback: every token must appear as a
// substring of task, reason, or explanation.
func (s *Store) searchLike(ctx context.Context, query string, limit int) ([]Record, error) {
	fields := strings.Fields(query)
	if len(fields) == 0 {
		return nil, nil
	}
	var conds []string
	var args []any
	for _, tok := range fields {
		p := likePattern(tok)
		conds = append(conds, `(r.task LIKE ? ESCAPE '\' OR r.reason LIKE ? ESCAPE '\' OR r.explanation LIKE ? ESCAPE '\')`)
		args = append(args, p, p, p)
	}
	q := `SELECT ` + recordColumns + ` FROM records r WHERE ` +
		strings.Join(conds, " AND ") + ` ORDER BY r.seq ASC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: like search: %w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("store: like search scan: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: like search rows: %w", err)
	}
	if err := s.loadResources(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ExportJSONL streams records matching the filter as canonical JSON
// lines to w ("taskgrant audit export --format jsonl"). It streams row
// by row and never buffers the full result.
func (s *Store) ExportJSONL(ctx context.Context, w io.Writer, f ListFilter) (int64, error) {
	where, args, limit := f.build()
	if f.Limit <= 0 {
		limit = 1<<62 - 1 // export everything unless the caller bounds it
	}
	q := `SELECT ` + recordColumns + ` FROM records r` + where + ` ORDER BY r.seq ASC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return 0, fmt.Errorf("store: export: %w", err)
	}
	defer rows.Close()
	var n int64
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return n, fmt.Errorf("store: export scan: %w", err)
		}
		one := []Record{rec}
		if err := s.loadResources(ctx, one); err != nil {
			return n, err
		}
		line, err := exportLine(one[0])
		if err != nil {
			return n, fmt.Errorf("store: export encode: %w", err)
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return n, fmt.Errorf("store: export write: %w", err)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return n, fmt.Errorf("store: export rows: %w", err)
	}
	return n, nil
}

// ScopeGrant is one live grant inside a ScopeReport.
type ScopeGrant struct {
	GrantID      string    `json:"grant_id"`
	Profile      string    `json:"profile,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Capabilities []string  `json:"capabilities,omitempty"`
	Actions      []string  `json:"actions,omitempty"`
	Resources    []string  `json:"resources,omitempty"`
}

// ScopeReport is the union of an agent's live-window grants: what the
// agent can do right now across every unexpired session ("taskgrant
// audit scope", creep review).
type ScopeReport struct {
	Agent        string       `json:"agent"`
	GeneratedAt  time.Time    `json:"generated_at"`
	LiveGrants   []ScopeGrant `json:"live_grants"`
	Actions      []string     `json:"actions"`      // union, sorted
	Resources    []string     `json:"resources"`    // union, sorted
	Capabilities []string     `json:"capabilities"` // union, sorted
}

// scopeBody is the subset of a minted decision body Scope reads.
type scopeBody struct {
	Expiration      string `json:"expiration"`
	ExpandedActions []any  `json:"expanded_actions"`
	Capabilities    []any  `json:"capabilities"`
	STS             *struct {
		Expiration string `json:"expiration"`
	} `json:"sts"`
}

// Scope aggregates the agent's live-window grants at now. It scans
// minted records (grant_decision and approval kinds) young enough to
// still be live under the STS ceiling and keeps those whose recorded
// expiration is after now.
func (s *Store) Scope(ctx context.Context, agent string, now time.Time) (ScopeReport, error) {
	report := ScopeReport{Agent: agent, GeneratedAt: now.UTC()}
	// 12 h is the STS session ceiling; nothing older can still be live.
	since := now.Add(-13 * time.Hour)
	recs, err := s.List(ctx, ListFilter{Agent: agent, Since: since, Limit: 1 << 20})
	if err != nil {
		return ScopeReport{}, err
	}
	actions := map[string]struct{}{}
	resources := map[string]struct{}{}
	capabilities := map[string]struct{}{}
	for _, rec := range recs {
		if rec.Kind != domain.RecordGrantDecision && rec.Kind != domain.RecordApproval {
			continue
		}
		var body scopeBody
		if err := json.Unmarshal(rec.Body, &body); err != nil {
			continue // non-conforming body, skip in aggregation
		}
		exp := parseExpiration(body)
		if exp.IsZero() || !exp.After(now) {
			continue
		}
		g := ScopeGrant{GrantID: rec.GrantID, Profile: rec.Profile, ExpiresAt: exp}
		for _, a := range body.ExpandedActions {
			if str, ok := a.(string); ok {
				g.Actions = append(g.Actions, str)
				actions[str] = struct{}{}
			}
		}
		for _, c := range body.Capabilities {
			if id := capabilityID(c); id != "" {
				g.Capabilities = append(g.Capabilities, id)
				capabilities[id] = struct{}{}
			}
		}
		g.Resources = rec.Resources
		for _, r := range rec.Resources {
			resources[r] = struct{}{}
		}
		report.LiveGrants = append(report.LiveGrants, g)
	}
	report.Actions = sortedKeys(actions)
	report.Resources = sortedKeys(resources)
	report.Capabilities = sortedKeys(capabilities)
	return report, nil
}

// parseExpiration reads the credential expiry from a decision body,
// checking the top-level and STS-block locations.
func parseExpiration(b scopeBody) time.Time {
	for _, raw := range []string{b.Expiration, stsExpiration(b)} {
		if raw == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

func stsExpiration(b scopeBody) string {
	if b.STS == nil {
		return ""
	}
	return b.STS.Expiration
}

// capabilityID extracts a capability id from either a plain string or
// a {"id": ..., "version": ...} object.
func capabilityID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if id, ok := t["id"].(string); ok {
			return id
		}
	}
	return ""
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
