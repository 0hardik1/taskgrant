// Package store is the taskgrant persistence layer (architecture
// section 9): the append-only decision log on SQLite with a hash chain
// and an external anchor, plus the durable security state of invariant
// I5 (rate ledger, first-use set, pending approvals, idempotency keys)
// and the query paths the audit CLI needs.
//
// Concurrency model: one writer. Every mutation serializes through one
// mutex; reads use the connection pool under WAL.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // driver name "sqlite"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// GenesisHash is the prev_hash of the first record of a chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ErrNotFound marks a lookup that matched no row.
var ErrNotFound = errors.New("store: not found")

// ErrAlreadyDecided marks a pending-approval decision attempt on a row
// that is no longer pending.
var ErrAlreadyDecided = errors.New("store: approval already decided")

// Record is one decision log record: the promoted envelope columns plus
// the canonical JSON body. Task, Reason, and Explanation feed the FTS
// index; they hold raw agent bytes and every human-facing render must
// sanitize them (section 12.5).
type Record struct {
	Seq            int64             `json:"seq"`
	RecordID       string            `json:"record_id"`
	GrantID        string            `json:"grant_id"`
	AgentID        string            `json:"agent_id"`
	TS             time.Time         `json:"ts"`
	Kind           domain.RecordKind `json:"kind"`
	Outcome        string            `json:"outcome,omitempty"`
	Profile        string            `json:"profile,omitempty"`
	SourceIdentity string            `json:"source_identity,omitempty"`
	AccessKeyID    string            `json:"access_key_id,omitempty"`
	Task           string            `json:"task,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Explanation    string            `json:"explanation,omitempty"`
	Resources      []string          `json:"resources,omitempty"`
	Body           json.RawMessage   `json:"body"`
	PrevHash       string            `json:"prev_hash"`
	Hash           string            `json:"hash"`
}

// Options configures Open.
type Options struct {
	// Path is the SQLite database file path.
	Path string
	// MirrorJSONLPath, when set, appends every record as one JSON line
	// at write time for log-shipper tailing (section 9.2).
	MirrorJSONLPath string
	// Logger receives operational warnings. Defaults to slog.Default().
	Logger *slog.Logger
}

// Store is one open decision log database. Safe for concurrent use.
type Store struct {
	db     *sql.DB
	logger *slog.Logger

	writeMu  sync.Mutex // serializes every write and guards the head
	headSeq  int64
	headHash string

	ftsEnabled bool

	mirrorMu sync.Mutex
	mirror   *os.File

	anchorMu   sync.Mutex
	anchorStop chan struct{}
	anchorDone chan struct{}
}

// Open opens or creates the database at opts.Path, applies the schema,
// and loads the chain head.
func Open(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("store: path is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if dir := filepath.Dir(opts.Path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: create dir: %w", err)
		}
	}
	dsn := "file:" + url.PathEscape(opts.Path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)

	s := &Store{db: db, logger: opts.Logger}
	if err := s.applySchema(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.loadHead(); err != nil {
		db.Close()
		return nil, err
	}
	if opts.MirrorJSONLPath != "" {
		f, err := os.OpenFile(opts.MirrorJSONLPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("store: open mirror jsonl: %w", err)
		}
		s.mirror = f
	}
	return s, nil
}

// Close stops the anchor loop, closes the mirror file, and closes the
// database.
func (s *Store) Close() error {
	s.stopAnchorLoop()
	var errs []error
	s.mirrorMu.Lock()
	if s.mirror != nil {
		if err := s.mirror.Close(); err != nil {
			errs = append(errs, err)
		}
		s.mirror = nil
	}
	s.mirrorMu.Unlock()
	if err := s.db.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// FTSEnabled reports whether the FTS5 index is active. When false the
// Search method falls back to LIKE matching.
func (s *Store) FTSEnabled() bool { return s.ftsEnabled }

const schemaSQL = `
CREATE TABLE IF NOT EXISTS records (
	seq             INTEGER PRIMARY KEY AUTOINCREMENT,
	record_id       TEXT    NOT NULL UNIQUE,
	grant_id        TEXT    NOT NULL DEFAULT '',
	agent_id        TEXT    NOT NULL DEFAULT '',
	ts              INTEGER NOT NULL,
	kind            TEXT    NOT NULL,
	outcome         TEXT    NOT NULL DEFAULT '',
	profile         TEXT    NOT NULL DEFAULT '',
	source_identity TEXT    NOT NULL DEFAULT '',
	access_key_id   TEXT    NOT NULL DEFAULT '',
	task            TEXT    NOT NULL DEFAULT '',
	reason          TEXT    NOT NULL DEFAULT '',
	explanation     TEXT    NOT NULL DEFAULT '',
	body            TEXT    NOT NULL,
	prev_hash       TEXT    NOT NULL,
	hash            TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_grant    ON records(grant_id);
CREATE INDEX IF NOT EXISTS idx_records_agent_ts ON records(agent_id, ts);
CREATE INDEX IF NOT EXISTS idx_records_ts       ON records(ts);
CREATE INDEX IF NOT EXISTS idx_records_kind     ON records(kind);
CREATE INDEX IF NOT EXISTS idx_records_outcome  ON records(outcome);
CREATE INDEX IF NOT EXISTS idx_records_srcid    ON records(source_identity);
CREATE INDEX IF NOT EXISTS idx_records_akid     ON records(access_key_id);

CREATE TABLE IF NOT EXISTS record_resources (
	record_id TEXT NOT NULL,
	resource  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_resources_record   ON record_resources(record_id);
CREATE INDEX IF NOT EXISTS idx_resources_resource ON record_resources(resource);

CREATE TABLE IF NOT EXISTS rate_buckets (
	agent      TEXT    NOT NULL,
	capability TEXT    NOT NULL,
	tokens     REAL    NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (agent, capability)
);

CREATE TABLE IF NOT EXISTS capability_uses (
	agent      TEXT    NOT NULL,
	capability TEXT    NOT NULL,
	used_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_capuses_agent ON capability_uses(agent, used_at);

CREATE TABLE IF NOT EXISTS first_use (
	agent         TEXT    NOT NULL,
	capability    TEXT    NOT NULL,
	first_used_at INTEGER NOT NULL,
	approved      INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (agent, capability)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
	agent      TEXT    NOT NULL,
	key        TEXT    NOT NULL,
	grant_id   TEXT    NOT NULL,
	expires_at INTEGER NOT NULL,
	PRIMARY KEY (agent, key)
);
CREATE INDEX IF NOT EXISTS idx_idem_expires ON idempotency_keys(expires_at);

CREATE TABLE IF NOT EXISTS pending_approvals (
	grant_id     TEXT    PRIMARY KEY,
	agent_id     TEXT    NOT NULL,
	profile      TEXT    NOT NULL DEFAULT '',
	task         TEXT    NOT NULL DEFAULT '',
	reason       TEXT    NOT NULL DEFAULT '',
	policy_json  TEXT    NOT NULL DEFAULT '',
	capabilities TEXT    NOT NULL DEFAULT '[]',
	required_by  TEXT    NOT NULL DEFAULT '',
	status       TEXT    NOT NULL DEFAULT 'pending',
	received_at  INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	decided_at   INTEGER NOT NULL DEFAULT 0,
	approver     TEXT    NOT NULL DEFAULT '',
	method       TEXT    NOT NULL DEFAULT '',
	note         TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_approvals(status, received_at);
`

const ftsSQL = `
CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(task, reason, explanation);
CREATE TRIGGER IF NOT EXISTS records_fts_ai AFTER INSERT ON records BEGIN
	INSERT INTO records_fts(rowid, task, reason, explanation)
	VALUES (new.seq, new.task, new.reason, new.explanation);
END;
CREATE TRIGGER IF NOT EXISTS records_fts_ad AFTER DELETE ON records BEGIN
	DELETE FROM records_fts WHERE rowid = old.seq;
END;
`

func (s *Store) applySchema() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("store: apply schema: %w", err)
	}
	// FTS5 is compiled into modernc builds by default. If this build
	// lacks it, fall back to LIKE search and say so loudly.
	if _, err := s.db.Exec(ftsSQL); err != nil {
		s.ftsEnabled = false
		s.logger.Warn("store: FTS5 unavailable, audit search falls back to LIKE matching",
			"error", err)
	} else {
		s.ftsEnabled = true
	}
	return nil
}

func (s *Store) loadHead() error {
	row := s.db.QueryRow(`SELECT seq, hash FROM records ORDER BY seq DESC LIMIT 1`)
	var seq int64
	var hash string
	switch err := row.Scan(&seq, &hash); {
	case errors.Is(err, sql.ErrNoRows):
		s.headSeq, s.headHash = 0, GenesisHash
	case err != nil:
		return fmt.Errorf("store: load chain head: %w", err)
	default:
		s.headSeq, s.headHash = seq, hash
	}
	return nil
}

// chainHash computes sha256(prev_hash || canonical_json_body) in hex.
// prev is the 64-char hex of the previous hash (or GenesisHash).
func chainHash(prev string, canonicalBody []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(canonicalBody)
	return hex.EncodeToString(h.Sum(nil))
}

// timeToNanos converts a time to the stored integer form. Zero time
// stores as 0. Integer nanoseconds compare correctly in SQL, which
// RFC3339 strings with trimmed fractional zeros do not.
func timeToNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixNano()
}

// nanosToTime inverts timeToNanos.
func nanosToTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// Append validates rec, canonicalizes its body, extends the hash chain,
// and inserts the record with its resources in one transaction. On
// return rec carries its assigned Seq, RecordID, TS, PrevHash, Hash,
// and canonical Body. The mirror JSONL file, when configured, receives
// the record after commit.
func (s *Store) Append(ctx context.Context, rec *Record) error {
	if !rec.Kind.Valid() {
		return fmt.Errorf("store: invalid record kind %q", string(rec.Kind))
	}
	if rec.GrantID == "" && rec.Kind != domain.RecordPrune {
		return fmt.Errorf("store: record kind %s requires a grant id", rec.Kind)
	}
	if len(rec.Body) == 0 {
		return errors.New("store: record body is required")
	}
	canonical, err := CanonicalizeJSON(rec.Body)
	if err != nil {
		return fmt.Errorf("store: record body: %w", err)
	}
	if rec.RecordID == "" {
		rec.RecordID = domain.NewGrantID()
	}
	if rec.TS.IsZero() {
		rec.TS = time.Now().UTC()
	} else {
		rec.TS = rec.TS.UTC()
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()

	if err := s.appendLocked(ctx, tx, rec, canonical); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	s.headSeq, s.headHash = rec.Seq, rec.Hash
	s.mirrorWrite(*rec)
	return nil
}

// appendLocked inserts one record inside an open transaction. The
// caller holds writeMu and commits; on success it must update the head
// to (rec.Seq, rec.Hash).
func (s *Store) appendLocked(ctx context.Context, tx *sql.Tx, rec *Record, canonical []byte) error {
	rec.PrevHash = s.headHash
	rec.Hash = chainHash(rec.PrevHash, canonical)
	rec.Body = canonical

	res, err := tx.ExecContext(ctx, `
		INSERT INTO records (record_id, grant_id, agent_id, ts, kind, outcome,
			profile, source_identity, access_key_id, task, reason, explanation,
			body, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.RecordID, rec.GrantID, rec.AgentID, timeToNanos(rec.TS),
		string(rec.Kind), rec.Outcome, rec.Profile, rec.SourceIdentity,
		rec.AccessKeyID, rec.Task, rec.Reason, rec.Explanation,
		string(canonical), rec.PrevHash, rec.Hash)
	if err != nil {
		return fmt.Errorf("store: insert record: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("store: record seq: %w", err)
	}
	rec.Seq = seq
	for _, r := range rec.Resources {
		if r == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO record_resources (record_id, resource) VALUES (?, ?)`,
			rec.RecordID, r); err != nil {
			return fmt.Errorf("store: insert resource: %w", err)
		}
	}
	return nil
}

// mirrorWrite appends one export line to the mirror JSONL file. Mirror
// failures never fail the append; they are logged.
func (s *Store) mirrorWrite(rec Record) {
	s.mirrorMu.Lock()
	defer s.mirrorMu.Unlock()
	if s.mirror == nil {
		return
	}
	line, err := exportLine(rec)
	if err != nil {
		s.logger.Error("store: mirror jsonl encode failed", "record_id", rec.RecordID, "error", err)
		return
	}
	if _, err := s.mirror.Write(append(line, '\n')); err != nil {
		s.logger.Error("store: mirror jsonl write failed", "record_id", rec.RecordID, "error", err)
	}
}

// exportLine renders one record as its canonical JSONL export form.
func exportLine(rec Record) ([]byte, error) {
	type exported struct {
		RecordID       string          `json:"record_id"`
		GrantID        string          `json:"grant_id"`
		AgentID        string          `json:"agent_id"`
		TS             string          `json:"ts"`
		Kind           string          `json:"kind"`
		Outcome        string          `json:"outcome"`
		Profile        string          `json:"profile"`
		SourceIdentity string          `json:"source_identity"`
		AccessKeyID    string          `json:"access_key_id"`
		Resources      []string        `json:"resources,omitempty"`
		Body           json.RawMessage `json:"body"`
		PrevHash       string          `json:"prev_hash"`
		Hash           string          `json:"hash"`
	}
	e := exported{
		RecordID:       rec.RecordID,
		GrantID:        rec.GrantID,
		AgentID:        rec.AgentID,
		TS:             rec.TS.UTC().Format(time.RFC3339Nano),
		Kind:           string(rec.Kind),
		Outcome:        rec.Outcome,
		Profile:        rec.Profile,
		SourceIdentity: rec.SourceIdentity,
		AccessKeyID:    rec.AccessKeyID,
		Resources:      rec.Resources,
		Body:           rec.Body,
		PrevHash:       rec.PrevHash,
		Hash:           rec.Hash,
	}
	return CanonicalJSON(e)
}

// scanRecord reads one records row. The column order must match
// recordColumns.
const recordColumns = `seq, record_id, grant_id, agent_id, ts, kind, outcome,
	profile, source_identity, access_key_id, task, reason, explanation,
	body, prev_hash, hash`

// recordColumnsQualified is recordColumns with every column bound to
// the records alias r, for joins where names would be ambiguous.
const recordColumnsQualified = `r.seq, r.record_id, r.grant_id, r.agent_id, r.ts,
	r.kind, r.outcome, r.profile, r.source_identity, r.access_key_id,
	r.task, r.reason, r.explanation, r.body, r.prev_hash, r.hash`

type rowScanner interface{ Scan(dest ...any) error }

func scanRecord(sc rowScanner) (Record, error) {
	var rec Record
	var ts int64
	var kind, body string
	err := sc.Scan(&rec.Seq, &rec.RecordID, &rec.GrantID, &rec.AgentID, &ts,
		&kind, &rec.Outcome, &rec.Profile, &rec.SourceIdentity,
		&rec.AccessKeyID, &rec.Task, &rec.Reason, &rec.Explanation,
		&body, &rec.PrevHash, &rec.Hash)
	if err != nil {
		return Record{}, err
	}
	rec.TS = nanosToTime(ts)
	rec.Kind = domain.RecordKind(kind)
	rec.Body = json.RawMessage(body)
	return rec, nil
}

// loadResources fills the Resources field of the given records.
func (s *Store) loadResources(ctx context.Context, recs []Record) error {
	for i := range recs {
		rows, err := s.db.QueryContext(ctx,
			`SELECT resource FROM record_resources WHERE record_id = ? ORDER BY resource`,
			recs[i].RecordID)
		if err != nil {
			return fmt.Errorf("store: load resources: %w", err)
		}
		var resources []string
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				rows.Close()
				return fmt.Errorf("store: scan resource: %w", err)
			}
			resources = append(resources, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("store: resources rows: %w", err)
		}
		rows.Close()
		recs[i].Resources = resources
	}
	return nil
}

// likePattern escapes a raw substring for a LIKE ... ESCAPE '\' clause.
func likePattern(sub string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(sub) + "%"
}
