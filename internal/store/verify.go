package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// ChainError describes where and how chain verification failed.
type ChainError struct {
	Seq      int64
	RecordID string
	Reason   string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("store: chain broken at seq %d (record %s): %s", e.Seq, e.RecordID, e.Reason)
}

// VerifyResult summarizes one successful chain walk.
type VerifyResult struct {
	Records  int64  // records verified
	FirstSeq int64  // first record present (later than 1 after pruning)
	HeadSeq  int64  // last record verified
	HeadHash string // chain head hash
}

// Verify re-walks the hash chain from the earliest record present. For
// each record it recomputes sha256(prev_hash || body) and checks both
// the stored hash and the linkage to the previous record. The first
// record's prev_hash is the trust anchor of the walk: after a prune it
// points at a pruned record, and the prune record's last_pruned_hash
// plus the export cover the gap (section 9.3).
func (s *Store) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, record_id, body, prev_hash, hash FROM records ORDER BY seq ASC`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("store: verify query: %w", err)
	}
	defer rows.Close()

	var res VerifyResult
	var prevHash string
	first := true
	for rows.Next() {
		var seq int64
		var recordID, body, prev, hash string
		if err := rows.Scan(&seq, &recordID, &body, &prev, &hash); err != nil {
			return VerifyResult{}, fmt.Errorf("store: verify scan: %w", err)
		}
		if first {
			res.FirstSeq = seq
			first = false
		} else if prev != prevHash {
			return VerifyResult{}, &ChainError{Seq: seq, RecordID: recordID,
				Reason: fmt.Sprintf("prev_hash %s does not match previous record hash %s", prev, prevHash)}
		}
		canonical, err := CanonicalizeJSON([]byte(body))
		if err != nil {
			return VerifyResult{}, &ChainError{Seq: seq, RecordID: recordID,
				Reason: fmt.Sprintf("stored body is not valid JSON: %v", err)}
		}
		if string(canonical) != body {
			return VerifyResult{}, &ChainError{Seq: seq, RecordID: recordID,
				Reason: "stored body is not in canonical form"}
		}
		if got := chainHash(prev, canonical); got != hash {
			return VerifyResult{}, &ChainError{Seq: seq, RecordID: recordID,
				Reason: fmt.Sprintf("recomputed hash %s does not match stored hash %s", got, hash)}
		}
		prevHash = hash
		res.Records++
		res.HeadSeq = seq
		res.HeadHash = hash
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("store: verify rows: %w", err)
	}
	if res.Records == 0 {
		res.HeadHash = GenesisHash
	}
	return res, nil
}

// PruneResult summarizes one prune run.
type PruneResult struct {
	Pruned         int64  // records removed
	LastPrunedSeq  int64  // seq of the newest removed record
	LastPrunedHash string // hash of the newest removed record
	PruneRecordID  string // record_id of the appended prune record
}

// pruneBody is the body of the prune record (section 9.3). It carries
// the last pruned hash so verification works forward from every prune
// point.
type pruneBody struct {
	Kind            string `json:"kind"`
	Cutoff          string `json:"cutoff"`
	PrunedCount     int64  `json:"pruned_count"`
	LastPrunedSeq   int64  `json:"last_pruned_seq"`
	LastPrunedHash  string `json:"last_pruned_hash"`
	FirstPrunedSeq  int64  `json:"first_pruned_seq"`
	FirstPrunedHash string `json:"first_pruned_hash"`
}

// Prune removes the contiguous prefix of records older than cutoff.
// It exports every removed record as JSONL to exportW first, then in
// one transaction deletes the prefix and appends a prune record that
// carries the last pruned hash. Only a contiguous prefix is ever
// removed, so the remaining chain stays verifiable. A nil exportW is an
// error whenever at least one record would be pruned.
func (s *Store) Prune(ctx context.Context, cutoff time.Time, exportW io.Writer) (PruneResult, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// The prefix ends before the first record at or past the cutoff.
	var boundary int64
	row := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MIN(seq), 0) FROM records WHERE ts >= ?`, timeToNanos(cutoff))
	if err := row.Scan(&boundary); err != nil {
		return PruneResult{}, fmt.Errorf("store: prune boundary: %w", err)
	}
	var where string
	var args []any
	if boundary == 0 {
		// Every record is older than the cutoff.
		where = `ts < ?`
		args = []any{timeToNanos(cutoff)}
	} else {
		where = `seq < ?`
		args = []any{boundary}
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+recordColumns+` FROM records WHERE `+where+` ORDER BY seq ASC`, args...)
	if err != nil {
		return PruneResult{}, fmt.Errorf("store: prune select: %w", err)
	}
	var doomed []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			rows.Close()
			return PruneResult{}, fmt.Errorf("store: prune scan: %w", err)
		}
		doomed = append(doomed, rec)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return PruneResult{}, fmt.Errorf("store: prune rows: %w", err)
	}
	rows.Close()

	if len(doomed) == 0 {
		return PruneResult{}, nil
	}
	if exportW == nil {
		return PruneResult{}, errors.New("store: prune requires an export writer")
	}
	if err := s.loadResources(ctx, doomed); err != nil {
		return PruneResult{}, err
	}
	for _, rec := range doomed {
		line, err := exportLine(rec)
		if err != nil {
			return PruneResult{}, fmt.Errorf("store: prune export encode: %w", err)
		}
		if _, err := exportW.Write(append(line, '\n')); err != nil {
			return PruneResult{}, fmt.Errorf("store: prune export write: %w", err)
		}
	}

	first := doomed[0]
	last := doomed[len(doomed)-1]
	body, err := CanonicalJSON(pruneBody{
		Kind:            string(domain.RecordPrune),
		Cutoff:          cutoff.UTC().Format(time.RFC3339Nano),
		PrunedCount:     int64(len(doomed)),
		LastPrunedSeq:   last.Seq,
		LastPrunedHash:  last.Hash,
		FirstPrunedSeq:  first.Seq,
		FirstPrunedHash: first.Hash,
	})
	if err != nil {
		return PruneResult{}, fmt.Errorf("store: prune body: %w", err)
	}
	pruneRec := &Record{
		Kind: domain.RecordPrune,
		TS:   time.Now().UTC(),
		Body: body,
	}
	pruneRec.RecordID = domain.NewGrantID()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PruneResult{}, fmt.Errorf("store: prune begin: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM record_resources WHERE record_id IN
			(SELECT record_id FROM records WHERE seq <= ?)`, last.Seq); err != nil {
		return PruneResult{}, fmt.Errorf("store: prune resources: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM records WHERE seq <= ?`, last.Seq); err != nil {
		return PruneResult{}, fmt.Errorf("store: prune delete: %w", err)
	}
	if err := s.appendLocked(ctx, tx, pruneRec, body); err != nil {
		return PruneResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return PruneResult{}, fmt.Errorf("store: prune commit: %w", err)
	}
	s.headSeq, s.headHash = pruneRec.Seq, pruneRec.Hash
	s.mirrorWrite(*pruneRec)

	return PruneResult{
		Pruned:         int64(len(doomed)),
		LastPrunedSeq:  last.Seq,
		LastPrunedHash: last.Hash,
		PruneRecordID:  pruneRec.RecordID,
	}, nil
}

// RetentionCutoff converts log.retention_days into a prune cutoff.
// Zero days means keep forever; the returned ok is false then.
func RetentionCutoff(retentionDays int, now time.Time) (time.Time, bool) {
	if retentionDays <= 0 {
		return time.Time{}, false
	}
	return now.UTC().AddDate(0, 0, -retentionDays), true
}

// Get returns one record by record_id.
func (s *Store) Get(ctx context.Context, recordID string) (Record, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+recordColumns+` FROM records WHERE record_id = ?`, recordID)
	rec, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("store: get record: %w", err)
	}
	recs := []Record{rec}
	if err := s.loadResources(ctx, recs); err != nil {
		return Record{}, err
	}
	return recs[0], nil
}
