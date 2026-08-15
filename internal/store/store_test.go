package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
)

func openTestStore(t *testing.T, opts Options) *Store {
	t.Helper()
	if opts.Path == "" {
		opts.Path = filepath.Join(t.TempDir(), "decisions.db")
	}
	s, err := Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func appendDecision(t *testing.T, s *Store, agent, task string, ts time.Time, resources ...string) *Record {
	t.Helper()
	grantID := domain.NewGrantID()
	body, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"grant_id":       grantID,
		"agent_id":       agent,
		"task":           task,
		"outcome":        "auto_approved",
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	rec := &Record{
		GrantID:   grantID,
		AgentID:   agent,
		TS:        ts,
		Kind:      domain.RecordGrantDecision,
		Outcome:   "auto_approved",
		Profile:   "s3-archiver",
		Task:      task,
		Resources: resources,
		Body:      body,
	}
	if err := s.Append(context.Background(), rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	return rec
}

func TestAppendAndVerify(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	base := time.Now().UTC()

	var last *Record
	for i := 0; i < 5; i++ {
		last = appendDecision(t, s, "invoice-bot", fmt.Sprintf("task %d", i), base.Add(time.Duration(i)*time.Second))
	}
	if last.PrevHash == "" || last.Hash == "" {
		t.Fatal("append did not set chain hashes")
	}
	res, err := s.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Records != 5 {
		t.Fatalf("verified %d records, want 5", res.Records)
	}
	if res.HeadHash != last.Hash {
		t.Fatalf("head hash %s, want %s", res.HeadHash, last.Hash)
	}
}

func TestVerifyCatchesMutatedMiddleRecord(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		appendDecision(t, s, "invoice-bot", fmt.Sprintf("task %d", i), base.Add(time.Duration(i)*time.Second))
	}
	// Tamper with the third record's body directly.
	if _, err := s.db.Exec(
		`UPDATE records SET body = replace(body, 'task 2', 'task 2 FORGED') WHERE seq = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	_, err := s.Verify(ctx)
	var chainErr *ChainError
	if !errors.As(err, &chainErr) {
		t.Fatalf("Verify after tamper: got %v, want *ChainError", err)
	}
	if chainErr.Seq != 3 {
		t.Fatalf("chain error at seq %d, want 3", chainErr.Seq)
	}
}

func TestVerifyCatchesRelinkedChain(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	base := time.Now().UTC()
	for i := 0; i < 3; i++ {
		appendDecision(t, s, "invoice-bot", fmt.Sprintf("task %d", i), base.Add(time.Duration(i)*time.Second))
	}
	// Break the linkage without touching bodies.
	if _, err := s.db.Exec(
		`UPDATE records SET prev_hash = ? WHERE seq = 2`, GenesisHash); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := s.Verify(ctx); err == nil {
		t.Fatal("Verify accepted a relinked chain")
	}
}

func TestChainSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.db")
	s := openTestStore(t, Options{Path: path})
	base := time.Now().UTC()
	first := appendDecision(t, s, "invoice-bot", "before restart", base)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2 := openTestStore(t, Options{Path: path})
	second := appendDecision(t, s2, "invoice-bot", "after restart", base.Add(time.Second))
	if second.PrevHash != first.Hash {
		t.Fatalf("chain did not continue across reopen: prev %s, want %s", second.PrevHash, first.Hash)
	}
	if _, err := s2.Verify(context.Background()); err != nil {
		t.Fatalf("Verify after reopen: %v", err)
	}
}

func TestPruneKeepsChainVerifiable(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	base := time.Now().UTC().Add(-10 * time.Hour)
	var recs []*Record
	for i := 0; i < 6; i++ {
		recs = append(recs, appendDecision(t, s, "invoice-bot",
			fmt.Sprintf("task %d", i), base.Add(time.Duration(i)*time.Hour)))
	}

	var export bytes.Buffer
	cutoff := base.Add(3*time.Hour + time.Minute) // prunes records 0..3
	res, err := s.Prune(ctx, cutoff, &export)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if res.Pruned != 4 {
		t.Fatalf("pruned %d, want 4", res.Pruned)
	}
	if res.LastPrunedHash != recs[3].Hash {
		t.Fatalf("last pruned hash %s, want %s", res.LastPrunedHash, recs[3].Hash)
	}

	// The export carries every pruned record.
	lines := 0
	sc := bufio.NewScanner(&export)
	for sc.Scan() {
		lines++
		var obj map[string]any
		if err := json.Unmarshal(sc.Bytes(), &obj); err != nil {
			t.Fatalf("export line %d is not JSON: %v", lines, err)
		}
	}
	if lines != 4 {
		t.Fatalf("export holds %d lines, want 4", lines)
	}

	// The remaining chain verifies forward from the prune point.
	vres, err := s.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify after prune: %v", err)
	}
	if vres.Records != 3 { // two surviving decisions plus the prune record
		t.Fatalf("verified %d records, want 3", vres.Records)
	}

	// The prune record carries the last pruned hash.
	chain, err := s.List(ctx, ListFilter{Kind: domain.RecordPrune})
	if err != nil {
		t.Fatalf("List prune: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("prune records: %d, want 1", len(chain))
	}
	var body pruneBody
	if err := json.Unmarshal(chain[0].Body, &body); err != nil {
		t.Fatalf("prune body: %v", err)
	}
	if body.LastPrunedHash != recs[3].Hash {
		t.Fatalf("prune body last hash %s, want %s", body.LastPrunedHash, recs[3].Hash)
	}

	// Appending after a prune keeps verifying.
	appendDecision(t, s, "invoice-bot", "post prune", time.Now().UTC())
	if _, err := s.Verify(ctx); err != nil {
		t.Fatalf("Verify after post-prune append: %v", err)
	}
}

func TestPruneRequiresExportWriter(t *testing.T) {
	s := openTestStore(t, Options{})
	appendDecision(t, s, "invoice-bot", "old task", time.Now().UTC().Add(-time.Hour))
	if _, err := s.Prune(context.Background(), time.Now().UTC(), nil); err == nil {
		t.Fatal("Prune accepted a nil export writer with rows to prune")
	}
}

func TestMirrorJSONL(t *testing.T) {
	dir := t.TempDir()
	mirror := filepath.Join(dir, "decisions.jsonl")
	s := openTestStore(t, Options{Path: filepath.Join(dir, "d.db"), MirrorJSONLPath: mirror})
	rec := appendDecision(t, s, "invoice-bot", "mirrored task", time.Now().UTC())

	data, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatalf("read mirror: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("mirror lines: %d, want 1", len(lines))
	}
	var obj struct {
		RecordID string `json:"record_id"`
		Hash     string `json:"hash"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &obj); err != nil {
		t.Fatalf("mirror line: %v", err)
	}
	if obj.RecordID != rec.RecordID || obj.Hash != rec.Hash {
		t.Fatalf("mirror line mismatch: %+v vs record %s/%s", obj, rec.RecordID, rec.Hash)
	}
}

func TestAppendRejectsBadRecords(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	tests := []struct {
		name string
		rec  Record
	}{
		{"invalid kind", Record{Kind: "bogus", GrantID: "g", Body: json.RawMessage(`{}`)}},
		{"missing grant id", Record{Kind: domain.RecordGrantDecision, Body: json.RawMessage(`{}`)}},
		{"empty body", Record{Kind: domain.RecordGrantDecision, GrantID: "g"}},
		{"invalid body", Record{Kind: domain.RecordGrantDecision, GrantID: "g", Body: json.RawMessage(`{`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := tt.rec
			if err := s.Append(ctx, &rec); err == nil {
				t.Fatal("Append accepted a bad record")
			}
		})
	}
}
