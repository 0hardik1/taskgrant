package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
)

func TestListFilters(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	base := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)

	a := appendDecision(t, s, "invoice-bot", "archive invoices", base,
		"arn:aws:s3:::acme-invoices-prod", "arn:aws:s3:::acme-invoices-prod/2026/*")
	b := appendDecision(t, s, "ci-bot", "run refactor", base.Add(time.Hour),
		"arn:aws:s3:::acme-ci-cache/*")
	_ = b

	tests := []struct {
		name   string
		filter ListFilter
		want   []string // record ids
	}{
		{"by agent", ListFilter{Agent: "invoice-bot"}, []string{a.RecordID}},
		{"by outcome", ListFilter{Outcome: "auto_approved"}, []string{a.RecordID, b.RecordID}},
		{"by profile", ListFilter{Profile: "s3-archiver"}, []string{a.RecordID, b.RecordID}},
		{"by since", ListFilter{Since: base.Add(30 * time.Minute)}, []string{b.RecordID}},
		{"by until", ListFilter{Until: base.Add(30 * time.Minute)}, []string{a.RecordID}},
		{"by resource glob", ListFilter{ResourcePattern: "arn:aws:s3:::acme-invoices-prod*"}, []string{a.RecordID}},
		{"by kind", ListFilter{Kind: domain.RecordGrantDecision}, []string{a.RecordID, b.RecordID}},
		{"no match", ListFilter{Agent: "ghost"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.List(ctx, tt.filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d records, want %d", len(got), len(tt.want))
			}
			for i, rec := range got {
				if rec.RecordID != tt.want[i] {
					t.Fatalf("record %d: %s, want %s", i, rec.RecordID, tt.want[i])
				}
			}
		})
	}
}

func TestGrantChain(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	base := time.Now().UTC()

	first := appendDecision(t, s, "invoice-bot", "step one", base)
	// A second record on the same grant (an approval).
	approval := &Record{
		GrantID: first.GrantID,
		AgentID: "invoice-bot",
		TS:      base.Add(time.Minute),
		Kind:    domain.RecordApproval,
		Outcome: "approved",
		Body:    json.RawMessage(`{"approver":"human","method":"cli"}`),
	}
	if err := s.Append(ctx, approval); err != nil {
		t.Fatalf("Append approval: %v", err)
	}
	appendDecision(t, s, "invoice-bot", "unrelated grant", base.Add(2*time.Minute))

	chain, err := s.GrantChain(ctx, first.GrantID)
	if err != nil {
		t.Fatalf("GrantChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length %d, want 2", len(chain))
	}
	if chain[0].Kind != domain.RecordGrantDecision || chain[1].Kind != domain.RecordApproval {
		t.Fatalf("chain kinds: %s, %s", chain[0].Kind, chain[1].Kind)
	}
}

func TestSearchFTS(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	if !s.FTSEnabled() {
		t.Fatal("FTS5 is not available in this modernc.org/sqlite build; the LIKE fallback would be active. Say so loudly in the report.")
	}
	base := time.Now().UTC()
	hit := appendDecision(t, s, "invoice-bot", "archive invoice lifecycle to glacier", base)
	appendDecision(t, s, "ci-bot", "run the refactor suite", base.Add(time.Second))

	got, err := s.Search(ctx, "invoice lifecycle", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].RecordID != hit.RecordID {
		t.Fatalf("search hits: %+v, want only %s", recordIDs(got), hit.RecordID)
	}

	// Hostile query syntax must not error.
	if _, err := s.Search(ctx, `" OR 1=1 -- ( NEAR/ *`, 10); err != nil {
		t.Fatalf("hostile query: %v", err)
	}
	// Empty query returns nothing.
	got, err = s.Search(ctx, "   ", 10)
	if err != nil || got != nil {
		t.Fatalf("empty query: %v %v", got, err)
	}
}

func TestSearchLikeFallback(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	base := time.Now().UTC()
	hit := appendDecision(t, s, "invoice-bot", "archive invoice lifecycle to glacier", base)
	appendDecision(t, s, "ci-bot", "run the refactor suite", base.Add(time.Second))

	got, err := s.searchLike(ctx, "invoice lifecycle", 10)
	if err != nil {
		t.Fatalf("searchLike: %v", err)
	}
	if len(got) != 1 || got[0].RecordID != hit.RecordID {
		t.Fatalf("like hits: %v, want only %s", recordIDs(got), hit.RecordID)
	}
	// LIKE metacharacters in the query are literals.
	got, err = s.searchLike(ctx, "100%", 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("metacharacter query: %v %v", recordIDs(got), err)
	}
}

func recordIDs(recs []Record) []string {
	ids := make([]string, 0, len(recs))
	for _, r := range recs {
		ids = append(ids, r.RecordID)
	}
	return ids
}

func TestExportJSONL(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	base := time.Now().UTC()
	appendDecision(t, s, "invoice-bot", "one", base, "arn:aws:s3:::b1")
	appendDecision(t, s, "invoice-bot", "two", base.Add(time.Second))

	var buf bytes.Buffer
	n, err := s.ExportJSONL(ctx, &buf, ListFilter{Agent: "invoice-bot"})
	if err != nil {
		t.Fatalf("ExportJSONL: %v", err)
	}
	if n != 2 {
		t.Fatalf("exported %d, want 2", n)
	}
	sc := bufio.NewScanner(&buf)
	lines := 0
	for sc.Scan() {
		lines++
		var obj struct {
			RecordID string          `json:"record_id"`
			Body     json.RawMessage `json:"body"`
			Hash     string          `json:"hash"`
		}
		if err := json.Unmarshal(sc.Bytes(), &obj); err != nil {
			t.Fatalf("line %d: %v", lines, err)
		}
		if obj.RecordID == "" || obj.Hash == "" || len(obj.Body) == 0 {
			t.Fatalf("line %d incomplete: %s", lines, sc.Text())
		}
	}
	if lines != 2 {
		t.Fatalf("lines %d, want 2", lines)
	}
}

func TestScopeAggregatesLiveGrants(t *testing.T) {
	s := openTestStore(t, Options{})
	ctx := context.Background()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

	mkBody := func(exp time.Time, actions []string, caps []map[string]any) json.RawMessage {
		b, err := json.Marshal(map[string]any{
			"expanded_actions": actions,
			"capabilities":     caps,
			"sts":              map[string]any{"expiration": exp.Format(time.RFC3339)},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	live := &Record{
		GrantID: domain.NewGrantID(), AgentID: "invoice-bot",
		TS: now.Add(-5 * time.Minute), Kind: domain.RecordGrantDecision,
		Outcome: "auto_approved", Profile: "s3-archiver",
		Resources: []string{"arn:aws:s3:::acme-invoices-prod/2026/*"},
		Body: mkBody(now.Add(10*time.Minute),
			[]string{"s3:GetObject", "s3:ListBucket"},
			[]map[string]any{{"id": "s3.read-prefix", "version": 3}}),
	}
	expired := &Record{
		GrantID: domain.NewGrantID(), AgentID: "invoice-bot",
		TS: now.Add(-2 * time.Hour), Kind: domain.RecordGrantDecision,
		Outcome: "auto_approved", Profile: "s3-archiver",
		Resources: []string{"arn:aws:sqs:us-east-1:222222222222:jobs"},
		Body: mkBody(now.Add(-time.Hour),
			[]string{"sqs:ReceiveMessage"},
			[]map[string]any{{"id": "sqs.consume", "version": 1}}),
	}
	otherAgent := &Record{
		GrantID: domain.NewGrantID(), AgentID: "ci-bot",
		TS: now.Add(-5 * time.Minute), Kind: domain.RecordGrantDecision,
		Outcome: "auto_approved",
		Body: mkBody(now.Add(10*time.Minute),
			[]string{"lambda:InvokeFunction"}, nil),
	}
	for _, rec := range []*Record{live, expired, otherAgent} {
		if err := s.Append(ctx, rec); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	report, err := s.Scope(ctx, "invoice-bot", now)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(report.LiveGrants) != 1 || report.LiveGrants[0].GrantID != live.GrantID {
		t.Fatalf("live grants: %+v", report.LiveGrants)
	}
	wantActions := []string{"s3:GetObject", "s3:ListBucket"}
	if len(report.Actions) != 2 || report.Actions[0] != wantActions[0] || report.Actions[1] != wantActions[1] {
		t.Fatalf("actions: %v, want %v", report.Actions, wantActions)
	}
	if len(report.Capabilities) != 1 || report.Capabilities[0] != "s3.read-prefix" {
		t.Fatalf("capabilities: %v", report.Capabilities)
	}
	if len(report.Resources) != 1 || report.Resources[0] != "arn:aws:s3:::acme-invoices-prod/2026/*" {
		t.Fatalf("resources: %v", report.Resources)
	}
}
