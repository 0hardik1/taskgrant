package revoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// fakeWriter is an in-memory PolicyWriter that also detects concurrent
// entry: every call flips a busy flag and fails the test when a second
// call arrives while one is in flight.
type fakeWriter struct {
	t    *testing.T
	mu   sync.Mutex
	docs map[string]map[string]string // role -> policy name -> document

	busy    atomic.Int32
	puts    atomic.Int32
	deletes atomic.Int32

	failPut error
}

func newFakeWriter(t *testing.T) *fakeWriter {
	return &fakeWriter{t: t, docs: map[string]map[string]string{}}
}

func (f *fakeWriter) enter() {
	if f.busy.Add(1) != 1 {
		f.t.Error("concurrent PolicyWriter call: writes are not serialized")
	}
	time.Sleep(time.Millisecond) // widen the race window
}

func (f *fakeWriter) exit() { f.busy.Add(-1) }

func (f *fakeWriter) PutRolePolicy(_ context.Context, role, name, doc string) error {
	f.enter()
	defer f.exit()
	if f.failPut != nil {
		return f.failPut
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.docs[role] == nil {
		f.docs[role] = map[string]string{}
	}
	f.docs[role][name] = doc
	f.puts.Add(1)
	return nil
}

func (f *fakeWriter) GetRolePolicy(_ context.Context, role, name string) (string, error) {
	f.enter()
	defer f.exit()
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, ok := f.docs[role][name]
	if !ok {
		return "", ErrNoSuchPolicy
	}
	return doc, nil
}

func (f *fakeWriter) DeleteRolePolicy(_ context.Context, role, name string) error {
	f.enter()
	defer f.exit()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.docs[role][name]; !ok {
		return ErrNoSuchPolicy
	}
	delete(f.docs[role], name)
	f.deletes.Add(1)
	return nil
}

func (f *fakeWriter) document(role string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.docs[role][PolicyName]
}

func newTestRevoker(t *testing.T, w PolicyWriter, clock func() time.Time) *Revoker {
	t.Helper()
	r, err := New(w, Options{Clock: clock})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

var testNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func TestRoleWideDenyDocument(t *testing.T) {
	stmt := RoleWideDeny(testNow, 30*time.Second, 12*time.Hour)
	if stmt.Effect != "Deny" || stmt.Action != "*" || stmt.Resource != "*" {
		t.Fatalf("statement shape: %+v", stmt)
	}
	got := stmt.Condition["DateLessThan"]["aws:TokenIssueTime"]
	want := testNow.Add(30 * time.Second).Format(time.RFC3339)
	if got != want {
		t.Fatalf("issue-time cutoff %s, want %s", got, want)
	}
	if _, ok := stmt.Condition["StringEquals"]; ok {
		t.Fatal("role-wide deny must not carry a principal-tag condition")
	}
	if exp, ok := sidExpiry(stmt.Sid); !ok || !exp.Equal(testNow.Add(30*time.Second).Add(12*time.Hour)) {
		t.Fatalf("sid expiry: %v ok=%v", exp, ok)
	}
}

func TestGrantDenyDocument(t *testing.T) {
	grantID := domain.NewGrantID()
	expiry := testNow.Add(15 * time.Minute)
	stmt, err := GrantDeny(grantID, testNow, 30*time.Second, 12*time.Hour, expiry)
	if err != nil {
		t.Fatalf("GrantDeny: %v", err)
	}
	if got := stmt.Condition["StringEquals"]["aws:PrincipalTag/taskgrant:grant"]; got != grantID {
		t.Fatalf("principal tag condition %q, want %q", got, grantID)
	}
	if got := stmt.Condition["DateLessThan"]["aws:TokenIssueTime"]; got != testNow.Add(30*time.Second).Format(time.RFC3339) {
		t.Fatalf("issue-time cutoff: %s", got)
	}
	if exp, ok := sidExpiry(stmt.Sid); !ok || !exp.Equal(expiry.Add(30*time.Second).Truncate(time.Second)) {
		t.Fatalf("sid expiry: %v ok=%v", exp, ok)
	}
}

func TestGrantDenyNeverKeyedOnCallerRef(t *testing.T) {
	// I3 by construction: only a valid broker ULID enters a condition.
	// Anything an agent could put in caller_ref that is not a ULID is
	// rejected before a document exists.
	badIDs := []string{
		"agent-local-correlation-id",
		"caller_ref",
		"",
		"tg-01K2G3H4J5K6M7N8P9Q0R1S2T3", // prefixed form, not a bare ULID
		strings.Repeat("A", 26) + "x",
	}
	for _, id := range badIDs {
		if _, err := GrantDeny(id, testNow, 0, time.Hour, testNow); err == nil {
			t.Fatalf("GrantDeny accepted non-ULID %q", id)
		}
	}

	// And a valid document never references the caller_ref tag key.
	stmt, err := GrantDeny(domain.NewGrantID(), testNow, 0, time.Hour, testNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Document{Version: PolicyVersion, Statement: []Statement{stmt}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "caller_ref") {
		t.Fatalf("document references caller_ref: %s", raw)
	}
	if !strings.Contains(string(raw), "aws:PrincipalTag/"+domain.TagKeyGrant) {
		t.Fatalf("document lacks the broker grant tag condition: %s", raw)
	}
}

func TestRevokeRoleWritesPolicy(t *testing.T) {
	w := newFakeWriter(t)
	r := newTestRevoker(t, w, func() time.Time { return testNow })
	res, err := r.RevokeRole(context.Background(), "taskgrant-s3-archiver")
	if err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}
	if res.Statements != 1 || res.Deleted || res.Sid == "" {
		t.Fatalf("result: %+v", res)
	}
	var doc Document
	if err := json.Unmarshal([]byte(w.document("taskgrant-s3-archiver")), &doc); err != nil {
		t.Fatalf("stored document: %v", err)
	}
	if doc.Version != PolicyVersion || len(doc.Statement) != 1 {
		t.Fatalf("stored document: %+v", doc)
	}
}

func TestRevokeGrantAccumulatesAndGCs(t *testing.T) {
	w := newFakeWriter(t)
	now := testNow
	r := newTestRevoker(t, w, func() time.Time { return now })
	ctx := context.Background()
	role := "taskgrant-s3-archiver"

	g1 := domain.NewGrantID()
	g2 := domain.NewGrantID()
	if _, err := r.RevokeGrant(ctx, role, g1, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	res, err := r.RevokeGrant(ctx, role, g2, now.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res.Statements != 2 {
		t.Fatalf("statements %d, want 2", res.Statements)
	}

	// Advance past g1's expiry plus margin: GC drops it, keeps g2.
	now = testNow.Add(10 * time.Minute)
	gcRes, err := r.GC(ctx, role)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if len(gcRes.RemovedSids) != 1 || !strings.Contains(gcRes.RemovedSids[0], g1) {
		t.Fatalf("removed sids: %v", gcRes.RemovedSids)
	}
	if gcRes.Statements != 1 {
		t.Fatalf("statements after gc: %d", gcRes.Statements)
	}

	// Advance past everything: the policy empties and is deleted.
	now = testNow.Add(24 * time.Hour)
	gcRes, err = r.GC(ctx, role)
	if err != nil {
		t.Fatal(err)
	}
	if !gcRes.Deleted {
		t.Fatalf("expected policy deletion: %+v", gcRes)
	}
	if w.document(role) != "" {
		t.Fatal("policy still present after empty GC")
	}
	// GC of a role with no policy is a no-op delete.
	if _, err := r.GC(ctx, role); err != nil {
		t.Fatalf("GC on missing policy: %v", err)
	}
}

func TestRevokeGrantIdempotentSid(t *testing.T) {
	w := newFakeWriter(t)
	r := newTestRevoker(t, w, func() time.Time { return testNow })
	ctx := context.Background()
	g := domain.NewGrantID()
	exp := testNow.Add(10 * time.Minute)
	if _, err := r.RevokeGrant(ctx, "role-a", g, exp); err != nil {
		t.Fatal(err)
	}
	res, err := r.RevokeGrant(ctx, "role-a", g, exp)
	if err != nil {
		t.Fatal(err)
	}
	if res.Statements != 1 {
		t.Fatalf("duplicate revocation duplicated the statement: %d", res.Statements)
	}
}

func TestWritesAreSerialized(t *testing.T) {
	w := newFakeWriter(t)
	r := newTestRevoker(t, w, time.Now)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			role := fmt.Sprintf("role-%d", i%3)
			if _, err := r.RevokeGrant(ctx, role, domain.NewGrantID(), time.Now().Add(time.Hour)); err != nil {
				t.Errorf("RevokeGrant: %v", err)
			}
		}(i)
	}
	wg.Wait()
	// The fakeWriter's busy flag asserts no concurrent entry; here we
	// only confirm every write landed.
	if int(w.puts.Load()) != 16 {
		t.Fatalf("puts %d, want 16", w.puts.Load())
	}
}

func TestSizeCeilingAndWarning(t *testing.T) {
	w := newFakeWriter(t)
	r, err := New(w, Options{Clock: func() time.Time { return testNow }, WarnChars: 400})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ctx := context.Background()

	// Two grant statements cross the 400-char warn threshold.
	var res Result
	for i := 0; i < 2; i++ {
		res, err = r.RevokeGrant(ctx, "role-a", domain.NewGrantID(), testNow.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
	}
	if !res.Warned {
		t.Fatalf("no warning at %d chars with threshold 400", res.PolicyChars)
	}

	// A pre-existing near-ceiling foreign-sid document forces the hard
	// ceiling error without clobbering IAM.
	big := Document{Version: PolicyVersion}
	for i := 0; len(mustJSON(t, big)) < MaxInlinePolicyChars-200; i++ {
		big.Statement = append(big.Statement, Statement{
			Sid:      fmt.Sprintf("keepMe%04d", i),
			Effect:   "Deny",
			Action:   "*",
			Resource: "*",
			Condition: map[string]map[string]string{
				"DateLessThan": {"aws:TokenIssueTime": testNow.Format(time.RFC3339)},
			},
		})
	}
	w.docs["role-b"] = map[string]string{PolicyName: mustJSON(t, big)}
	before := w.document("role-b")
	_, err = r.RevokeGrant(ctx, "role-b", domain.NewGrantID(), testNow.Add(time.Hour))
	if !errors.Is(err, ErrPolicyTooLarge) {
		t.Fatalf("err %v, want ErrPolicyTooLarge", err)
	}
	if w.document("role-b") != before {
		t.Fatal("oversized write mutated the stored policy")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUnparseablePolicyIsNeverClobbered(t *testing.T) {
	w := newFakeWriter(t)
	w.docs["role-a"] = map[string]string{PolicyName: "{not json"}
	r := newTestRevoker(t, w, time.Now)
	if _, err := r.RevokeRole(context.Background(), "role-a"); err == nil {
		t.Fatal("revoker overwrote an unparseable policy")
	}
	if w.document("role-a") != "{not json" {
		t.Fatal("unparseable policy was mutated")
	}
}

func TestForeignSidsSurviveGC(t *testing.T) {
	w := newFakeWriter(t)
	foreign := Document{Version: PolicyVersion, Statement: []Statement{{
		Sid: "OperatorManagedDeny", Effect: "Deny", Action: "*", Resource: "*",
	}}}
	w.docs["role-a"] = map[string]string{PolicyName: mustJSON(t, foreign)}
	r := newTestRevoker(t, w, func() time.Time { return testNow.Add(48 * time.Hour) })
	res, err := r.GC(context.Background(), "role-a")
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted || res.Statements != 1 || len(res.RemovedSids) != 0 {
		t.Fatalf("foreign statement was collected: %+v", res)
	}
}

func TestCloseStopsWorker(t *testing.T) {
	w := newFakeWriter(t)
	r, err := New(w, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	r.Close() // idempotent
	if _, err := r.RevokeRole(context.Background(), "role-a"); !errors.Is(err, ErrClosed) {
		t.Fatalf("err %v, want ErrClosed", err)
	}
}

func TestRoleNameFromARN(t *testing.T) {
	tests := []struct {
		arn     string
		want    string
		wantErr bool
	}{
		{"arn:aws:iam::222222222222:role/taskgrant-s3-archiver", "taskgrant-s3-archiver", false},
		{"arn:aws:iam::222222222222:role/path/to/my-role", "my-role", false},
		{"arn:aws:iam::222222222222:user/nope", "", true},
		{"taskgrant-s3-archiver", "", true},
		{"arn:aws:iam::222222222222:role/", "", true},
	}
	for _, tt := range tests {
		got, err := RoleNameFromARN(tt.arn)
		if tt.wantErr {
			if err == nil {
				t.Errorf("%s: want error", tt.arn)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: got %q err=%v, want %q", tt.arn, got, err, tt.want)
		}
	}
}
