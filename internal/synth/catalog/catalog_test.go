package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/0hardik1/taskgrant/internal/dataset"
)

const testdataDataset = "../../../testdata/iam-dataset.json"
const starterCatalogDir = "../../../examples/catalog"

func loadTestDataset(t *testing.T) *dataset.Dataset {
	t.Helper()
	ds, err := dataset.Load(testdataDataset)
	if err != nil {
		t.Fatalf("load dataset: %v", err)
	}
	return ds
}

func loadStarter(t *testing.T) *Snapshot {
	t.Helper()
	ds := loadTestDataset(t)
	snap, err := Load(starterCatalogDir, ds, WithoutGitCommit())
	if err != nil {
		t.Fatalf("load starter catalog: %v", err)
	}
	return snap
}

func TestStarterCatalogLoads(t *testing.T) {
	snap := loadStarter(t)

	want := []string{
		"dynamodb.query", "lambda.invoke", "logs.read",
		"s3.read-prefix", "s3.write-prefix", "sqs.consume", "sqs.produce",
	}
	got := snap.IDs()
	if len(got) != len(want) {
		t.Fatalf("capability ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("capability ids = %v, want %v", got, want)
		}
	}

	c, ok := snap.Capability("s3.read-prefix")
	if !ok {
		t.Fatal("s3.read-prefix missing")
	}
	if c.Version != 3 {
		t.Errorf("s3.read-prefix version = %d, want 3", c.Version)
	}
	if c.AccessCeiling != dataset.AccessList {
		t.Errorf("s3.read-prefix ceiling = %q, want List", c.AccessCeiling)
	}
	if c.MaxDurationSeconds != 900 {
		t.Errorf("s3.read-prefix max duration = %d, want 900", c.MaxDurationSeconds)
	}
	if len(c.Actions) != 3 {
		t.Errorf("s3.read-prefix actions = %v, want 3 entries", c.Actions)
	}

	lr, ok := snap.Capability("logs.read")
	if !ok {
		t.Fatal("logs.read missing")
	}
	if !lr.ManagedPolicy || lr.ManagedPolicyARN == "" {
		t.Errorf("logs.read managed policy = (%v, %q), want (true, arn)", lr.ManagedPolicy, lr.ManagedPolicyARN)
	}

	if snap.DatasetHash() == "" || snap.Hash() == "" {
		t.Error("snapshot hash or dataset hash empty")
	}
}

func TestSnapshotHashDeterministic(t *testing.T) {
	ds := loadTestDataset(t)
	a, err := Load(starterCatalogDir, ds, WithoutGitCommit())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(starterCatalogDir, ds, WithoutGitCommit())
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash() != b.Hash() {
		t.Errorf("hashes differ across identical loads: %s vs %s", a.Hash(), b.Hash())
	}
	if a.CatalogHash() != a.Hash() {
		t.Errorf("CatalogHash without git commit should equal Hash")
	}
}

func TestForAgentFiltering(t *testing.T) {
	ds := loadTestDataset(t)
	dir := t.TempDir()
	writeFile(t, dir, "allowlists.yaml", `
allowlists:
  b: [acme-invoices-prod]
resource_patterns:
  - arn:aws:s3:::acme-invoices-prod
  - arn:aws:s3:::acme-invoices-prod/*
`)
	writeFile(t, dir, "open.yaml", `
id: t.open
version: 1
summary: visible to all
actions: [s3:ListBucket]
access_ceiling: List
params:
  bucket: {type: arn_component, allowlist_ref: b}
resources:
  - {template: 'arn:aws:s3:::{bucket}', for_actions: [s3:ListBucket]}
`)
	writeFile(t, dir, "restricted.yaml", `
id: t.restricted
version: 1
summary: one agent only
actions: [s3:GetObject]
access_ceiling: Read
params:
  bucket: {type: arn_component, allowlist_ref: b}
resources:
  - {template: 'arn:aws:s3:::{bucket}/*', for_actions: [s3:GetObject]}
agents: [ci-refactor-bot]
`)
	snap, err := Load(dir, ds, WithoutGitCommit())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Len() != 2 {
		t.Fatalf("full snapshot has %d capabilities, want 2", snap.Len())
	}

	view := snap.ForAgent("other-agent")
	if view.Len() != 1 {
		t.Fatalf("filtered view has %d capabilities, want 1", view.Len())
	}
	if _, ok := view.Capability("t.restricted"); ok {
		t.Error("restricted capability leaked into another agent's view")
	}
	if _, ok := view.Capability("t.open"); !ok {
		t.Error("open capability missing from view")
	}
	if view.Hash() != snap.Hash() {
		t.Error("view hash must equal the full snapshot hash")
	}
	if view.AgentFilter() != "other-agent" {
		t.Errorf("AgentFilter = %q", view.AgentFilter())
	}

	botView := snap.ForAgent("ci-refactor-bot")
	if botView.Len() != 2 {
		t.Fatalf("bot view has %d capabilities, want 2", botView.Len())
	}
}

func TestStoreAtomicSwap(t *testing.T) {
	snap := loadStarter(t)
	st := NewStore(snap)
	if st.Current() != snap {
		t.Fatal("Current did not return the stored snapshot")
	}

	view := st.SnapshotForAgent("nobody")
	if view == nil || view.AgentFilter() != "nobody" {
		t.Fatal("SnapshotForAgent did not filter")
	}

	// Concurrent readers during a swap must always observe a complete
	// snapshot.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cur := st.Current()
				if cur == nil || cur.Len() == 0 {
					t.Error("observed incomplete snapshot")
					return
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		prev := st.Swap(snap)
		if prev == nil {
			t.Error("Swap returned nil previous snapshot")
		}
	}
	close(stop)
	wg.Wait()

	if got := st.Swap(nil); got != snap {
		t.Error("Swap(nil) must keep the current snapshot")
	}
}

func TestParamExamplesSkipWildcardEntries(t *testing.T) {
	snap := loadStarter(t)
	ex := snap.ParamExamples("s3.read-prefix", "bucket", 10)
	if len(ex) == 0 {
		t.Fatal("no examples returned")
	}
	for _, e := range ex {
		if strings.Contains(e, "*") {
			t.Errorf("example %q contains a wildcard", e)
		}
	}
}

func TestAllowlistAccessors(t *testing.T) {
	snap := loadStarter(t)
	entries, ok := snap.Allowlist("s3-buckets")
	if !ok || len(entries) == 0 {
		t.Fatal("s3-buckets allowlist missing")
	}
	if _, ok := snap.Allowlist("nope"); ok {
		t.Error("unknown allowlist reported present")
	}
	if len(snap.ResourcePatterns()) == 0 {
		t.Error("no resource patterns")
	}
	if !snap.ResourceMatchesAllowlist("arn:aws:s3:::acme-invoices-prod/2026/x.csv") {
		t.Error("concrete object ARN should match the admin patterns")
	}
	if snap.ResourceMatchesAllowlist("arn:aws:s3:::evil-bucket/x") {
		t.Error("foreign bucket ARN must not match")
	}
}

func TestGlobCovers(t *testing.T) {
	tests := []struct {
		outer, inner string
		want         bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"a*", "abc", true},
		{"a*", "a", true},
		{"a*", "b", false},
		{"a*b", "a*b", true},
		{"a*", "a*b", true},
		{"a*b", "a*", false},
		{"*", "anything*here", true},
		{"abc", "a*", false},
		{"a*c*", "a*c", true},
		{"prefix/*", "prefix/deep/*", true},
		{"prefix/deep/*", "prefix/*", false},
	}
	for _, tt := range tests {
		if got := globCovers(tt.outer, tt.inner); got != tt.want {
			t.Errorf("globCovers(%q, %q) = %v, want %v", tt.outer, tt.inner, got, tt.want)
		}
	}
}

func TestARNMatchingDoesNotCrossFields(t *testing.T) {
	// A glob in one ARN field must not swallow the following fields.
	if arnMatches("arn:aws:s3:*", "arn:aws:s3:::bucket") {
		t.Error("truncated pattern must not match")
	}
	if arnMatches("arn:aws:sqs:*:*:q", "arn:aws:sqs:us-east-1:111122223333:other") {
		t.Error("resource mismatch must not match")
	}
	if !arnMatches("arn:aws:sqs:*:*:q*", "arn:aws:sqs:us-east-1:111122223333:q1") {
		t.Error("expected match")
	}
	// The region glob must not extend into the account field.
	if arnMatches("arn:aws:sqs:us-*555:q", "arn:aws:sqs:us-east-1:444455556666:q") {
		t.Error("glob crossed the region/account boundary")
	}
	if arnCovers("arn:aws:s3:::b*", "arn:aws:s3:::b/*") == false {
		t.Error("bucket glob covers object paths within the resource field")
	}
	if arnCovers("arn:aws:s3:::b", "arn:aws:s3:::b/*") {
		t.Error("literal bucket pattern must not cover object paths")
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
