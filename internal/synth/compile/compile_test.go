package compile

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
)

const (
	testdataDataset   = "../../../testdata/iam-dataset.json"
	starterCatalogDir = "../../../examples/catalog"
	testRegion        = "us-east-1"
	testAccount       = "222222222222"
)

func loadEnv(t *testing.T) (*dataset.Dataset, *catalog.Snapshot, *Compiler) {
	t.Helper()
	ds, err := dataset.Load(testdataDataset)
	if err != nil {
		t.Fatalf("load dataset: %v", err)
	}
	snap, err := catalog.Load(starterCatalogDir, ds, catalog.WithoutGitCommit())
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	c, err := New(ds)
	if err != nil {
		t.Fatal(err)
	}
	return ds, snap, c
}

func selection(t *testing.T, snap *catalog.Snapshot, capID string, params map[string]string) Selection {
	t.Helper()
	cp, ok := snap.Capability(capID)
	if !ok {
		t.Fatalf("capability %s not in catalog", capID)
	}
	vp, err := snap.ValidateParams(capID, params)
	if err != nil {
		t.Fatalf("validate params for %s: %v", capID, err)
	}
	return Selection{Capability: cp, Params: vp}
}

func mustCompile(t *testing.T, c *Compiler, in Input) *Output {
	t.Helper()
	out, err := c.Compile(in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return out
}

func baseInput(sels ...Selection) Input {
	return Input{
		Selections: sels,
		Region:     testRegion,
		Accounts:   []string{testAccount},
	}
}

func TestCompileS3ReadPrefixShape(t *testing.T) {
	_, snap, c := loadEnv(t)
	out := mustCompile(t, c, baseInput(
		selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}),
	))

	var doc struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid       string          `json:"Sid"`
			Effect    string          `json:"Effect"`
			Action    json.RawMessage `json:"Action"`
			Resource  json.RawMessage `json:"Resource"`
			Condition map[string]map[string]json.RawMessage
		} `json:"Statement"`
	}
	if err := json.Unmarshal(out.PolicyJSON, &doc); err != nil {
		t.Fatalf("policy is not valid JSON: %v\n%s", err, out.PolicyJSON)
	}
	if doc.Version != PolicyVersion {
		t.Errorf("Version = %q", doc.Version)
	}
	if len(doc.Statement) != 2 {
		t.Fatalf("statement count = %d, want 2\n%s", len(doc.Statement), out.PolicyJSON)
	}
	for _, s := range doc.Statement {
		if s.Effect != "Allow" {
			t.Errorf("Effect = %q", s.Effect)
		}
		if s.Sid == "" || !strings.HasPrefix(s.Sid, "TgS3ReadPrefix") {
			t.Errorf("Sid = %q", s.Sid)
		}
		// G5: every statement carries region and account conditions
		// (s3 is a global-namespace service).
		se, ok := s.Condition["StringEquals"]
		if !ok {
			t.Fatalf("statement lacks StringEquals condition: %s", out.PolicyJSON)
		}
		if _, ok := se["aws:RequestedRegion"]; !ok {
			t.Error("missing aws:RequestedRegion (G5)")
		}
		if _, ok := se["aws:ResourceAccount"]; !ok {
			t.Error("missing aws:ResourceAccount (G5)")
		}
	}
	// Explanation is index-parallel.
	if len(out.Explanation.Statements) != len(doc.Statement) {
		t.Errorf("explanation length %d != statements %d", len(out.Explanation.Statements), len(doc.Statement))
	}
	for _, ex := range out.Explanation.Statements {
		if ex.CapabilityID != "s3.read-prefix" || ex.CapabilityVersion != 3 {
			t.Errorf("explanation entry = %+v", ex)
		}
		if ex.Reason == "" {
			t.Error("empty reason")
		}
	}
	// Expanded actions enumerate everything, no wildcards.
	if len(out.ExpandedActions) != 3 {
		t.Errorf("expanded actions = %v", out.ExpandedActions)
	}
	for _, a := range out.ExpandedActions {
		if strings.ContainsAny(a, "*?") {
			t.Errorf("wildcard in expanded action %q (I2)", a)
		}
	}
	if len(out.StepsApplied) != 1 || out.StepsApplied[0] != StepMinify {
		t.Errorf("steps = %v", out.StepsApplied)
	}
}

func TestCompileDeterministicAndOrderIndependent(t *testing.T) {
	_, snap, c := loadEnv(t)
	s1 := selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"})
	s2 := selection(t, snap, "dynamodb.query", map[string]string{"table": "invoices"})
	s3 := selection(t, snap, "sqs.produce", map[string]string{"queue": "invoice-events"})

	a := mustCompile(t, c, baseInput(s1, s2, s3))
	b := mustCompile(t, c, baseInput(s3, s1, s2))
	cOut := mustCompile(t, c, baseInput(s2, s3, s1))

	if string(a.PolicyJSON) != string(b.PolicyJSON) || string(b.PolicyJSON) != string(cOut.PolicyJSON) {
		t.Errorf("selection order changed output bytes (I6)\nA: %s\nB: %s\nC: %s",
			a.PolicyJSON, b.PolicyJSON, cOut.PolicyJSON)
	}
	// Repeat compilation is byte-identical.
	again := mustCompile(t, c, baseInput(s1, s2, s3))
	if string(a.PolicyJSON) != string(again.PolicyJSON) {
		t.Error("repeat compilation differs (I6)")
	}
}

func TestCompileNoWildcardActionEverEmitted(t *testing.T) {
	ds, snap, c := loadEnv(t)
	_ = ds
	sels := []Selection{
		selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}),
		selection(t, snap, "logs.read", map[string]string{"log_group": "/aws/lambda/invoice-processor"}),
		selection(t, snap, "lambda.invoke", map[string]string{"function": "invoice-processor"}),
	}
	out := mustCompile(t, c, baseInput(sels...))

	var doc struct {
		Statement []struct {
			Action json.RawMessage `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(out.PolicyJSON, &doc); err != nil {
		t.Fatal(err)
	}
	for _, s := range doc.Statement {
		var one string
		var many []string
		if err := json.Unmarshal(s.Action, &one); err == nil {
			many = []string{one}
		} else if err := json.Unmarshal(s.Action, &many); err != nil {
			t.Fatalf("Action is neither string nor list: %s", s.Action)
		}
		for _, a := range many {
			if strings.ContainsAny(a, "*?") {
				t.Errorf("emitted action %q contains a wildcard (I2)", a)
			}
		}
	}
}

func TestCompileWildcardCapabilityActionRejected(t *testing.T) {
	ds, snap, c := loadEnv(t)
	_ = ds
	sel := selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"})

	// A hand-built capability that bypassed the loader must still be
	// rejected at compile time (the seam re-verifies).
	rogue := *sel.Capability
	rogue.Actions = []string{"s3:Get*"}
	_, err := c.Compile(baseInput(Selection{Capability: &rogue, Params: sel.Params}))
	if err == nil || !strings.Contains(err.Error(), "I2") {
		t.Errorf("wildcard action not rejected: %v", err)
	}
}

func TestCompileHostileParamValueRejected(t *testing.T) {
	_, snap, c := loadEnv(t)
	sel := selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"})

	// Forged ValidatedParam values that skipped validation must fail
	// closed at the compile boundary.
	for _, hostile := range []string{"", "a*b", "a?b", "a b", "x${aws:username}", "a\x1b[31m"} {
		forged := map[string]catalog.ValidatedParam{
			"bucket": {Name: "bucket", Value: "acme-invoices-prod"},
			"prefix": {Name: "prefix", Value: hostile},
		}
		if _, err := c.Compile(baseInput(Selection{Capability: sel.Capability, Params: forged})); err == nil {
			t.Errorf("forged param value %q accepted", hostile)
		}
	}
}

func TestCompileRegionRequired(t *testing.T) {
	_, snap, c := loadEnv(t)
	in := baseInput(selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}))
	in.Region = ""
	if _, err := c.Compile(in); err == nil || !strings.Contains(err.Error(), "aws:RequestedRegion") {
		t.Errorf("missing region not rejected: %v", err)
	}
}

func TestCompileAccountsRequiredForS3(t *testing.T) {
	_, snap, c := loadEnv(t)
	in := baseInput(selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}))
	in.Accounts = nil
	if _, err := c.Compile(in); err == nil || !strings.Contains(err.Error(), "aws:ResourceAccount") {
		t.Errorf("missing accounts not rejected: %v", err)
	}
}

func TestCompileResourceAccountForWildcardAllowlistEntry(t *testing.T) {
	_, snap, c := loadEnv(t)
	// acme-ml-scratch only matches the acme-ml-* glob entry, so
	// aws:ResourceAccount is mandatory even without the s3 rule.
	sel := selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-ml-scratch", "prefix": "m/"})
	if !sel.Params["bucket"].FromWildcardEntry {
		t.Fatal("test setup: bucket should match via wildcard entry")
	}
	out := mustCompile(t, c, baseInput(sel))
	if !strings.Contains(string(out.PolicyJSON), `"aws:ResourceAccount":"222222222222"`) {
		t.Errorf("policy lacks aws:ResourceAccount: %s", out.PolicyJSON)
	}
}

func TestCompileWildcardAccountFieldGetsResourceAccount(t *testing.T) {
	_, snap, c := loadEnv(t)
	// dynamodb templates use a wildcard account field, which triggers
	// the injection even though dynamodb is not a global-namespace
	// service.
	out := mustCompile(t, c, baseInput(
		selection(t, snap, "dynamodb.query", map[string]string{"table": "invoices"}),
	))
	if !strings.Contains(string(out.PolicyJSON), `"aws:ResourceAccount"`) {
		t.Errorf("policy lacks aws:ResourceAccount: %s", out.PolicyJSON)
	}
}

func TestCompileUnsupportedConditionKeyFailsClosed(t *testing.T) {
	_, snap, c := loadEnv(t)
	sel := selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"})

	rogue := *sel.Capability
	rogue.Conditions = []catalog.ConditionTemplate{{
		Key: "dynamodb:LeadingKeys", Op: "StringEquals", Value: "x",
	}}
	_, err := c.Compile(baseInput(Selection{Capability: &rogue, Params: sel.Params}))
	if err == nil || !strings.Contains(err.Error(), "not supported by action") {
		t.Errorf("unsupported condition key not rejected: %v", err)
	}
}

func TestCompileDuplicateSelectionRejected(t *testing.T) {
	_, snap, c := loadEnv(t)
	sel := selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"})
	if _, err := c.Compile(baseInput(sel, sel)); err == nil {
		t.Error("duplicate capability selection accepted")
	}
}

func TestCompileIdenticalStatementsMergedAcrossCapabilities(t *testing.T) {
	_, snap, c := loadEnv(t)
	// sqs.consume and sqs.produce share sqs:GetQueueAttributes on the
	// same queue resource with the same conditions after injection,
	// but their action groupings differ, so no byte-identical
	// statement dedupe applies. Verify instead with two identical
	// hand-built selections of the same shape under different ids.
	sel := selection(t, snap, "sqs.produce", map[string]string{"queue": "invoice-events"})
	clone := *sel.Capability
	clone.ID = "sqs.produce-copy"
	out := mustCompile(t, c, baseInput(sel, Selection{Capability: &clone, Params: sel.Params}))

	var doc struct {
		Statement []json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(out.PolicyJSON, &doc); err != nil {
		t.Fatal(err)
	}
	// Sids differ per capability, so dedupe happens on the identity
	// without Sid: expect exactly one statement, owned by the first
	// capability in sort order.
	if len(doc.Statement) != 1 {
		t.Fatalf("statement count = %d, want 1 after cross-capability dedupe\n%s", len(doc.Statement), out.PolicyJSON)
	}
	if out.Explanation.Statements[0].CapabilityID != "sqs.produce" {
		t.Errorf("surviving statement credited to %q", out.Explanation.Statements[0].CapabilityID)
	}
}

func TestReductionLadderDropSidsAndOffload(t *testing.T) {
	_, snap, c := loadEnv(t)
	s3sel := selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"})
	logsSel := selection(t, snap, "logs.read", map[string]string{"log_group": "/aws/lambda/invoice-processor"})

	full := mustCompile(t, c, baseInput(s3sel, logsSel))

	// Force the ladder: a budget just below the full render drops
	// Sids; tighter still offloads logs.read (managed_policy: true).
	in := baseInput(s3sel, logsSel)
	in.MaxPolicyChars = full.Chars - 1
	out := mustCompile(t, c, in)
	if out.Chars >= full.Chars {
		t.Errorf("ladder did not shrink the policy: %d -> %d", full.Chars, out.Chars)
	}
	joined := strings.Join(out.StepsApplied, ",")
	if !strings.Contains(joined, StepMerge) || !strings.Contains(joined, StepDropSids) {
		t.Errorf("steps = %v", out.StepsApplied)
	}

	noSids := out
	if strings.Contains(string(noSids.PolicyJSON), `"Sid"`) && strings.Contains(joined, StepOffload) == false {
		// Sids must be gone once drop_sids ran and the doc still holds.
		t.Errorf("Sids still present after drop_sids: %s", noSids.PolicyJSON)
	}

	// Now a budget small enough that only offload can satisfy it.
	tight := baseInput(s3sel, logsSel)
	tight.MaxPolicyChars = 700
	out2 := mustCompile(t, c, tight)
	if len(out2.PolicyArns) != 1 || out2.PolicyArns[0] != "arn:aws:iam::222222222222:policy/taskgrant-logs-read" {
		t.Fatalf("PolicyArns = %v", out2.PolicyArns)
	}
	if strings.Contains(string(out2.PolicyJSON), "logs:") {
		t.Errorf("offloaded capability still in inline policy: %s", out2.PolicyJSON)
	}
	// Explanation stays index-parallel to the inline statements only.
	var doc struct {
		Statement []json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(out2.PolicyJSON, &doc); err != nil {
		t.Fatal(err)
	}
	if len(out2.Explanation.Statements) != len(doc.Statement) {
		t.Errorf("explanation length %d != inline statements %d", len(out2.Explanation.Statements), len(doc.Statement))
	}
	// Expanded actions still include the offloaded capability.
	found := false
	for _, a := range out2.ExpandedActions {
		if strings.HasPrefix(a, "logs:") {
			found = true
		}
	}
	if !found {
		t.Error("expanded actions lost the offloaded capability")
	}
}

func TestReductionLadderOverBudget(t *testing.T) {
	_, snap, c := loadEnv(t)
	in := baseInput(
		selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}),
		selection(t, snap, "dynamodb.query", map[string]string{"table": "invoices"}),
	)
	in.MaxPolicyChars = 100 // impossible
	_, err := c.Compile(in)
	var obe *OverBudgetError
	if !errors.As(err, &obe) {
		t.Fatalf("want OverBudgetError, got %v", err)
	}
	if obe.Chars <= obe.Budget {
		t.Errorf("OverBudgetError chars %d not over budget %d", obe.Chars, obe.Budget)
	}
	if len(obe.Attribution) != 2 {
		t.Errorf("attribution = %v, want both capabilities", obe.Attribution)
	}
	for id, n := range obe.Attribution {
		if n <= 0 {
			t.Errorf("attribution[%s] = %d", id, n)
		}
	}
	msg := obe.Error()
	if !strings.Contains(msg, "s3.read-prefix") || !strings.Contains(msg, "chars") {
		t.Errorf("error message %q lacks per-capability attribution", msg)
	}
}

func TestCompactSemanticsSameSelectionTighterBudget(t *testing.T) {
	// Compact (section 7.3) is Compile on the same selection with a
	// tighter budget: verify determinism under the tighter budget.
	_, snap, c := loadEnv(t)
	sels := []Selection{
		selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}),
		selection(t, snap, "logs.read", map[string]string{"log_group": "/aws/lambda/invoice-processor"}),
	}
	full := mustCompile(t, c, baseInput(sels...))
	tighter := baseInput(sels...)
	tighter.MaxPolicyChars = full.Chars * 80 / 100
	a := mustCompile(t, c, tighter)
	b := mustCompile(t, c, tighter)
	if string(a.PolicyJSON) != string(b.PolicyJSON) {
		t.Error("Compact-style recompile not deterministic")
	}
	if a.Chars > tighter.MaxPolicyChars {
		t.Errorf("result %d chars over the tighter budget %d", a.Chars, tighter.MaxPolicyChars)
	}
}

func TestCompileForceFlags(t *testing.T) {
	_, snap, c := loadEnv(t)
	sels := []Selection{
		selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}),
		selection(t, snap, "logs.read", map[string]string{"log_group": "/aws/lambda/invoice-processor"}),
	}
	in := baseInput(sels...)
	in.ForceDropSids = true
	in.ForceOffloadManaged = true
	out := mustCompile(t, c, in)
	if strings.Contains(string(out.PolicyJSON), `"Sid"`) {
		t.Errorf("ForceDropSids left Sids in place: %s", out.PolicyJSON)
	}
	if len(out.PolicyArns) != 1 {
		t.Errorf("ForceOffloadManaged did not offload: %v", out.PolicyArns)
	}
	if strings.Contains(string(out.PolicyJSON), "logs:") {
		t.Error("offloaded statements still inline")
	}
	joined := strings.Join(out.StepsApplied, ",")
	if !strings.Contains(joined, StepDropSids) || !strings.Contains(joined, StepOffload) {
		t.Errorf("steps = %v", out.StepsApplied)
	}
}

func TestCompileEmptySelections(t *testing.T) {
	ds, _, c := loadEnv(t)
	_ = ds
	if _, err := c.Compile(Input{}); err == nil {
		t.Error("empty input accepted")
	}
}

func TestAttributionCoversAllInlineCapabilities(t *testing.T) {
	_, snap, c := loadEnv(t)
	out := mustCompile(t, c, baseInput(
		selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}),
		selection(t, snap, "sqs.consume", map[string]string{"queue": "invoice-events"}),
	))
	if len(out.Attribution) != 2 {
		t.Fatalf("attribution = %v", out.Attribution)
	}
	total := 0
	for _, n := range out.Attribution {
		total += n
	}
	if total >= out.Chars {
		t.Errorf("statement bytes %d must be under document bytes %d", total, out.Chars)
	}
}
