package guardrails

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/0hardik1/taskgrant/internal/dataset"
)

// testDataset deliberately mislabels lambda:AddPermission as Read: the
// shipped escalation denylist must win regardless of dataset labels.
const testDataset = `{
  "schema_version": 1,
  "source_commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "actions": {
    "s3:GetObject": {"access_level": "Read", "resource_types": ["object"],
      "condition_keys": ["s3:ExistingObjectTag/<key>"]},
    "s3:ListBucket": {"access_level": "List", "resource_types": ["bucket"],
      "condition_keys": ["s3:prefix", "s3:delimiter"]},
    "s3:PutObject": {"access_level": "Write", "resource_types": ["object"],
      "condition_keys": ["s3:x-amz-acl"]},
    "s3:PutBucketPolicy": {"access_level": "Permissions management", "resource_types": ["bucket"],
      "condition_keys": []},
    "sqs:SendMessage": {"access_level": "Write", "resource_types": ["queue"],
      "condition_keys": ["aws:ResourceTag/${TagKey}"]},
    "sqs:ReceiveMessage": {"access_level": "Read", "resource_types": ["queue"],
      "condition_keys": ["aws:ResourceTag/${TagKey}"]},
    "sqs:TagQueue": {"access_level": "Tagging", "resource_types": ["queue"],
      "condition_keys": []},
    "iam:PassRole": {"access_level": "Write", "resource_types": ["role"],
      "condition_keys": ["iam:PassedToService"]},
    "iam:GetRole": {"access_level": "Read", "resource_types": ["role"], "condition_keys": []},
    "iam:ListRoles": {"access_level": "List", "resource_types": [], "condition_keys": []},
    "lambda:AddPermission": {"access_level": "Read", "resource_types": ["function"],
      "condition_keys": []},
    "lambda:InvokeFunction": {"access_level": "Write", "resource_types": ["function"],
      "condition_keys": []},
    "route53:ListHostedZones": {"access_level": "List", "resource_types": [], "condition_keys": []},
    "ec2:DescribeInstances": {"access_level": "List", "resource_types": [], "condition_keys": []}
  }
}`

func testEvaluator(t *testing.T, mutate func(*Config)) *Evaluator {
	t.Helper()
	ds, err := dataset.LoadBytes([]byte(testDataset))
	if err != nil {
		t.Fatalf("load test dataset: %v", err)
	}
	cfg := Config{
		ResourceAllowlist: []string{
			"arn:aws:s3:::acme-invoices-prod",
			"arn:aws:s3:::acme-invoices-prod/*",
			"arn:aws:sqs:us-*:111122223333:orders-*",
		},
		Accounts: []string{"111122223333"},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	e, err := New(ds, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// goodPolicy is a fully conforming read policy.
func goodPolicy() []byte {
	return []byte(`{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":["s3:GetObject"],` +
		`"Resource":["arn:aws:s3:::acme-invoices-prod/2026/*"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"}}},` +
		`{"Effect":"Allow","Action":["s3:ListBucket"],` +
		`"Resource":["arn:aws:s3:::acme-invoices-prod"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"},` +
		`"StringLike":{"s3:prefix":"2026/*"}}}]}`)
}

func baseInput(policy []byte) Input {
	return Input{
		PolicyJSON: policy,
		AgentID:    "invoice-bot",
		Profile:    "s3-archiver",
		Capabilities: []CapabilityMeta{
			{ID: "s3.read-prefix", MaxDurationSeconds: 900},
		},
		State: &fakeState{},
	}
}

type fakeState struct {
	denyToken  map[string]bool
	tokenErr   error
	creepCount int
	creepErr   error
	takeCalls  []string
}

func (f *fakeState) TakeToken(_ context.Context, agentID, capabilityID string) (bool, error) {
	f.takeCalls = append(f.takeCalls, agentID+"/"+capabilityID)
	if f.tokenErr != nil {
		return false, f.tokenErr
	}
	return !f.denyToken[capabilityID], nil
}

func (f *fakeState) DistinctCapabilityCount(_ context.Context, _ string, _ []string) (int, error) {
	if f.creepErr != nil {
		return 0, f.creepErr
	}
	return f.creepCount, nil
}

func verdictOf(t *testing.T, res Result, name string) Verdict {
	t.Helper()
	c, ok := res.Check(name)
	if !ok {
		t.Fatalf("check %s missing; got %+v", name, res.Checks)
	}
	return c.Verdict
}

func TestEvaluatePassReportsEveryCheck(t *testing.T) {
	e := testEvaluator(t, nil)
	res := e.Evaluate(context.Background(), baseInput(goodPolicy()))

	wantOrder := []string{
		CheckStructure, CheckExistence, CheckAccessLevels, CheckServiceDenylist,
		CheckResourceAllowlist, CheckConditions, CheckSizeBudget,
		CheckDurationClamp, CheckCapabilityCount, CheckRateLimit, CheckCreep,
	}
	if len(res.Checks) != len(wantOrder) {
		t.Fatalf("got %d checks, want %d: %+v", len(res.Checks), len(wantOrder), res.Checks)
	}
	for i, name := range wantOrder {
		if res.Checks[i].Name != name {
			t.Errorf("check[%d] = %s, want %s", i, res.Checks[i].Name, name)
		}
		if res.Checks[i].Verdict != Pass {
			t.Errorf("check %s = %s (%s), want pass", name, res.Checks[i].Verdict, res.Checks[i].Detail)
		}
		if res.Checks[i].Detail == "" {
			t.Errorf("check %s has no detail; passes must report too", name)
		}
	}
	if res.Overall != Pass {
		t.Errorf("overall = %s, want pass", res.Overall)
	}
	if !res.OK() {
		t.Error("OK() = false on a clean pass")
	}
	want := []string{"s3:GetObject", "s3:ListBucket"}
	if len(res.ExpandedActions) != 2 || res.ExpandedActions[0] != want[0] || res.ExpandedActions[1] != want[1] {
		t.Errorf("ExpandedActions = %v, want %v", res.ExpandedActions, want)
	}
	if res.EffectiveDurationSeconds != 900 {
		t.Errorf("EffectiveDurationSeconds = %d, want 900", res.EffectiveDurationSeconds)
	}
}

func TestG0Structure(t *testing.T) {
	cases := []struct {
		name    string
		policy  string
		wantSub string
	}{
		{"not_action", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"s3:*","Resource":"*"}]}`, "banned element \"NotAction\""},
		{"not_resource", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::x"}]}`, "banned element \"NotResource\""},
		{"principal", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":"*"}]}`, "banned element \"Principal\""},
		{"deny_effect", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`, "Effect must be Allow"},
		{"wrong_version", `{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, "Version must be"},
		{"bad_charset", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::snowman-` + "☃" + `"}]}`, "STS policy charset"},
		{"not_json", `not a policy`, "not a JSON object"},
		{"no_statement", `{"Version":"2012-10-17"}`, "no Statement"},
		{"unknown_field", `{"Version":"2012-10-17","Extra":1,"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, "unexpected top-level field"},
	}
	e := testEvaluator(t, nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.Evaluate(context.Background(), baseInput([]byte(tc.policy)))
			c, _ := res.Check(CheckStructure)
			if c.Verdict != Fail {
				t.Fatalf("G0 = %s, want fail (%s)", c.Verdict, c.Detail)
			}
			if !strings.Contains(c.Detail, tc.wantSub) {
				t.Errorf("G0 detail %q does not contain %q", c.Detail, tc.wantSub)
			}
			if res.Overall != Fail {
				t.Errorf("overall = %s, want fail", res.Overall)
			}
		})
	}
}

func TestG0FatalSkipsContentChecksClosed(t *testing.T) {
	e := testEvaluator(t, nil)
	res := e.Evaluate(context.Background(), baseInput([]byte(`[]`)))
	for _, name := range []string{CheckExistence, CheckAccessLevels, CheckServiceDenylist, CheckResourceAllowlist, CheckConditions} {
		if v := verdictOf(t, res, name); v != Fail {
			t.Errorf("%s = %s, want fail (fail closed on unparseable policy)", name, v)
		}
	}
	if len(res.Checks) != 11 {
		t.Errorf("got %d checks, want all 11 even on fatal parse", len(res.Checks))
	}
}

func TestG1UnknownActionFailsClosed(t *testing.T) {
	e := testEvaluator(t, nil)
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:GetObject","s3:TotallyMadeUp"],"Resource":["arn:aws:s3:::acme-invoices-prod/*"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"}}}]}`)
	res := e.Evaluate(context.Background(), baseInput(policy))
	c, _ := res.Check(CheckExistence)
	if c.Verdict != Fail {
		t.Fatalf("G1 = %s, want fail (%s)", c.Verdict, c.Detail)
	}
	if !strings.Contains(c.Detail, "not in pinned dataset") {
		t.Errorf("G1 detail %q lacks the fail-closed reason", c.Detail)
	}
	// The known action still flows into later checks.
	if len(res.ExpandedActions) != 1 || res.ExpandedActions[0] != "s3:GetObject" {
		t.Errorf("ExpandedActions = %v, want the surviving expansion", res.ExpandedActions)
	}
}

func TestG1WildcardSpanningEscalation(t *testing.T) {
	// iam:* expands over the dataset; the expansion spans iam:PassRole
	// (escalation denylist) and the iam service is denied outright. The
	// wildcard cannot hide behind its literal string.
	e := testEvaluator(t, nil)
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["iam:*"],"Resource":["arn:aws:iam::111122223333:role/x"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
	res := e.Evaluate(context.Background(), baseInput(policy))

	if v := verdictOf(t, res, CheckExistence); v != Pass {
		t.Errorf("G1 = %s, want pass (iam:* expands against the dataset)", v)
	}
	g2, _ := res.Check(CheckAccessLevels)
	if g2.Verdict != Fail {
		t.Fatalf("G2 = %s, want fail (%s)", g2.Verdict, g2.Detail)
	}
	if !strings.Contains(g2.Detail, "iam:PassRole") {
		t.Errorf("G2 detail %q does not name the spanned escalation action", g2.Detail)
	}
	g3, _ := res.Check(CheckServiceDenylist)
	if g3.Verdict != Fail || !strings.Contains(g3.Detail, "iam") {
		t.Errorf("G3 = %s (%s), want fail naming iam", g3.Verdict, g3.Detail)
	}
}

func TestG2MislabeledDatasetDenylistWins(t *testing.T) {
	// lambda:AddPermission is labeled Read in the test dataset and Read
	// is an allowed level; the shipped escalation denylist must still
	// deny it.
	e := testEvaluator(t, func(cfg *Config) {
		cfg.ResourceAllowlist = append(cfg.ResourceAllowlist,
			"arn:aws:lambda:us-east-1:111122223333:function:*")
	})
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["lambda:AddPermission"],"Resource":["arn:aws:lambda:us-east-1:111122223333:function:etl"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
	res := e.Evaluate(context.Background(), baseInput(policy))
	g2, _ := res.Check(CheckAccessLevels)
	if g2.Verdict != Fail {
		t.Fatalf("G2 = %s, want fail (%s)", g2.Verdict, g2.Detail)
	}
	if !strings.Contains(g2.Detail, "escalation denylist") || !strings.Contains(g2.Detail, "lambda:AddPermission") {
		t.Errorf("G2 detail %q must attribute the deny to the denylist", g2.Detail)
	}
}

func TestG2AccessLevelSet(t *testing.T) {
	writePolicy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::acme-invoices-prod/in/*"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"}}}]}`)

	e := testEvaluator(t, nil)
	res := e.Evaluate(context.Background(), baseInput(writePolicy))
	if v := verdictOf(t, res, CheckAccessLevels); v != Fail {
		t.Errorf("Write under default [Read, List]: G2 = %s, want fail", v)
	}

	in := baseInput(writePolicy)
	in.AllowedAccessLevels = []string{"Read", "List", "Write"}
	res = e.Evaluate(context.Background(), in)
	if v := verdictOf(t, res, CheckAccessLevels); v != Pass {
		c, _ := res.Check(CheckAccessLevels)
		t.Errorf("Write with profile set including Write: G2 = %s (%s), want pass", v, c.Detail)
	}
}

func TestG2PermissionsManagementUnconditional(t *testing.T) {
	e := testEvaluator(t, func(cfg *Config) {
		cfg.ResourceAllowlist = append(cfg.ResourceAllowlist, "arn:aws:s3:::acme-invoices-prod")
	})
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:PutBucketPolicy"],"Resource":["arn:aws:s3:::acme-invoices-prod"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"}}}]}`)
	in := baseInput(policy)
	in.AllowedAccessLevels = []string{"Read", "List", "Write", "Tagging"}
	res := e.Evaluate(context.Background(), in)
	g2, _ := res.Check(CheckAccessLevels)
	if g2.Verdict != Fail || !strings.Contains(g2.Detail, "Permissions management") {
		t.Errorf("G2 = %s (%s), want unconditional Permissions management fail", g2.Verdict, g2.Detail)
	}

	// The level cannot be configured as allowed at all.
	ds, _ := dataset.LoadBytes([]byte(testDataset))
	if _, err := New(ds, Config{AllowedAccessLevels: []string{"Read", "Permissions management"}}); err == nil {
		t.Error("New accepted Permissions management in the allowed set")
	}
}

func TestG2TaggingDoubleOptIn(t *testing.T) {
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["sqs:TagQueue"],"Resource":["arn:aws:sqs:us-east-1:111122223333:orders-main"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
	e := testEvaluator(t, nil)

	cases := []struct {
		name   string
		levels []string
		optIn  bool
		want   Verdict
	}{
		{"neither", []string{"Read", "List"}, false, Fail},
		{"config_only", []string{"Read", "List", "Tagging"}, false, Fail},
		{"capability_only", []string{"Read", "List"}, true, Fail},
		{"both", []string{"Read", "List", "Tagging"}, true, Pass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput(policy)
			in.AllowedAccessLevels = tc.levels
			in.Capabilities = []CapabilityMeta{{ID: "sqs.tag", TaggingOptIn: tc.optIn}}
			res := e.Evaluate(context.Background(), in)
			if v := verdictOf(t, res, CheckAccessLevels); v != tc.want {
				c, _ := res.Check(CheckAccessLevels)
				t.Errorf("G2 = %s (%s), want %s", v, c.Detail, tc.want)
			}
		})
	}
}

func TestG3ExtraDenyServiceExtends(t *testing.T) {
	e := testEvaluator(t, func(cfg *Config) {
		cfg.ExtraDenyServices = []string{"sqs"}
	})
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["sqs:ReceiveMessage"],"Resource":["arn:aws:sqs:us-east-1:111122223333:orders-main"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
	res := e.Evaluate(context.Background(), baseInput(policy))
	g3, _ := res.Check(CheckServiceDenylist)
	if g3.Verdict != Fail || !strings.Contains(g3.Detail, "sqs") {
		t.Errorf("G3 = %s (%s), want fail on configured extra service", g3.Verdict, g3.Detail)
	}
}

func TestG4ResourceAllowlist(t *testing.T) {
	e := testEvaluator(t, nil)
	cases := []struct {
		name     string
		resource string
		want     Verdict
	}{
		{"exact_match", "arn:aws:s3:::acme-invoices-prod", Pass},
		{"prefix_match", "arn:aws:s3:::acme-invoices-prod/2026/x.csv", Pass},
		{"queue_glob_match", "arn:aws:sqs:us-east-1:111122223333:orders-main", Pass},
		{"unlisted_bucket", "arn:aws:s3:::acme-data-exfil/x", Fail},
		// The allowlist glob "us-*" sits in the region field. A naive
		// whole-string glob would let it swallow ":999999999999:" and
		// cross into a foreign account; field-split matching must not.
		{"glob_must_not_cross_account", "arn:aws:sqs:us-east-1:999999999999:orders-x:111122223333:orders-y", Fail},
		{"foreign_account_queue", "arn:aws:sqs:us-east-1:999999999999:orders-main", Fail},
		{"not_an_arn", "acme-invoices-prod/2026/x", Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := "s3:GetObject"
			if strings.Contains(tc.resource, ":sqs:") {
				svc = "sqs:ReceiveMessage"
			}
			policy := []byte(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
				`"Action":[%q],"Resource":[%q],`+
				`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"}}}]}`,
				svc, tc.resource))
			res := e.Evaluate(context.Background(), baseInput(policy))
			if v := verdictOf(t, res, CheckResourceAllowlist); v != tc.want {
				c, _ := res.Check(CheckResourceAllowlist)
				t.Errorf("G4 = %s (%s), want %s", v, c.Detail, tc.want)
			}
		})
	}
}

func TestG4ResourceStar(t *testing.T) {
	e := testEvaluator(t, nil)
	starPolicy := func(action string) []byte {
		return []byte(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
			`"Action":[%q],"Resource":"*",`+
			`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`, action))
	}

	// Resource-free action with capability opt-in: allowed.
	in := baseInput(starPolicy("ec2:DescribeInstances"))
	in.Capabilities = []CapabilityMeta{{ID: "ec2.describe", ResourceStarOptIn: true}}
	res := e.Evaluate(context.Background(), in)
	if v := verdictOf(t, res, CheckResourceAllowlist); v != Pass {
		c, _ := res.Check(CheckResourceAllowlist)
		t.Errorf("resource-free star with opt-in: G4 = %s (%s), want pass", v, c.Detail)
	}

	// Same action without the opt-in: denied.
	in = baseInput(starPolicy("ec2:DescribeInstances"))
	res = e.Evaluate(context.Background(), in)
	if v := verdictOf(t, res, CheckResourceAllowlist); v != Fail {
		t.Errorf("resource-free star without opt-in: G4 = %s, want fail", v)
	}

	// Resource-typed action can never use star, opt-in or not.
	in = baseInput(starPolicy("s3:GetObject"))
	in.Capabilities = []CapabilityMeta{{ID: "s3.read", ResourceStarOptIn: true}}
	res = e.Evaluate(context.Background(), in)
	g4, _ := res.Check(CheckResourceAllowlist)
	if g4.Verdict != Fail || !strings.Contains(g4.Detail, "takes resource types") {
		t.Errorf("resource-typed star: G4 = %s (%s), want fail", g4.Verdict, g4.Detail)
	}
}

func TestG5Conditions(t *testing.T) {
	e := testEvaluator(t, nil)

	t.Run("missing_requested_region", func(t *testing.T) {
		policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::acme-invoices-prod/*"],` +
			`"Condition":{"StringEquals":{"aws:ResourceAccount":"111122223333"}}}]}`)
		res := e.Evaluate(context.Background(), baseInput(policy))
		g5, _ := res.Check(CheckConditions)
		if g5.Verdict != Fail || !strings.Contains(g5.Detail, "aws:RequestedRegion") {
			t.Errorf("G5 = %s (%s), want RequestedRegion fail", g5.Verdict, g5.Detail)
		}
	})

	t.Run("global_service_exempt_from_region", func(t *testing.T) {
		in := baseInput([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["route53:ListHostedZones"],"Resource":"*"}]}`))
		in.Capabilities = []CapabilityMeta{{ID: "route53.list", ResourceStarOptIn: true}}
		res := e.Evaluate(context.Background(), in)
		if v := verdictOf(t, res, CheckConditions); v != Pass {
			c, _ := res.Check(CheckConditions)
			t.Errorf("G5 = %s (%s), want pass under the global-service exemption", v, c.Detail)
		}
	})

	t.Run("s3_requires_resource_account", func(t *testing.T) {
		policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::acme-invoices-prod/*"],` +
			`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
		res := e.Evaluate(context.Background(), baseInput(policy))
		g5, _ := res.Check(CheckConditions)
		if g5.Verdict != Fail || !strings.Contains(g5.Detail, "aws:ResourceAccount") {
			t.Errorf("G5 = %s (%s), want ResourceAccount fail for the global-namespace service", g5.Verdict, g5.Detail)
		}
	})

	t.Run("resource_account_must_match_configured", func(t *testing.T) {
		policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::acme-invoices-prod/*"],` +
			`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"999999999999"}}}]}`)
		res := e.Evaluate(context.Background(), baseInput(policy))
		g5, _ := res.Check(CheckConditions)
		if g5.Verdict != Fail || !strings.Contains(g5.Detail, "not a configured account") {
			t.Errorf("G5 = %s (%s), want foreign-account fail", g5.Verdict, g5.Detail)
		}
	})

	t.Run("unsupported_condition_key", func(t *testing.T) {
		// s3:prefix is supported by s3:ListBucket but not s3:GetObject;
		// an unsupported key silently deadens the statement.
		policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::acme-invoices-prod/*"],` +
			`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"},` +
			`"StringLike":{"s3:prefix":"2026/*"}}}]}`)
		res := e.Evaluate(context.Background(), baseInput(policy))
		g5, _ := res.Check(CheckConditions)
		if g5.Verdict != Fail || !strings.Contains(g5.Detail, "s3:prefix") {
			t.Errorf("G5 = %s (%s), want unsupported-key fail", g5.Verdict, g5.Detail)
		}
	})

	t.Run("wildcard_allowlist_capability_forces_resource_account", func(t *testing.T) {
		policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["sqs:ReceiveMessage"],"Resource":["arn:aws:sqs:us-east-1:111122223333:orders-main"],` +
			`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
		in := baseInput(policy)
		in.Capabilities = []CapabilityMeta{{ID: "sqs.consume", WildcardAllowlistResource: true}}
		res := e.Evaluate(context.Background(), in)
		g5, _ := res.Check(CheckConditions)
		if g5.Verdict != Fail || !strings.Contains(g5.Detail, "aws:ResourceAccount") {
			t.Errorf("G5 = %s (%s), want ResourceAccount required by capability flag", g5.Verdict, g5.Detail)
		}
	})
}

// TestG5OperatorAllowlist is the regression suite for the operator
// gap: a non-conforming synthesizer must not satisfy G5 with a
// negating or loosening operator that carries the mandatory key (or
// its configured value) while inverting or removing the constraint.
func TestG5OperatorAllowlist(t *testing.T) {
	e := testEvaluator(t, nil)
	cases := []struct {
		name      string
		condition string
		wantSubs  []string
	}{
		{
			// The exact exfiltration channel of the finding: the
			// configured account under StringNotEquals grants the
			// action ONLY in foreign accounts.
			"string_not_equals_inverts_account",
			`{"StringEquals":{"aws:RequestedRegion":"us-east-1"},"StringNotEquals":{"aws:ResourceAccount":"111122223333"}}`,
			[]string{"StringNotEquals", "outside the positive-constraint allowlist", "aws:ResourceAccount", "not positively pinned"},
		},
		{
			"null_operator_removes_region",
			`{"Null":{"aws:RequestedRegion":"true"},"StringEquals":{"aws:ResourceAccount":"111122223333"}}`,
			[]string{"Null", "outside the positive-constraint allowlist", "aws:RequestedRegion", "not positively pinned"},
		},
		{
			"if_exists_tolerates_absence",
			`{"StringEqualsIfExists":{"aws:RequestedRegion":"us-east-1"},"StringEquals":{"aws:ResourceAccount":"111122223333"}}`,
			[]string{"StringEqualsIfExists", "outside the positive-constraint allowlist", "aws:RequestedRegion"},
		},
		{
			"for_all_values_passes_on_empty",
			`{"ForAllValues:StringEquals":{"aws:RequestedRegion":"us-east-1"},"StringEquals":{"aws:ResourceAccount":"111122223333"}}`,
			[]string{"ForAllValues:StringEquals", "outside the positive-constraint allowlist"},
		},
		{
			"date_operator_not_positive",
			`{"DateGreaterThan":{"aws:CurrentTime":"2026-01-01T00:00:00Z"},"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"}}`,
			[]string{"DateGreaterThan", "outside the positive-constraint allowlist"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := []byte(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
				`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::acme-invoices-prod/*"],`+
				`"Condition":%s}]}`, tc.condition))
			res := e.Evaluate(context.Background(), baseInput(policy))
			g5, _ := res.Check(CheckConditions)
			if g5.Verdict != Fail {
				t.Fatalf("G5 = %s (%s), want fail", g5.Verdict, g5.Detail)
			}
			for _, sub := range tc.wantSubs {
				if !strings.Contains(g5.Detail, sub) {
					t.Errorf("G5 detail %q does not contain %q", g5.Detail, sub)
				}
			}
			if res.Overall != Fail {
				t.Errorf("overall = %s, want fail", res.Overall)
			}
		})
	}
}

// TestG5WildcardValueDoesNotPin covers the loosening variant: an
// allowed operator (StringLike) whose wildcard value removes the
// mandatory constraint instead of pinning it.
func TestG5WildcardValueDoesNotPin(t *testing.T) {
	e := testEvaluator(t, nil)
	cases := []struct {
		name      string
		condition string
		wantKey   string
	}{
		{
			"star_region",
			`{"StringLike":{"aws:RequestedRegion":"*"},"StringEquals":{"aws:ResourceAccount":"111122223333"}}`,
			"aws:RequestedRegion",
		},
		{
			"prefix_glob_account",
			`{"StringEquals":{"aws:RequestedRegion":"us-east-1"},"StringLike":{"aws:ResourceAccount":"1111*"}}`,
			"aws:ResourceAccount",
		},
		{
			"question_mark_region",
			`{"StringLike":{"aws:RequestedRegion":"us-east-?"},"StringEquals":{"aws:ResourceAccount":"111122223333"}}`,
			"aws:RequestedRegion",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := []byte(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
				`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::acme-invoices-prod/*"],`+
				`"Condition":%s}]}`, tc.condition))
			res := e.Evaluate(context.Background(), baseInput(policy))
			g5, _ := res.Check(CheckConditions)
			if g5.Verdict != Fail {
				t.Fatalf("G5 = %s (%s), want fail", g5.Verdict, g5.Detail)
			}
			if !strings.Contains(g5.Detail, tc.wantKey) || !strings.Contains(g5.Detail, "not positively pinned") {
				t.Errorf("G5 detail %q must name %s as not positively pinned", g5.Detail, tc.wantKey)
			}
		})
	}

	// A wildcard-free StringLike pin is equivalent to StringEquals and
	// stays acceptable (admin catalogs may author it).
	t.Run("wildcard_free_stringlike_pins", func(t *testing.T) {
		policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::acme-invoices-prod/*"],` +
			`"Condition":{"StringLike":{"aws:RequestedRegion":"us-east-1"},` +
			`"StringEquals":{"aws:ResourceAccount":"111122223333"}}}]}`)
		res := e.Evaluate(context.Background(), baseInput(policy))
		if v := verdictOf(t, res, CheckConditions); v != Pass {
			c, _ := res.Check(CheckConditions)
			t.Errorf("G5 = %s (%s), want pass for a wildcard-free StringLike pin", v, c.Detail)
		}
	})
}

// TestG5AccountFieldWildcardForcesResourceAccount covers the
// policy-bytes-only trigger: a glob in a resource ARN's account field
// demands aws:ResourceAccount without relying on seam-reported
// wildcard-allowlist provenance.
func TestG5AccountFieldWildcardForcesResourceAccount(t *testing.T) {
	e := testEvaluator(t, func(cfg *Config) {
		cfg.ResourceAllowlist = append(cfg.ResourceAllowlist, "arn:aws:sqs:us-*:*:orders-*")
	})

	t.Run("missing_account_condition_fails", func(t *testing.T) {
		policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["sqs:ReceiveMessage"],"Resource":["arn:aws:sqs:us-east-1:*:orders-main"],` +
			`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
		res := e.Evaluate(context.Background(), baseInput(policy))
		g5, _ := res.Check(CheckConditions)
		if g5.Verdict != Fail || !strings.Contains(g5.Detail, "aws:ResourceAccount") {
			t.Errorf("G5 = %s (%s), want ResourceAccount required for a wildcard account field", g5.Verdict, g5.Detail)
		}
	})

	t.Run("pinned_account_condition_passes", func(t *testing.T) {
		policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["sqs:ReceiveMessage"],"Resource":["arn:aws:sqs:us-east-1:*:orders-main"],` +
			`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"}}}]}`)
		res := e.Evaluate(context.Background(), baseInput(policy))
		if v := verdictOf(t, res, CheckConditions); v != Pass {
			c, _ := res.Check(CheckConditions)
			t.Errorf("G5 = %s (%s), want pass with the account pinned", v, c.Detail)
		}
	})

	t.Run("concrete_account_field_needs_no_condition", func(t *testing.T) {
		policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":["sqs:ReceiveMessage"],"Resource":["arn:aws:sqs:us-east-1:111122223333:orders-main"],` +
			`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
		res := e.Evaluate(context.Background(), baseInput(policy))
		if v := verdictOf(t, res, CheckConditions); v != Pass {
			c, _ := res.Check(CheckConditions)
			t.Errorf("G5 = %s (%s), want pass for a concrete account field", v, c.Detail)
		}
	})
}

func TestG6SizeBudget(t *testing.T) {
	e := testEvaluator(t, nil)
	in := baseInput(goodPolicy())
	in.MaxPolicyChars = 100
	res := e.Evaluate(context.Background(), in)
	g6, _ := res.Check(CheckSizeBudget)
	if g6.Verdict != Fail || !strings.Contains(g6.Detail, "over the 100 budget") {
		t.Errorf("G6 = %s (%s), want fail over explicit budget", g6.Verdict, g6.Detail)
	}

	in.MaxPolicyChars = len(goodPolicy()) + 5 // inside the 90 percent band
	res = e.Evaluate(context.Background(), in)
	if v := verdictOf(t, res, CheckSizeBudget); v != Warn {
		t.Errorf("G6 = %s, want warn near budget", v)
	}

	in.MaxPolicyChars = 0 // default 1748
	res = e.Evaluate(context.Background(), in)
	if v := verdictOf(t, res, CheckSizeBudget); v != Pass {
		t.Errorf("G6 = %s, want pass under default budget", v)
	}
}

func TestG7DurationClampMatrix(t *testing.T) {
	cases := []struct {
		name      string
		requested int
		capCap    int
		profCap   int
		globalCfg int
		chained   bool
		want      int
	}{
		{"default_when_zero", 0, 0, 0, 0, false, 900},
		{"floor_short_request", 600, 0, 0, 0, false, 900},
		{"request_within_caps", 2000, 0, 0, 0, false, 2000},
		{"profile_cap_wins", 3000, 0, 1800, 0, false, 1800},
		{"capability_cap_wins", 3000, 900, 1800, 0, false, 900},
		{"global_default_caps", 7200, 0, 0, 0, false, 3600},
		{"long_sessions_configured", 7200, 0, 0, 7200, false, 7200},
		{"chained_ceiling", 7200, 0, 0, 7200, true, 3600},
		{"chained_does_not_raise", 1800, 0, 0, 7200, true, 1800},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testEvaluator(t, func(cfg *Config) {
				cfg.GlobalMaxDurationSeconds = tc.globalCfg
			})
			in := baseInput(goodPolicy())
			in.RequestedDurationSeconds = tc.requested
			in.ProfileMaxDurationSeconds = tc.profCap
			in.BrokerChained = tc.chained
			in.Capabilities = []CapabilityMeta{{ID: "c1", MaxDurationSeconds: tc.capCap}}
			res := e.Evaluate(context.Background(), in)
			if res.EffectiveDurationSeconds != tc.want {
				c, _ := res.Check(CheckDurationClamp)
				t.Errorf("effective = %d (%s), want %d", res.EffectiveDurationSeconds, c.Detail, tc.want)
			}
			if v := verdictOf(t, res, CheckDurationClamp); v != Pass {
				t.Errorf("G7 = %s, want pass (clamping is not a failure)", v)
			}
		})
	}
}

func TestG8CapabilityCount(t *testing.T) {
	e := testEvaluator(t, nil)
	in := baseInput(goodPolicy())
	in.Capabilities = []CapabilityMeta{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	res := e.Evaluate(context.Background(), in)
	if v := verdictOf(t, res, CheckCapabilityCount); v != Fail {
		t.Errorf("4 capabilities: G8 count = %s, want fail (max 3)", v)
	}
}

func TestG8RateLimit(t *testing.T) {
	e := testEvaluator(t, nil)

	t.Run("token_denied", func(t *testing.T) {
		in := baseInput(goodPolicy())
		st := &fakeState{denyToken: map[string]bool{"s3.read-prefix": true}}
		in.State = st
		res := e.Evaluate(context.Background(), in)
		g8, _ := res.Check(CheckRateLimit)
		if g8.Verdict != Fail || !strings.Contains(g8.Detail, "s3.read-prefix") {
			t.Errorf("G8 rate = %s (%s), want fail naming the capability", g8.Verdict, g8.Detail)
		}
		if len(st.takeCalls) != 1 || st.takeCalls[0] != "invoice-bot/s3.read-prefix" {
			t.Errorf("TakeToken calls = %v, want per (agent, capability)", st.takeCalls)
		}
	})

	t.Run("store_error_fails_closed", func(t *testing.T) {
		in := baseInput(goodPolicy())
		in.State = &fakeState{tokenErr: errors.New("db locked")}
		res := e.Evaluate(context.Background(), in)
		if v := verdictOf(t, res, CheckRateLimit); v != Fail {
			t.Errorf("G8 rate on store error = %s, want fail (fail closed)", v)
		}
	})

	t.Run("nil_state_warns", func(t *testing.T) {
		in := baseInput(goodPolicy())
		in.State = nil
		res := e.Evaluate(context.Background(), in)
		if v := verdictOf(t, res, CheckRateLimit); v != Warn {
			t.Errorf("G8 rate without state = %s, want warn", v)
		}
		if v := verdictOf(t, res, CheckCreep); v != Warn {
			t.Errorf("G8 creep without state = %s, want warn", v)
		}
	})
}

func TestG8Creep(t *testing.T) {
	e := testEvaluator(t, nil)
	cases := []struct {
		name  string
		count int
		err   error
		want  Verdict
	}{
		{"under_alert", 4, nil, Pass},
		{"at_alert", 5, nil, Warn},
		{"under_cap", 9, nil, Warn},
		{"at_hard_cap", 10, nil, NeedsApproval},
		{"store_error", 0, errors.New("db gone"), Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput(goodPolicy())
			in.State = &fakeState{creepCount: tc.count, creepErr: tc.err}
			res := e.Evaluate(context.Background(), in)
			if v := verdictOf(t, res, CheckCreep); v != tc.want {
				c, _ := res.Check(CheckCreep)
				t.Errorf("G8 creep = %s (%s), want %s", v, c.Detail, tc.want)
			}
			if tc.want == NeedsApproval && res.Overall != NeedsApproval {
				t.Errorf("overall = %s, want needs_approval", res.Overall)
			}
		})
	}
}

func TestDetailSanitization(t *testing.T) {
	// Hostile bytes inside the policy must not reach a rendered detail
	// with control sequences intact. The JSON-escaped ESC decodes into
	// the resource string while the raw policy bytes stay charset-clean,
	// so the ANSI sequence survives parsing and must be stripped at
	// render time.
	e := testEvaluator(t, nil)
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::evil\u001b[31mred"],` +
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1","aws:ResourceAccount":"111122223333"}}}]}`)
	res := e.Evaluate(context.Background(), baseInput(policy))
	for _, c := range res.Checks {
		if strings.ContainsRune(c.Detail, 0x1b) {
			t.Errorf("check %s detail carries a raw ESC byte: %q", c.Name, c.Detail)
		}
	}
	g4, _ := res.Check(CheckResourceAllowlist)
	if g4.Verdict != Fail {
		t.Errorf("G4 = %s, want fail for the hostile resource", g4.Verdict)
	}
	if !strings.Contains(g4.Detail, "evil") {
		t.Errorf("G4 detail %q should still attribute the failing resource", g4.Detail)
	}
}

func TestArnPatternMatchBoundaries(t *testing.T) {
	cases := []struct {
		pattern  string
		resource string
		want     bool
	}{
		{"arn:aws:s3:::bkt/*", "arn:aws:s3:::bkt/key", true},
		{"arn:aws:s3:::bkt/*", "arn:aws:s3:::bkt2/key", false},
		// Policy resources are themselves patterns; a literal '*' in the
		// candidate is matched by the allowlist glob.
		{"arn:aws:s3:::bkt/*", "arn:aws:s3:::bkt/2026/*", true},
		// Region-field glob must not cross into the account field.
		{"arn:aws:sqs:us-*:111122223333:q", "arn:aws:sqs:us-east-1:999999999999:x:111122223333:q", false},
		// Resource-field glob may span embedded colons past the account.
		{"arn:aws:logs:us-east-1:111122223333:log-group:*", "arn:aws:logs:us-east-1:111122223333:log-group:/aws/x:stream", true},
		{"arn:aws:s3:::bkt", "arn:aws:s3:::bkt", true},
		{"arn:aws:s3:::bkt", "not-an-arn", false},
		{"*", "arn:aws:s3:::bkt", false},
	}
	for _, tc := range cases {
		if got := arnPatternMatch(tc.pattern, tc.resource); got != tc.want {
			t.Errorf("arnPatternMatch(%q, %q) = %t, want %t", tc.pattern, tc.resource, got, tc.want)
		}
	}
}
