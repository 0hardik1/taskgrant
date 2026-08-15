package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0hardik1/taskgrant/internal/approvals"
	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/guardrails"
	"github.com/0hardik1/taskgrant/internal/mcpserver"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/stsmint"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
)

// testPolicy is a small syntactically plausible session policy.
const testPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::acme-invoices-prod/2026/*"]}]}`

const testDatasetJSON = `{
  "schema_version": 1,
  "source_commit": "test",
  "actions": {
    "s3:GetObject": {"access_level": "Read", "resource_types": ["object"], "condition_keys": []},
    "s3:ListBucket": {"access_level": "List", "resource_types": ["bucket"], "condition_keys": ["s3:prefix"]},
    "s3:PutObject": {"access_level": "Write", "resource_types": ["object"], "condition_keys": []}
  }
}`

// fakeSynth is a scripted synthesizer seam.
type fakeSynth struct {
	mu           sync.Mutex
	calls        int
	compactCalls int
	res          synth.Result
	err          error
	compactRes   *synth.Result
	compactErr   error
}

func (f *fakeSynth) Synthesize(_ context.Context, _ synth.Request) (synth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.res, f.err
}

func (f *fakeSynth) Compact(_ context.Context, prev synth.Result, maxChars int) (synth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.compactCalls++
	if f.compactErr != nil {
		return synth.Result{}, f.compactErr
	}
	if f.compactRes != nil {
		return *f.compactRes, nil
	}
	out := prev
	if len(out.PolicyJSON) > maxChars && maxChars > 0 {
		out.PolicyJSON = out.PolicyJSON[:maxChars]
	}
	return out, nil
}

func (f *fakeSynth) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeSynth) compactCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.compactCalls
}

// fakeEvaluator returns a scripted guardrails result.
type fakeEvaluator struct {
	mu  sync.Mutex
	res guardrails.Result
}

func (f *fakeEvaluator) Evaluate(context.Context, guardrails.Input) guardrails.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.res
}

func passResult() guardrails.Result {
	var checks []guardrails.Check
	for _, name := range []string{
		guardrails.CheckStructure, guardrails.CheckExistence, guardrails.CheckAccessLevels,
		guardrails.CheckServiceDenylist, guardrails.CheckResourceAllowlist, guardrails.CheckConditions,
		guardrails.CheckSizeBudget, guardrails.CheckDurationClamp, guardrails.CheckCapabilityCount,
		guardrails.CheckRateLimit, guardrails.CheckCreep,
	} {
		checks = append(checks, guardrails.Check{Name: name, Verdict: guardrails.Pass})
	}
	return guardrails.Result{
		Checks:                   checks,
		Overall:                  guardrails.Pass,
		ExpandedActions:          []string{"s3:GetObject"},
		EffectiveDurationSeconds: 900,
		PolicyChars:              len(testPolicy),
	}
}

// fakeMinter is a scripted STS seam.
type fakeMinter struct {
	mu sync.Mutex
	// err makes every mint fail with it.
	err error
	// compactFirst simulates one PackedPolicyTooLarge: the compact
	// callback runs once, then the mint succeeds on its output.
	compactFirst bool
	lastPolicy   []byte
	mints        int
}

func (f *fakeMinter) MintWithCompact(ctx context.Context, req stsmint.MintRequest, compact stsmint.CompactFunc) (*stsmint.Minted, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mints++
	if f.err != nil {
		return nil, f.err
	}
	policy := req.PolicyJSON
	if f.compactFirst && compact != nil {
		tighter := len(policy) * 8 / 10
		p, _, err := compact(ctx, tighter)
		if err != nil {
			return nil, &stsmint.PolicyTooLargeError{Attempts: [2]stsmint.MintAttempt{
				{PolicyChars: len(policy)}, {PolicyChars: len(policy)},
			}}
		}
		policy = p
	}
	f.lastPolicy = policy
	return &stsmint.Minted{
		Credentials: stsmint.NewCredentials(
			"AKIATESTKEYID", "TESTSECRETACCESSKEY", "TESTSESSIONTOKEN",
			time.Now().Add(15*time.Minute).UTC()),
		AssumedRoleARN:          "arn:aws:sts::222222222222:assumed-role/tg-p1/tg-bot-" + req.GrantID,
		RoleSessionName:         "tg-bot-" + req.GrantID,
		SourceIdentity:          "tg-" + req.GrantID,
		SessionTags:             map[string]string{"taskgrant:agent": req.AgentID, "taskgrant:grant": req.GrantID},
		TransitiveTagKeys:       []string{"taskgrant:agent", "taskgrant:grant"},
		PackedPolicySizePercent: 42,
		STSRequestID:            "sts-req-1",
	}, nil
}

// fakeCatalog satisfies the Catalog seam with no snapshot.
type fakeCatalog struct{}

func (fakeCatalog) Current() *catalog.Snapshot                { return nil }
func (fakeCatalog) SnapshotForAgent(string) *catalog.Snapshot { return nil }

// harness bundles one wired test broker.
type harness struct {
	b     *Broker
	st    *store.Store
	synth *fakeSynth
	eval  *fakeEvaluator
	mint  *fakeMinter
	cfg   *config.Config
	// cat overrides the default snapshot-less fakeCatalog when set.
	cat Catalog
}

func testConfig() *config.Config {
	return &config.Config{
		Version: 1,
		Server:  config.ServerConfig{Transport: config.TransportStdio, DefaultAgent: "bot"},
		AWS: config.AWSConfig{
			STSRegion:              "us-east-1",
			DefaultDurationSeconds: 900,
			MaxDurationSeconds:     3600,
			Accounts:               []string{"222222222222"},
		},
		Agents: map[string]config.AgentConfig{
			"bot": {Profiles: []string{"p1"}, DefaultProfile: "p1"},
		},
		Profiles: map[string]config.ProfileConfig{
			"p1": {RoleARN: "arn:aws:iam::222222222222:role/tg-p1", MaxDurationSeconds: 1800},
		},
		Approvals: config.ApprovalsConfig{PendingTTLSeconds: 900},
		Log:       config.LogConfig{Path: "unused"},
	}
}

func newHarness(t *testing.T, mutate func(*harness)) *harness {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "test.db"), Logger: logger})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	h := &harness{
		st: st,
		synth: &fakeSynth{res: synth.Result{
			Verdict:           synth.VerdictPolicy,
			PolicyJSON:        []byte(testPolicy),
			EffectiveDuration: 900 * time.Second,
			Capabilities:      []synth.CapabilityRef{{ID: "s3.read-prefix", Version: 3}},
			ExpandedActions:   []string{"s3:GetObject"},
		}},
		eval: &fakeEvaluator{res: passResult()},
		mint: &fakeMinter{},
		cfg:  testConfig(),
	}
	if mutate != nil {
		mutate(h)
	}

	appr, err := approvals.New(st, 900*time.Second, approvals.Options{Logger: logger})
	if err != nil {
		t.Fatalf("approvals.New: %v", err)
	}
	ds, err := dataset.LoadBytes([]byte(testDatasetJSON))
	if err != nil {
		t.Fatalf("dataset.LoadBytes: %v", err)
	}
	var cat Catalog = fakeCatalog{}
	if h.cat != nil {
		cat = h.cat
	}
	b, err := New(Deps{
		Config:    h.cfg,
		Synth:     h.synth,
		Evaluator: h.eval,
		Approvals: appr,
		Minter:    h.mint,
		Log:       st,
		Catalog:   cat,
		Dataset:   ds,
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}
	h.b = b
	return h
}

func grantReq() mcpserver.GrantRequest {
	return mcpserver.GrantRequest{
		Task:      "archive invoices",
		Reason:    "ticket OPS-1",
		Transport: mcpserver.TransportStdio,
	}
}

func TestRequestGrantAutoApprove(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	view, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "active" {
		t.Fatalf("status = %q, want active (detail %q, code %q)", view.Status, view.Detail, view.DenialCode)
	}
	if view.Credentials == nil || view.Credentials.AccessKeyID != "AKIATESTKEYID" {
		t.Fatalf("credentials missing from the auto-approve response: %+v", view.Credentials)
	}
	if _, err := domain.ParseGrantID(view.GrantID); err != nil {
		t.Fatalf("grant id %q is not a ULID: %v", view.GrantID, err)
	}

	// First-use bookkeeping (I5): the pair is marked used and approved.
	seen, approved, err := h.st.FirstUseSeen(ctx, "bot", "s3.read-prefix")
	if err != nil || !seen || !approved {
		t.Fatalf("first-use not marked: seen=%v approved=%v err=%v", seen, approved, err)
	}

	// The decision log carries the access key id and never a secret (I4).
	recs, err := h.st.GrantChain(ctx, view.GrantID)
	if err != nil || len(recs) == 0 {
		t.Fatalf("GrantChain: %v (%d records)", err, len(recs))
	}
	sawKeyID, sawOutcome := false, false
	for _, r := range recs {
		body := string(r.Body)
		if strings.Contains(body, "TESTSECRETACCESSKEY") || strings.Contains(body, "TESTSESSIONTOKEN") {
			t.Fatalf("a secret leaked into the decision log: %s", body)
		}
		if strings.Contains(body, "AKIATESTKEYID") {
			sawKeyID = true
		}
		if strings.Contains(body, `"outcome":"auto_approved"`) {
			sawOutcome = true
		}
	}
	if !sawKeyID || !sawOutcome {
		t.Fatalf("decision record incomplete: access_key_id=%v auto_approved=%v", sawKeyID, sawOutcome)
	}
}

func TestCredentialsDeliveredExactlyOnce(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	view, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil || view.Status != "active" || view.Credentials == nil {
		t.Fatalf("setup: %v %+v", err, view)
	}
	again, err := h.b.GetGrant(ctx, "bot", view.GrantID)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if again.Status != "active" {
		t.Fatalf("status = %q, want active", again.Status)
	}
	if again.Credentials != nil {
		t.Fatal("credentials redelivered with server.credential_redelivery off (I4)")
	}
}

func TestCrossAgentLookupIsNotFound(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	view, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if _, err := h.b.GetGrant(ctx, "other-bot", view.GrantID); !errors.Is(err, mcpserver.ErrNotFound) {
		t.Fatalf("cross-agent GetGrant err = %v, want ErrNotFound", err)
	}
}

func TestIdempotencyKeyReplay(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	req := grantReq()
	req.IdempotencyKey = "run-1-step-3"
	first, err := h.b.RequestGrant(ctx, "bot", req)
	if err != nil || first.Status != "active" {
		t.Fatalf("first request: %v %+v", err, first)
	}
	second, err := h.b.RequestGrant(ctx, "bot", req)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if second.GrantID != first.GrantID {
		t.Fatalf("replay minted a new grant: %s then %s", first.GrantID, second.GrantID)
	}
	if got := h.synth.callCount(); got != 1 {
		t.Fatalf("synthesizer ran %d times, want 1 (replay must not re-run the pipeline)", got)
	}
	if h.mint.mints != 1 {
		t.Fatalf("minted %d times, want 1", h.mint.mints)
	}
}

func TestBoundaryDenials(t *testing.T) {
	cases := []struct {
		name     string
		agent    string
		profile  string
		wantCode domain.DenialCode
	}{
		{"unknown agent", "ghost", "", domain.DenyAgentNotPermitted},
		{"profile not on allowlist", "bot", "p2", domain.DenyProfileNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			req := grantReq()
			req.Profile = tc.profile
			view, err := h.b.RequestGrant(context.Background(), tc.agent, req)
			if err != nil {
				t.Fatalf("RequestGrant: %v", err)
			}
			if view.Status != "denied" || view.DenialCode != tc.wantCode {
				t.Fatalf("got status %q code %q, want denied %q", view.Status, view.DenialCode, tc.wantCode)
			}
			if h.synth.callCount() != 0 {
				t.Fatal("synthesizer ran for a boundary denial")
			}
		})
	}
}

func TestSynthDenialPassesThrough(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.synth.res = synth.Result{Verdict: synth.VerdictDeny, DenialCode: string(domain.DenyNoMatch)}
	})
	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "denied" || view.DenialCode != domain.DenyNoMatch {
		t.Fatalf("got %q/%q, want denied/NO_MATCH", view.Status, view.DenialCode)
	}
	if h.mint.mints != 0 {
		t.Fatal("a denied grant reached STS")
	}
}

func TestGuardrailFailureOverridesSeam(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		res := passResult()
		res.Overall = guardrails.Fail
		for i := range res.Checks {
			if res.Checks[i].Name == guardrails.CheckAccessLevels {
				res.Checks[i].Verdict = guardrails.Fail
				res.Checks[i].Detail = "Write is not allowed for this profile"
			}
		}
		h.eval.res = res
	})
	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "denied" || view.DenialCode != domain.DenyGuardrailViolation {
		t.Fatalf("got %q/%q, want denied/GUARDRAIL_VIOLATION", view.Status, view.DenialCode)
	}
	if h.mint.mints != 0 {
		t.Fatal("a guardrail-failed policy reached STS (anchor rule 2)")
	}
}

func TestRateLimitedDenialCode(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		res := passResult()
		res.Overall = guardrails.Fail
		for i := range res.Checks {
			if res.Checks[i].Name == guardrails.CheckRateLimit {
				res.Checks[i].Verdict = guardrails.Fail
				res.Checks[i].Detail = "token bucket empty"
			}
		}
		h.eval.res = res
	})
	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.DenialCode != domain.DenyRateLimited {
		t.Fatalf("code = %q, want RATE_LIMITED", view.DenialCode)
	}
}

func TestEmptyPolicyFromSeamDenied(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.synth.res.PolicyJSON = nil
	})
	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "denied" || view.DenialCode != domain.DenyGuardrailViolation {
		t.Fatalf("got %q/%q, want denied/GUARDRAIL_VIOLATION", view.Status, view.DenialCode)
	}
}

func TestClarificationRoundRecorded(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.synth.res = synth.Result{
			Verdict: synth.VerdictNeedsClarification,
			Clarification: &synth.Clarification{
				Code:       string(domain.DenyMissingParam),
				Questions:  []string{"which bucket?"},
				RetryToken: "tok.abc",
				Round:      1,
			},
		}
	})
	ctx := context.Background()
	view, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "needs_clarification" || view.Clarification == nil {
		t.Fatalf("got %q (clar %v), want needs_clarification", view.Status, view.Clarification)
	}
	recs, err := h.st.GrantChain(ctx, view.GrantID)
	if err != nil || len(recs) != 1 {
		t.Fatalf("GrantChain: %v (%d records, want 1)", err, len(recs))
	}
	if recs[0].Kind != domain.RecordClarification {
		t.Fatalf("record kind = %q, want clarification", recs[0].Kind)
	}
	if strings.Contains(string(recs[0].Body), "tok.abc") {
		t.Fatal("the raw retry token leaked into the log; only its hash belongs there")
	}
}

func TestApprovalParkAndApprove(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.synth.res.Verdict = synth.VerdictPendingApproval
	})
	ctx := context.Background()

	view, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "pending_approval" {
		t.Fatalf("status = %q, want pending_approval", view.Status)
	}
	if h.mint.mints != 0 {
		t.Fatal("STS was called at request time for a parked grant (anchor rule 1)")
	}

	out, err := h.b.ApproveGrant(ctx, view.GrantID, approvals.Identity{Approver: "ops", Method: approvals.MethodCLI}, "ok")
	if err != nil {
		t.Fatalf("ApproveGrant: %v", err)
	}
	if out.Decision != "approved" || out.MintOutcome != MintOutcomeMinted {
		t.Fatalf("outcome = %+v, want approved/minted", out)
	}
	if h.mint.mints != 1 {
		t.Fatalf("minted %d times, want 1 (mint at approval time)", h.mint.mints)
	}

	// The poll flow: the first get_grant after approval carries the one
	// delivery, the second must not (I4).
	after, err := h.b.GetGrant(ctx, "bot", view.GrantID)
	if err != nil || after.Status != "active" {
		t.Fatalf("post-approval state: %v %+v", err, after)
	}
	if after.Credentials == nil {
		t.Fatal("the poll flow never delivered the credentials")
	}
	second, err := h.b.GetGrant(ctx, "bot", view.GrantID)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if second.Credentials != nil {
		t.Fatal("get_grant redelivered credentials (I4)")
	}
}

func TestApprovalBlockedWaitDeliversCredentials(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.synth.res.Verdict = synth.VerdictPendingApproval
	})
	ctx := context.Background()

	req := grantReq()
	req.WaitSeconds = 10
	type answer struct {
		view *mcpserver.GrantView
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		v, err := h.b.RequestGrant(ctx, "bot", req)
		done <- answer{v, err}
	}()

	// Approve as soon as the pending row lands.
	deadline := time.After(5 * time.Second)
	for {
		_, err := h.b.ApproveGrant(ctx, pendingGrantID(t, h), approvals.Identity{Approver: "ops", Method: approvals.MethodCLI}, "ok")
		if err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("no pending approval appeared: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}

	a := <-done
	if a.err != nil {
		t.Fatalf("RequestGrant: %v", a.err)
	}
	if a.view.Status != "active" || a.view.Credentials == nil {
		t.Fatalf("blocked wait answered %q (creds %v), want active with credentials", a.view.Status, a.view.Credentials != nil)
	}
	if a.view.Credentials.SecretAccessKey != "TESTSECRETACCESSKEY" {
		t.Fatal("the blocked waiter did not receive the plaintext delivery")
	}
}

// pendingGrantID finds the single pending grant in the store.
func pendingGrantID(t *testing.T, h *harness) string {
	t.Helper()
	rows, err := h.st.ListPendingApprovals(context.Background(), store.StatusPending)
	if err != nil || len(rows) == 0 {
		return "no-pending-grant-yet"
	}
	return rows[0].GrantID
}

func TestHumanDenial(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.synth.res.Verdict = synth.VerdictPendingApproval
	})
	ctx := context.Background()
	view, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil || view.Status != "pending_approval" {
		t.Fatalf("setup: %v %+v", err, view)
	}
	out, err := h.b.DenyGrant(ctx, view.GrantID, approvals.Identity{Approver: "ops", Method: approvals.MethodCLI}, "no")
	if err != nil || out.Decision != "denied" {
		t.Fatalf("DenyGrant: %v %+v", err, out)
	}
	after, err := h.b.GetGrant(ctx, "bot", view.GrantID)
	if err != nil || after.Status != "denied" || after.DenialCode != domain.DenyApprovalDenied {
		t.Fatalf("post-denial: %v %+v", err, after)
	}
	if h.mint.mints != 0 {
		t.Fatal("a denied grant reached STS")
	}
}

func TestConfigRuleParksGrant(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.cfg.Approvals.Rules = []config.ApprovalRule{{
			Match:  config.ApprovalMatch{AccessLevel: "Read"},
			Action: config.ActionRequireApproval,
		}}
	})
	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "pending_approval" {
		t.Fatalf("status = %q, want pending_approval via config rule", view.Status)
	}
}

func TestCompactRetryOnPackedPolicyTooLarge(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.mint.compactFirst = true
	})
	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "active" {
		t.Fatalf("status = %q, want active after the compact retry", view.Status)
	}
	if got := h.synth.compactCount(); got != 1 {
		t.Fatalf("Compact ran %d times, want exactly 1", got)
	}
	if len(h.mint.lastPolicy) >= len(testPolicy) {
		t.Fatalf("the compacted policy is not tighter: %d vs %d chars", len(h.mint.lastPolicy), len(testPolicy))
	}
}

func TestPolicyTooLargeDenial(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.mint.err = &stsmint.PolicyTooLargeError{Attempts: [2]stsmint.MintAttempt{
			{PolicyChars: 2000, Message: "PackedPolicyTooLarge"},
			{PolicyChars: 1600, Message: "PackedPolicyTooLarge"},
		}}
	})
	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "denied" || view.DenialCode != domain.DenyPolicyTooLarge {
		t.Fatalf("got %q/%q, want denied/POLICY_TOO_LARGE", view.Status, view.DenialCode)
	}
}

func TestSTSErrorIsSanitized(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.mint.err = fmt.Errorf("operation error STS: AssumeRole, arn:aws:iam::222222222222:role/tg-p1 not authorized")
	})
	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "denied" || view.DenialCode != domain.DenySTSError {
		t.Fatalf("got %q/%q, want denied/STS_ERROR", view.Status, view.DenialCode)
	}
	if strings.Contains(view.Detail, "arn:aws:iam") {
		t.Fatalf("raw STS error leaked to the agent: %q", view.Detail)
	}
}

func TestPendingExpirySweep(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "test.db"), Logger: logger})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	appr, err := approvals.New(st, 50*time.Millisecond, approvals.Options{Logger: logger})
	if err != nil {
		t.Fatalf("approvals.New: %v", err)
	}
	ds, err := dataset.LoadBytes([]byte(testDatasetJSON))
	if err != nil {
		t.Fatalf("dataset: %v", err)
	}
	fs := &fakeSynth{res: synth.Result{
		Verdict:    synth.VerdictPendingApproval,
		PolicyJSON: []byte(testPolicy),
		Capabilities: []synth.CapabilityRef{
			{ID: "s3.read-prefix", Version: 3},
		},
	}}
	fm := &fakeMinter{}
	b, err := New(Deps{
		Config: testConfig(), Synth: fs, Evaluator: &fakeEvaluator{res: passResult()},
		Approvals: appr, Minter: fm, Log: st, Catalog: fakeCatalog{}, Dataset: ds, Logger: logger,
	})
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}

	ctx := context.Background()
	view, err := b.RequestGrant(ctx, "bot", grantReq())
	if err != nil || view.Status != "pending_approval" {
		t.Fatalf("setup: %v %+v", err, view)
	}

	time.Sleep(80 * time.Millisecond)
	b.SweepOnce(ctx)

	after, err := b.GetGrant(ctx, "bot", view.GrantID)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if after.Status != "denied" || after.DenialCode != domain.DenyApprovalTimeout {
		t.Fatalf("got %q/%q, want denied/APPROVAL_TIMEOUT after the sweep", after.Status, after.DenialCode)
	}
	if !after.HumanApprovalAvailable {
		t.Fatal("expired-pending answers must advertise the approval path")
	}
	if fm.mints != 0 {
		t.Fatal("an expired pending grant reached STS")
	}
}

// craftRetryToken builds a retry token the broker can peek: the payload
// carries the grant ULID and round, HMAC-signed part is arbitrary since
// the broker peek does not verify the signature (the real synthesizer
// does). The fake synthesizer used in these tests ignores the token, so
// these tests isolate the broker's ownership and single-use gate.
func craftRetryToken(grantID string, round int) string {
	body, _ := json.Marshal(struct {
		GrantID string `json:"g"`
		AgentID string `json:"a"`
		Round   int    `json:"r"`
	}{GrantID: grantID, AgentID: "bot", Round: round})
	return base64.RawURLEncoding.EncodeToString(body) + ".c2ln"
}

func clarifyResult(round int) synth.Result {
	return synth.Result{
		Verdict: synth.VerdictNeedsClarification,
		Clarification: &synth.Clarification{
			Code:       string(domain.DenyMissingParam),
			Questions:  []string{"which bucket?"},
			RetryToken: "issued.token",
			Round:      round,
		},
	}
}

func policyResult() synth.Result {
	return synth.Result{
		Verdict:           synth.VerdictPolicy,
		PolicyJSON:        []byte(testPolicy),
		EffectiveDuration: 900 * time.Second,
		Capabilities:      []synth.CapabilityRef{{ID: "s3.read-prefix", Version: 3}},
		ExpandedActions:   []string{"s3:GetObject"},
	}
}

func setSynthRes(h *harness, res synth.Result) {
	h.synth.mu.Lock()
	h.synth.res = res
	h.synth.mu.Unlock()
}

// TestRetryTokenCrossAgentIsolation is the F1 regression (scenario
// S051): a retry token issued to one agent must never resolve, let alone
// mint, under a different agent. The broker gate returns the sanitized
// NOT_FOUND before any synthesize or mint (sections 4.1, 3). Before the
// fix, the intruder minted live credentials under the victim's grant
// ULID.
func TestRetryTokenCrossAgentIsolation(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.cfg.Agents["intruder"] = config.AgentConfig{Profiles: []string{"p1"}, DefaultProfile: "p1"}
		h.synth.res = clarifyResult(1)
	})
	ctx := context.Background()

	first, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil || first.Status != "needs_clarification" {
		t.Fatalf("setup: %v %+v", err, first)
	}

	// The intruder would supply the missing param; the seam would mint.
	setSynthRes(h, policyResult())

	retry := grantReq()
	retry.RetryToken = craftRetryToken(first.GrantID, 1)
	_, err = h.b.RequestGrant(ctx, "intruder", retry)
	if !errors.Is(err, mcpserver.ErrNotFound) {
		t.Fatalf("cross-agent retry err = %v, want ErrNotFound", err)
	}
	if h.mint.mints != 0 {
		t.Fatalf("cross-agent retry minted %d times under another agent's grant, want 0", h.mint.mints)
	}
}

// TestRetryTokenSingleUseAfterMint is the F2 regression (scenario
// S050): once a retry has resolved a grant to a live mint, replaying the
// same token must not mint a second time under the same ULID.
func TestRetryTokenSingleUseAfterMint(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.synth.res = clarifyResult(1)
	})
	ctx := context.Background()

	first, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil || first.Status != "needs_clarification" {
		t.Fatalf("setup: %v %+v", err, first)
	}

	// First valid retry mints exactly once (the legitimate happy path,
	// scenarios S046/S047).
	setSynthRes(h, policyResult())
	token := craftRetryToken(first.GrantID, 1)
	retry := grantReq()
	retry.RetryToken = token
	view, err := h.b.RequestGrant(ctx, "bot", retry)
	if err != nil || view.Status != "active" {
		t.Fatalf("first retry: %v %+v", err, view)
	}
	if view.GrantID != first.GrantID {
		t.Fatalf("retry attached to a new grant %s, want original %s", view.GrantID, first.GrantID)
	}
	if h.mint.mints != 1 {
		t.Fatalf("first retry minted %d times, want 1", h.mint.mints)
	}

	// Replaying the same token must be rejected with no second mint.
	replay := grantReq()
	replay.RetryToken = token
	again, err := h.b.RequestGrant(ctx, "bot", replay)
	if err != nil {
		t.Fatalf("replay returned error: %v", err)
	}
	if again.Status != "denied" || again.DenialCode != domain.DenyClarificationExhausted {
		t.Fatalf("replay = %q/%q, want denied/CLARIFICATION_EXHAUSTED", again.Status, again.DenialCode)
	}
	if h.mint.mints != 1 {
		t.Fatalf("replay minted again: total %d mints, want 1", h.mint.mints)
	}

	// The log carries exactly one mint under this ULID (one auto_approved
	// record, one access key id).
	recs, err := h.st.GrantChain(ctx, first.GrantID)
	if err != nil {
		t.Fatalf("GrantChain: %v", err)
	}
	minted, keyIDs := 0, 0
	for _, r := range recs {
		if strings.Contains(string(r.Body), `"outcome":"auto_approved"`) {
			minted++
		}
		keyIDs += strings.Count(string(r.Body), "AKIATESTKEYID")
	}
	if minted != 1 || keyIDs != 1 {
		t.Fatalf("log shows %d mints and %d access key ids under one ULID, want 1 and 1", minted, keyIDs)
	}
}

// TestRetryTokenAfterExhaustedRejected is the F3 regression (scenario
// S048): after two rounds deny CLARIFICATION_EXHAUSTED, a retry token
// must not mint on the now-closed grant, even with a now-valid param.
func TestRetryTokenAfterExhaustedRejected(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.synth.res = clarifyResult(1)
	})
	ctx := context.Background()

	first, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil || first.Status != "needs_clarification" {
		t.Fatalf("round 1: %v %+v", err, first)
	}

	// Round-1 retry produces round-2 clarification.
	setSynthRes(h, clarifyResult(2))
	r1 := grantReq()
	r1.RetryToken = craftRetryToken(first.GrantID, 1)
	v1, err := h.b.RequestGrant(ctx, "bot", r1)
	if err != nil || v1.Status != "needs_clarification" {
		t.Fatalf("round 2: %v %+v", err, v1)
	}

	// Round-2 retry exhausts the clarification budget.
	setSynthRes(h, synth.Result{Verdict: synth.VerdictDeny, DenialCode: string(domain.DenyClarificationExhausted)})
	r2 := grantReq()
	r2.RetryToken = craftRetryToken(first.GrantID, 2)
	v2, err := h.b.RequestGrant(ctx, "bot", r2)
	if err != nil || v2.Status != "denied" || v2.DenialCode != domain.DenyClarificationExhausted {
		t.Fatalf("exhaustion: %v %+v", err, v2)
	}
	if h.mint.mints != 0 {
		t.Fatalf("exhausted grant minted %d times, want 0", h.mint.mints)
	}

	// Replaying the round-2 token with a now-valid param must not mint on
	// the closed grant.
	setSynthRes(h, policyResult())
	replay := grantReq()
	replay.RetryToken = craftRetryToken(first.GrantID, 2)
	v3, err := h.b.RequestGrant(ctx, "bot", replay)
	if err != nil {
		t.Fatalf("replay error: %v", err)
	}
	if v3.Status != "denied" {
		t.Fatalf("replay on exhausted grant = %q, want denied", v3.Status)
	}
	if h.mint.mints != 0 {
		t.Fatalf("replay minted on an exhausted grant: %d mints, want 0", h.mint.mints)
	}
}

func TestReleaseGrant(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	view, err := h.b.RequestGrant(ctx, "bot", grantReq())
	if err != nil || view.Status != "active" {
		t.Fatalf("setup: %v %+v", err, view)
	}
	rel, err := h.b.ReleaseGrant(ctx, "bot", view.GrantID, "succeeded", "done")
	if err != nil {
		t.Fatalf("ReleaseGrant: %v", err)
	}
	if rel.Outcome != "succeeded" || rel.ReleasedAt.IsZero() {
		t.Fatalf("release view = %+v", rel)
	}
	recs, err := h.st.GrantChain(ctx, view.GrantID)
	if err != nil {
		t.Fatalf("GrantChain: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Kind == domain.RecordRelease {
			found = true
		}
	}
	if !found {
		t.Fatal("no release record appended")
	}
}
