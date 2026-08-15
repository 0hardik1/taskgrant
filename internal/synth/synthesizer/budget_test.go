package synthesizer

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/match"
)

// twoCapRequest selects one inline and one managed-eligible
// capability so the ladder's offload step has something to move.
func twoCapRequest(grantID string) synth.Request {
	req := baseRequest(grantID)
	req.Hints.Capabilities = []synth.CapabilityHint{
		{ID: "s3.read-prefix", Params: map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}},
		{ID: "sqs.consume", Params: map[string]string{"queue": "invoice-jobs"}},
	}
	return req
}

func selections(req synth.Request, snapCaps map[string]int) []SelectedCapability {
	var out []SelectedCapability
	for _, h := range req.Hints.Capabilities {
		out = append(out, SelectedCapability{ID: h.ID, Version: snapCaps[h.ID], Params: h.Params})
	}
	return out
}

var versionByID = map[string]int{"s3.read-prefix": 3, "s3.write-prefix": 1, "sqs.consume": 2}

func TestReductionLadderDropsSids(t *testing.T) {
	e := newEnv(t, nil)
	req := baseRequest("grant-l1")
	sel := selections(req, versionByID)
	withSids := e.compiler.renderSize(sel, CompileOptions{})
	noSids := e.compiler.renderSize(sel, CompileOptions{DropSids: true})
	if noSids >= withSids {
		t.Fatalf("test setup broken: noSids %d must be smaller than withSids %d", noSids, withSids)
	}

	req.MaxPolicyChars = noSids // fits only after dropping Sids
	res, err := e.synth.Synthesize(context.Background(), req)
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if res.Verdict != synth.VerdictPolicy {
		t.Fatalf("verdict = %q", res.Verdict)
	}
	if len(res.PolicyJSON) != noSids {
		t.Fatalf("policy is %d chars, want the Sid-less render of %d", len(res.PolicyJSON), noSids)
	}
	last := e.compiler.inputs[len(e.compiler.inputs)-1]
	if !last.Options.DropSids || last.Options.OffloadManaged {
		t.Fatalf("final compile options = %+v, want DropSids only", last.Options)
	}
	if bytes.Contains(res.PolicyJSON, []byte(`"Sid"`)) {
		t.Fatal("Sids must be gone under the tightened budget")
	}
}

func TestReductionLadderOffloadsManaged(t *testing.T) {
	e := newEnv(t, nil)
	req := twoCapRequest("grant-l2")
	sel := selections(req, versionByID)
	noSids := e.compiler.renderSize(sel, CompileOptions{DropSids: true})
	offloaded := e.compiler.renderSize(sel, CompileOptions{DropSids: true, OffloadManaged: true})
	if offloaded >= noSids {
		t.Fatalf("test setup broken: offloaded %d must be smaller than noSids %d", offloaded, noSids)
	}

	req.MaxPolicyChars = offloaded // fits only after offload
	res, err := e.synth.Synthesize(context.Background(), req)
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if res.Verdict != synth.VerdictPolicy {
		t.Fatalf("verdict = %q", res.Verdict)
	}
	if len(res.PolicyArns) != 1 || res.PolicyArns[0] != "arn:aws:iam::222222222222:policy/tg-sqs.consume" {
		t.Fatalf("PolicyArns = %v, want the managed offload ARN", res.PolicyArns)
	}
	if bytes.Contains(res.PolicyJSON, []byte("sqs.consume")) {
		t.Fatal("offloaded capability statements must leave the inline policy")
	}
}

func TestOverBudgetDenialWithAttribution(t *testing.T) {
	e := newEnv(t, nil)
	req := baseRequest("grant-l3")
	req.MaxPolicyChars = 10 // nothing fits
	res, trace, err := e.synth.SynthesizeTraced(context.Background(), req)
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if res.Verdict != synth.VerdictDeny || res.DenialCode != domain.DenyOverBudget.String() {
		t.Fatalf("got %q %q, want deny OVER_BUDGET", res.Verdict, res.DenialCode)
	}
	if e.compiler.calls != 3 {
		t.Errorf("compiler ran %d times, want the full 3-step ladder", e.compiler.calls)
	}
	joined := strings.Join(trace.DenialDetail, "\n")
	if !strings.Contains(joined, "s3.read-prefix") || !strings.Contains(joined, "over by") {
		t.Fatalf("attribution must name capabilities and overage: %v", trace.DenialDetail)
	}
}

func TestCompactReRendersSameSelection(t *testing.T) {
	e := newEnv(t, func(d *Deps, env *env) {
		// A classifier is configured; Compact must never touch it.
		env.classifier = &match.StubClassifier{}
		d.Classifier = env.classifier
	})
	req := twoCapRequest("grant-c1")
	prev, err := e.synth.Synthesize(context.Background(), req)
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if prev.Verdict != synth.VerdictPolicy {
		t.Fatalf("setup verdict = %q", prev.Verdict)
	}

	sel := selections(req, versionByID)
	tighter := e.compiler.renderSize(sel, CompileOptions{DropSids: true})
	compilerCallsBefore := e.compiler.calls

	got, err := e.synth.Compact(context.Background(), prev, tighter)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if got.Verdict != synth.VerdictPolicy {
		t.Fatalf("Compact verdict = %q", got.Verdict)
	}
	if len(got.PolicyJSON) > tighter {
		t.Fatalf("compacted policy %d chars exceeds budget %d", len(got.PolicyJSON), tighter)
	}
	if len(got.Capabilities) != len(prev.Capabilities) {
		t.Fatalf("Compact changed the capability selection: %+v vs %+v", got.Capabilities, prev.Capabilities)
	}
	for i := range got.Capabilities {
		if got.Capabilities[i] != prev.Capabilities[i] {
			t.Fatalf("Compact changed capability %d: %+v vs %+v", i, got.Capabilities[i], prev.Capabilities[i])
		}
	}
	if got.EffectiveDuration != prev.EffectiveDuration {
		t.Error("Compact must keep the effective duration")
	}
	if e.compiler.calls == compilerCallsBefore {
		t.Error("Compact must re-render through the compiler")
	}
	// Determinism: compacting again yields byte-identical output.
	again, err := e.synth.Compact(context.Background(), prev, tighter)
	if err != nil {
		t.Fatalf("second Compact: %v", err)
	}
	if !bytes.Equal(got.PolicyJSON, again.PolicyJSON) {
		t.Fatal("Compact is not deterministic")
	}
}

func TestCompactNeverRematches(t *testing.T) {
	stub := &match.StubClassifier{}
	e := newEnv(t, func(d *Deps, env *env) { d.Classifier = stub })
	prev, err := e.synth.Synthesize(context.Background(), baseRequest("grant-c2"))
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	callsBefore := stub.Calls
	if _, err := e.synth.Compact(context.Background(), prev, len(prev.PolicyJSON)); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if stub.Calls != callsBefore {
		t.Fatal("Compact consulted the classifier; it must never re-match")
	}
}

func TestCompactStillTooLarge(t *testing.T) {
	e := newEnv(t, nil)
	prev, err := e.synth.Synthesize(context.Background(), baseRequest("grant-c3"))
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	got, err := e.synth.Compact(context.Background(), prev, 10)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if got.Verdict != synth.VerdictDeny || got.DenialCode != domain.DenyPolicyTooLarge.String() {
		t.Fatalf("got %q %q, want deny POLICY_TOO_LARGE", got.Verdict, got.DenialCode)
	}
}

func TestCompactRejectsNonPolicyResults(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := e.synth.Compact(context.Background(), synth.Result{Verdict: synth.VerdictDeny}, 100); err == nil {
		t.Fatal("Compact must reject a non-policy previous result")
	}
	if _, err := e.synth.Compact(context.Background(), synth.Result{Verdict: synth.VerdictPolicy}, 0); err == nil {
		t.Fatal("Compact must reject a non-positive budget")
	}
}
