package main

// Adapters that wire the concrete foundation packages onto the
// consumer-side seams the synthesizer defines (deps.go of
// internal/synth/synthesizer). This file is the only place the seams
// meet the concrete types; the packages themselves stay decoupled.

import (
	"context"
	"fmt"

	"github.com/0hardik1/taskgrant/internal/guardrails"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
	"github.com/0hardik1/taskgrant/internal/synth/compile"
	"github.com/0hardik1/taskgrant/internal/synth/match"
	"github.com/0hardik1/taskgrant/internal/synth/synthesizer"
)

// snapshotView adapts a *catalog.Snapshot to the match.Snapshot seam:
// agent-filtered capability views for the matchers and the gate.
type snapshotView struct {
	snap *catalog.Snapshot
}

var _ match.Snapshot = snapshotView{}

func (v snapshotView) Hash() string {
	if v.snap == nil {
		return ""
	}
	return v.snap.CatalogHash()
}

func (v snapshotView) Capabilities() []match.Capability {
	if v.snap == nil {
		return nil
	}
	caps := v.snap.Capabilities()
	out := make([]match.Capability, 0, len(caps))
	for _, c := range caps {
		out = append(out, v.convert(c))
	}
	return out
}

func (v snapshotView) Lookup(id string) (match.Capability, bool) {
	if v.snap == nil {
		return match.Capability{}, false
	}
	c, ok := v.snap.Capability(id)
	if !ok {
		return match.Capability{}, false
	}
	return v.convert(c), true
}

// convert renders the matcher-facing view of one catalog entry. Every
// declared param is required (catalog.ValidateParams enforces the same
// rule).
func (v snapshotView) convert(c *catalog.Capability) match.Capability {
	out := match.Capability{
		ID:                 c.ID,
		Version:            c.Version,
		Summary:            c.Summary,
		Keywords:           c.Match.Keywords,
		ServicePrefixes:    c.Match.ServicePrefixes,
		Examples:           c.Match.Examples,
		RequiresApproval:   c.RequiresApproval,
		MaxDurationSeconds: c.MaxDurationSeconds,
	}
	for _, name := range c.ParamNames() {
		p := c.Params[name]
		out.Params = append(out.Params, match.ParamSpec{
			Name:          name,
			Required:      true,
			ExpectedShape: p.ExpectedShape(),
			Examples:      v.snap.ParamExamples(c.ID, name, 3),
		})
	}
	return out
}

// catalogAdapter implements synthesizer.Catalog over the atomic
// catalog store: hot reload swaps snapshots, in-flight requests keep
// theirs.
type catalogAdapter struct {
	store *catalog.Store
}

var _ synthesizer.Catalog = catalogAdapter{}

func (a catalogAdapter) SnapshotFor(agentID string) match.Snapshot {
	return snapshotView{snap: a.store.SnapshotForAgent(agentID)}
}

// paramsAdapter implements synthesizer.ParamValidator over the current
// catalog snapshot's grammar and allowlist validation.
type paramsAdapter struct {
	store *catalog.Store
}

var _ synthesizer.ParamValidator = paramsAdapter{}

func (a paramsAdapter) ValidateParams(capabilityID string, params map[string]string) []synthesizer.ParamError {
	snap := a.store.Current()
	if snap == nil {
		return []synthesizer.ParamError{{Capability: capabilityID, Reason: "catalog unavailable"}}
	}
	_, err := snap.ValidateParams(capabilityID, params)
	if err == nil {
		return nil
	}
	if perr, ok := err.(*catalog.ParamError); ok {
		return []synthesizer.ParamError{{
			Capability:    perr.Capability,
			Name:          perr.Param,
			Reason:        perr.Reason,
			ExpectedShape: expectedShape(snap, capabilityID, perr.Param),
			Examples:      snap.ParamExamples(capabilityID, perr.Param, 3),
		}}
	}
	return []synthesizer.ParamError{{Capability: capabilityID, Reason: "unknown capability"}}
}

func expectedShape(snap *catalog.Snapshot, capID, param string) string {
	c, ok := snap.Capability(capID)
	if !ok {
		return ""
	}
	p, ok := c.Params[param]
	if !ok {
		return ""
	}
	return p.ExpectedShape()
}

// compilerAdapter implements synthesizer.Compiler over the
// deterministic compile package. Region and accounts are fixed at
// construction (aws.sts_region, aws.accounts) so the same selection
// always renders byte-identically (invariant I6); maxPolicyArns is
// reduced by the largest profile static ceiling so offload can never
// push the combined PolicyArns list past the STS maximum of 10.
type compilerAdapter struct {
	store         *catalog.Store
	compiler      *compile.Compiler
	region        string
	accounts      []string
	maxPolicyArns int
}

var _ synthesizer.Compiler = compilerAdapter{}

func (a compilerAdapter) Compile(_ context.Context, in synthesizer.CompileInput) (synthesizer.CompileResult, error) {
	snap := a.store.Current()
	if snap == nil {
		return synthesizer.CompileResult{}, fmt.Errorf("compile: catalog unavailable")
	}
	sels := make([]compile.Selection, 0, len(in.Capabilities))
	for _, sc := range in.Capabilities {
		c, ok := snap.Capability(sc.ID)
		if !ok {
			return synthesizer.CompileResult{}, fmt.Errorf("compile: capability %q is not in the catalog", sc.ID)
		}
		validated, err := snap.ValidateParams(sc.ID, sc.Params)
		if err != nil {
			return synthesizer.CompileResult{}, fmt.Errorf("compile: capability %s params: %w", sc.ID, err)
		}
		sels = append(sels, compile.Selection{Capability: c, Params: validated})
	}
	out, err := a.compiler.Compile(compile.Input{
		Selections:          sels,
		Region:              a.region,
		Accounts:            a.accounts,
		MaxPolicyChars:      in.MaxChars,
		MaxPolicyArns:       a.maxPolicyArns,
		ForceDropSids:       in.Options.DropSids,
		ForceOffloadManaged: in.Options.OffloadManaged,
	})
	if err != nil {
		var over *compile.OverBudgetError
		if asOverBudget(err, &over) {
			// The synthesizer's ladder driver decides on OVER_BUDGET by
			// comparing len(PolicyJSON) against the budget; hand it a
			// placeholder of the real over-budget length plus the
			// per-capability attribution. The placeholder bytes never
			// reach a policy: an over-budget result is always denied.
			return synthesizer.CompileResult{
				PolicyJSON:         make([]byte, over.Chars),
				PerCapabilityChars: over.Attribution,
			}, nil
		}
		return synthesizer.CompileResult{}, err
	}
	return synthesizer.CompileResult{
		PolicyJSON:         out.PolicyJSON,
		PolicyArns:         out.PolicyArns,
		Explanation:        out.Explanation,
		ExpandedActions:    out.ExpandedActions,
		PerCapabilityChars: out.Attribution,
	}, nil
}

// asOverBudget unwraps a *compile.OverBudgetError.
func asOverBudget(err error, target **compile.OverBudgetError) bool {
	if e, ok := err.(*compile.OverBudgetError); ok {
		*target = e
		return true
	}
	return false
}

// synthGuardrailAdapter implements synthesizer.GuardrailEvaluator: the
// compile-time guardrail run inside the synthesizer. It carries no
// durable state (G8 rate and creep report warn on this run); the
// broker's own run stays authoritative and injects the store.
type synthGuardrailAdapter struct {
	evaluator *guardrails.Evaluator
	store     *catalog.Store
	chained   bool
}

var _ synthesizer.GuardrailEvaluator = synthGuardrailAdapter{}

func (a synthGuardrailAdapter) Evaluate(ctx context.Context, policyJSON []byte, meta synthesizer.GuardrailMeta) ([]synthesizer.GuardrailVerdict, error) {
	in := guardrails.Input{
		PolicyJSON:                policyJSON,
		AgentID:                   meta.AgentID,
		Profile:                   meta.Profile.Name,
		ProfileMaxDurationSeconds: meta.Profile.MaxDurationSeconds,
		Capabilities:              a.capabilityMeta(meta.Capabilities),
		BrokerChained:             a.chained,
	}
	res := a.evaluator.Evaluate(ctx, in)
	out := make([]synthesizer.GuardrailVerdict, 0, len(res.Checks))
	for _, c := range res.Checks {
		verdict := string(c.Verdict)
		if c.Verdict == guardrails.NeedsApproval {
			// The synthesizer vocabulary is pass/warn/fail; a human gate
			// is not a compile-time failure. The broker's authoritative
			// run routes needs_approval to the approval queue.
			verdict = synthesizer.GuardrailWarn
		}
		out = append(out, synthesizer.GuardrailVerdict{Check: c.Name, Result: verdict, Detail: c.Detail})
	}
	return out, nil
}

func (a synthGuardrailAdapter) capabilityMeta(refs []synth.CapabilityRef) []guardrails.CapabilityMeta {
	snap := a.store.Current()
	out := make([]guardrails.CapabilityMeta, 0, len(refs))
	for _, ref := range refs {
		m := guardrails.CapabilityMeta{ID: ref.ID}
		if snap != nil {
			if c, ok := snap.Capability(ref.ID); ok {
				m.MaxDurationSeconds = c.MaxDurationSeconds
				m.TaggingOptIn = c.AccessCeiling == "Tagging"
			}
		}
		out = append(out, m)
	}
	return out
}
