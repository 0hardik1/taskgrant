// Package synthesizer implements the internal/synth.Synthesizer seam:
// the section 5.4 pipeline (normalize, decision cache, match, gate,
// param resolution, compile, guardrails, budget) plus the section 5.6
// clarification loop and the section 7.3 Compact re-render.
//
// The synthesizer consumes the catalog, compiler, guardrail evaluator,
// param validator, and first-use ledger through consumer-side
// interfaces (deps.go), so it builds and tests independently of the
// sibling packages developed in parallel.
package synthesizer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/match"
)

// Version is the synth_version recorded in decision records.
const Version = "1"

// Policy size and duration bounds (sections 7.1 and 6 G7).
const (
	// DefaultMaxPolicyChars is used when the broker passes no budget:
	// the 2,048 char STS plaintext limit minus the 300 char session
	// tag headroom margin.
	DefaultMaxPolicyChars = 2048 - 300
	// MinDurationSeconds is the floor and default session duration.
	MinDurationSeconds = 900
)

// Deps are the injected dependencies of the Synthesizer. Catalog,
// Compiler, Guardrails, and Params are required. Classifier is
// optional (nil means no LLM, the fully supported default). Cache is
// optional (nil disables decision caching). FirstUse is required when
// FirstUseApproval is true.
type Deps struct {
	Catalog    Catalog
	Compiler   Compiler
	Guardrails GuardrailEvaluator
	Params     ParamValidator
	Cache      DecisionCache
	Classifier match.Classifier
	// FirstUse is the durable first-use predicate (invariant I5).
	FirstUse match.FirstUseFunc
	// FirstUseApproval mirrors guardrails.first_use_approval.
	FirstUseApproval bool
	// DatasetHash and ConfigHash pin every result (invariant I6).
	DatasetHash string
	ConfigHash  string
	// RetryTokenKey signs clarification retry tokens. When empty, a
	// stable key is derived from ConfigHash so tokens survive
	// restarts.
	RetryTokenKey []byte
	// DefaultDurationSeconds defaults to MinDurationSeconds (900).
	DefaultDurationSeconds int
}

// Trace is the synthesis trace for the decision record (section 9.1):
// which matcher ran, its candidates, model id and prompt hash,
// guardrail verdicts, and denial detail such as OVER_BUDGET
// attribution. The broker obtains it via SynthesizeTraced.
type Trace struct {
	IntentHash         string
	CacheHit           bool
	Matcher            string
	Structured         bool
	Candidates         []match.Candidate
	ModelID            string
	PromptTemplateHash string
	Guardrails         []GuardrailVerdict
	// DenialDetail carries agent-consumable denial context, for
	// example per-capability byte attribution for OVER_BUDGET.
	DenialDetail []string
	// Notes are log-only diagnostics.
	Notes []string
	// ApprovalReasons are log-only reasons a human gate was required.
	ApprovalReasons []string
	// FirstUseCapabilities lists ids that triggered first-use review.
	FirstUseCapabilities []string
}

// Synthesizer implements synth.Synthesizer.
type Synthesizer struct {
	catalog          Catalog
	compiler         Compiler
	guardrails       GuardrailEvaluator
	params           ParamValidator
	cache            DecisionCache
	classifier       match.Classifier
	rules            match.RulesMatcher
	gate             match.Gate
	firstUse         match.FirstUseFunc
	firstUseApproval bool
	datasetHash      string
	configHash       string
	tokenKey         []byte
	defaultDuration  int
}

var _ synth.Synthesizer = (*Synthesizer)(nil)

// New builds a Synthesizer from its dependencies, validating the
// required ones.
func New(deps Deps) (*Synthesizer, error) {
	var missing []string
	if deps.Catalog == nil {
		missing = append(missing, "Catalog")
	}
	if deps.Compiler == nil {
		missing = append(missing, "Compiler")
	}
	if deps.Guardrails == nil {
		missing = append(missing, "Guardrails")
	}
	if deps.Params == nil {
		missing = append(missing, "Params")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("synthesizer: missing required dependencies: %s", strings.Join(missing, ", "))
	}
	if deps.FirstUseApproval && deps.FirstUse == nil {
		return nil, fmt.Errorf("synthesizer: FirstUseApproval is enabled but FirstUse is nil")
	}
	key := deps.RetryTokenKey
	if len(key) == 0 {
		if deps.ConfigHash == "" {
			return nil, fmt.Errorf("synthesizer: ConfigHash is required to derive the retry token key")
		}
		key = deriveTokenKey(deps.ConfigHash)
	}
	dur := deps.DefaultDurationSeconds
	if dur <= 0 {
		dur = MinDurationSeconds
	}
	return &Synthesizer{
		catalog:          deps.Catalog,
		compiler:         deps.Compiler,
		guardrails:       deps.Guardrails,
		params:           deps.Params,
		cache:            deps.Cache,
		classifier:       deps.Classifier,
		gate:             match.Gate{FirstUse: deps.FirstUse, FirstUseApproval: deps.FirstUseApproval},
		firstUse:         deps.FirstUse,
		firstUseApproval: deps.FirstUseApproval,
		datasetHash:      deps.DatasetHash,
		configHash:       deps.ConfigHash,
		tokenKey:         key,
		defaultDuration:  dur,
	}, nil
}

// Synthesize implements synth.Synthesizer.
func (s *Synthesizer) Synthesize(ctx context.Context, req synth.Request) (synth.Result, error) {
	res, _, err := s.SynthesizeTraced(ctx, req)
	return res, err
}

// SynthesizeTraced runs the pipeline and additionally returns the
// synthesis trace for the decision record. The broker integration can
// type-assert the seam interface to reach it.
func (s *Synthesizer) SynthesizeTraced(ctx context.Context, req synth.Request) (synth.Result, Trace, error) {
	trace := Trace{}
	if req.GrantID == "" || req.AgentID == "" {
		return synth.Result{}, trace, fmt.Errorf("synthesizer: request requires GrantID and AgentID")
	}
	budget := req.MaxPolicyChars
	if budget <= 0 {
		budget = DefaultMaxPolicyChars
	}

	// Clarification round bookkeeping (section 5.6). A forged or
	// mismatched token is a protocol violation surfaced as an error.
	round := 0
	if req.RetryToken != "" {
		p, err := verifyRetryToken(s.tokenKey, req.RetryToken, req.AgentID)
		if err != nil {
			return synth.Result{}, trace, err
		}
		if p.GrantID != req.GrantID {
			return synth.Result{}, trace, fmt.Errorf("%w: token grant mismatch", ErrInvalidRetryToken)
		}
		round = p.Round
	}

	// Step 1: normalize and hash.
	task := NormalizeTask(req.Task)
	intentHash := IntentHash(req.Task, req.Hints)
	trace.IntentHash = intentHash

	snap := s.catalog.SnapshotFor(req.AgentID)
	hashes := resultHashes{catalog: snap.Hash(), dataset: s.datasetHash, config: s.configHash}

	// Step 2: decision cache. A hit replays the prior compilation
	// under this grant's ULID; approval requirements are re-derived,
	// never replayed.
	key := CacheKey{
		AgentID:        req.AgentID,
		Profile:        req.Profile.Name,
		IntentHash:     intentHash,
		CatalogHash:    hashes.catalog,
		DatasetHash:    hashes.dataset,
		ConfigHash:     hashes.config,
		MaxPolicyChars: budget,
	}
	if s.cache != nil {
		if cached, ok := s.cache.Get(key); ok {
			if res, ok := s.replay(req.AgentID, snap, cached, hashes, &trace); ok {
				trace.CacheHit = true
				return res, trace, nil
			}
		}
	}

	// Step 3: match. Rules first; LLM only when rules abstain.
	mres := s.rules.Match(snap, task, req.Hints)
	if mres.Abstained {
		if s.classifier == nil {
			trace.recordMatch(mres)
			return s.deny(domain.DenyNeedsStructuredHints, hashes, &trace,
				"no structured hints and no keyword match; call list_capabilities and retry with a capabilities hint"), trace, nil
		}
		lres, err := match.LLMMatcher{Classifier: s.classifier}.Match(ctx, snap, task)
		if err != nil {
			// Degrade, never hard-fail the broker on classifier
			// outage: the structured-hints path stays fully
			// functional without an LLM.
			trace.recordMatch(mres)
			trace.Notes = append(trace.Notes, fmt.Sprintf("llm matcher unavailable, degrading: %v", err))
			return s.deny(domain.DenyNeedsStructuredHints, hashes, &trace,
				"free-text matching is unavailable; retry with a structured capabilities hint"), trace, nil
		}
		mres = lres
	}
	trace.recordMatch(mres)

	// Step 4: confidence gate (section 5.5).
	dec, err := s.gate.Decide(req.AgentID, mres, req.Hints, snap)
	if err != nil {
		return synth.Result{}, trace, err
	}
	trace.ApprovalReasons = dec.ApprovalReasons
	trace.FirstUseCapabilities = dec.FirstUse
	switch dec.Outcome {
	case match.GateDeny:
		return s.deny(dec.DenialCode, hashes, &trace, dec.ApprovalReasons...), trace, nil
	case match.GateClarify:
		res := s.clarify(req.AgentID, req.GrantID, intentHash, round, clarifyPayload{
			code:          dec.ClarifyCode,
			questions:     dec.Questions,
			missingParams: dec.MissingParams,
			candidates:    dec.Candidates,
		}, hashes, &trace)
		return res, trace, nil
	case match.GateProceed, match.GatePendingApproval:
		// continue below
	default:
		return synth.Result{}, trace, fmt.Errorf("synthesizer: unknown gate outcome %q", dec.Outcome)
	}

	// Step 5: param resolution. The gate already merged extracted and
	// hinted params (hinted wins). Full grammar and allowlist
	// validation applies to every param regardless of origin.
	var perrs []ParamError
	for _, sel := range dec.Selected {
		perrs = append(perrs, s.params.ValidateParams(sel.Capability.ID, sel.Params)...)
	}
	if len(perrs) > 0 {
		res := s.clarify(req.AgentID, req.GrantID, intentHash, round, invalidParamPayload(dec.Selected, perrs), hashes, &trace)
		return res, trace, nil
	}

	// Step 6 and 8: compile under the reduction ladder.
	selected := make([]SelectedCapability, 0, len(dec.Selected))
	refs := make([]synth.CapabilityRef, 0, len(dec.Selected))
	for _, sel := range dec.Selected {
		selected = append(selected, SelectedCapability{
			ID:      sel.Capability.ID,
			Version: sel.Capability.Version,
			Params:  sel.Params,
		})
		refs = append(refs, synth.CapabilityRef{ID: sel.Capability.ID, Version: sel.Capability.Version})
	}
	cres, fits, attribution, err := s.compileLadder(ctx, selected, budget)
	if err != nil {
		return synth.Result{}, trace, err
	}
	if !fits {
		trace.DenialDetail = attribution
		return s.deny(domain.DenyOverBudget, hashes, &trace, attribution...), trace, nil
	}

	// Step 7: guardrails at compile time; hard failures fail closed.
	verdicts, err := s.guardrails.Evaluate(ctx, cres.PolicyJSON, GuardrailMeta{
		AgentID:         req.AgentID,
		Profile:         req.Profile,
		Capabilities:    refs,
		ExpandedActions: cres.ExpandedActions,
	})
	if err != nil {
		return synth.Result{}, trace, fmt.Errorf("synthesizer: guardrail evaluation failed closed: %w", err)
	}
	trace.Guardrails = verdicts
	if fails := guardrailFailures(verdicts); len(fails) > 0 {
		trace.DenialDetail = fails
		return s.deny(domain.DenyGuardrailViolation, hashes, &trace, fails...), trace, nil
	}

	verdict := synth.VerdictPolicy
	if dec.Outcome == match.GatePendingApproval {
		verdict = synth.VerdictPendingApproval
	}
	result := synth.Result{
		Verdict:           verdict,
		PolicyJSON:        cres.PolicyJSON,
		PolicyArns:        cres.PolicyArns,
		EffectiveDuration: s.effectiveDuration(req, dec.Selected),
		Explanation:       cres.Explanation,
		Capabilities:      refs,
		ExpandedActions:   cres.ExpandedActions,
		CatalogHash:       hashes.catalog,
		DatasetHash:       hashes.dataset,
		ConfigHash:        hashes.config,
	}

	// Step 9 side effect: cache the compilation for replay.
	if s.cache != nil {
		s.cache.Put(key, CachedDecision{
			PolicyJSON:        result.PolicyJSON,
			PolicyArns:        result.PolicyArns,
			EffectiveDuration: result.EffectiveDuration,
			Explanation:       result.Explanation,
			Capabilities:      result.Capabilities,
			ExpandedActions:   result.ExpandedActions,
		})
	}
	return result, trace, nil
}

// Compact implements synth.Synthesizer: a deterministic re-render of
// the SAME capability selection under a tighter budget. It never
// re-matches and never consults the classifier; the selection and its
// validated params are reconstructed from the previous result's
// explanation (section 7.3).
func (s *Synthesizer) Compact(ctx context.Context, prev synth.Result, maxChars int) (synth.Result, error) {
	if prev.Verdict != synth.VerdictPolicy && prev.Verdict != synth.VerdictPendingApproval {
		return synth.Result{}, fmt.Errorf("synthesizer: Compact requires a policy-bearing result, got verdict %q", prev.Verdict)
	}
	if maxChars <= 0 {
		return synth.Result{}, fmt.Errorf("synthesizer: Compact requires a positive budget, got %d", maxChars)
	}
	if len(prev.Capabilities) == 0 {
		return synth.Result{}, fmt.Errorf("synthesizer: Compact requires a capability selection")
	}

	params, err := paramsFromExplanation(prev)
	if err != nil {
		return synth.Result{}, err
	}
	selected := make([]SelectedCapability, 0, len(prev.Capabilities))
	for _, ref := range prev.Capabilities {
		p := params[ref.ID]
		if p == nil {
			// A capability whose statements were fully offloaded to a
			// managed policy has no inline explanation and needs no
			// params.
			p = map[string]string{}
		}
		if perrs := s.params.ValidateParams(ref.ID, p); len(perrs) > 0 {
			return synth.Result{}, fmt.Errorf(
				"synthesizer: Compact re-validation failed for capability %s: %d param violations", ref.ID, len(perrs))
		}
		selected = append(selected, SelectedCapability{ID: ref.ID, Version: ref.Version, Params: p})
	}

	hashes := resultHashes{catalog: prev.CatalogHash, dataset: prev.DatasetHash, config: prev.ConfigHash}
	cres, fits, _, err := s.compileLadder(ctx, selected, maxChars)
	if err != nil {
		return synth.Result{}, err
	}
	if !fits {
		return synth.Result{
			Verdict:     synth.VerdictDeny,
			DenialCode:  domain.DenyPolicyTooLarge.String(),
			CatalogHash: hashes.catalog,
			DatasetHash: hashes.dataset,
			ConfigHash:  hashes.config,
		}, nil
	}

	verdicts, err := s.guardrails.Evaluate(ctx, cres.PolicyJSON, GuardrailMeta{
		Capabilities:    prev.Capabilities,
		ExpandedActions: cres.ExpandedActions,
	})
	if err != nil {
		return synth.Result{}, fmt.Errorf("synthesizer: Compact guardrail evaluation failed closed: %w", err)
	}
	if fails := guardrailFailures(verdicts); len(fails) > 0 {
		return synth.Result{
			Verdict:     synth.VerdictDeny,
			DenialCode:  domain.DenyGuardrailViolation.String(),
			CatalogHash: hashes.catalog,
			DatasetHash: hashes.dataset,
			ConfigHash:  hashes.config,
		}, nil
	}

	return synth.Result{
		Verdict:           synth.VerdictPolicy,
		PolicyJSON:        cres.PolicyJSON,
		PolicyArns:        cres.PolicyArns,
		EffectiveDuration: prev.EffectiveDuration,
		Explanation:       cres.Explanation,
		Capabilities:      append([]synth.CapabilityRef(nil), prev.Capabilities...),
		ExpandedActions:   cres.ExpandedActions,
		CatalogHash:       hashes.catalog,
		DatasetHash:       hashes.dataset,
		ConfigHash:        hashes.config,
	}, nil
}

// paramsFromExplanation reconstructs the validated per-capability
// params from an index-parallel explanation. Conflicting values for
// the same param are a malformed input.
func paramsFromExplanation(prev synth.Result) (map[string]map[string]string, error) {
	params := map[string]map[string]string{}
	for _, st := range prev.Explanation.Statements {
		m := params[st.CapabilityID]
		if m == nil {
			m = map[string]string{}
			params[st.CapabilityID] = m
		}
		for k, v := range st.Params {
			if existing, ok := m[k]; ok && existing != v {
				return nil, fmt.Errorf(
					"synthesizer: Compact input is malformed: capability %s param %s has conflicting values", st.CapabilityID, k)
			}
			m[k] = v
		}
	}
	return params, nil
}

// compileLadder runs section 7.3 in order: (1) minify and (2) merge
// always happen inside the compiler, then (3) drop optional Sids,
// then (4) offload managed-policy capabilities to PolicyArns. There
// is no wildcard-coalescing step (invariant I2). It returns the last
// compilation, whether it fits, and OVER_BUDGET attribution lines
// when it does not.
func (s *Synthesizer) compileLadder(ctx context.Context, selected []SelectedCapability, budget int) (CompileResult, bool, []string, error) {
	attempts := []CompileOptions{
		{},
		{DropSids: true},
		{DropSids: true, OffloadManaged: true},
	}
	var last CompileResult
	for _, opt := range attempts {
		cres, err := s.compiler.Compile(ctx, CompileInput{Capabilities: selected, MaxChars: budget, Options: opt})
		if err != nil {
			return CompileResult{}, false, nil, fmt.Errorf("synthesizer: compile: %w", err)
		}
		if len(cres.PolicyJSON) <= budget {
			return cres, true, nil, nil
		}
		last = cres
	}
	return last, false, overBudgetAttribution(last, budget), nil
}

// overBudgetAttribution renders per-capability byte attribution, for
// example "s3.read-prefix: 412 chars, over by 203", so the agent can
// split the task intelligently (ladder step 5).
func overBudgetAttribution(cres CompileResult, budget int) []string {
	over := len(cres.PolicyJSON) - budget
	type entry struct {
		id    string
		chars int
	}
	entries := make([]entry, 0, len(cres.PerCapabilityChars))
	for id, chars := range cres.PerCapabilityChars {
		entries = append(entries, entry{id, chars})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].chars != entries[j].chars {
			return entries[i].chars > entries[j].chars
		}
		return entries[i].id < entries[j].id
	})
	lines := make([]string, 0, len(entries)+1)
	lines = append(lines, fmt.Sprintf("policy is %d chars, budget %d, over by %d", len(cres.PolicyJSON), budget, over))
	for _, e := range entries {
		lines = append(lines, fmt.Sprintf("%s: %d chars, over by %d", e.id, e.chars, over))
	}
	return lines
}

// effectiveDuration computes min(requested, capability caps, profile
// cap) with the 900 second floor and default. The broker's G7 clamp
// runs on top of this.
func (s *Synthesizer) effectiveDuration(req synth.Request, selected []match.Selected) time.Duration {
	eff := req.Hints.DurationSeconds
	if eff <= 0 {
		eff = s.defaultDuration
	}
	for _, sel := range selected {
		if c := sel.Capability.MaxDurationSeconds; c > 0 && c < eff {
			eff = c
		}
	}
	if c := req.Profile.MaxDurationSeconds; c > 0 && c < eff {
		eff = c
	}
	if eff < MinDurationSeconds {
		eff = MinDurationSeconds
	}
	return time.Duration(eff) * time.Second
}

// replay adapts a cached decision to a new grant. Approval
// requirements (requires_approval, first use) are re-derived against
// the current snapshot and ledger; when the cached capability set no
// longer resolves, replay reports false and the full pipeline runs.
func (s *Synthesizer) replay(agentID string, snap match.Snapshot, cached CachedDecision, hashes resultHashes, trace *Trace) (synth.Result, bool) {
	verdict := synth.VerdictPolicy
	for _, ref := range cached.Capabilities {
		capability, ok := snap.Lookup(ref.ID)
		if !ok || capability.Version != ref.Version {
			return synth.Result{}, false
		}
		if capability.RequiresApproval {
			verdict = synth.VerdictPendingApproval
			trace.ApprovalReasons = append(trace.ApprovalReasons,
				fmt.Sprintf("capability %s requires approval", ref.ID))
		}
		if s.firstUseApproval {
			fu, err := s.firstUse(agentID, ref.ID)
			if err != nil {
				fu = true
				trace.ApprovalReasons = append(trace.ApprovalReasons,
					fmt.Sprintf("first-use check for capability %s failed, failing closed to approval: %v", ref.ID, err))
			}
			if fu {
				verdict = synth.VerdictPendingApproval
				trace.FirstUseCapabilities = append(trace.FirstUseCapabilities, ref.ID)
				trace.ApprovalReasons = append(trace.ApprovalReasons,
					fmt.Sprintf("first use of capability %s by agent %s", ref.ID, agentID))
			}
		}
	}
	return synth.Result{
		Verdict:           verdict,
		PolicyJSON:        cached.PolicyJSON,
		PolicyArns:        cached.PolicyArns,
		EffectiveDuration: cached.EffectiveDuration,
		Explanation:       cached.Explanation,
		Capabilities:      cached.Capabilities,
		ExpandedActions:   cached.ExpandedActions,
		CatalogHash:       hashes.catalog,
		DatasetHash:       hashes.dataset,
		ConfigHash:        hashes.config,
	}, true
}

// resultHashes bundles the three input hashes stamped on every result.
type resultHashes struct {
	catalog, dataset, config string
}

// deny builds a denial result. Detail lines land in the trace, which
// the broker renders (template text only, sanitized on display).
func (s *Synthesizer) deny(code domain.DenialCode, hashes resultHashes, trace *Trace, detail ...string) synth.Result {
	if len(detail) > 0 {
		trace.DenialDetail = append(trace.DenialDetail, detail...)
	}
	return synth.Result{
		Verdict:     synth.VerdictDeny,
		DenialCode:  code.String(),
		CatalogHash: hashes.catalog,
		DatasetHash: hashes.dataset,
		ConfigHash:  hashes.config,
	}
}

// clarifyPayload is the material of one clarification round.
type clarifyPayload struct {
	code          domain.DenialCode
	questions     []string
	missingParams []synth.MissingParam
	candidates    []synth.CandidateCapability
}

// invalidParamPayload converts validator errors into a clarification
// payload with code INVALID_PARAM. Reasons are folded into the
// expected-shape text; sanitized for display defensively even though
// the validator contract forbids echoing raw agent bytes.
func invalidParamPayload(selected []match.Selected, perrs []ParamError) clarifyPayload {
	p := clarifyPayload{code: domain.DenyInvalidParam}
	names := make([]string, 0, len(perrs))
	for _, e := range perrs {
		shape := e.ExpectedShape
		if e.Reason != "" {
			reason := domain.SanitizeForDisplay(e.Reason)
			if len(reason) > 256 {
				reason = reason[:256]
			}
			if shape == "" {
				shape = reason
			} else {
				shape = reason + "; expected " + shape
			}
		}
		p.missingParams = append(p.missingParams, synth.MissingParam{
			Capability:    e.Capability,
			Name:          e.Name,
			ExpectedShape: shape,
			Examples:      append([]string(nil), e.Examples...),
		})
		names = append(names, e.Capability+"."+e.Name)
	}
	sort.SliceStable(p.missingParams, func(i, j int) bool {
		if p.missingParams[i].Capability != p.missingParams[j].Capability {
			return p.missingParams[i].Capability < p.missingParams[j].Capability
		}
		return p.missingParams[i].Name < p.missingParams[j].Name
	})
	sort.Strings(names)
	for _, sel := range selected {
		p.candidates = append(p.candidates, synth.CandidateCapability{
			ID:      sel.Capability.ID,
			Summary: sel.Capability.Summary,
		})
	}
	p.questions = []string{
		fmt.Sprintf("Correct the invalid params: %s.", strings.Join(names, ", ")),
		"Retry with a structured capabilities hint carrying corrected values.",
	}
	return p
}

// clarify builds a needs_clarification result with a signed retry
// token, or CLARIFICATION_EXHAUSTED after MaxClarificationRounds. The
// token is bound to agentID so only the issuing agent can present it
// (section 4.1).
func (s *Synthesizer) clarify(agentID, grantID, intentHash string, priorRound int, p clarifyPayload, hashes resultHashes, trace *Trace) synth.Result {
	next := priorRound + 1
	if next > MaxClarificationRounds {
		return s.deny(domain.DenyClarificationExhausted, hashes, trace,
			fmt.Sprintf("clarification limit of %d rounds reached", MaxClarificationRounds))
	}
	token := signRetryToken(s.tokenKey, retryTokenPayload{
		GrantID:    grantID,
		AgentID:    agentID,
		IntentHash: intentHash,
		Round:      next,
	})
	return synth.Result{
		Verdict: synth.VerdictNeedsClarification,
		Clarification: &synth.Clarification{
			Code:          p.code.String(),
			Questions:     p.questions,
			MissingParams: p.missingParams,
			Candidates:    p.candidates,
			RetryToken:    token,
			Round:         next,
		},
		CatalogHash: hashes.catalog,
		DatasetHash: hashes.dataset,
		ConfigHash:  hashes.config,
	}
}

// guardrailFailures collects hard-failure detail lines.
func guardrailFailures(verdicts []GuardrailVerdict) []string {
	var fails []string
	for _, v := range verdicts {
		if v.Result == GuardrailFail {
			fails = append(fails, fmt.Sprintf("%s: %s", v.Check, v.Detail))
		}
	}
	return fails
}

// recordMatch copies matcher fields into the trace.
func (t *Trace) recordMatch(res match.MatchResult) {
	t.Matcher = res.Matcher
	t.Structured = res.Structured
	t.Candidates = res.Candidates
	t.ModelID = res.ModelID
	t.PromptTemplateHash = res.PromptTemplateHash
	t.Notes = append(t.Notes, res.Notes...)
}
