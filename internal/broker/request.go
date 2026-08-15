package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/guardrails"
	"github.com/0hardik1/taskgrant/internal/mcpserver"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/synthesizer"
)

// RequestGrant runs one request_grant call end to end (section 5.4
// steps 1..9 and 11), blocking up to req.WaitSeconds for a human
// approval when asked to.
func (b *Broker) RequestGrant(ctx context.Context, agentID string, req mcpserver.GrantRequest) (*mcpserver.GrantView, error) {
	now := b.now()

	// Resolve the grant identity first: a clarification retry attaches
	// to its original grant ULID (section 5.6); everything else mints a
	// fresh ULID at receipt that never changes afterward.
	grantID := ""
	isRetry := req.RetryToken != ""
	if isRetry {
		id, round, ok := peekRetryToken(req.RetryToken)
		if !ok {
			return &mcpserver.GrantView{
				Status:    "error",
				ErrorCode: mcpserver.CodeInvalidArgument,
				Detail:    "retry_token: malformed",
			}, nil
		}
		grantID = id

		// Retry ownership and state gate. This runs BEFORE any
		// synthesize or mint work and reads durable grant state
		// (invariant I5) so it holds across a broker restart.
		owner, openRound, open, found := b.retryTarget(ctx, grantID)
		if !found || owner != agentID {
			// Section 4.1: a retry token whose grant does not exist, or
			// belongs to another agent, gets the same sanitized NOT_FOUND
			// as a cross-agent get_grant. Existence is never confirmed and
			// "wrong agent" is never distinguished from "no such grant".
			// No synthesize, no mint: this closes the cross-agent
			// credential-isolation hole (trust model section 3).
			return nil, errNotFound
		}
		if !open || round != openRound {
			// Section 5.6: a retry resolves a grant only while it sits in
			// an OPEN clarification round matching the token. A resolved or
			// terminal grant (auto_approved, minted, active, denied,
			// exhausted, expired_pending), or a token for a round already
			// consumed or superseded, cannot reopen the negotiation. Deny
			// cleanly with no mint; nothing is persisted here, so an
			// already-resolved grant keeps its true state and its single
			// mint.
			b.incOutcome("denied")
			return &mcpserver.GrantView{
				GrantID:    grantID,
				Status:     "denied",
				DenialCode: domain.DenyClarificationExhausted,
				Detail:     "this clarification round is closed; a retry token cannot reopen a resolved grant",
			}, nil
		}
	} else {
		grantID = domain.NewGrantID()
	}

	// Boundary checks: agent and profile (received -> denied edges).
	profileName, profileCfg, denyCode, denyDetail := b.resolveProfile(agentID, req.Profile)
	if denyCode != "" {
		e := b.newEntry(grantID, agentID, req.Profile, req, now)
		return b.denyEntry(ctx, e, denyCode, "broker", denyDetail), nil
	}

	// Idempotency-key replay: a repeated key inside its window returns
	// the existing grant's current state, no re-mint. Retries carry
	// their own grant identity and skip the key path.
	if req.IdempotencyKey != "" && !isRetry {
		stored, created, err := b.log.PutIdempotencyKey(ctx, agentID, req.IdempotencyKey,
			grantID, now, now.Add(IdempotencyWindow))
		if err != nil {
			b.logger.Error("broker: idempotency key store failed", "agent", agentID, "err", err)
			return &mcpserver.GrantView{
				GrantID: grantID, Status: "error",
				ErrorCode: mcpserver.CodeInternal,
				Detail:    "internal error; the incident is logged",
			}, nil
		}
		if !created && stored != grantID {
			view, err := b.GetGrant(ctx, agentID, stored)
			if err == nil {
				return view, nil
			}
			b.logger.Warn("broker: idempotency replay target missing; processing fresh",
				"agent", agentID, "stored_grant", stored)
		}
	}

	// Retry continuation: reuse the original entry when we still have
	// it, so the state chain stays on one grant.
	var e *grantEntry
	if isRetry {
		if prev, ok := b.entry(grantID); ok && prev.grant.AgentID == agentID &&
			prev.grant.State == domain.StateNeedsClarification {
			e = prev
			b.mu.Lock()
			e.req = req
			e.req.Transport = req.Transport
			b.setStateLocked(e, domain.StateSynthesized)
			// Re-enter the pipeline: synthesized -> guardrails happens
			// below after the new synthesis run.
			e.grant.State = domain.StateReceived
			b.mu.Unlock()
		}
	}
	if e == nil {
		e = b.newEntry(grantID, agentID, profileName, req, now)
	}
	e.grant.Profile = profileName

	// Synthesize through the seam (step 3..8 live behind it).
	sreq := synth.Request{
		GrantID: grantID,
		AgentID: agentID,
		Profile: synth.ProfileInfo{
			Name:               profileName,
			RoleARN:            profileCfg.RoleARN,
			Region:             b.cfg.ProfileRegion(profileName),
			MaxDurationSeconds: b.cfg.EffectiveMaxDurationSeconds(profileName),
			PolicyARNs:         profileCfg.PolicyARNs,
		},
		Task:           req.Task,
		Reason:         req.Reason,
		Hints:          synth.Hints{Capabilities: req.Capabilities, Services: req.Services, Resources: req.Resources, Access: req.Access, DurationSeconds: req.DurationSeconds},
		RetryToken:     req.RetryToken,
		MaxPolicyChars: PolicyBudgetChars,
	}

	var (
		res   synth.Result
		trace *synthesizer.Trace
		err   error
	)
	if ts, ok := b.synth.(TracedSynthesizer); ok {
		var t synthesizer.Trace
		res, t, err = ts.SynthesizeTraced(ctx, sreq)
		trace = &t
	} else {
		res, err = b.synth.Synthesize(ctx, sreq)
	}
	if err != nil {
		if errors.Is(err, synthesizer.ErrInvalidRetryToken) {
			return &mcpserver.GrantView{
				GrantID: grantID, Status: "error",
				ErrorCode: mcpserver.CodeInvalidArgument,
				Detail:    "retry_token: invalid or expired",
			}, nil
		}
		b.logger.Error("broker: synthesis failed", "grant_id", grantID, "err", err)
		b.recordError(ctx, e, "synthesizer")
		return &mcpserver.GrantView{
			GrantID: grantID, Status: "error",
			ErrorCode: mcpserver.CodeInternal,
			Detail:    "internal error; the incident is logged",
		}, nil
	}

	b.mu.Lock()
	b.setStateLocked(e, domain.StateSynthesized)
	e.result = res
	e.trace = trace
	b.mu.Unlock()

	switch res.Verdict {
	case synth.VerdictDeny:
		return b.denySynth(ctx, e, res, trace), nil
	case synth.VerdictNeedsClarification:
		return b.clarify(ctx, e, res, trace), nil
	case synth.VerdictPolicy, synth.VerdictPendingApproval:
		return b.verifyAndDecide(ctx, e, res, trace, profileCfg, req.WaitSeconds)
	default:
		b.logger.Error("broker: unknown synthesizer verdict", "grant_id", grantID, "verdict", string(res.Verdict))
		b.recordError(ctx, e, "synthesizer")
		return &mcpserver.GrantView{
			GrantID: grantID, Status: "error",
			ErrorCode: mcpserver.CodeInternal,
			Detail:    "internal error; the incident is logged",
		}, nil
	}
}

// newEntry registers a fresh grant entry in state received.
func (b *Broker) newEntry(grantID, agentID, profile string, req mcpserver.GrantRequest, now time.Time) *grantEntry {
	e := &grantEntry{
		grant: domain.Grant{
			GrantID:        grantID,
			AgentID:        agentID,
			Profile:        profile,
			State:          domain.StateReceived,
			IdempotencyKey: req.IdempotencyKey,
			ReceivedAt:     now,
		},
		req: req,
	}
	b.putEntry(e)
	return e
}

// peekRetryToken reads the grant ULID and round out of a retry token
// payload without verifying the signature; the synthesizer verifies the
// HMAC and the agent binding authoritatively. The broker uses the peeked
// grant id and round only to route the retry to its grant and to gate on
// the grant's current open round; a forged round simply fails the gate
// (round mismatch) or the synthesizer (bad HMAC). Only a well-formed ULID
// is accepted here.
func peekRetryToken(token string) (grantID string, round int, ok bool) {
	if len(token) > 1024 {
		return "", 0, false
	}
	body64, _, cut := strings.Cut(token, ".")
	if !cut {
		return "", 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body64)
	if err != nil {
		return "", 0, false
	}
	var p struct {
		GrantID string `json:"g"`
		Round   int    `json:"r"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", 0, false
	}
	if _, err := domain.ParseGrantID(p.GrantID); err != nil {
		return "", 0, false
	}
	return p.GrantID, p.Round, true
}

// retryTarget resolves the owning agent and the current open
// clarification round of the grant a retry token points at. The live
// in-memory entry wins when present; otherwise the durable decision log
// is reconstructed (invariant I5), so the ownership and single-use gate
// survives a broker restart. found is false when no such grant exists.
func (b *Broker) retryTarget(ctx context.Context, grantID string) (owner string, openRound int, open, found bool) {
	b.mu.Lock()
	e, ok := b.grants[grantID]
	if ok {
		owner = e.grant.AgentID
		open = e.grant.State == domain.StateNeedsClarification
		if open && e.result.Clarification != nil {
			openRound = e.result.Clarification.Round
		}
	}
	b.mu.Unlock()
	if ok {
		return owner, openRound, open, true
	}

	recs, err := b.log.GrantChain(ctx, grantID)
	if err != nil || len(recs) == 0 {
		return "", 0, false, false
	}
	open, openRound = openClarificationRound(recs)
	return recs[0].AgentID, openRound, open, true
}

// openClarificationRound reports whether the persisted grant chain ends
// in an open clarification round and, if so, its round number. Records
// arrive in chain (seq) order, so the last state-bearing record wins: a
// grant_decision or approval record moves the grant off
// needs_clarification and closes the negotiation.
func openClarificationRound(recs []store.Record) (open bool, round int) {
	for _, rec := range recs {
		switch rec.Kind {
		case domain.RecordClarification:
			open = true
			var body decisionBody
			if err := json.Unmarshal(rec.Body, &body); err == nil && body.Clar != nil {
				round = body.Clar.Round
			}
		case domain.RecordGrantDecision, domain.RecordApproval:
			open = false
			round = 0
		}
	}
	return open, round
}

// denyEntry finalizes a denial from any pipeline stage and appends the
// decision record.
func (b *Broker) denyEntry(ctx context.Context, e *grantEntry, code domain.DenialCode, deniedBy, detail string, denialDetail ...string) *mcpserver.GrantView {
	now := b.now()
	b.mu.Lock()
	e.grant.DecidedAt = now
	e.denial = code
	e.detail = detail
	// Walk to denied through whatever legal edge applies.
	switch e.grant.State {
	case domain.StateReceived, domain.StateSynthesized, domain.StateGuardrails,
		domain.StateAutoApproved, domain.StateApproved, domain.StatePendingApproval,
		domain.StateNeedsClarification:
		b.setStateLocked(e, domain.StateDenied)
	}
	e.markTerminal(now)
	b.mu.Unlock()

	body := b.baseBody(e, domain.RecordGrantDecision, domain.NewGrantID())
	fillSynthesis(&body, e.result, e.trace)
	fillGuardrails(&body, e.guard)
	body.MaxPolicyChars = e.budget()
	body.Outcome = "denied"
	body.DeniedBy = deniedBy
	body.DenialCode = code.String()
	if detail != "" {
		body.DenialDetail = append(body.DenialDetail, detail)
	}
	body.DenialDetail = append(body.DenialDetail, denialDetail...)
	_ = b.appendRecord(ctx, e, domain.RecordGrantDecision, body)
	b.incOutcome("denied")

	return b.buildView(e)
}

// denySynth handles a seam denial verdict.
func (b *Broker) denySynth(ctx context.Context, e *grantEntry, res synth.Result, trace *synthesizer.Trace) *mcpserver.GrantView {
	code := domain.DenialCode(res.DenialCode)
	if !code.Valid() {
		code = domain.DenyNoMatch
	}
	detail := denialDetailText(code, trace)
	return b.denyEntry(ctx, e, code, "synthesizer", detail)
}

// denialDetailText renders agent-facing denial detail from template
// material only (trace detail lines are template-rendered upstream).
func denialDetailText(code domain.DenialCode, trace *synthesizer.Trace) string {
	if trace != nil && len(trace.DenialDetail) > 0 {
		return strings.Join(trace.DenialDetail, "; ")
	}
	switch code {
	case domain.DenyNoMatch:
		return "no capability matched the declared task; call list_capabilities and retry with a structured hint"
	case domain.DenyNeedsStructuredHints:
		return "free-text matching is unavailable; call list_capabilities and retry with a structured capabilities hint"
	case domain.DenyClarificationExhausted:
		return "the clarification round limit was reached"
	}
	return ""
}

// clarify records one clarification round and returns the structured
// payload (section 5.6). The full exchange is one linked chain in the
// log.
func (b *Broker) clarify(ctx context.Context, e *grantEntry, res synth.Result, trace *synthesizer.Trace) *mcpserver.GrantView {
	now := b.now()
	b.mu.Lock()
	b.setStateLocked(e, domain.StateNeedsClarification)
	e.grant.DecidedAt = now
	b.mu.Unlock()

	body := b.baseBody(e, domain.RecordClarification, domain.NewGrantID())
	fillSynthesis(&body, res, trace)
	body.Outcome = "needs_clarification"
	if c := res.Clarification; c != nil {
		cb := &clarificationBody{
			Code:            c.Code,
			Round:           c.Round,
			Questions:       c.Questions,
			RetryTokenSHA:   sha8(c.RetryToken),
			ExhaustionLimit: synthesizer.MaxClarificationRounds,
		}
		for _, mp := range c.MissingParams {
			cb.MissingParams = append(cb.MissingParams, mp.Capability+"."+mp.Name)
		}
		for _, cand := range c.Candidates {
			cb.Candidates = append(cb.Candidates, cand.ID)
		}
		if trace != nil {
			cb.IntentHash = trace.IntentHash
		}
		body.Clar = cb
	}
	_ = b.appendRecord(ctx, e, domain.RecordClarification, body)
	b.incOutcome("needs_clarification")
	return b.buildView(e)
}

// recordError appends an error-outcome record.
func (b *Broker) recordError(ctx context.Context, e *grantEntry, deniedBy string) {
	b.mu.Lock()
	e.errorCode = mcpserver.CodeInternal
	e.grant.DecidedAt = b.now()
	e.markTerminal(b.now())
	b.mu.Unlock()
	body := b.baseBody(e, domain.RecordGrantDecision, domain.NewGrantID())
	body.Outcome = "error"
	body.DeniedBy = deniedBy
	_ = b.appendRecord(ctx, e, domain.RecordGrantDecision, body)
	b.incOutcome("error")
}

// verifyAndDecide is the authoritative broker half of the pipeline:
// guardrail re-verification of the concrete policy (anchor rule 2),
// approval routing (config rules, first-use, needs_approval verdicts),
// and the auto-approve mint.
func (b *Broker) verifyAndDecide(ctx context.Context, e *grantEntry, res synth.Result, trace *synthesizer.Trace, profileCfg profileConfig, waitSeconds int) (*mcpserver.GrantView, error) {
	b.mu.Lock()
	b.setStateLocked(e, domain.StateGuardrails)
	b.mu.Unlock()

	if len(res.PolicyJSON) == 0 {
		return b.denyEntry(ctx, e, domain.DenyGuardrailViolation, "guardrail:G0.structure",
			"the synthesizer returned an empty inline policy"), nil
	}

	meta, wildcardResource := b.capabilityMeta(res)
	ginput := guardrails.Input{
		PolicyJSON:                res.PolicyJSON,
		AgentID:                   e.grant.AgentID,
		Profile:                   e.grant.Profile,
		RequestedDurationSeconds:  int(res.EffectiveDuration / time.Second),
		ProfileMaxDurationSeconds: profileCfg.MaxDurationSeconds,
		Capabilities:              meta,
		RequireResourceAccount:    wildcardResource,
		BrokerChained:             b.chained,
		State:                     stateAdapter{log: b.log, clock: b.clock},
	}
	gres := b.evaluator.Evaluate(ctx, ginput)

	b.mu.Lock()
	e.guard = &gres
	e.effectiveSeconds = gres.EffectiveDurationSeconds
	b.mu.Unlock()

	if gres.Overall == guardrails.Fail {
		code := domain.DenyGuardrailViolation
		deniedBy := "guardrail"
		var details []string
		for _, c := range gres.FailedChecks() {
			if deniedBy == "guardrail" {
				deniedBy = "guardrail:" + c.Name
			}
			if c.Name == guardrails.CheckRateLimit {
				code = domain.DenyRateLimited
			}
			details = append(details, c.Name+": "+c.Detail)
		}
		return b.denyEntry(ctx, e, code, deniedBy, strings.Join(details, "; ")), nil
	}

	// G8 cross-check (anchor rule 2): the rate, creep, and count
	// controls key on the seam-reported capability ids, so the policy's
	// authoritative expansion must stay inside the union of those
	// capabilities' catalog actions. A seam that under-reports its
	// selection while emitting a broader policy is denied here rather
	// than allowed to dodge the durable G8 ledgers.
	if declared, ok := b.declaredActionSet(res.Capabilities); ok {
		if extra := uncoveredActions(declared, gres.ExpandedActions); len(extra) > 0 {
			const maxNamed = 8
			if len(extra) > maxNamed {
				extra = append(extra[:maxNamed:maxNamed], fmt.Sprintf("and %d more", len(extra)-maxNamed))
			}
			return b.denyEntry(ctx, e, domain.DenyGuardrailViolation, "broker:capability-coverage",
				"policy grants actions outside the declared capability set: "+strings.Join(extra, ", ")), nil
		}
	}

	// Approval routing (section 11): the seam verdict (requires_approval
	// or first-use), a guardrail needs_approval verdict, or a config
	// approval rule all park the grant.
	requiredBy := ""
	if res.Verdict == synth.VerdictPendingApproval {
		requiredBy = "first_use"
		if trace != nil && len(trace.FirstUseCapabilities) == 0 {
			requiredBy = "capability_rule"
		}
	}
	if requiredBy == "" && gres.Overall == guardrails.NeedsApproval {
		for _, c := range gres.Checks {
			if c.Verdict == guardrails.NeedsApproval {
				requiredBy = "guardrail:" + c.Name
				break
			}
		}
	}
	if requiredBy == "" {
		if idx, required := b.approvalRuleRequired(e.grant.AgentID, e.grant.Profile, res); required {
			requiredBy = ruleName(idx)
		}
	}

	if requiredBy != "" {
		return b.parkForApproval(ctx, e, res, trace, requiredBy, waitSeconds)
	}
	return b.autoApprove(ctx, e)
}

// profileConfig is the subset of config.ProfileConfig the pipeline
// threads through (aliased so tests can build it directly).
type profileConfig = configProfile

// parkForApproval parks a grant durably and optionally blocks for the
// decision.
func (b *Broker) parkForApproval(ctx context.Context, e *grantEntry, res synth.Result, trace *synthesizer.Trace, requiredBy string, waitSeconds int) (*mcpserver.GrantView, error) {
	now := b.now()
	capIDs := make([]string, 0, len(res.Capabilities))
	for _, ref := range res.Capabilities {
		capIDs = append(capIDs, ref.ID)
	}
	pending := store.PendingApproval{
		GrantID:      e.grant.GrantID,
		AgentID:      e.grant.AgentID,
		Profile:      e.grant.Profile,
		Task:         e.req.Task,
		Reason:       e.req.Reason,
		PolicyJSON:   string(res.PolicyJSON),
		Capabilities: capIDs,
		RequiredBy:   requiredBy,
		ReceivedAt:   now,
	}
	if _, err := b.approvals.Submit(ctx, pending); err != nil {
		b.logger.Error("broker: approval submit failed", "grant_id", e.grant.GrantID, "err", err)
		b.recordError(ctx, e, "broker")
		return &mcpserver.GrantView{
			GrantID: e.grant.GrantID, Status: "error",
			ErrorCode: mcpserver.CodeInternal,
			Detail:    "internal error; the incident is logged",
		}, nil
	}

	b.mu.Lock()
	b.setStateLocked(e, domain.StatePendingApproval)
	e.grant.DecidedAt = now
	e.requiredBy = requiredBy
	e.mintDone = make(chan struct{})
	b.mu.Unlock()

	body := b.baseBody(e, domain.RecordGrantDecision, domain.NewGrantID())
	fillSynthesis(&body, res, trace)
	fillGuardrails(&body, e.guard)
	body.MaxPolicyChars = e.budget()
	body.Outcome = "pending_approval"
	body.GrantedDurationSeconds = e.effectiveSeconds
	body.Approval = &approvalBody{RequiredBy: requiredBy}
	_ = b.appendRecord(ctx, e, domain.RecordGrantDecision, body)
	b.incOutcome("pending_approval")

	if waitSeconds > 0 {
		return b.waitForDecision(ctx, e, waitSeconds), nil
	}
	return b.buildView(e), nil
}

// waitForDecision blocks up to waitSeconds for the human decision
// (section 11 step 2), then hands back the resulting view: credentials
// when approved and minted, a denial, or the pending poll hint on
// timeout.
func (b *Broker) waitForDecision(ctx context.Context, e *grantEntry, waitSeconds int) *mcpserver.GrantView {
	wctx, cancel := context.WithTimeout(ctx, time.Duration(waitSeconds)*time.Second)
	defer cancel()

	d, err := b.approvals.WaitDecision(wctx, e.grant.GrantID)
	if err != nil {
		// Timeout or context end: still pending, return the poll hint.
		return b.buildView(e)
	}
	switch d.Status {
	case store.StatusApproved:
		// The mint runs in the approver's goroutine; wait for it.
		b.mu.Lock()
		done := e.mintDone
		b.mu.Unlock()
		if done != nil {
			select {
			case <-done:
			case <-time.After(mintWaitCeiling):
			case <-ctx.Done():
			}
		}
		return b.viewWithDelivery(e)
	case store.StatusDenied:
		return b.buildView(e)
	case store.StatusExpiredPending:
		b.finalizeExpiredPending(ctx, e)
		return b.buildView(e)
	default:
		return b.buildView(e)
	}
}

// finalizeExpiredPending flips a grant to expired_pending and appends
// the approval record for the expiry, exactly once.
func (b *Broker) finalizeExpiredPending(ctx context.Context, e *grantEntry) {
	now := b.now()
	b.mu.Lock()
	if e.grant.State != domain.StatePendingApproval {
		b.mu.Unlock()
		return
	}
	b.setStateLocked(e, domain.StateExpiredPending)
	e.markTerminal(now)
	done := e.mintDone
	e.mintDone = nil
	b.mu.Unlock()
	if done != nil {
		close(done)
	}

	body := b.baseBody(e, domain.RecordApproval, domain.NewGrantID())
	body.Outcome = "expired_pending"
	body.Approval = &approvalBody{Decision: "expired_pending", RequiredBy: e.requiredBy}
	_ = b.appendRecord(ctx, e, domain.RecordApproval, body)
	b.incOutcome("expired_pending")
}

// autoApprove mints immediately (anchor rule 1: STS at decision time)
// and appends the auto_approved record with the STS block.
func (b *Broker) autoApprove(ctx context.Context, e *grantEntry) (*mcpserver.GrantView, error) {
	now := b.now()
	b.mu.Lock()
	b.setStateLocked(e, domain.StateAutoApproved)
	e.grant.DecidedAt = now
	b.mu.Unlock()

	minted, attempts, mintErr := b.mintGrant(ctx, e)
	if mintErr != nil {
		code, deniedBy, detail := classifyMintError(mintErr)
		view := b.denyEntryMint(ctx, e, code, deniedBy, detail, attempts)
		return view, nil
	}

	b.mu.Lock()
	b.setStateLocked(e, domain.StateMinted)
	e.grant.MintedAt = b.now()
	e.grant.ExpiresAt = minted.Credentials.Expiration()
	e.minted = minted
	d := minted.Credentials.Delivery()
	e.delivery = &d
	b.setStateLocked(e, domain.StateActive)
	b.mu.Unlock()

	b.afterMint(ctx, e)

	body := b.baseBody(e, domain.RecordGrantDecision, domain.NewGrantID())
	fillSynthesis(&body, e.currentResult(), e.trace)
	fillGuardrails(&body, e.guard)
	body.MaxPolicyChars = e.budget()
	body.Outcome = "auto_approved"
	body.GrantedDurationSeconds = e.effectiveSeconds
	body.MintAttempts = attempts
	fillSTS(&body, minted, b.roleARN(e.grant.Profile))
	_ = b.appendRecord(ctx, e, domain.RecordGrantDecision, body)
	b.incOutcome("auto_approved")
	if b.metrics != nil && minted.PackedPolicySizePercent >= 0 {
		b.metrics.ObservePackedPolicySize(minted.PackedPolicySizePercent)
	}

	return b.viewWithDelivery(e), nil
}

// denyEntryMint denies after a failed mint, keeping the mint attempts
// in the record.
func (b *Broker) denyEntryMint(ctx context.Context, e *grantEntry, code domain.DenialCode, deniedBy, detail string, attempts []mintAttemptBody) *mcpserver.GrantView {
	now := b.now()
	b.mu.Lock()
	e.grant.DecidedAt = now
	e.denial = code
	e.detail = detail
	switch e.grant.State {
	case domain.StateAutoApproved, domain.StateApproved:
		b.setStateLocked(e, domain.StateDenied)
	}
	e.markTerminal(now)
	b.mu.Unlock()

	body := b.baseBody(e, domain.RecordGrantDecision, domain.NewGrantID())
	fillSynthesis(&body, e.currentResult(), e.trace)
	fillGuardrails(&body, e.guard)
	body.MaxPolicyChars = e.budget()
	body.Outcome = "denied"
	body.DeniedBy = deniedBy
	body.DenialCode = code.String()
	body.MintAttempts = attempts
	if detail != "" {
		body.DenialDetail = []string{detail}
	}
	_ = b.appendRecord(ctx, e, domain.RecordGrantDecision, body)
	b.incOutcome("denied")
	return b.buildView(e)
}

// currentResult returns the compacted result when a Compact retry
// replaced the policy, else the original.
func (e *grantEntry) currentResult() synth.Result { return e.result }

// afterMint performs the post-mint durable bookkeeping: the first-use
// set records every (agent, capability) pair as used and approved.
func (b *Broker) afterMint(ctx context.Context, e *grantEntry) {
	now := b.now()
	for _, ref := range e.result.Capabilities {
		if err := b.log.MarkFirstUse(ctx, e.grant.AgentID, ref.ID, now, true); err != nil {
			b.logger.Error("broker: first-use bookkeeping failed",
				"grant_id", e.grant.GrantID, "capability", ref.ID, "err", err)
		}
	}
}

// roleARN resolves a profile's role ARN; empty for unknown profiles.
func (b *Broker) roleARN(profile string) string {
	if p, ok := b.cfg.Profiles[profile]; ok {
		return p.RoleARN
	}
	return ""
}
