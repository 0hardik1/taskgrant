package match

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/synth"
)

// Confidence gate thresholds, exactly the section 5.5 table.
const (
	// ProceedThreshold: top candidate confidence required to proceed.
	ProceedThreshold = 0.80
	// MarginThreshold: minimum lead of the top candidate over the
	// runner-up; below it the match is ambiguous.
	MarginThreshold = 0.20
	// NoMatchThreshold: below it (or with no candidate) the gate
	// denies NO_MATCH.
	NoMatchThreshold = 0.50
	// MaxCapabilitiesPerGrant mirrors guardrail G8.
	MaxCapabilitiesPerGrant = 3
)

// GateOutcome classifies one gate decision.
type GateOutcome string

const (
	GateProceed         GateOutcome = "proceed"
	GateClarify         GateOutcome = "clarify"
	GateDeny            GateOutcome = "deny"
	GatePendingApproval GateOutcome = "pending_approval"
)

// FirstUseFunc reports whether (agentID, capabilityID) has never been
// granted before. The implementation must be durable (invariant I5);
// the store package provides it and the integration step injects it.
type FirstUseFunc func(agentID, capabilityID string) (bool, error)

// Selected is one gated capability with its merged (still unvalidated)
// params: extracted params overlaid by hinted params, hinted winning
// on conflict.
type Selected struct {
	Capability Capability
	Params     map[string]string
}

// GateDecision is the outcome of the confidence gate.
type GateDecision struct {
	Outcome GateOutcome
	// Selected is set for GateProceed and GatePendingApproval: the
	// capability set to resolve, compile, and (maybe) park for
	// approval.
	Selected []Selected
	// DenialCode is set for GateDeny.
	DenialCode domain.DenialCode
	// ClarifyCode is set for GateClarify: MISSING_PARAM or
	// AMBIGUOUS_MATCH.
	ClarifyCode   domain.DenialCode
	MissingParams []synth.MissingParam
	Candidates    []synth.CandidateCapability
	Questions     []string
	// FirstUse lists capability ids that triggered the first-use
	// approval rule.
	FirstUse []string
	// ApprovalReasons are log-only reasons a human gate is required.
	ApprovalReasons []string
}

// Gate applies the section 5.5 confidence table.
type Gate struct {
	// FirstUse is the durable first-use predicate. Required when
	// FirstUseApproval is true.
	FirstUse FirstUseFunc
	// FirstUseApproval mirrors guardrails.first_use_approval (default
	// true per section 10).
	FirstUseApproval bool
}

// Decide gates one MatchResult. Row order per the table, top to
// bottom precedence:
//
//  1. no candidate, or top < 0.50: deny NO_MATCH
//  2. top in [0.50, 0.80) or margin < 0.20 (competing candidates
//     only): clarification AMBIGUOUS_MATCH with a candidate list
//  3. required params missing: clarification MISSING_PARAM naming
//     every missing param with its expected shape and examples
//  4. any selected capability requires_approval, or first use of an
//     (agent, capability) pair with first_use_approval on: pending
//     approval
//  5. otherwise: proceed
//
// Structured hint candidates (confidence 1.0) form a requested set,
// not competing alternatives, so rule 2's margin does not apply to
// them; all of them are selected together (max 3, G8).
func (g Gate) Decide(agentID string, res MatchResult, hints synth.Hints, snap Snapshot) (GateDecision, error) {
	if len(res.Candidates) == 0 {
		return GateDecision{Outcome: GateDeny, DenialCode: domain.DenyNoMatch}, nil
	}

	var chosen []Candidate
	if res.Structured {
		chosen = res.Candidates
	} else {
		top := res.Candidates[0]
		if top.Confidence < NoMatchThreshold {
			return GateDecision{Outcome: GateDeny, DenialCode: domain.DenyNoMatch}, nil
		}
		margin := 1.0
		if len(res.Candidates) > 1 {
			margin = top.Confidence - res.Candidates[1].Confidence
		}
		if top.Confidence < ProceedThreshold || margin < MarginThreshold {
			return ambiguousDecision(res.Candidates, snap), nil
		}
		chosen = res.Candidates[:1]
	}

	if len(chosen) > MaxCapabilitiesPerGrant {
		return GateDecision{
			Outcome:    GateDeny,
			DenialCode: domain.DenyGuardrailViolation,
			ApprovalReasons: []string{fmt.Sprintf(
				"G8: %d capabilities requested, maximum %d per grant", len(chosen), MaxCapabilitiesPerGrant)},
		}, nil
	}

	selected, err := mergeSelected(chosen, hints, snap)
	if err != nil {
		return GateDecision{}, err
	}

	if missing := missingRequiredParams(selected); len(missing) > 0 {
		return missingParamDecision(selected, missing), nil
	}

	var reasons, firstUse []string
	for _, sel := range selected {
		if sel.Capability.RequiresApproval {
			reasons = append(reasons, fmt.Sprintf("capability %s requires approval", sel.Capability.ID))
		}
	}
	if g.FirstUseApproval {
		if g.FirstUse == nil {
			return GateDecision{}, fmt.Errorf("match: first-use approval is enabled but the gate has no FirstUse dependency")
		}
		for _, sel := range selected {
			fu, err := g.FirstUse(agentID, sel.Capability.ID)
			if err != nil {
				// Fail closed: an unreadable first-use ledger routes
				// through a human instead of auto-approving.
				fu = true
				reasons = append(reasons, fmt.Sprintf(
					"first-use check for capability %s failed, failing closed to approval: %v", sel.Capability.ID, err))
			}
			if fu {
				firstUse = append(firstUse, sel.Capability.ID)
				reasons = append(reasons, fmt.Sprintf(
					"first use of capability %s by agent %s", sel.Capability.ID, agentID))
			}
		}
	}

	if len(reasons) > 0 {
		return GateDecision{
			Outcome:         GatePendingApproval,
			Selected:        selected,
			FirstUse:        firstUse,
			ApprovalReasons: reasons,
		}, nil
	}
	return GateDecision{Outcome: GateProceed, Selected: selected}, nil
}

// mergeSelected resolves candidates against the snapshot and merges
// hinted params over extracted params (hinted wins on conflict).
func mergeSelected(chosen []Candidate, hints synth.Hints, snap Snapshot) ([]Selected, error) {
	hinted := make(map[string]map[string]string, len(hints.Capabilities))
	for _, h := range hints.Capabilities {
		if hinted[h.ID] == nil {
			hinted[h.ID] = map[string]string{}
		}
		for k, v := range h.Params {
			if _, exists := hinted[h.ID][k]; !exists {
				hinted[h.ID][k] = v
			}
		}
	}

	selected := make([]Selected, 0, len(chosen))
	for _, c := range chosen {
		capability, ok := snap.Lookup(c.CapabilityID)
		if !ok {
			// Matchers guarantee closed-world candidates; a miss here
			// is an implementation bug, not agent input.
			return nil, fmt.Errorf("match: gated candidate %q is not in the snapshot", c.CapabilityID)
		}
		merged := cloneParams(c.Params)
		for k, v := range hinted[c.CapabilityID] {
			merged[k] = v
		}
		selected = append(selected, Selected{Capability: capability, Params: merged})
	}
	return selected, nil
}

// missingRequiredParams names every required param absent (or blank)
// in the merged set, in deterministic order.
func missingRequiredParams(selected []Selected) []synth.MissingParam {
	var missing []synth.MissingParam
	for _, sel := range selected {
		for _, ps := range sel.Capability.Params {
			if !ps.Required {
				continue
			}
			if strings.TrimSpace(sel.Params[ps.Name]) == "" {
				missing = append(missing, synth.MissingParam{
					Capability:    sel.Capability.ID,
					Name:          ps.Name,
					ExpectedShape: ps.ExpectedShape,
					Examples:      append([]string(nil), ps.Examples...),
				})
			}
		}
	}
	sort.SliceStable(missing, func(i, j int) bool {
		if missing[i].Capability != missing[j].Capability {
			return missing[i].Capability < missing[j].Capability
		}
		return missing[i].Name < missing[j].Name
	})
	return missing
}

// ambiguousDecision builds the "confirm by id" clarification of table
// row three. Candidate summaries come from the agent's own snapshot
// only.
func ambiguousDecision(cands []Candidate, snap Snapshot) GateDecision {
	dec := GateDecision{Outcome: GateClarify, ClarifyCode: domain.DenyAmbiguousMatch}
	ids := make([]string, 0, len(cands))
	for _, c := range cands {
		summary := ""
		if capability, ok := snap.Lookup(c.CapabilityID); ok {
			summary = capability.Summary
		}
		dec.Candidates = append(dec.Candidates, synth.CandidateCapability{ID: c.CapabilityID, Summary: summary})
		ids = append(ids, c.CapabilityID)
	}
	dec.Questions = []string{
		fmt.Sprintf("Confirm the intended capability by id: %s.", strings.Join(ids, ", ")),
		"Retry with a structured capabilities hint naming the confirmed id and its params.",
	}
	return dec
}

// missingParamDecision builds the "name the params" clarification of
// table row two.
func missingParamDecision(selected []Selected, missing []synth.MissingParam) GateDecision {
	dec := GateDecision{
		Outcome:       GateClarify,
		ClarifyCode:   domain.DenyMissingParam,
		MissingParams: missing,
	}
	names := make([]string, 0, len(missing))
	for _, m := range missing {
		names = append(names, m.Capability+"."+m.Name)
	}
	for _, sel := range selected {
		dec.Candidates = append(dec.Candidates, synth.CandidateCapability{
			ID:      sel.Capability.ID,
			Summary: sel.Capability.Summary,
		})
	}
	dec.Questions = []string{
		fmt.Sprintf("Provide values for: %s.", strings.Join(names, ", ")),
		"Retry with a structured capabilities hint carrying the missing params.",
	}
	return dec
}
