package broker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/guardrails"
	"github.com/0hardik1/taskgrant/internal/synth"
)

// stateAdapter adapts the store's durable security state to the
// guardrail evaluator's StateStore seam (G8, invariant I5). Store
// errors propagate so the evaluator fails closed.
type stateAdapter struct {
	log   DecisionLog
	clock func() time.Time
}

// TakeToken implements guardrails.StateStore: one token from the
// per (agent, capability) bucket at the documented rate and burst.
func (a stateAdapter) TakeToken(ctx context.Context, agentID, capabilityID string) (bool, error) {
	return a.log.TakeToken(ctx, agentID, capabilityID,
		guardrails.RateTokensPerHour, guardrails.RateTokensPerHour, a.clock().UTC())
}

// DistinctCapabilityCount implements guardrails.StateStore. Recording
// the includeIDs first both counts them in and feeds the durable creep
// ledger, so an induced restart never resets anti-creep state.
func (a stateAdapter) DistinctCapabilityCount(ctx context.Context, agentID string, includeIDs []string) (int, error) {
	now := a.clock().UTC()
	for _, id := range includeIDs {
		if err := a.log.RecordCapabilityUse(ctx, agentID, id, now); err != nil {
			return 0, err
		}
	}
	return a.log.DistinctCapabilities24h(ctx, agentID, now)
}

var _ guardrails.StateStore = stateAdapter{}

// capabilityMeta resolves the guardrail metadata of the selected
// capabilities from the current catalog snapshot, and reports whether
// any parameter value matched a wildcard allowlist entry (which makes
// aws:ResourceAccount mandatory, G5).
func (b *Broker) capabilityMeta(res synth.Result) ([]guardrails.CapabilityMeta, bool) {
	snap := b.catalog.Current()
	wildcardAny := false
	out := make([]guardrails.CapabilityMeta, 0, len(res.Capabilities))
	for _, ref := range res.Capabilities {
		m := guardrails.CapabilityMeta{ID: ref.ID}
		if snap != nil {
			if c, ok := snap.Capability(ref.ID); ok {
				m.MaxDurationSeconds = c.MaxDurationSeconds
				m.TaggingOptIn = c.AccessCeiling == dataset.AccessTagging
				if params := capabilityParams(res.Explanation, ref.ID); len(params) > 0 {
					if vps, err := snap.ValidateParams(ref.ID, params); err == nil {
						for _, vp := range vps {
							if vp.FromWildcardEntry {
								m.WildcardAllowlistResource = true
								wildcardAny = true
							}
						}
					}
				}
			}
		}
		out = append(out, m)
	}
	return out, wildcardAny
}

// declaredActionSet builds the union of the declared capabilities'
// catalog actions, lowercased. ok reports whether a catalog snapshot
// was available to resolve against; without one there is nothing to
// cross-check (the guardrail evaluator still bounds the policy
// itself). Capability ids absent from the catalog contribute no
// actions, so inventing ids cannot widen the set.
func (b *Broker) declaredActionSet(refs []synth.CapabilityRef) (map[string]struct{}, bool) {
	snap := b.catalog.Current()
	if snap == nil {
		return nil, false
	}
	declared := make(map[string]struct{})
	for _, ref := range refs {
		if c, ok := snap.Capability(ref.ID); ok {
			for _, a := range c.Actions {
				declared[strings.ToLower(a)] = struct{}{}
			}
		}
	}
	return declared, true
}

// uncoveredActions returns the expanded actions absent from the
// declared set, sorted. The G8 controls (rate bucket, creep ledger,
// capability count) key on the seam-reported capability ids; requiring
// the policy's authoritative expansion to stay inside the union of
// those capabilities' catalog actions stops a non-conforming seam from
// under-reporting its selection while emitting a broader policy, which
// would otherwise dodge the durable anti-creep state (anchor rule 2).
func uncoveredActions(declared map[string]struct{}, expanded []string) []string {
	var out []string
	for _, a := range expanded {
		if _, ok := declared[strings.ToLower(a)]; !ok {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// approvalRuleRequired evaluates approvals.rules first match wins
// (section 10): a matching require_approval rule parks the grant, a
// matching auto_approve rule stops rule processing, and no match means
// no rule-driven approval.
func (b *Broker) approvalRuleRequired(agentID, profile string, res synth.Result) (int, bool) {
	if len(b.cfg.Approvals.Rules) == 0 {
		return -1, false
	}
	levels := b.accessLevels(res.ExpandedActions)
	capIDs := make(map[string]struct{}, len(res.Capabilities))
	for _, ref := range res.Capabilities {
		capIDs[ref.ID] = struct{}{}
	}
	for i, rule := range b.cfg.Approvals.Rules {
		if !ruleMatches(rule.Match, agentID, profile, capIDs, levels) {
			continue
		}
		return i, rule.Action == config.ActionRequireApproval
	}
	return -1, false
}

// ruleMatches reports whether every non-empty match field applies.
func ruleMatches(m config.ApprovalMatch, agentID, profile string, capIDs map[string]struct{}, levels map[string]struct{}) bool {
	if m.Agent != "" && m.Agent != agentID {
		return false
	}
	if m.Profile != "" && m.Profile != profile {
		return false
	}
	if m.Capability != "" {
		if _, ok := capIDs[m.Capability]; !ok {
			return false
		}
	}
	if m.AccessLevel != "" {
		if _, ok := levels[m.AccessLevel]; !ok {
			return false
		}
	}
	return true
}

// accessLevels resolves the distinct dataset access levels of the
// expanded action list.
func (b *Broker) accessLevels(actions []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, a := range actions {
		if info, ok := b.ds.Lookup(a); ok {
			out[string(info.AccessLevel)] = struct{}{}
		}
	}
	return out
}

// ruleName renders the required_by tag for a config rule index.
func ruleName(idx int) string {
	return fmt.Sprintf("rule:%d", idx)
}
