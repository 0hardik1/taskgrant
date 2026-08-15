package guardrails

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/taskgrant/internal/dataset"
)

// Evaluate runs every guardrail of section 6 against one concrete
// policy document and its evaluation context. It always returns the
// full ordered check list, passes included; the overall verdict is the
// worst individual verdict. Evaluate never panics on hostile input.
func (e *Evaluator) Evaluate(ctx context.Context, in Input) Result {
	res := Result{PolicyChars: len(in.PolicyJSON)}

	doc := parsePolicy(in.PolicyJSON)

	// G0 structure.
	res.Checks = append(res.Checks, e.checkStructure(in.PolicyJSON, doc))

	if doc.fatal {
		const skipped = "not evaluated: policy failed structural parsing; failing closed"
		for _, name := range []string{
			CheckExistence, CheckAccessLevels, CheckServiceDenylist,
			CheckResourceAllowlist, CheckConditions,
		} {
			res.Checks = append(res.Checks, newCheck(name, Fail, skipped))
		}
	} else {
		// G1 existence, on expansion. Later checks run on the expansion.
		res.Checks = append(res.Checks, e.checkExistence(doc))
		res.ExpandedActions = collectExpanded(doc)
		res.Checks = append(res.Checks, e.checkAccessLevels(res.ExpandedActions, in))
		res.Checks = append(res.Checks, e.checkServiceDenylist(doc, res.ExpandedActions))
		res.Checks = append(res.Checks, e.checkResourceAllowlist(doc, in))
		res.Checks = append(res.Checks, e.checkConditions(doc, in))
	}

	// G6 size budget.
	res.Checks = append(res.Checks, e.checkSizeBudget(in))

	// G7 duration clamp.
	g7, effective := e.checkDurationClamp(in)
	res.Checks = append(res.Checks, g7)
	res.EffectiveDurationSeconds = effective

	// G8 rate and creep, durable.
	res.Checks = append(res.Checks, e.checkCapabilityCount(in))
	res.Checks = append(res.Checks, e.checkRateLimit(ctx, in))
	res.Checks = append(res.Checks, e.checkCreep(ctx, in))

	res.Overall = aggregate(res.Checks)
	return res
}

// checkStructure is G0: banned elements, Allow-only effects, the exact
// policy version, and the STS charset.
func (e *Evaluator) checkStructure(raw []byte, doc *parsedPolicy) Check {
	problems := append([]string(nil), doc.problems...)
	problems = append(problems, checkSTSCharset(raw)...)
	if len(problems) > 0 {
		return newCheck(CheckStructure, Fail, joinCapped(problems, 8))
	}
	return newCheck(CheckStructure, Pass,
		fmt.Sprintf("%d statements, Version %s, Allow-only, STS charset ok",
			len(doc.statements), doc.version))
}

// checkExistence is G1: every action pattern expands against the
// pinned dataset; unknown actions and zero-match wildcards fail closed.
// Successful expansions are recorded on the statements so every later
// check runs on enumerated actions.
func (e *Evaluator) checkExistence(doc *parsedPolicy) Check {
	var problems []string
	patterns := 0
	for si := range doc.statements {
		st := &doc.statements[si]
		seen := map[string]struct{}{}
		for _, pat := range st.actions {
			patterns++
			acts, err := e.ds.Expand(pat)
			if err != nil {
				problems = append(problems, fmt.Sprintf("statement[%d]: %v", si, err))
				continue
			}
			for _, a := range acts {
				if _, dup := seen[a]; !dup {
					seen[a] = struct{}{}
					st.expanded = append(st.expanded, a)
				}
			}
		}
		sort.Strings(st.expanded)
	}
	if len(problems) > 0 {
		return newCheck(CheckExistence, Fail, joinCapped(problems, 8))
	}
	total := len(collectExpanded(doc))
	return newCheck(CheckExistence, Pass,
		fmt.Sprintf("%d action patterns expanded to %d known actions (dataset %s)",
			patterns, total, shortHash(e.ds.Hash())))
}

// collectExpanded merges every statement expansion, sorted and
// deduplicated.
func collectExpanded(doc *parsedPolicy) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, st := range doc.statements {
		for _, a := range st.expanded {
			if _, dup := seen[a]; !dup {
				seen[a] = struct{}{}
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// checkAccessLevels is G2: the allowed access-level set, the
// unconditional "Permissions management" deny, the Tagging double
// opt-in, and the shipped escalation denylist that applies regardless
// of dataset labels (the dataset is a community scrape and can
// mislabel).
func (e *Evaluator) checkAccessLevels(expanded []string, in Input) Check {
	allowed := e.defaultLevels
	if in.AllowedAccessLevels != nil {
		set, err := accessLevelSet(in.AllowedAccessLevels)
		if err != nil {
			return newCheck(CheckAccessLevels, Fail,
				fmt.Sprintf("invalid allowed access-level set: %v; failing closed", err))
		}
		allowed = set
	}
	_, taggingConfigured := allowed[string(dataset.AccessTagging)]
	taggingOptIn := false
	for _, c := range in.Capabilities {
		if c.TaggingOptIn {
			taggingOptIn = true
			break
		}
	}

	var escalation, permsMgmt, tagging, levels []string
	for _, a := range expanded {
		if dataset.IsEscalationAction(a) {
			escalation = append(escalation, a)
		}
		info, ok := e.ds.Lookup(a)
		if !ok {
			// Unreachable post-expansion; fail closed regardless.
			levels = append(levels, a+" (unknown)")
			continue
		}
		switch {
		case info.AccessLevel == dataset.AccessPermissionsManagement:
			permsMgmt = append(permsMgmt, a)
		case info.AccessLevel == dataset.AccessTagging:
			if !taggingConfigured || !taggingOptIn {
				tagging = append(tagging, a)
			}
		default:
			if _, ok := allowed[string(info.AccessLevel)]; !ok {
				levels = append(levels, fmt.Sprintf("%s (%s)", a, info.AccessLevel))
			}
		}
	}

	var problems []string
	if len(escalation) > 0 {
		problems = append(problems,
			"escalation denylist (applies regardless of dataset labels): "+joinCapped(escalation, 6))
	}
	if len(permsMgmt) > 0 {
		problems = append(problems,
			"Permissions management denied unconditionally: "+joinCapped(permsMgmt, 6))
	}
	if len(tagging) > 0 {
		problems = append(problems,
			"Tagging requires config listing and capability opt-in: "+joinCapped(tagging, 6))
	}
	if len(levels) > 0 {
		problems = append(problems,
			fmt.Sprintf("outside allowed levels %v: %s", sortedKeys(allowed), joinCapped(levels, 6)))
	}
	if len(problems) > 0 {
		return newCheck(CheckAccessLevels, Fail, joinCapped(problems, 4))
	}
	return newCheck(CheckAccessLevels, Pass,
		fmt.Sprintf("%d actions within allowed levels %v, none on the escalation denylist",
			len(expanded), sortedKeys(allowed)))
}

// checkServiceDenylist is G3: the mandatory core denylist plus config
// extensions. Both raw literal patterns and the expansion are checked.
func (e *Evaluator) checkServiceDenylist(doc *parsedPolicy, expanded []string) Check {
	hits := map[string]struct{}{}
	for _, svc := range servicesOf(expanded) {
		if _, denied := e.denyServices[svc]; denied {
			hits[svc] = struct{}{}
		}
	}
	// Literal service prefixes of raw patterns, so a denied service
	// still reports even when its actions failed expansion.
	for _, st := range doc.statements {
		for _, pat := range st.actions {
			svc, _, ok := strings.Cut(pat, ":")
			if !ok || strings.ContainsAny(svc, "*?") {
				continue
			}
			svc = strings.ToLower(svc)
			if _, denied := e.denyServices[svc]; denied {
				hits[svc] = struct{}{}
			}
		}
	}
	if len(hits) > 0 {
		var list []string
		for svc := range hits {
			list = append(list, svc)
		}
		sort.Strings(list)
		return newCheck(CheckServiceDenylist, Fail,
			"denied services referenced: "+joinCapped(list, 8))
	}
	return newCheck(CheckServiceDenylist, Pass,
		fmt.Sprintf("no denied service referenced (%d core + %d configured)",
			len(mandatoryDenyServices), len(e.cfg.ExtraDenyServices)))
}

// checkResourceAllowlist is G4: every rendered Resource matches an
// admin allowlist pattern with field-split glob matching, and
// Resource "*" is legal only for actions the dataset marks as taking
// no resource type, and only with an explicit capability opt-in.
func (e *Evaluator) checkResourceAllowlist(doc *parsedPolicy, in Input) Check {
	starOptIn := false
	for _, c := range in.Capabilities {
		if c.ResourceStarOptIn {
			starOptIn = true
			break
		}
	}

	var problems []string
	resources := 0
	for si, st := range doc.statements {
		for _, res := range st.resources {
			resources++
			if res == "*" {
				if !starOptIn {
					problems = append(problems, fmt.Sprintf(
						"statement[%d]: Resource \"*\" without a capability opt-in", si))
				}
				if len(st.expanded) == 0 {
					problems = append(problems, fmt.Sprintf(
						"statement[%d]: Resource \"*\" with no verifiable actions", si))
					continue
				}
				for _, a := range st.expanded {
					info, ok := e.ds.Lookup(a)
					if !ok || len(info.ResourceTypes) > 0 {
						problems = append(problems, fmt.Sprintf(
							"statement[%d]: action %s takes resource types; Resource \"*\" not allowed", si, a))
					}
				}
				continue
			}
			if !e.resourceAllowed(res) {
				problems = append(problems, fmt.Sprintf(
					"statement[%d]: resource %q matches no allowlist pattern", si, res))
			}
		}
	}
	if len(problems) > 0 {
		return newCheck(CheckResourceAllowlist, Fail, joinCapped(problems, 8))
	}
	return newCheck(CheckResourceAllowlist, Pass,
		fmt.Sprintf("%d resources within the admin allowlist (%d patterns)",
			resources, len(e.cfg.ResourceAllowlist)))
}

// resourceAllowed reports whether one rendered resource matches any
// admin allowlist pattern. An empty allowlist allows nothing.
func (e *Evaluator) resourceAllowed(resource string) bool {
	for _, pattern := range e.cfg.ResourceAllowlist {
		if arnPatternMatch(pattern, resource) {
			return true
		}
	}
	return false
}

// allowedConditionOperators is the closed positive-constraint operator
// set the evaluator accepts, mirroring the catalog loader's allowlist
// exactly (conforming policies can only carry these: admin templates
// are load-checked against the same set and the compiler injects
// StringEquals). Everything else fails closed: negating operators
// (StringNotEquals, Null), absence-tolerant forms (...IfExists,
// ForAllValues:..., ForAnyValue:...), and date or arithmetic operators
// can each invert or remove a mandatory constraint, so a
// non-conforming synthesizer must not be able to smuggle one past the
// broker's authoritative run (G5, anchor rule 2).
var allowedConditionOperators = map[string]struct{}{
	"StringEquals":           {},
	"StringEqualsIgnoreCase": {},
	"StringLike":             {},
	"ArnEquals":              {},
	"ArnLike":                {},
	"NumericEquals":          {},
	"NumericLessThanEquals":  {},
	"Bool":                   {},
	"IpAddress":              {},
}

// checkConditions is G5: every condition operator inside the
// positive-constraint allowlist, aws:RequestedRegion positively pinned
// on every statement (with global-service exemptions),
// aws:ResourceAccount positively pinned when the context requires it,
// and dataset-confirmed support for every condition key, because an
// unsupported key silently deadens its statement. "Positively pinned"
// means an equality-style operator with wildcard-free values: mere key
// presence under a negating or loosening form satisfies nothing.
func (e *Evaluator) checkConditions(doc *parsedPolicy, in Input) Check {
	requireRA := in.RequireResourceAccount
	for _, c := range in.Capabilities {
		if c.WildcardAllowlistResource {
			requireRA = true
			break
		}
	}

	var problems []string
	for si := range doc.statements {
		st := &doc.statements[si]
		svcs := servicesOf(st.expanded)

		// Operator allowlist first: an operator outside the set can
		// invert or remove any constraint below regardless of which key
		// it holds.
		for _, op := range st.operators() {
			if _, ok := allowedConditionOperators[op]; !ok {
				problems = append(problems, fmt.Sprintf(
					"statement[%d]: condition operator %q is outside the positive-constraint allowlist", si, op))
			}
		}

		exempt := len(svcs) > 0
		for _, svc := range svcs {
			if _, ok := e.globalExempt[svc]; !ok {
				exempt = false
				break
			}
		}
		if !exempt {
			if len(st.constrainingConditionValues("aws:RequestedRegion")) == 0 {
				problems = append(problems, mandatoryConditionProblem(si, st, "aws:RequestedRegion"))
			}
		}

		needRA := requireRA
		if !needRA {
			for _, svc := range svcs {
				if _, ok := e.globalNamespace[svc]; ok {
					needRA = true
					break
				}
			}
		}
		// Independent of any seam-reported provenance: a glob in a
		// resource ARN's account field leaves the owning account
		// unpinned by the resource itself, recoverable from the policy
		// bytes alone.
		if !needRA {
			for _, r := range st.resources {
				if accountFieldWildcard(r) {
					needRA = true
					break
				}
			}
		}
		if needRA {
			vals := st.constrainingConditionValues("aws:ResourceAccount")
			if len(vals) == 0 {
				problems = append(problems, mandatoryConditionProblem(si, st, "aws:ResourceAccount"))
			} else if len(e.accounts) > 0 {
				for _, v := range vals {
					if _, ok := e.accounts[v]; !ok {
						problems = append(problems, fmt.Sprintf(
							"statement[%d]: aws:ResourceAccount value %q is not a configured account", si, v))
					}
				}
			}
		}

		for _, key := range st.conditionKeys() {
			for _, a := range st.expanded {
				if !e.ds.SupportsConditionKey(a, key) {
					problems = append(problems, fmt.Sprintf(
						"statement[%d]: condition key %q is not supported by action %s (would silently deaden the statement)",
						si, key, a))
				}
			}
		}
	}
	if len(problems) > 0 {
		return newCheck(CheckConditions, Fail, joinCapped(problems, 8))
	}
	return newCheck(CheckConditions, Pass,
		fmt.Sprintf("operators within the allowlist, mandatory conditions positively pinned and supported on %d statements",
			len(doc.statements)))
}

// mandatoryConditionProblem renders the G5 failure for one mandatory
// key: wholly absent, or present only in forms that do not positively
// pin it.
func mandatoryConditionProblem(si int, st *parsedStatement, key string) string {
	if st.hasConditionKey(key) {
		return fmt.Sprintf(
			"statement[%d]: %s is present but not positively pinned (an equality-style operator with wildcard-free values is required)",
			si, key)
	}
	return fmt.Sprintf("statement[%d]: missing mandatory %s condition", si, key)
}

// checkSizeBudget is G6.
func (e *Evaluator) checkSizeBudget(in Input) Check {
	budget := in.MaxPolicyChars
	if budget <= 0 {
		budget = e.maxPolicyChars
	}
	chars := len(in.PolicyJSON)
	switch {
	case chars > budget:
		return newCheck(CheckSizeBudget, Fail,
			fmt.Sprintf("policy is %d chars, over the %d budget by %d", chars, budget, chars-budget))
	case chars*10 > budget*9:
		return newCheck(CheckSizeBudget, Warn,
			fmt.Sprintf("policy is %d chars of %d budget (over 90 percent)", chars, budget))
	default:
		return newCheck(CheckSizeBudget, Pass,
			fmt.Sprintf("policy is %d chars of %d budget", chars, budget))
	}
}

// checkDurationClamp is G7. It returns the check and the effective
// duration in seconds:
// min(request, capability cap, profile cap, global cap), floored and
// defaulted at 900, and hard-capped at 3600 when the broker itself
// runs on session credentials.
func (e *Evaluator) checkDurationClamp(in Input) (Check, int) {
	requested := in.RequestedDurationSeconds
	if requested <= 0 {
		requested = DurationFloorSeconds
	}
	effective := requested
	clamps := []string{fmt.Sprintf("request %ds", requested)}

	capCap := 0
	for _, c := range in.Capabilities {
		if c.MaxDurationSeconds > 0 && (capCap == 0 || c.MaxDurationSeconds < capCap) {
			capCap = c.MaxDurationSeconds
		}
	}
	if capCap > 0 {
		clamps = append(clamps, fmt.Sprintf("capability cap %ds", capCap))
		if capCap < effective {
			effective = capCap
		}
	}
	if in.ProfileMaxDurationSeconds > 0 {
		clamps = append(clamps, fmt.Sprintf("profile cap %ds", in.ProfileMaxDurationSeconds))
		if in.ProfileMaxDurationSeconds < effective {
			effective = in.ProfileMaxDurationSeconds
		}
	}
	clamps = append(clamps, fmt.Sprintf("global cap %ds", e.globalMaxSeconds))
	if e.globalMaxSeconds < effective {
		effective = e.globalMaxSeconds
	}
	if in.BrokerChained && effective > ChainedDurationCapSeconds {
		effective = ChainedDurationCapSeconds
		clamps = append(clamps, fmt.Sprintf("chained-broker ceiling %ds", ChainedDurationCapSeconds))
	}
	if effective < DurationFloorSeconds {
		effective = DurationFloorSeconds
	}

	detail := fmt.Sprintf("effective %ds = min(%s), floor %ds",
		effective, strings.Join(clamps, ", "), DurationFloorSeconds)
	return newCheck(CheckDurationClamp, Pass, detail), effective
}

// checkCapabilityCount is the pure part of G8: max 3 capabilities per
// grant.
func (e *Evaluator) checkCapabilityCount(in Input) Check {
	n := len(in.Capabilities)
	if n > MaxCapabilitiesPerGrant {
		return newCheck(CheckCapabilityCount, Fail,
			fmt.Sprintf("%d capabilities exceed the per-grant maximum of %d", n, MaxCapabilitiesPerGrant))
	}
	return newCheck(CheckCapabilityCount, Pass,
		fmt.Sprintf("%d capabilities of max %d", n, MaxCapabilitiesPerGrant))
}

// checkRateLimit is the durable rate part of G8: one token per
// (agent, capability) from the injected store. Store errors fail
// closed. A nil store (the synthesizer-side run) reports warn; the
// authoritative broker run must inject one.
func (e *Evaluator) checkRateLimit(ctx context.Context, in Input) Check {
	if in.State == nil {
		return newCheck(CheckRateLimit, Warn,
			"durable state not injected; rate limit not checked on this run")
	}
	var exhausted []string
	for _, c := range in.Capabilities {
		ok, err := in.State.TakeToken(ctx, in.AgentID, c.ID)
		if err != nil {
			return newCheck(CheckRateLimit, Fail,
				fmt.Sprintf("rate state error for capability %s: %v; failing closed", c.ID, err))
		}
		if !ok {
			exhausted = append(exhausted, c.ID)
		}
	}
	if len(exhausted) > 0 {
		return newCheck(CheckRateLimit, Fail,
			fmt.Sprintf("rate limit exhausted (%d/h per agent and capability): %s",
				RateTokensPerHour, joinCapped(exhausted, 6)))
	}
	return newCheck(CheckRateLimit, Pass,
		fmt.Sprintf("rate tokens available for %d capabilities (%d/h each)",
			len(in.Capabilities), RateTokensPerHour))
}

// checkCreep is the durable creep part of G8: the rolling 24 h
// distinct-capability counter, alert at 5, hard cap 10 with human
// override (needs_approval).
func (e *Evaluator) checkCreep(ctx context.Context, in Input) Check {
	if in.State == nil {
		return newCheck(CheckCreep, Warn,
			"durable state not injected; capability creep not checked on this run")
	}
	ids := make([]string, 0, len(in.Capabilities))
	for _, c := range in.Capabilities {
		ids = append(ids, c.ID)
	}
	n, err := in.State.DistinctCapabilityCount(ctx, in.AgentID, ids)
	if err != nil {
		return newCheck(CheckCreep, Fail,
			fmt.Sprintf("creep state error: %v; failing closed", err))
	}
	switch {
	case n >= CreepHardCap:
		return newCheck(CheckCreep, NeedsApproval,
			fmt.Sprintf("distinct capabilities in 24h: %d reaches the hard cap %d; human override required",
				n, CreepHardCap))
	case n >= CreepAlertThreshold:
		return newCheck(CheckCreep, Warn,
			fmt.Sprintf("distinct capabilities in 24h: %d at or over the alert threshold %d (cap %d)",
				n, CreepAlertThreshold, CreepHardCap))
	default:
		return newCheck(CheckCreep, Pass,
			fmt.Sprintf("distinct capabilities in 24h: %d (alert %d, cap %d)",
				n, CreepAlertThreshold, CreepHardCap))
	}
}

// sortedKeys renders a string set as a sorted slice for stable detail
// strings.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// shortHash abbreviates a hex hash for detail strings.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
