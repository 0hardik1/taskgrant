// Package compile turns a validated capability selection into the
// canonical minified session policy JSON of architecture section 7.2:
// actions grouped by (resource template set, condition set) per
// capability, validated params rendered into admin-authored templates,
// identical statements merged across capabilities, canonical ordering
// for byte-stable output (invariant I6), and an explanation
// index-parallel to Statement. It also implements the reduction ladder
// of section 7.3 as composable steps and injects the mandatory G5
// conditions at compile time. Emitted Action lists never contain a
// wildcard (invariant I2); the compiler asserts it.
package compile

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
)

// PolicyVersion is the only policy language version G0 accepts.
const PolicyVersion = "2012-10-17"

// DefaultMaxPolicyArns is the STS PolicyArns ceiling (section 7.1).
const DefaultMaxPolicyArns = 10

// Ladder step names recorded in Output.StepsApplied.
const (
	StepMinify   = "minify"
	StepMerge    = "merge"
	StepDropSids = "drop_sids"
	StepOffload  = "offload_policy_arns"
)

// Selection pairs one catalog capability with its validated params.
// Params must come from catalog.ValidateParams; the compiler still
// re-checks the values defensively (the seam is re-verified, never
// trusted).
type Selection struct {
	Capability *catalog.Capability
	Params     map[string]catalog.ValidatedParam
}

// Input is one compilation request.
type Input struct {
	Selections []Selection
	// Region is the value for the mandatory aws:RequestedRegion
	// condition (G5). Required unless every statement is exempt as
	// global-service.
	Region string
	// Accounts is the configured account list for aws:ResourceAccount
	// injection (G5). Required whenever a statement needs it.
	Accounts []string
	// MaxPolicyChars is the size budget for the minified inline policy
	// JSON. Zero means unlimited (no ladder beyond minify).
	MaxPolicyChars int
	// MaxPolicyArns caps the managed policies the offload step may
	// emit. Zero means DefaultMaxPolicyArns. The broker must reduce
	// this by any profile static ceiling ARNs it will attach.
	MaxPolicyArns int
	// ForceDropSids applies ladder step 3 before any budget check,
	// for callers that drive the ladder explicitly.
	ForceDropSids bool
	// ForceOffloadManaged applies ladder step 4 before any budget
	// check, for callers that drive the ladder explicitly.
	ForceOffloadManaged bool
}

// Output is one deterministic compilation result.
type Output struct {
	// PolicyJSON is the canonical minified policy document. Nil when
	// every statement was offloaded to PolicyArns.
	PolicyJSON []byte
	// PolicyArns lists managed policies offloaded by the ladder,
	// sorted.
	PolicyArns []string
	// Explanation is index-parallel to the Statement array of
	// PolicyJSON.
	Explanation synth.Explanation
	// ExpandedActions is the full enumerated action list across the
	// whole selection, offloaded capabilities included, sorted.
	ExpandedActions []string
	// Chars is len(PolicyJSON).
	Chars int
	// Attribution maps capability id to the bytes its inline
	// statements occupy in the final document, for OVER_BUDGET
	// reporting.
	Attribution map[string]int
	// StepsApplied lists the ladder steps that ran, in order.
	StepsApplied []string
}

// OverBudgetError reports a policy that stayed over budget after the
// full reduction ladder, with per-capability byte attribution so the
// agent can split the task intelligently (section 7.3 step 5).
type OverBudgetError struct {
	Budget      int
	Chars       int
	Attribution map[string]int
}

// Error implements error.
func (e *OverBudgetError) Error() string {
	ids := make([]string, 0, len(e.Attribution))
	for id := range e.Attribution {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	fmt.Fprintf(&b, "policy is %d chars, budget %d (over by %d)", e.Chars, e.Budget, e.Chars-e.Budget)
	for i, id := range ids {
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s: %d chars", id, e.Attribution[id])
	}
	return b.String()
}

// Compiler compiles selections against one pinned dataset.
type Compiler struct {
	ds *dataset.Dataset
}

// New returns a Compiler bound to the pinned dataset.
func New(ds *dataset.Dataset) (*Compiler, error) {
	if ds == nil {
		return nil, errors.New("compile: nil dataset")
	}
	return &Compiler{ds: ds}, nil
}

// placeholderRE matches {param} placeholders in templates.
var placeholderRE = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)

// Compile runs the full pipeline: build, dedupe, render, and the
// reduction ladder until the result fits MaxPolicyChars. The output is
// a pure function of the input (invariant I6): identical selections,
// params, and budget produce byte-identical PolicyJSON.
func (c *Compiler) Compile(in Input) (*Output, error) {
	if len(in.Selections) == 0 {
		return nil, errors.New("compile: no selections")
	}

	// Sort selections by capability id and refuse duplicates: the
	// selection set is a set, and sorting makes everything after this
	// point order-independent.
	sels := append([]Selection(nil), in.Selections...)
	sort.SliceStable(sels, func(i, j int) bool {
		return sels[i].Capability.ID < sels[j].Capability.ID
	})
	for i := 1; i < len(sels); i++ {
		if sels[i].Capability.ID == sels[i-1].Capability.ID {
			return nil, fmt.Errorf("compile: capability %q selected twice", sels[i].Capability.ID)
		}
	}

	p := &Policy{withSids: true}
	expandedSet := make(map[string]struct{})
	for _, sel := range sels {
		stmts, err := c.buildSelection(sel, in)
		if err != nil {
			return nil, err
		}
		p.stmts = append(p.stmts, stmts...)
		for _, a := range sel.Capability.Actions {
			expandedSet[a] = struct{}{}
		}
	}
	p.dedupeIdentical()

	maxArns := in.MaxPolicyArns
	if maxArns == 0 {
		maxArns = DefaultMaxPolicyArns
	}

	steps := []string{StepMinify}
	if in.ForceDropSids && p.DropSids() {
		steps = append(steps, StepDropSids)
	}
	if in.ForceOffloadManaged && p.OffloadManaged(maxArns) {
		steps = append(steps, StepOffload)
	}
	doc, sizes, err := p.Render()
	if err != nil {
		return nil, err
	}
	if in.MaxPolicyChars > 0 && len(doc) > in.MaxPolicyChars {
		// Ladder step 2: merge statements with identical Resource and
		// Condition.
		p.Merge()
		steps = append(steps, StepMerge)
		if doc, sizes, err = p.Render(); err != nil {
			return nil, err
		}
	}
	if in.MaxPolicyChars > 0 && len(doc) > in.MaxPolicyChars {
		// Ladder step 3: drop optional Sids; the explanation maps by
		// index.
		if p.DropSids() {
			steps = append(steps, StepDropSids)
			if doc, sizes, err = p.Render(); err != nil {
				return nil, err
			}
		}
	}
	if in.MaxPolicyChars > 0 && len(doc) > in.MaxPolicyChars {
		// Ladder step 4: offload managed_policy capabilities to
		// PolicyArns.
		if p.OffloadManaged(maxArns) {
			steps = append(steps, StepOffload)
			if doc, sizes, err = p.Render(); err != nil {
				return nil, err
			}
		}
	}

	attribution := p.attribution(sizes)
	if in.MaxPolicyChars > 0 && len(doc) > in.MaxPolicyChars {
		return nil, &OverBudgetError{
			Budget:      in.MaxPolicyChars,
			Chars:       len(doc),
			Attribution: attribution,
		}
	}

	expanded := make([]string, 0, len(expandedSet))
	for a := range expandedSet {
		expanded = append(expanded, a)
	}
	sort.Strings(expanded)

	out := &Output{
		PolicyJSON:      doc,
		PolicyArns:      append([]string(nil), p.policyArns...),
		Explanation:     p.explanation(),
		ExpandedActions: expanded,
		Chars:           len(doc),
		Attribution:     attribution,
		StepsApplied:    steps,
	}
	return out, nil
}

// buildSelection compiles one capability selection into statements:
// actions grouped by (resource template set, condition template set),
// params rendered, mandatory conditions injected.
func (c *Compiler) buildSelection(sel Selection, in Input) ([]*stmt, error) {
	cp := sel.Capability
	if cp == nil {
		return nil, errors.New("compile: nil capability in selection")
	}

	// Every declared param must be present and safe; every provided
	// param must be declared. This re-verifies what
	// catalog.ValidateParams produced, because the compiler must fail
	// closed even on a misbehaving caller.
	for name := range sel.Params {
		if _, ok := cp.Params[name]; !ok {
			return nil, fmt.Errorf("compile: capability %s: param %q is not declared", cp.ID, name)
		}
	}
	values := make(map[string]string, len(sel.Params))
	explParams := make(map[string]string, len(sel.Params))
	fromWildcard := make(map[string]bool, len(sel.Params))
	for _, name := range cp.ParamNames() {
		vp, ok := sel.Params[name]
		if !ok {
			return nil, fmt.Errorf("compile: capability %s: param %q has no validated value", cp.ID, name)
		}
		if err := assertSafeParamValue(vp.Value); err != nil {
			return nil, fmt.Errorf("compile: capability %s: param %q: %v", cp.ID, name, err)
		}
		values[name] = vp.Value
		explParams[name] = vp.Value
		fromWildcard[name] = vp.FromWildcardEntry
	}

	// Group actions by (resource template set, condition template
	// set). Actions are sorted at catalog load, so group order is
	// deterministic.
	type group struct {
		actions  []string
		resIdxs  []int
		condIdxs []int
	}
	var groups []*group
	byKey := make(map[string]*group)
	for _, action := range cp.Actions {
		if strings.ContainsAny(action, "*?") {
			return nil, fmt.Errorf("compile: capability %s: action %q contains a wildcard (I2)", cp.ID, action)
		}
		info, ok := c.ds.Lookup(action)
		if !ok {
			return nil, fmt.Errorf("compile: capability %s: action %q is not in the pinned dataset", cp.ID, action)
		}
		if dataset.IsEscalationAction(info.Action) {
			return nil, fmt.Errorf("compile: capability %s: action %q is on the escalation denylist", cp.ID, info.Action)
		}
		var resIdxs, condIdxs []int
		for i := range cp.Resources {
			if cp.Resources[i].AppliesTo(info.Action) {
				resIdxs = append(resIdxs, i)
			}
		}
		if len(resIdxs) == 0 {
			return nil, fmt.Errorf("compile: capability %s: action %q has no resource template", cp.ID, info.Action)
		}
		for i := range cp.Conditions {
			if cp.Conditions[i].AppliesTo(info.Action) {
				condIdxs = append(condIdxs, i)
			}
		}
		key := fmt.Sprint(resIdxs, "|", condIdxs)
		g, ok := byKey[key]
		if !ok {
			g = &group{resIdxs: resIdxs, condIdxs: condIdxs}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.actions = append(g.actions, info.Action)
	}

	var stmts []*stmt
	for _, g := range groups {
		s := &stmt{
			capID:      cp.ID,
			capVersion: cp.Version,
			summary:    cp.Summary,
			explParams: explParams,
			managed:    cp.ManagedPolicy,
			managedARN: cp.ManagedPolicyARN,
			conds:      make(map[string]map[string][]string),
		}
		s.actions = append([]string(nil), g.actions...)
		sort.Strings(s.actions)

		wildcardValue := false
		seenRes := make(map[string]struct{})
		for _, ri := range g.resIdxs {
			tpl := cp.Resources[ri].Template
			rendered, used, err := renderTemplate(tpl, values)
			if err != nil {
				return nil, fmt.Errorf("compile: capability %s: resource %q: %v", cp.ID, tpl, err)
			}
			if err := assertSafeResource(rendered); err != nil {
				return nil, fmt.Errorf("compile: capability %s: resource %q: %v", cp.ID, tpl, err)
			}
			for _, u := range used {
				if fromWildcard[u] {
					wildcardValue = true
				}
			}
			if _, dup := seenRes[rendered]; !dup {
				seenRes[rendered] = struct{}{}
				s.resources = append(s.resources, rendered)
			}
		}
		sort.Strings(s.resources)

		for _, ci := range g.condIdxs {
			ct := cp.Conditions[ci]
			rendered, _, err := renderTemplate(ct.Value, values)
			if err != nil {
				return nil, fmt.Errorf("compile: capability %s: condition %s: %v", cp.ID, ct.Key, err)
			}
			// A condition key that an action does not support silently
			// deadens the statement, so unsupported keys fail closed
			// (G5).
			for _, a := range s.actions {
				if !c.ds.SupportsConditionKey(a, ct.Key) {
					return nil, fmt.Errorf("compile: capability %s: condition key %q is not supported by action %q", cp.ID, ct.Key, a)
				}
			}
			s.addCond(ct.Op, ct.Key, rendered)
		}

		if err := c.injectMandatoryConditions(s, in, wildcardValue); err != nil {
			return nil, fmt.Errorf("compile: capability %s: %v", cp.ID, err)
		}
		stmts = append(stmts, s)
	}
	return stmts, nil
}

// renderTemplate substitutes validated param values into an
// admin-authored template. It returns the rendered string and the
// param names used. An unresolved placeholder fails closed.
func renderTemplate(tpl string, values map[string]string) (string, []string, error) {
	var used []string
	var missing []string
	rendered := placeholderRE.ReplaceAllStringFunc(tpl, func(m string) string {
		name := m[1 : len(m)-1]
		v, ok := values[name]
		if !ok {
			missing = append(missing, name)
			return m
		}
		used = append(used, name)
		return v
	})
	if len(missing) > 0 {
		return "", nil, fmt.Errorf("unresolved placeholders %v", missing)
	}
	if strings.ContainsAny(rendered, "{}") {
		return "", nil, errors.New("stray braces after render")
	}
	return rendered, used, nil
}

// assertSafeParamValue re-checks a validated value at the compile
// boundary: no wildcards, no whitespace, no variable expansion, no
// control bytes.
func assertSafeParamValue(v string) error {
	if v == "" {
		return errors.New("empty value")
	}
	for _, r := range v {
		if r == '*' || r == '?' {
			return errors.New("value contains a wildcard")
		}
		if unicode.IsSpace(r) {
			return errors.New("value contains whitespace")
		}
		if r < 0x20 || r == 0x7f {
			return errors.New("value contains a control character")
		}
	}
	if strings.Contains(v, "${") {
		return errors.New("value contains ${")
	}
	return nil
}

// assertSafeResource checks a fully rendered Resource entry. A '*' is
// allowed: its position came from the admin template, never from a
// param value.
func assertSafeResource(r string) error {
	if !strings.HasPrefix(r, "arn:") {
		return errors.New("rendered resource is not an ARN")
	}
	if strings.ContainsAny(r, " \t\n?") || strings.Contains(r, "${") {
		return errors.New("rendered resource contains forbidden characters")
	}
	return nil
}
