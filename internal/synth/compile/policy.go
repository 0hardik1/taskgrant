package compile

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/0hardik1/taskgrant/internal/synth"
)

// stmt is one policy statement in the AST, tagged with the capability
// that produced it so explanations and byte attribution survive every
// ladder step.
type stmt struct {
	capID      string
	capVersion int
	summary    string
	explParams map[string]string
	actions    []string // sorted canonical action names
	resources  []string // sorted rendered ARNs
	// conds maps operator to key to values.
	conds      map[string]map[string][]string
	managed    bool
	managedARN string
}

// addCond appends one condition value, deduplicating and keeping
// values sorted.
func (s *stmt) addCond(op, key, value string) {
	if s.conds[op] == nil {
		s.conds[op] = make(map[string][]string)
	}
	vals := s.conds[op][key]
	for _, v := range vals {
		if v == value {
			return
		}
	}
	vals = append(vals, value)
	sort.Strings(vals)
	s.conds[op][key] = vals
}

// hasCondKey reports whether any operator already carries the key,
// case-insensitively.
func (s *stmt) hasCondKey(key string) bool {
	lk := strings.ToLower(key)
	for _, keys := range s.conds {
		for k := range keys {
			if strings.ToLower(k) == lk {
				return true
			}
		}
	}
	return false
}

// identityKey is the canonical byte form of the statement without its
// Sid, used for cross-capability dedupe and merge grouping.
func (s *stmt) identityKey() string {
	b, err := renderStatement(s, "")
	if err != nil {
		// Statements are built from validated parts; a render failure
		// here is a programming error surfaced by Render anyway. Use a
		// non-colliding key.
		return "err:" + s.capID + ":" + strings.Join(s.actions, ",")
	}
	return string(b)
}

// resourceCondKey is the canonical byte form of Resource plus
// Condition only, used by the merge step.
func (s *stmt) resourceCondKey() string {
	clone := &stmt{resources: s.resources, conds: s.conds}
	b, err := renderStatement(clone, "")
	if err != nil {
		return "err:" + strings.Join(s.resources, ",")
	}
	return string(b)
}

// sidFor derives the statement Sid: "Tg" plus the capability id
// camelized to the Sid charset, plus the per-capability ordinal.
func sidFor(capID string, ordinal int) string {
	var b strings.Builder
	b.WriteString("Tg")
	upper := true
	for _, r := range capID {
		switch {
		case r >= 'a' && r <= 'z':
			if upper {
				b.WriteRune(unicode.ToUpper(r))
			} else {
				b.WriteRune(r)
			}
			upper = false
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			upper = false
		default:
			upper = true
		}
	}
	b.WriteString(strconv.Itoa(ordinal))
	return b.String()
}

// Policy is the mutable policy AST the reduction ladder operates on.
// Every step is deterministic; the zero value is unusable, build one
// through Compiler.Compile.
type Policy struct {
	stmts      []*stmt
	withSids   bool
	policyArns []string
}

// dedupeIdentical removes byte-identical statements across
// capabilities (section 7.2), keeping the first occurrence in
// canonical order. The survivor's capability owns the statement for
// explanation and attribution.
func (p *Policy) dedupeIdentical() {
	seen := make(map[string]struct{})
	kept := p.stmts[:0]
	for _, s := range p.stmts {
		k := s.identityKey()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		kept = append(kept, s)
	}
	p.stmts = kept
}

// Merge is reduction ladder step 2: statements of the same capability
// with identical Resource and Condition merge into one, their Action
// lists unioned. Merging stays within a capability so every statement
// still traces to exactly one capability in the explanation. It
// reports whether anything changed.
func (p *Policy) Merge() bool {
	type bucket struct{ first *stmt }
	byKey := make(map[string]*bucket)
	kept := p.stmts[:0]
	changed := false
	for _, s := range p.stmts {
		key := s.capID + "\x00" + s.resourceCondKey()
		if b, ok := byKey[key]; ok {
			merged := make(map[string]struct{}, len(b.first.actions)+len(s.actions))
			for _, a := range b.first.actions {
				merged[a] = struct{}{}
			}
			for _, a := range s.actions {
				merged[a] = struct{}{}
			}
			union := make([]string, 0, len(merged))
			for a := range merged {
				union = append(union, a)
			}
			sort.Strings(union)
			b.first.actions = union
			changed = true
			continue
		}
		byKey[key] = &bucket{first: s}
		kept = append(kept, s)
	}
	p.stmts = kept
	return changed
}

// DropSids is reduction ladder step 3: Sids leave the rendered
// document; the explanation maps by index. It reports whether Sids
// were present.
func (p *Policy) DropSids() bool {
	had := p.withSids
	p.withSids = false
	return had
}

// OffloadManaged is reduction ladder step 4: every statement of a
// managed_policy capability leaves the inline policy and the
// capability's pre-provisioned managed policy ARN joins PolicyArns,
// bounded by maxArns. Capabilities offload in sorted id order for
// determinism. It reports whether anything was offloaded.
func (p *Policy) OffloadManaged(maxArns int) bool {
	if maxArns <= 0 {
		return false
	}
	// Collect offload candidates in sorted capability order.
	arnByCap := make(map[string]string)
	for _, s := range p.stmts {
		if s.managed && s.managedARN != "" {
			arnByCap[s.capID] = s.managedARN
		}
	}
	if len(arnByCap) == 0 {
		return false
	}
	capIDs := make([]string, 0, len(arnByCap))
	for id := range arnByCap {
		capIDs = append(capIDs, id)
	}
	sort.Strings(capIDs)

	offload := make(map[string]struct{})
	arnSet := make(map[string]struct{}, len(p.policyArns))
	for _, a := range p.policyArns {
		arnSet[a] = struct{}{}
	}
	for _, id := range capIDs {
		arn := arnByCap[id]
		if _, have := arnSet[arn]; have {
			offload[id] = struct{}{}
			continue
		}
		if len(arnSet) >= maxArns {
			break
		}
		arnSet[arn] = struct{}{}
		offload[id] = struct{}{}
	}
	if len(offload) == 0 {
		return false
	}

	kept := p.stmts[:0]
	for _, s := range p.stmts {
		if _, off := offload[s.capID]; off {
			continue
		}
		kept = append(kept, s)
	}
	p.stmts = kept

	arns := make([]string, 0, len(arnSet))
	for a := range arnSet {
		arns = append(arns, a)
	}
	sort.Strings(arns)
	p.policyArns = arns
	return true
}

// Render emits the canonical minified document plus per-statement byte
// sizes (for attribution). A policy with zero statements renders to
// nil.
func (p *Policy) Render() ([]byte, []int, error) {
	return renderPolicy(p.stmts, p.withSids)
}

// attribution sums the final per-statement byte sizes per capability.
func (p *Policy) attribution(sizes []int) map[string]int {
	out := make(map[string]int)
	for i, s := range p.stmts {
		if i < len(sizes) {
			out[s.capID] += sizes[i]
		}
	}
	return out
}

// explanation builds the index-parallel explanation for the current
// inline statements. Reasons render from the admin-authored capability
// summary plus the validated params, never from agent text.
func (p *Policy) explanation() synth.Explanation {
	var ex synth.Explanation
	for _, s := range p.stmts {
		ex.Statements = append(ex.Statements, synth.StatementExplanation{
			CapabilityID:      s.capID,
			CapabilityVersion: s.capVersion,
			Params:            s.explParams,
			Reason:            renderReason(s.summary, s.explParams),
		})
	}
	return ex
}

// renderReason renders the deterministic template-based reason string.
func renderReason(summary string, params map[string]string) string {
	if len(params) == 0 {
		return summary
	}
	names := make([]string, 0, len(params))
	for n := range params {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(summary)
	b.WriteString(" (")
	for i, n := range names {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(n)
		b.WriteString("=")
		b.WriteString(params[n])
	}
	b.WriteString(")")
	return b.String()
}
