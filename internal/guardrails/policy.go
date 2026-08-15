package guardrails

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// policyVersion is the only accepted policy language version (G0).
const policyVersion = "2012-10-17"

// bannedStatementFields are the statement elements G0 rejects
// permanently. "Everything except X" is modeled as narrower Allow
// templates, never as NotAction or NotResource; Principal has no place
// in an identity session policy.
var bannedStatementFields = map[string]struct{}{
	"NotAction":    {},
	"NotResource":  {},
	"Principal":    {},
	"NotPrincipal": {},
}

// parsedStatement is one decoded policy statement.
type parsedStatement struct {
	sid       string
	effect    string
	actions   []string // raw patterns as written
	resources []string
	// conditions maps operator -> condition key -> values.
	conditions map[string]map[string][]string
	// expanded holds the canonical enumerated actions after G1.
	expanded []string
}

// parsedPolicy is the decoded document plus every structural problem
// found on the way (all of them feed G0).
type parsedPolicy struct {
	version    string
	statements []parsedStatement
	problems   []string
	// fatal marks a document that did not decode at all; later checks
	// that need statements report fail with a skipped detail.
	fatal bool
}

// parsePolicy decodes hostile policy bytes strictly. It never panics
// and keeps whatever decoded so later checks can still report richly.
func parsePolicy(raw []byte) *parsedPolicy {
	p := &parsedPolicy{}
	if len(bytes.TrimSpace(raw)) == 0 {
		p.fatal = true
		p.problems = append(p.problems, "policy document is empty")
		return p
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var top map[string]json.RawMessage
	if err := dec.Decode(&top); err != nil {
		p.fatal = true
		p.problems = append(p.problems, fmt.Sprintf("policy is not a JSON object: %v", err))
		return p
	}
	if dec.More() {
		p.problems = append(p.problems, "trailing data after the policy document")
	}

	var stmtRaw json.RawMessage
	for key, val := range top {
		switch key {
		case "Version":
			if err := json.Unmarshal(val, &p.version); err != nil {
				p.problems = append(p.problems, "Version is not a string")
			}
		case "Id":
			var id string
			if err := json.Unmarshal(val, &id); err != nil {
				p.problems = append(p.problems, "Id is not a string")
			}
		case "Statement":
			stmtRaw = val
		default:
			p.problems = append(p.problems, fmt.Sprintf("unexpected top-level field %q", key))
		}
	}

	if p.version != policyVersion {
		p.problems = append(p.problems,
			fmt.Sprintf("Version must be %q, got %q", policyVersion, p.version))
	}

	if stmtRaw == nil {
		p.fatal = true
		p.problems = append(p.problems, "policy has no Statement")
		return p
	}

	var stmtList []json.RawMessage
	if err := json.Unmarshal(stmtRaw, &stmtList); err != nil {
		// A single statement object is legal policy JSON.
		stmtList = []json.RawMessage{stmtRaw}
	}
	if len(stmtList) == 0 {
		p.fatal = true
		p.problems = append(p.problems, "Statement list is empty")
		return p
	}

	for i, raw := range stmtList {
		st, probs := parseStatement(i, raw)
		p.statements = append(p.statements, st)
		p.problems = append(p.problems, probs...)
	}
	return p
}

// parseStatement decodes one statement and reports its structural
// problems (banned elements, non-Allow effects, missing pieces).
func parseStatement(idx int, raw json.RawMessage) (parsedStatement, []string) {
	st := parsedStatement{conditions: map[string]map[string][]string{}}
	var problems []string
	at := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf("statement[%d]: %s", idx, fmt.Sprintf(format, args...)))
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		at("not a JSON object: %v", err)
		return st, problems
	}

	for key, val := range fields {
		if _, banned := bannedStatementFields[key]; banned {
			at("banned element %q", key)
			continue
		}
		switch key {
		case "Sid":
			if err := json.Unmarshal(val, &st.sid); err != nil {
				at("Sid is not a string")
			}
		case "Effect":
			if err := json.Unmarshal(val, &st.effect); err != nil {
				at("Effect is not a string")
			}
		case "Action":
			list, err := stringOrList(val)
			if err != nil {
				at("Action: %v", err)
			}
			st.actions = list
		case "Resource":
			list, err := stringOrList(val)
			if err != nil {
				at("Resource: %v", err)
			}
			st.resources = list
		case "Condition":
			cond, errs := parseConditions(val)
			st.conditions = cond
			for _, e := range errs {
				at("Condition: %s", e)
			}
		default:
			at("unexpected field %q", key)
		}
	}

	if st.effect != "Allow" {
		at("Effect must be Allow, got %q", st.effect)
	}
	if len(st.actions) == 0 {
		at("no Action")
	}
	if len(st.resources) == 0 {
		at("no Resource")
	}
	return st, problems
}

// stringOrList decodes a policy element that is a string or a string
// list. Empty lists and empty strings are errors.
func stringOrList(raw json.RawMessage) ([]string, error) {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, fmt.Errorf("empty string")
		}
		return []string{single}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("not a string or string list")
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	for _, s := range list {
		if s == "" {
			return nil, fmt.Errorf("empty string in list")
		}
	}
	return list, nil
}

// parseConditions decodes the Condition block: operator -> key ->
// value(s). Scalar values (string, bool, number) normalize to one
// string; lists keep every element.
func parseConditions(raw json.RawMessage) (map[string]map[string][]string, []string) {
	out := map[string]map[string][]string{}
	var errs []string
	var ops map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ops); err != nil {
		return out, []string{"not an operator map"}
	}
	for op, keys := range ops {
		out[op] = map[string][]string{}
		for key, val := range keys {
			vals, err := conditionValues(val)
			if err != nil {
				errs = append(errs, fmt.Sprintf("operator %q key %q: %v", op, key, err))
				continue
			}
			out[op][key] = vals
		}
	}
	return out, errs
}

// conditionValues normalizes one condition value to strings.
func conditionValues(raw json.RawMessage) ([]string, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	switch t := v.(type) {
	case string:
		return []string{t}, nil
	case bool:
		return []string{fmt.Sprintf("%t", t)}, nil
	case json.Number:
		return []string{t.String()}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, el := range t {
			switch e := el.(type) {
			case string:
				out = append(out, e)
			case bool:
				out = append(out, fmt.Sprintf("%t", e))
			case json.Number:
				out = append(out, e.String())
			default:
				return nil, fmt.Errorf("unsupported value type in list")
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported value type")
	}
}

// checkSTSCharset verifies the whole document satisfies the STS policy
// plaintext charset: tab, linefeed, carriage return, and U+0020 through
// U+00FF. Invalid UTF-8 decodes as U+FFFD and fails.
func checkSTSCharset(raw []byte) []string {
	for i, r := range string(raw) {
		if r == '\t' || r == '\n' || r == '\r' || (r >= 0x20 && r <= 0xFF) {
			continue
		}
		return []string{fmt.Sprintf("character U+%04X at byte %d is outside the STS policy charset", r, i)}
	}
	return nil
}

// mandatoryPinOperators are the operators under which a G5 mandatory
// key (aws:RequestedRegion, aws:ResourceAccount) counts as positively
// pinned. StringLike qualifies only because wildcard values are
// rejected separately; every other operator either negates the
// constraint (StringNotEquals, Null), tolerates key absence
// (...IfExists, ForAllValues:...), or compares non-string semantics.
var mandatoryPinOperators = map[string]struct{}{
	"StringEquals":           {},
	"StringEqualsIgnoreCase": {},
	"StringLike":             {},
}

// operators returns the statement's condition operators, sorted and
// deduplicated.
func (st *parsedStatement) operators() []string {
	out := make([]string, 0, len(st.conditions))
	for op := range st.conditions {
		out = append(out, op)
	}
	sort.Strings(out)
	return out
}

// hasConditionKey reports whether the key appears under any operator,
// matching case-insensitively.
func (st *parsedStatement) hasConditionKey(key string) bool {
	lk := strings.ToLower(key)
	for _, keys := range st.conditions {
		for k := range keys {
			if strings.ToLower(k) == lk {
				return true
			}
		}
	}
	return false
}

// constrainingConditionValues returns the values of the given key
// collected only from operator entries that positively pin it: an
// equality-style string operator whose values are all non-empty and
// free of glob metacharacters. Values under any other operator or
// shape never satisfy a G5 mandate; a negating or absence-tolerant
// operator inverts the constraint and a wildcard value removes it, so
// key presence alone proves nothing (anchor rule 2: the broker
// re-verifies the seam and trusts nothing about the synthesizer).
func (st *parsedStatement) constrainingConditionValues(key string) []string {
	lk := strings.ToLower(key)
	var out []string
	for op, keys := range st.conditions {
		if _, ok := mandatoryPinOperators[op]; !ok {
			continue
		}
		for k, vals := range keys {
			if strings.ToLower(k) != lk || len(vals) == 0 {
				continue
			}
			pinned := true
			for _, v := range vals {
				if v == "" || strings.ContainsAny(v, "*?") {
					pinned = false
					break
				}
			}
			if pinned {
				out = append(out, vals...)
			}
		}
	}
	sort.Strings(out)
	return out
}

// conditionKeys returns every condition key of the statement, sorted
// and deduplicated.
func (st *parsedStatement) conditionKeys() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, keys := range st.conditions {
		for k := range keys {
			if _, dup := seen[k]; !dup {
				seen[k] = struct{}{}
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// servicesOf returns the lowercase service prefixes of enumerated
// actions, sorted and deduplicated.
func servicesOf(actions []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, a := range actions {
		svc, _, ok := strings.Cut(a, ":")
		if !ok {
			continue
		}
		svc = strings.ToLower(svc)
		if _, dup := seen[svc]; !dup {
			seen[svc] = struct{}{}
			out = append(out, svc)
		}
	}
	sort.Strings(out)
	return out
}

// accountFieldWildcard reports whether an ARN's account field carries a
// glob, leaving the owning account unpinned by the resource itself. G5
// then demands aws:ResourceAccount independently of any seam-reported
// provenance; the conforming compiler injects the condition in exactly
// the same case. Non-ARN strings (including Resource "*", which G4
// gates separately) report false.
func accountFieldWildcard(resource string) bool {
	parts := strings.SplitN(resource, ":", 6)
	if len(parts) != 6 {
		return false
	}
	return strings.ContainsAny(parts[4], "*?")
}

// arnPatternMatch reports whether the rendered resource matches one
// admin allowlist pattern. Both sides split into the six ARN fields
// (arn:partition:service:region:account:resource) before any glob runs,
// so a glob in one field can never consume a separator and cross the
// partition or account fields (G4). The final resource field keeps any
// embedded colons and globs may span them; the identity fields are
// already fixed by then.
func arnPatternMatch(pattern, resource string) bool {
	pf := strings.SplitN(pattern, ":", 6)
	rf := strings.SplitN(resource, ":", 6)
	if len(pf) != 6 || len(rf) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if !globMatch(pf[i], rf[i]) {
			return false
		}
	}
	return true
}

// globMatch matches s against pattern where '*' matches any byte
// sequence and '?' matches exactly one byte. Case-sensitive: ARNs are.
// Iterative with backtracking.
func globMatch(pattern, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			mark = si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
