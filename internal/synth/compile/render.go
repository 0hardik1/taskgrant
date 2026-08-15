package compile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// docPrefix and docSuffix frame the canonical minified document. The
// document is assembled from individually rendered statements so the
// per-statement byte sizes used for attribution are exact.
const (
	docPrefix = `{"Version":"` + PolicyVersion + `","Statement":[`
	docSuffix = `]}`
)

// stmtJSON is the wire form of one statement. Field order is the
// canonical order; encoding/json emits struct fields in declaration
// order and sorts map keys, which makes the output byte-stable
// (invariant I6).
type stmtJSON struct {
	Sid       string                    `json:"Sid,omitempty"`
	Effect    string                    `json:"Effect"`
	Action    any                       `json:"Action"`
	Resource  any                       `json:"Resource"`
	Condition map[string]map[string]any `json:"Condition,omitempty"`
}

// renderPolicy emits the canonical minified policy document and the
// byte size of each rendered statement. Statements keep their build
// order: selections are sorted by capability id before building, so
// the order is canonical. Zero statements render to nil.
func renderPolicy(stmts []*stmt, withSids bool) ([]byte, []int, error) {
	if len(stmts) == 0 {
		return nil, nil, nil
	}
	var buf bytes.Buffer
	buf.WriteString(docPrefix)
	sizes := make([]int, len(stmts))
	ordinals := make(map[string]int)
	for i, s := range stmts {
		sid := ""
		if withSids {
			sid = sidFor(s.capID, ordinals[s.capID])
			ordinals[s.capID]++
		}
		b, err := renderStatement(s, sid)
		if err != nil {
			return nil, nil, err
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(b)
		sizes[i] = len(b)
	}
	buf.WriteString(docSuffix)
	return buf.Bytes(), sizes, nil
}

// renderStatement emits one canonical minified statement object. An
// empty sid omits the Sid member.
func renderStatement(s *stmt, sid string) ([]byte, error) {
	js := stmtJSON{
		Sid:      sid,
		Effect:   "Allow",
		Action:   scalarOrList(s.actions),
		Resource: scalarOrList(s.resources),
	}
	if len(s.conds) > 0 {
		cond := make(map[string]map[string]any, len(s.conds))
		for op, keys := range s.conds {
			m := make(map[string]any, len(keys))
			for k, vals := range keys {
				sorted := append([]string(nil), vals...)
				sort.Strings(sorted)
				m[k] = scalarOrList(sorted)
			}
			cond[op] = m
		}
		js.Condition = cond
	}
	return marshalCompact(js)
}

// scalarOrList renders a one-element list as its scalar, the compact
// IAM idiom; longer lists stay lists. Both forms are deterministic.
func scalarOrList(vals []string) any {
	if len(vals) == 1 {
		return vals[0]
	}
	return vals
}

// marshalCompact marshals without HTML escaping and without the
// trailing newline json.Encoder appends.
func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("render policy: %w", err)
	}
	b := buf.Bytes()
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	return b, nil
}
