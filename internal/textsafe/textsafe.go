// Package textsafe renders untrusted agent bytes safely on human-facing
// surfaces (architecture section 12.5). Agent-supplied strings such as
// task, reason, notes, and caller_ref can carry ANSI/C0 control
// sequences that repaint an approver's terminal. Storage keeps the raw
// bytes; every human-facing render passes through this package first.
//
// The single string sanitizer lives in internal/domain
// (SanitizeForDisplay) so there is exactly one implementation; this
// package re-exports it and adds helpers for whole JSON payloads and
// display truncation.
package textsafe

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// Sanitize strips C0 control bytes (except newline and tab), DEL, and
// ANSI escape sequences (CSI and OSC) from s. Call it on every
// human-facing render of agent-supplied text.
func Sanitize(s string) string { return domain.SanitizeForDisplay(s) }

// Truncate caps s at max runes for display. When the string is cut, the
// last three runes of the budget become "..." so the cut is visible.
// max values below 4 return at most max runes with no marker.
func Truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	if max < 4 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

// SanitizeValue walks a decoded JSON value (as produced by
// encoding/json into any) and sanitizes every string in it, including
// map keys. Numbers, booleans, nulls, and json.Number pass through
// untouched. The input value is not mutated; a cleaned copy is
// returned.
func SanitizeValue(v any) any {
	switch t := v.(type) {
	case string:
		return Sanitize(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[Sanitize(k)] = SanitizeValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = SanitizeValue(vv)
		}
		return out
	default:
		return v
	}
}

// SanitizeJSON re-encodes a JSON document with every string sanitized.
// Number precision is preserved via json.Number. Invalid JSON returns
// an error; callers decide whether to drop or replace the payload.
func SanitizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(SanitizeValue(v))
}
