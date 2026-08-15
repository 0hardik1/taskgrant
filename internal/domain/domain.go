// Package domain holds the shared domain types of taskgrant: the grant
// state machine, denial codes, record kinds, grant identity helpers, and
// the frozen session tag schema. Every other package imports these types;
// this package imports no taskgrant sibling.
package domain

import "strings"

// Session tag keys, frozen per section 8.3 of the architecture. The tag
// set is fixed at four keys because tags share the packed binary budget
// with the session policy.
const (
	// TagKeyAgent carries the broker-authored agent id. Transitive.
	TagKeyAgent = "taskgrant:agent"
	// TagKeyGrant carries the broker-authored grant ULID. Transitive.
	TagKeyGrant = "taskgrant:grant"
	// TagKeyProfile carries the profile name. Not transitive.
	TagKeyProfile = "taskgrant:profile"
	// TagKeyCallerRef carries the agent-supplied correlation id. It is
	// untrusted input and must never appear in an authorization, ABAC,
	// or revocation condition (invariant I3).
	TagKeyCallerRef = "taskgrant:caller_ref"
)

// CallerRefMaxLen is the maximum length of the sanitized caller_ref tag
// value per section 8.3.
const CallerRefMaxLen = 64

// TransitiveTagKeys returns the session tag keys that persist through
// role chaining. The slice is a fresh copy on every call.
func TransitiveTagKeys() []string {
	return []string{TagKeyAgent, TagKeyGrant}
}

// SanitizeCallerRef reduces an agent-supplied correlation id to the
// session tag value charset and caps its length at CallerRefMaxLen.
// Runes outside [A-Za-z0-9 _.:/=+@-] are dropped. The input is hostile
// bytes; the output is safe for an STS session tag value.
func SanitizeCallerRef(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if b.Len() >= CallerRefMaxLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '.' || r == ':' || r == '/' ||
			r == '=' || r == '+' || r == '@' || r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// SanitizeForDisplay strips C0 control bytes (except newline and tab),
// DEL, and ANSI escape sequences (CSI and OSC) from a string. Call it on
// every human-facing render of agent-supplied text such as task, reason,
// and caller_ref (section 12.5). Raw bytes stay untouched in storage;
// only the rendered view is cleaned.
func SanitizeForDisplay(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == 0x1b: // ESC: skip the whole escape sequence.
			i = skipEscapeSequence(s, i)
		case c == '\n' || c == '\t':
			b.WriteByte(c)
			i++
		case c < 0x20 || c == 0x7f: // other C0 controls and DEL
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// skipEscapeSequence returns the index just past the escape sequence
// that starts at s[i] (s[i] is ESC).
func skipEscapeSequence(s string, i int) int {
	i++ // consume ESC
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '[': // CSI: parameters, then one final byte in 0x40..0x7e.
		i++
		for i < len(s) {
			if s[i] >= 0x40 && s[i] <= 0x7e {
				return i + 1
			}
			i++
		}
		return i
	case ']': // OSC: terminated by BEL or ST (ESC \).
		i++
		for i < len(s) {
			if s[i] == 0x07 {
				return i + 1
			}
			if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
			i++
		}
		return i
	default: // two-byte escape such as ESC c
		return i + 1
	}
}
