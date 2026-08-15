package catalog

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxRawParamLen caps a raw parameter value before any other check
// runs. Values are hostile bytes; the cap bounds all later work.
const maxRawParamLen = 1024

// Base grammar bounds per param type. These always apply in addition
// to the admin pattern or allowlist, so a lax admin pattern can never
// widen the boundary beyond them.
const (
	maxARNComponentLen = 128
	maxPathPrefixLen   = 512
	maxIdentifierLen   = 128
)

// ValidatedParam is one parameter value that passed grammar and
// allowlist validation. Value is exactly the agent-supplied bytes: no
// wildcard is ever present, because a value-supplied '*' is rejected
// (section 5.2). Resource templates alone control where a wildcard is
// emitted.
type ValidatedParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// TrailingWildcard is retained for record compatibility and is always
	// false: an agent value can no longer carry a trailing '*'. The
	// wildcard is authored by the resource template, not the value.
	TrailingWildcard bool `json:"trailing_wildcard,omitempty"`
	// FromWildcardEntry records that the value matched a wildcard
	// allowlist entry rather than an exact one. The compiler injects
	// aws:ResourceAccount on statements built from such values (G5).
	FromWildcardEntry bool `json:"from_wildcard_entry,omitempty"`
}

// ParamError reports one missing or invalid parameter. The Reason text
// is built from admin-authored shapes only and never echoes raw agent
// bytes, so it is safe on every surface.
type ParamError struct {
	Capability string
	Param      string
	// Missing distinguishes MISSING_PARAM from INVALID_PARAM.
	Missing bool
	Reason  string
}

// Error implements error.
func (e *ParamError) Error() string {
	kind := "invalid"
	if e.Missing {
		kind = "missing"
	}
	return fmt.Sprintf("capability %s: param %s: %s: %s", e.Capability, e.Param, kind, e.Reason)
}

// ValidateParams validates raw agent-supplied values against one
// visible capability's declared params. Every declared param is
// required; unknown params are rejected. The first violation is
// returned as a *ParamError so callers can map it to MISSING_PARAM or
// INVALID_PARAM. Params are checked in sorted name order for
// deterministic errors (invariant I6).
func (s *Snapshot) ValidateParams(capID string, raw map[string]string) (map[string]ValidatedParam, error) {
	c, ok := s.caps[capID]
	if !ok {
		return nil, fmt.Errorf("capability %q is not in the catalog", capID)
	}

	for name := range raw {
		if _, declared := c.Params[name]; !declared {
			return nil, &ParamError{
				Capability: capID,
				Param:      sanitizeName(name),
				Reason:     "not a declared parameter of this capability",
			}
		}
	}

	out := make(map[string]ValidatedParam, len(c.Params))
	for _, name := range c.ParamNames() {
		p := c.Params[name]
		rawVal, present := raw[name]
		if !present || rawVal == "" {
			return nil, &ParamError{
				Capability: capID,
				Param:      name,
				Missing:    true,
				Reason:     "expected " + p.ExpectedShape(),
			}
		}
		vp, perr := s.validateOne(capID, p, rawVal)
		if perr != nil {
			return nil, perr
		}
		out[name] = vp
	}
	return out, nil
}

// validateOne validates a single raw value against one param.
func (s *Snapshot) validateOne(capID string, p *Param, raw string) (ValidatedParam, *ParamError) {
	invalid := func(reason string) (ValidatedParam, *ParamError) {
		return ValidatedParam{}, &ParamError{
			Capability: capID,
			Param:      p.Name,
			Reason:     reason + "; expected " + p.ExpectedShape(),
		}
	}

	if len(raw) > maxRawParamLen {
		return invalid(fmt.Sprintf("longer than %d bytes", maxRawParamLen))
	}
	if !utf8.ValidString(raw) {
		return invalid("not valid UTF-8")
	}

	value := raw
	if value == "" {
		return invalid("empty value")
	}

	// The emitted trailing wildcard is authored by the resource template
	// ('{prefix}*'), never by the agent value. AllowTrailingWildcard only
	// records that the template appends a wildcard; the value itself must
	// never carry '*' (or '?'). A value-supplied wildcard is rejected
	// below like any other forbidden character, so an agent can never
	// widen its own resource scope by injecting a '*' (section 5.2,
	// invariant I1). It is not stripped and silently normalized.
	//
	// Forbidden characters, independent of any admin pattern: the
	// grammar layer of invariant I1.
	for _, r := range value {
		if r == '*' || r == '?' {
			return invalid("contains a wildcard character")
		}
		if unicode.IsSpace(r) {
			return invalid("contains whitespace")
		}
		if r < 0x20 || r == 0x7f {
			return invalid("contains a control character")
		}
	}
	if strings.Contains(value, "${") {
		return invalid("contains ${")
	}

	// Base grammar for the param type.
	if reason, ok := checkBaseGrammar(p.Type, value); !ok {
		return invalid(reason)
	}

	// Admin pattern.
	if p.re != nil && !p.re.MatchString(value) {
		return invalid("does not match the pattern")
	}

	// Allowlist membership: exact entries first, then wildcard
	// entries. A wildcard-entry match is recorded for G5 injection.
	fromWildcard := false
	if p.AllowlistRef != "" {
		entries := s.allowlists[p.AllowlistRef]
		matched := false
		for _, e := range entries {
			if !strings.Contains(e, "*") && e == value {
				matched = true
				break
			}
		}
		if !matched {
			for _, e := range entries {
				if strings.Contains(e, "*") && globMatch(e, value) {
					matched = true
					fromWildcard = true
					break
				}
			}
		}
		if !matched {
			return invalid("not on the " + p.AllowlistRef + " allowlist")
		}
	}

	return ValidatedParam{
		Name:              p.Name,
		Value:             value,
		FromWildcardEntry: fromWildcard,
	}, nil
}

// checkBaseGrammar applies the built-in per-type grammar.
func checkBaseGrammar(t ParamType, value string) (string, bool) {
	switch t {
	case ParamARNComponent:
		if len(value) > maxARNComponentLen {
			return fmt.Sprintf("longer than %d characters", maxARNComponentLen), false
		}
		for i := 0; i < len(value); i++ {
			if !isARNComponentByte(value[i]) {
				return "contains a character outside the arn_component charset", false
			}
		}
	case ParamPathPrefix:
		if len(value) > maxPathPrefixLen {
			return fmt.Sprintf("longer than %d characters", maxPathPrefixLen), false
		}
		for i := 0; i < len(value); i++ {
			if !isPathPrefixByte(value[i]) {
				return "contains a character outside the path_prefix charset", false
			}
		}
	case ParamIdentifier:
		if len(value) > maxIdentifierLen {
			return fmt.Sprintf("longer than %d characters", maxIdentifierLen), false
		}
		for i := 0; i < len(value); i++ {
			if !isIdentifierByte(value[i]) {
				return "contains a character outside the identifier charset", false
			}
		}
	default:
		return "unknown param type", false
	}
	return "", true
}

// isARNComponentByte: one ARN field component; no '/', ':', or any
// glob or expansion character. ASCII only, so unicode homoglyphs are
// rejected wholesale.
func isARNComponentByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_' || c == '.' || c == '=' || c == '@' || c == ',' || c == '-':
		return true
	}
	return false
}

// isPathPrefixByte: slash-separated path text such as S3 key prefixes
// and log group names. No ':', so a value can never cross ARN fields.
func isPathPrefixByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_' || c == '/' || c == '.' || c == '=' || c == '+' ||
		c == ',' || c == '@' || c == '#' || c == '-':
		return true
	}
	return false
}

// isIdentifierByte: bare resource identifiers.
func isIdentifierByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_' || c == '.' || c == '-':
		return true
	}
	return false
}

// sanitizeName reduces an agent-supplied param name to a safe display
// form for error text: ASCII alphanumerics, '_', '-' kept, everything
// else dropped, capped at 32 bytes.
func sanitizeName(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 32; i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// MissingParamNames returns the declared params of capID absent from
// raw, sorted. A convenience for clarification payloads.
func (s *Snapshot) MissingParamNames(capID string, raw map[string]string) []string {
	c, ok := s.caps[capID]
	if !ok {
		return nil
	}
	var missing []string
	for name := range c.Params {
		if v, present := raw[name]; !present || v == "" {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}
