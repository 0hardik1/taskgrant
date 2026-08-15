package catalog

import "strings"

// globMatch matches s against pattern where '*' matches any byte
// sequence. There is no '?' support: catalog grammars and allowlists
// never admit it. Matching is case-sensitive; ARNs and most AWS
// resource names are case-sensitive.
func globMatch(pattern, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			mark = si
			pi++
		case pi < len(pattern) && pattern[pi] == s[si]:
			pi++
			si++
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

// globCovers reports whether every string matched by the inner glob is
// also matched by the outer glob. Both are '*' globs. The recurrence:
// a '*' in outer may absorb any leading symbol of inner, including an
// inner '*'; an inner '*' can only be absorbed by an outer '*',
// because it generates strings no literal can bound.
func globCovers(outer, inner string) bool {
	type key struct{ o, i int }
	memo := make(map[key]int) // 1 true, 2 false
	var rec func(o, i int) bool
	rec = func(o, i int) bool {
		k := key{o, i}
		if v, ok := memo[k]; ok {
			return v == 1
		}
		var res bool
		switch {
		case o == len(outer) && i == len(inner):
			res = true
		case o == len(outer):
			res = false
		case outer[o] == '*':
			res = rec(o+1, i) || (i < len(inner) && rec(o, i+1))
		case i == len(inner):
			res = false
		case inner[i] == '*':
			res = false
		default:
			res = outer[o] == inner[i] && rec(o+1, i+1)
		}
		if res {
			memo[k] = 1
		} else {
			memo[k] = 2
		}
		return res
	}
	return rec(0, 0)
}

// arnFieldCount is the number of colon-separated fields an ARN pattern
// must present: arn, partition, service, region, account, resource.
const arnFieldCount = 6

// arnCovers reports whether the outer ARN glob pattern covers the
// inner ARN glob pattern field-wise: the first five fields are matched
// independently so a glob never crosses the partition, service,
// region, or account boundary (G4), and the resource field is covered
// as one glob.
func arnCovers(outer, inner string) bool {
	op, ok := splitARNPattern(outer)
	if !ok {
		return false
	}
	ip, ok := splitARNPattern(inner)
	if !ok {
		return false
	}
	for f := 0; f < arnFieldCount; f++ {
		if !globCovers(op[f], ip[f]) {
			return false
		}
	}
	return true
}

// arnMatches reports whether the concrete ARN value matches the ARN
// glob pattern field-wise, with the same no-field-crossing rule as
// arnCovers.
func arnMatches(pattern, value string) bool {
	pp, ok := splitARNPattern(pattern)
	if !ok {
		return false
	}
	vp, ok := splitARNPattern(value)
	if !ok {
		return false
	}
	for f := 0; f < arnFieldCount; f++ {
		if !globMatch(pp[f], vp[f]) {
			return false
		}
	}
	return true
}

// splitARNPattern splits an ARN pattern into six fields.
func splitARNPattern(s string) ([]string, bool) {
	parts := strings.SplitN(s, ":", arnFieldCount)
	if len(parts) != arnFieldCount || parts[0] != "arn" {
		return nil, false
	}
	return parts, true
}

// collapseStars rewrites every run of consecutive '*' to a single '*'.
// Worst-case rendering can abut a param wildcard against a template
// wildcard; the collapsed form is equivalent and easier to read in
// error messages.
func collapseStars(s string) string {
	if !strings.Contains(s, "**") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prevStar := false
	for i := 0; i < len(s); i++ {
		if s[i] == '*' {
			if prevStar {
				continue
			}
			prevStar = true
		} else {
			prevStar = false
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
