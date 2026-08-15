// Package dataset loads and queries the pinned trimmed iam-dataset
// artifact (architecture section 5.3). The artifact is the ground truth
// for IAM action existence, access levels, resource types, and
// condition keys. It is hash-pinned: the synthesizer and the guardrail
// evaluator load the same file and assert the same hash, so a silent
// upstream change can never change enforcement.
package dataset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// SupportedSchemaVersion is the artifact schema this build understands.
const SupportedSchemaVersion = 1

// AccessLevel is the Service Authorization Reference access level of
// one IAM action.
type AccessLevel string

const (
	AccessRead                  AccessLevel = "Read"
	AccessList                  AccessLevel = "List"
	AccessWrite                 AccessLevel = "Write"
	AccessTagging               AccessLevel = "Tagging"
	AccessPermissionsManagement AccessLevel = "Permissions management"
)

// Valid reports whether l is a known access level.
func (l AccessLevel) Valid() bool {
	switch l {
	case AccessRead, AccessList, AccessWrite, AccessTagging, AccessPermissionsManagement:
		return true
	}
	return false
}

// String returns the wire form of the access level.
func (l AccessLevel) String() string { return string(l) }

// ErrUnknownAction marks a lookup or expansion that named an action the
// pinned dataset does not contain. Callers must fail closed on it.
var ErrUnknownAction = errors.New("action not in pinned dataset")

// ErrNoMatch marks a wildcard pattern that expands to zero actions.
// Callers must fail closed on it.
var ErrNoMatch = errors.New("pattern matches no action in pinned dataset")

// ActionInfo is the metadata of one IAM action.
type ActionInfo struct {
	// Action is the canonical "service:ActionName" form as shipped in
	// the artifact.
	Action string `json:"action"`
	// AccessLevel is the SAR access level. It informs; it is not solely
	// trusted. The escalation denylist applies regardless of it.
	AccessLevel AccessLevel `json:"access_level"`
	// ResourceTypes lists the resource types the action accepts. Empty
	// means the action takes no resource type, so a policy statement
	// for it needs Resource "*" (G4 gates that on capability opt-in).
	ResourceTypes []string `json:"resource_types"`
	// ConditionKeys lists the condition keys the action supports.
	// Templated keys keep their template form, for example
	// "aws:ResourceTag/${TagKey}" or "s3:ExistingObjectTag/<key>". Use
	// Dataset.SupportsConditionKey to test a concrete key against them.
	ConditionKeys []string `json:"condition_keys"`
}

// Dataset is one loaded, hash-pinned artifact. It is immutable after
// load and safe for concurrent use.
type Dataset struct {
	schemaVersion int
	sourceCommit  string
	hash          string
	actions       map[string]ActionInfo // key: lowercase "service:action"
	names         []string              // canonical names, sorted
}

// fileModel is the JSON wire form of the artifact.
type fileModel struct {
	SchemaVersion int                        `json:"schema_version"`
	SourceCommit  string                     `json:"source_commit"`
	Actions       map[string]fileActionModel `json:"actions"`
}

type fileActionModel struct {
	AccessLevel   string   `json:"access_level"`
	ResourceTypes []string `json:"resource_types"`
	ConditionKeys []string `json:"condition_keys"`
}

// Load reads and validates the artifact at path and records its SHA-256
// hash.
func Load(path string) (*Dataset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dataset: %w", err)
	}
	d, err := LoadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("dataset %s: %w", path, err)
	}
	return d, nil
}

// LoadBytes parses and validates artifact bytes. The recorded hash is
// the SHA-256 of the raw bytes exactly as given.
func LoadBytes(data []byte) (*Dataset, error) {
	sum := sha256.Sum256(data)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m fileModel
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse dataset: %w", err)
	}
	if m.SchemaVersion != SupportedSchemaVersion {
		return nil, fmt.Errorf("dataset schema_version %d is not supported (want %d)",
			m.SchemaVersion, SupportedSchemaVersion)
	}
	if m.SourceCommit == "" {
		return nil, errors.New("dataset source_commit is empty")
	}
	if len(m.Actions) == 0 {
		return nil, errors.New("dataset holds no actions")
	}

	d := &Dataset{
		schemaVersion: m.SchemaVersion,
		sourceCommit:  m.SourceCommit,
		hash:          hex.EncodeToString(sum[:]),
		actions:       make(map[string]ActionInfo, len(m.Actions)),
		names:         make([]string, 0, len(m.Actions)),
	}
	for name, a := range m.Actions {
		service, action, ok := strings.Cut(name, ":")
		if !ok || service == "" || action == "" {
			return nil, fmt.Errorf("action %q lacks a service:action form", name)
		}
		lvl := AccessLevel(a.AccessLevel)
		if !lvl.Valid() {
			return nil, fmt.Errorf("action %q has unknown access level %q", name, a.AccessLevel)
		}
		key := strings.ToLower(name)
		if _, dup := d.actions[key]; dup {
			return nil, fmt.Errorf("action %q appears twice (case collision)", name)
		}
		d.actions[key] = ActionInfo{
			Action:        name,
			AccessLevel:   lvl,
			ResourceTypes: append([]string(nil), a.ResourceTypes...),
			ConditionKeys: append([]string(nil), a.ConditionKeys...),
		}
		d.names = append(d.names, name)
	}
	sort.Strings(d.names)
	return d, nil
}

// Hash returns the SHA-256 hex of the raw artifact bytes. It goes into
// every decision record.
func (d *Dataset) Hash() string { return d.hash }

// SourceCommit returns the upstream iam-dataset commit the artifact was
// trimmed from.
func (d *Dataset) SourceCommit() string { return d.sourceCommit }

// SchemaVersion returns the artifact schema version.
func (d *Dataset) SchemaVersion() int { return d.schemaVersion }

// Len returns the number of actions in the artifact.
func (d *Dataset) Len() int { return len(d.names) }

// Actions returns every canonical action name, sorted. Fresh copy.
func (d *Dataset) Actions() []string {
	return append([]string(nil), d.names...)
}

// Lookup returns the metadata for one action. Matching is
// case-insensitive, mirroring IAM policy evaluation. The returned
// ActionInfo carries copies, so callers cannot mutate the dataset.
func (d *Dataset) Lookup(action string) (ActionInfo, bool) {
	info, ok := d.actions[strings.ToLower(strings.TrimSpace(action))]
	if !ok {
		return ActionInfo{}, false
	}
	info.ResourceTypes = append([]string(nil), info.ResourceTypes...)
	info.ConditionKeys = append([]string(nil), info.ConditionKeys...)
	return info, true
}

// validPatternRE bounds the charset of an action pattern before any
// matching runs. Patterns are untrusted input by the time guardrails
// see them (a non-conforming synthesizer could emit anything).
var validPatternRE = regexp.MustCompile(`^[A-Za-z0-9_*?:-]{1,128}$`)

// Expand resolves one action pattern against the dataset and fails
// closed on anything unknown:
//
//   - A literal action must exist; otherwise ErrUnknownAction.
//   - A wildcard pattern ("*" and "?" glob, case-insensitive) returns
//     every matching action, sorted; zero matches is ErrNoMatch.
//
// The results are canonical action names, so all later guardrail checks
// run on real enumerated actions (G1) and a wildcard that spans an
// escalation action cannot hide behind its literal string.
func (d *Dataset) Expand(pattern string) ([]string, error) {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return nil, errors.New("empty action pattern")
	}
	if !validPatternRE.MatchString(p) {
		return nil, fmt.Errorf("action pattern %q has invalid characters", pattern)
	}
	if !strings.ContainsAny(p, "*?") {
		info, ok := d.Lookup(p)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownAction, pattern)
		}
		return []string{info.Action}, nil
	}
	lp := strings.ToLower(p)
	var matches []string
	for _, name := range d.names {
		if globMatch(lp, strings.ToLower(name)) {
			matches = append(matches, name)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoMatch, pattern)
	}
	return matches, nil
}

// ExpandAll expands every pattern, deduplicates, and sorts. Any single
// failure fails the whole call (fail closed).
func (d *Dataset) ExpandAll(patterns []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	for _, p := range patterns {
		expanded, err := d.Expand(p)
		if err != nil {
			return nil, err
		}
		for _, a := range expanded {
			if _, dup := seen[a]; !dup {
				seen[a] = struct{}{}
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Global condition keys AWS supports on every action. G5 injects
// aws:RequestedRegion and aws:ResourceAccount into statements, so they
// must always test as supported even when a trimmed per-action key list
// does not repeat them.
var globalConditionKeys = map[string]struct{}{
	"aws:requestedregion":  {},
	"aws:resourceaccount":  {},
	"aws:sourceidentity":   {},
	"aws:tokenissuetime":   {},
	"aws:principalarn":     {},
	"aws:principalaccount": {},
	"aws:securetransport":  {},
}

// SupportsConditionKey reports whether the action supports the given
// concrete condition key. It handles three shapes, all
// case-insensitive:
//
//   - exact keys, for example "s3:prefix";
//   - templated keys in the artifact, for example
//     "aws:ResourceTag/${TagKey}" or "s3:ExistingObjectTag/<key>",
//     which a concrete key such as "aws:ResourceTag/env" satisfies;
//   - the always-available global keys (aws:RequestedRegion and
//     friends), supported for every known action.
//
// An unknown action supports nothing (fail closed).
func (d *Dataset) SupportsConditionKey(action, key string) bool {
	info, ok := d.Lookup(action)
	if !ok {
		return false
	}
	lk := strings.ToLower(key)
	if _, ok := globalConditionKeys[lk]; ok {
		return true
	}
	if lk == "aws:principaltag" || strings.HasPrefix(lk, "aws:principaltag/") {
		return true
	}
	for _, ck := range info.ConditionKeys {
		lck := strings.ToLower(ck)
		if lck == lk {
			return true
		}
		// Templated tail: "prefix/${TagKey}" or "prefix/<key>".
		for _, marker := range []string{"${", "<"} {
			if idx := strings.Index(lck, marker); idx > 0 {
				prefix := lck[:idx]
				if strings.HasPrefix(lk, prefix) && len(lk) > len(prefix) {
					return true
				}
			}
		}
	}
	return false
}

// globMatch matches s against pattern where '*' matches any byte
// sequence and '?' matches exactly one byte. Both inputs must already
// share case. Iterative with backtracking, linear for these inputs.
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
