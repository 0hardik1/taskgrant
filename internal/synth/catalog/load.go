package catalog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/domain"
)

// Duration bounds for capability max_duration_seconds (section 5.2).
const (
	MinDurationSeconds     = 900
	MaxDurationSeconds     = 3600
	DefaultDurationSeconds = 900
)

// maxWorstCaseCombos bounds the cartesian product of allowlist entries
// during the worst-case render check, so a huge allowlist cannot stall
// startup.
const maxWorstCaseCombos = 4096

// mandatoryDeniedServices is the G3 core service denylist. It is never
// shrinkable; loader options can only extend it.
var mandatoryDeniedServices = []string{
	"iam", "sts", "organizations", "account", "aws-portal", "billing",
	"payments", "invoicing", "ce", "cur", "tax", "sso", "sso-directory",
	"signin",
}

// MandatoryDeniedServices returns the G3 core service denylist as a
// fresh sorted slice.
func MandatoryDeniedServices() []string {
	out := append([]string(nil), mandatoryDeniedServices...)
	sort.Strings(out)
	return out
}

// allowedConditionOps is the closed set of condition operators a
// catalog entry may use.
var allowedConditionOps = map[string]struct{}{
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

var (
	capabilityIDRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	paramNameRE     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	allowlistNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	actionRE        = regexp.MustCompile(`^[a-z0-9-]{1,64}:[A-Za-z0-9]{1,100}$`)
	conditionKeyRE  = regexp.MustCompile(`^[A-Za-z0-9:/_.-]{1,128}$`)
	templateRE      = regexp.MustCompile(`^[A-Za-z0-9:_/.=+,@#{}*-]+$`)
	placeholderRE   = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)
	allowlistValRE  = regexp.MustCompile(`^[A-Za-z0-9_/.=+,@#*-]{1,512}$`)
	managedARNRE    = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}|aws):policy/[A-Za-z0-9_+=,.@/-]+$`)
	gitCommitRE     = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
)

// grammarProbes are strings a param grammar must reject: wildcards,
// whitespace of several scripts, and dollar-brace (section 5.2). The
// loader refuses any pattern that accepts a probe; runtime validation
// independently rejects the same characters, so the pair enforces the
// invariant even for patterns the probes cannot see through.
var grammarProbes = []string{
	"*", "a*", "*a", "a*b",
	"?", "a?", "?a", "a?b",
	" ", "a b", "\ta", "a\t", "a\nb", "a\rb", "a\vb", "a\fb",
	"a\u00a0b", "a\u2007b", "a\u2028b", "\u3000", "a\u200bb",
	"${", "a${b}", "${env}", "$", "a$b",
}

// Option adjusts loader behavior.
type Option func(*loadOptions)

type loadOptions struct {
	extraDeniedServices []string
	skipGitCommit       bool
}

// WithExtraDeniedServices adds config-supplied services to the
// mandatory core denylist for this load. The core is never removable.
func WithExtraDeniedServices(services ...string) Option {
	return func(o *loadOptions) {
		o.extraDeniedServices = append(o.extraDeniedServices, services...)
	}
}

// WithoutGitCommit skips the best-effort git commit lookup. Meant for
// tests that need a fully hermetic load.
func WithoutGitCommit() Option {
	return func(o *loadOptions) { o.skipGitCommit = true }
}

// YAML wire models. Decoding is strict: unknown fields refuse the load.

type capYAML struct {
	ID                 string               `yaml:"id"`
	Version            int                  `yaml:"version"`
	Summary            string               `yaml:"summary"`
	Match              matchYAML            `yaml:"match"`
	Actions            []string             `yaml:"actions"`
	AccessCeiling      string               `yaml:"access_ceiling"`
	Params             map[string]paramYAML `yaml:"params"`
	Resources          []resourceYAML       `yaml:"resources"`
	Conditions         []conditionYAML      `yaml:"conditions"`
	MaxDurationSeconds int                  `yaml:"max_duration_seconds"`
	RequiresApproval   bool                 `yaml:"requires_approval"`
	ManagedPolicy      bool                 `yaml:"managed_policy"`
	ManagedPolicyARN   string               `yaml:"managed_policy_arn"`
	Agents             []string             `yaml:"agents"`
}

type matchYAML struct {
	Keywords        []string `yaml:"keywords"`
	ServicePrefixes []string `yaml:"service_prefixes"`
	Examples        []string `yaml:"examples"`
}

type paramYAML struct {
	Type                  string `yaml:"type"`
	Pattern               string `yaml:"pattern"`
	AllowlistRef          string `yaml:"allowlist_ref"`
	AllowTrailingWildcard bool   `yaml:"allow_trailing_wildcard"`
}

type resourceYAML struct {
	Template   string   `yaml:"template"`
	ForActions []string `yaml:"for_actions"`
}

type conditionYAML struct {
	ForActions []string `yaml:"for_actions"`
	Key        string   `yaml:"key"`
	Op         string   `yaml:"op"`
	Value      string   `yaml:"value"`
}

type allowlistsYAML struct {
	Allowlists       map[string][]string `yaml:"allowlists"`
	ResourcePatterns []string            `yaml:"resource_patterns"`
}

// Load reads every YAML file in dir into an immutable Snapshot,
// enforcing every load-time invariant of section 5.2 against the
// pinned dataset. Files named allowlists.yaml or allowlists.yml hold
// the named allowlist sets and the admin resource patterns; every
// other .yaml/.yml file holds one or more capability documents. Any
// violation returns an error naming the file and field; on any error
// no snapshot is returned (violations refuse startup and hot reload).
func Load(dir string, ds *dataset.Dataset, opts ...Option) (*Snapshot, error) {
	if ds == nil {
		return nil, errors.New("catalog: nil dataset")
	}
	var lo loadOptions
	for _, opt := range opts {
		opt(&lo)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("catalog: read dir: %w", err)
	}
	var capFiles, allowFiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		base := strings.TrimSuffix(strings.ToLower(name), ext)
		if base == "allowlists" {
			allowFiles = append(allowFiles, name)
		} else {
			capFiles = append(capFiles, name)
		}
	}
	sort.Strings(capFiles)
	sort.Strings(allowFiles)
	if len(capFiles) == 0 {
		return nil, fmt.Errorf("catalog %s: no capability files", dir)
	}

	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	// Allowlists first: capabilities validate against them.
	allowlists := make(map[string][]string)
	var resourcePatterns []string
	for _, name := range allowFiles {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			fail("%s: %v", name, err)
			continue
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		var m allowlistsYAML
		if err := dec.Decode(&m); err != nil {
			fail("%s: parse: %v", name, err)
			continue
		}
		for setName, entries := range m.Allowlists {
			if !allowlistNameRE.MatchString(setName) {
				fail("%s: allowlists: set name %q must match %s", name, setName, allowlistNameRE.String())
				continue
			}
			if _, dup := allowlists[setName]; dup {
				fail("%s: allowlists: set %q defined twice", name, setName)
				continue
			}
			if len(entries) == 0 {
				fail("%s: allowlists.%s: empty set", name, setName)
				continue
			}
			for _, v := range entries {
				if !allowlistValRE.MatchString(v) {
					fail("%s: allowlists.%s: entry %q has invalid characters or length", name, setName, v)
				}
				if strings.Contains(v, "?") || strings.Contains(v, "${") {
					fail("%s: allowlists.%s: entry %q must not contain ? or ${", name, setName, v)
				}
			}
			allowlists[setName] = append([]string(nil), entries...)
		}
		for _, p := range m.ResourcePatterns {
			if _, ok := splitARNPattern(p); !ok {
				fail("%s: resource_patterns: %q is not a six-field ARN pattern", name, p)
				continue
			}
			if strings.ContainsAny(p, " \t?") || strings.Contains(p, "${") {
				fail("%s: resource_patterns: %q must not contain whitespace, ? or ${", name, p)
				continue
			}
			resourcePatterns = append(resourcePatterns, p)
		}
	}

	deniedServices := make(map[string]struct{}, len(mandatoryDeniedServices)+len(lo.extraDeniedServices))
	for _, s := range mandatoryDeniedServices {
		deniedServices[s] = struct{}{}
	}
	for _, s := range lo.extraDeniedServices {
		deniedServices[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}

	caps := make(map[string]*Capability)
	for _, name := range capFiles {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			fail("%s: %v", name, err)
			continue
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		for {
			var m capYAML
			err := dec.Decode(&m)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				fail("%s: parse: %v", name, err)
				break
			}
			c, capErrs := compileCapability(name, &m, ds, allowlists, resourcePatterns, deniedServices)
			errs = append(errs, capErrs...)
			if c == nil {
				continue
			}
			if prev, dup := caps[c.ID]; dup {
				fail("%s: capability %q already defined in %s", name, c.ID, prev.SourceFile)
				continue
			}
			caps[c.ID] = c
		}
	}

	// Referenced allowlists must exist; unreferenced ones are allowed
	// (other capabilities may arrive later), but referenced-missing is
	// always a hard error, reported per capability above.

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	snap, err := newSnapshot(caps, allowlists, resourcePatterns, ds.Hash())
	if err != nil {
		return nil, err
	}
	if !lo.skipGitCommit {
		snap.gitCommit = gitCommitFor(dir)
	}
	return snap, nil
}

// compileCapability validates one YAML capability document against
// every load-time invariant and compiles it. It returns nil plus the
// violations when any check fails.
func compileCapability(
	file string,
	m *capYAML,
	ds *dataset.Dataset,
	allowlists map[string][]string,
	resourcePatterns []string,
	deniedServices map[string]struct{},
) (*Capability, []error) {
	var errs []error
	fail := func(field, format string, args ...any) {
		prefix := fmt.Sprintf("%s: capability %q: %s: ", file, m.ID, field)
		errs = append(errs, errors.New(prefix+fmt.Sprintf(format, args...)))
	}

	if !capabilityIDRE.MatchString(m.ID) {
		errs = append(errs, fmt.Errorf("%s: capability id %q must match %s", file, m.ID, capabilityIDRE.String()))
		return nil, errs
	}
	if m.Version < 1 {
		fail("version", "must be >= 1, got %d", m.Version)
	}
	if strings.TrimSpace(m.Summary) == "" {
		fail("summary", "must not be empty")
	}

	// Access ceiling: valid level, never Permissions management.
	ceiling := dataset.AccessLevel(m.AccessCeiling)
	if !ceiling.Valid() {
		fail("access_ceiling", "unknown access level %q", m.AccessCeiling)
	} else if ceiling == dataset.AccessPermissionsManagement {
		fail("access_ceiling", "Permissions management is never grantable (G2)")
	}

	// Actions: literal, existing, under the ceiling, no denied
	// service, not on the escalation denylist.
	if len(m.Actions) == 0 {
		fail("actions", "must not be empty")
	}
	seenAction := make(map[string]struct{})
	actions := make([]string, 0, len(m.Actions))
	for _, raw := range m.Actions {
		a := strings.TrimSpace(raw)
		if strings.ContainsAny(a, "*?") {
			fail("actions", "%q contains a wildcard; actions must be enumerated (I2)", raw)
			continue
		}
		if !actionRE.MatchString(a) {
			fail("actions", "%q is not a service:Action name", raw)
			continue
		}
		info, ok := ds.Lookup(a)
		if !ok {
			fail("actions", "%q does not exist in the pinned dataset", raw)
			continue
		}
		key := strings.ToLower(info.Action)
		if _, dup := seenAction[key]; dup {
			fail("actions", "%q listed twice", info.Action)
			continue
		}
		seenAction[key] = struct{}{}
		svc, _, _ := strings.Cut(key, ":")
		if _, denied := deniedServices[svc]; denied {
			fail("actions", "%q belongs to denied service %q (G3)", info.Action, svc)
			continue
		}
		if dataset.IsEscalationAction(info.Action) {
			fail("actions", "%q is on the escalation denylist", info.Action)
			continue
		}
		if ceiling.Valid() && ceiling != dataset.AccessPermissionsManagement {
			if accessRank(info.AccessLevel) > accessRank(ceiling) {
				fail("actions", "%q has access level %q above the ceiling %q",
					info.Action, info.AccessLevel, ceiling)
				continue
			}
		}
		actions = append(actions, info.Action)
	}
	sort.Strings(actions)

	// Params: valid type, anchored grammar or allowlist, grammar
	// rejects wildcards, whitespace, and dollar-brace.
	params := make(map[string]*Param, len(m.Params))
	for pname, pm := range m.Params {
		field := "params." + pname
		if !paramNameRE.MatchString(pname) {
			fail("params", "name %q must match %s", pname, paramNameRE.String())
			continue
		}
		pt := ParamType(pm.Type)
		if !pt.Valid() {
			fail(field, "unknown type %q (want arn_component, path_prefix, or identifier)", pm.Type)
			continue
		}
		if pm.Pattern == "" && pm.AllowlistRef == "" {
			fail(field, "needs an anchored pattern or an allowlist_ref")
			continue
		}
		p := &Param{
			Name:                  pname,
			Type:                  pt,
			Pattern:               pm.Pattern,
			AllowlistRef:          pm.AllowlistRef,
			AllowTrailingWildcard: pm.AllowTrailingWildcard,
		}
		if pm.Pattern != "" {
			if !strings.HasPrefix(pm.Pattern, "^") || !strings.HasSuffix(pm.Pattern, "$") {
				fail(field, "pattern %q must be anchored with ^ and $", pm.Pattern)
				continue
			}
			re, err := regexp.Compile(pm.Pattern)
			if err != nil {
				fail(field, "pattern does not compile: %v", err)
				continue
			}
			bad := false
			for _, probe := range grammarProbes {
				if re.MatchString(probe) {
					fail(field, "pattern %q accepts forbidden probe %q (grammars must reject wildcards, whitespace, and dollar-brace)", pm.Pattern, probe)
					bad = true
					break
				}
			}
			if bad {
				continue
			}
			p.re = re
		}
		if pm.AllowlistRef != "" {
			if _, ok := allowlists[pm.AllowlistRef]; !ok {
				fail(field, "allowlist_ref %q is not defined in the catalog allowlists file", pm.AllowlistRef)
				continue
			}
		}
		params[pname] = p
	}

	// Resource templates: valid charset, placeholders declared, every
	// action covered, worst-case renders match the admin resource
	// patterns.
	usedParams := make(map[string]struct{})
	coveredActions := make(map[string]struct{})
	resources := make([]ResourceTemplate, 0, len(m.Resources))
	if len(m.Resources) == 0 {
		fail("resources", "must not be empty")
	}
	for i, rm := range m.Resources {
		field := fmt.Sprintf("resources[%d]", i)
		tpl := rm.Template
		if len(tpl) > 1024 || !templateRE.MatchString(tpl) || !strings.HasPrefix(tpl, "arn:") {
			fail(field, "template %q is not a valid ARN template", tpl)
			continue
		}
		names, err := placeholderNames(tpl)
		if err != nil {
			fail(field, "template %q: %v", tpl, err)
			continue
		}
		ok := true
		for _, n := range names {
			if _, declared := params[n]; !declared {
				fail(field, "template %q uses undeclared param {%s}", tpl, n)
				ok = false
				continue
			}
			usedParams[n] = struct{}{}
		}
		if !ok {
			continue
		}
		for _, fa := range rm.ForActions {
			if !containsFold(actions, fa) {
				fail(field, "for_actions entry %q is not one of the capability's actions", fa)
				ok = false
			}
		}
		if !ok {
			continue
		}
		rt := ResourceTemplate{Template: tpl, ForActions: append([]string(nil), rm.ForActions...)}
		for _, a := range actions {
			if rt.AppliesTo(a) {
				coveredActions[strings.ToLower(a)] = struct{}{}
			}
		}
		// Worst-case render against the admin resource patterns.
		renders, err := worstCaseRenders(tpl, names, params, allowlists)
		if err != nil {
			fail(field, "template %q: %v", tpl, err)
			continue
		}
		for _, r := range renders {
			if !coveredByAny(resourcePatterns, r) {
				fail(field, "worst-case render %q matches no admin resource pattern", r)
			}
		}
		resources = append(resources, rt)
	}
	for _, a := range actions {
		if _, ok := coveredActions[strings.ToLower(a)]; !ok {
			fail("resources", "action %q is covered by no resource template", a)
		}
	}

	// Condition templates: closed operator set, admin-fixed keys,
	// declared placeholders, keys supported by their actions per the
	// dataset.
	conditions := make([]ConditionTemplate, 0, len(m.Conditions))
	for i, cm := range m.Conditions {
		field := fmt.Sprintf("conditions[%d]", i)
		if _, ok := allowedConditionOps[cm.Op]; !ok {
			fail(field, "operator %q is not allowed", cm.Op)
			continue
		}
		if !conditionKeyRE.MatchString(cm.Key) || strings.Contains(cm.Key, "{") {
			fail(field, "key %q is not a fixed condition key", cm.Key)
			continue
		}
		if cm.Value == "" {
			fail(field, "value must not be empty")
			continue
		}
		names, err := placeholderNames(cm.Value)
		if err != nil {
			fail(field, "value %q: %v", cm.Value, err)
			continue
		}
		ok := true
		for _, n := range names {
			if _, declared := params[n]; !declared {
				fail(field, "value %q uses undeclared param {%s}", cm.Value, n)
				ok = false
				continue
			}
			usedParams[n] = struct{}{}
		}
		for _, fa := range cm.ForActions {
			if !containsFold(actions, fa) {
				fail(field, "for_actions entry %q is not one of the capability's actions", fa)
				ok = false
			}
		}
		if !ok {
			continue
		}
		ct := ConditionTemplate{
			ForActions: append([]string(nil), cm.ForActions...),
			Key:        cm.Key,
			Op:         cm.Op,
			Value:      cm.Value,
		}
		for _, a := range actions {
			if ct.AppliesTo(a) && !ds.SupportsConditionKey(a, cm.Key) {
				fail(field, "key %q is not supported by action %q per the dataset", cm.Key, a)
			}
		}
		conditions = append(conditions, ct)
	}

	// Every declared param must be used in a resource or condition
	// template.
	for pname := range params {
		if _, ok := usedParams[pname]; !ok {
			fail("params."+pname, "declared but used in no resource or condition template")
		}
	}

	// Duration within 900..3600, defaulting to 900.
	duration := m.MaxDurationSeconds
	if duration == 0 {
		duration = DefaultDurationSeconds
	}
	if duration < MinDurationSeconds || duration > MaxDurationSeconds {
		fail("max_duration_seconds", "must be within %d..%d, got %d",
			MinDurationSeconds, MaxDurationSeconds, m.MaxDurationSeconds)
	}

	// Managed policy pairing.
	if m.ManagedPolicy {
		if m.ManagedPolicyARN == "" {
			fail("managed_policy_arn", "required when managed_policy is true")
		} else if !managedARNRE.MatchString(m.ManagedPolicyARN) {
			fail("managed_policy_arn", "%q is not an IAM policy ARN", m.ManagedPolicyARN)
		}
	} else if m.ManagedPolicyARN != "" {
		fail("managed_policy_arn", "set but managed_policy is false")
	}

	// Agent restriction slugs.
	seenAgent := make(map[string]struct{})
	for _, a := range m.Agents {
		if err := domain.ValidateAgentID(a); err != nil {
			fail("agents", "%v", err)
			continue
		}
		if _, dup := seenAgent[a]; dup {
			fail("agents", "agent %q listed twice", a)
		}
		seenAgent[a] = struct{}{}
	}

	if len(errs) > 0 {
		return nil, errs
	}
	return &Capability{
		ID:      m.ID,
		Version: m.Version,
		Summary: strings.TrimSpace(m.Summary),
		Match: MatchHints{
			Keywords:        append([]string(nil), m.Match.Keywords...),
			ServicePrefixes: append([]string(nil), m.Match.ServicePrefixes...),
			Examples:        append([]string(nil), m.Match.Examples...),
		},
		Actions:            actions,
		AccessCeiling:      ceiling,
		Params:             params,
		Resources:          resources,
		Conditions:         conditions,
		MaxDurationSeconds: duration,
		RequiresApproval:   m.RequiresApproval,
		ManagedPolicy:      m.ManagedPolicy,
		ManagedPolicyARN:   m.ManagedPolicyARN,
		Agents:             append([]string(nil), m.Agents...),
		SourceFile:         file,
	}, nil
}

// accessRank orders access levels for ceiling comparison. Read and
// List share the lowest tier (the section 5.2 example places Read
// actions under a List ceiling); Tagging ranks above Write because tag
// writing is an ABAC escalation primitive (G2).
func accessRank(l dataset.AccessLevel) int {
	switch l {
	case dataset.AccessRead, dataset.AccessList:
		return 1
	case dataset.AccessWrite:
		return 2
	case dataset.AccessTagging:
		return 3
	default: // Permissions management and anything unknown
		return 4
	}
}

// placeholderNames extracts the ordered distinct {param} placeholder
// names of a template and rejects stray braces.
func placeholderNames(tpl string) ([]string, error) {
	stripped := placeholderRE.ReplaceAllString(tpl, "")
	if strings.ContainsAny(stripped, "{}") {
		return nil, errors.New("unbalanced or malformed { } placeholder")
	}
	var names []string
	seen := make(map[string]struct{})
	for _, m := range placeholderRE.FindAllStringSubmatch(tpl, -1) {
		if _, dup := seen[m[1]]; !dup {
			seen[m[1]] = struct{}{}
			names = append(names, m[1])
		}
	}
	return names, nil
}

// worstCaseRenders renders the template with every worst-case value
// combination: allowlist-backed params take each allowlist entry
// (wildcard entries stay as globs), grammar-only params take "*"
// because the grammar bounds characters, not reach.
func worstCaseRenders(tpl string, names []string, params map[string]*Param, allowlists map[string][]string) ([]string, error) {
	renders := []string{tpl}
	for _, n := range names {
		p := params[n]
		var values []string
		if p.AllowlistRef != "" {
			values = allowlists[p.AllowlistRef]
		} else {
			values = []string{"*"}
		}
		next := make([]string, 0, len(renders)*len(values))
		for _, r := range renders {
			for _, v := range values {
				next = append(next, strings.ReplaceAll(r, "{"+n+"}", v))
				if len(next) > maxWorstCaseCombos {
					return nil, fmt.Errorf("worst-case render combinations exceed %d", maxWorstCaseCombos)
				}
			}
		}
		renders = next
	}
	for i, r := range renders {
		renders[i] = collapseStars(r)
	}
	return renders, nil
}

// coveredByAny reports whether at least one admin pattern covers the
// rendered worst-case ARN glob.
func coveredByAny(patterns []string, rendered string) bool {
	for _, p := range patterns {
		if arnCovers(p, rendered) {
			return true
		}
	}
	return false
}

// containsFold reports whether list holds s under case folding.
func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// gitCommitFor best-effort resolves the git commit governing dir. An
// empty string means no commit was resolvable; the snapshot hash alone
// still pins the content.
func gitCommitFor(dir string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	commit := strings.TrimSpace(string(out))
	if !gitCommitRE.MatchString(commit) {
		return ""
	}
	return commit
}
