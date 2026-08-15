// Package catalog implements the capability catalog of architecture
// section 5.2: the capability model, the directory loader with every
// load-time invariant, named allowlist sets, immutable hash-pinned
// snapshots with per-agent views, and an atomic snapshot store for hot
// reload. The catalog defines what CAN be granted; agent-supplied
// parameter values are the only agent-controlled bytes and they face
// the grammars and allowlists defined here (invariant I1).
package catalog

import (
	"regexp"
	"sort"
	"strings"

	"github.com/0hardik1/taskgrant/internal/dataset"
)

// ParamType classifies a capability parameter. The type selects a
// built-in base grammar that always applies in addition to the
// admin-authored pattern or allowlist.
type ParamType string

const (
	// ParamARNComponent is one component of an ARN resource field, for
	// example a bucket or table name. The base grammar forbids '/' and
	// ':' so a value can never cross ARN fields or path segments the
	// template did not open.
	ParamARNComponent ParamType = "arn_component"
	// ParamPathPrefix is a slash-separated path prefix, for example an
	// S3 key prefix or a CloudWatch log group name.
	ParamPathPrefix ParamType = "path_prefix"
	// ParamIdentifier is a bare identifier such as a queue or function
	// name.
	ParamIdentifier ParamType = "identifier"
)

// Valid reports whether t is a known parameter type.
func (t ParamType) Valid() bool {
	switch t {
	case ParamARNComponent, ParamPathPrefix, ParamIdentifier:
		return true
	}
	return false
}

// String returns the wire form of the parameter type.
func (t ParamType) String() string { return string(t) }

// Param is one declared capability parameter. Every param carries an
// anchored grammar, an allowlist reference, or both; the loader
// refuses a param with neither.
type Param struct {
	Name string    `json:"name"`
	Type ParamType `json:"type"`
	// Pattern is the admin-authored anchored regular expression.
	// Optional when AllowlistRef is set.
	Pattern string `json:"pattern,omitempty"`
	// AllowlistRef names an allowlist set from the catalog directory's
	// allowlists file. Optional when Pattern is set.
	AllowlistRef string `json:"allowlist_ref,omitempty"`
	// AllowTrailingWildcard marks that this param feeds a resource
	// template that appends a trailing '*' (for example '{prefix}*'). It
	// does NOT permit the agent value to carry a '*': a value-supplied
	// wildcard is always rejected (section 5.2, invariant I1). The
	// template alone controls where a wildcard is emitted.
	AllowTrailingWildcard bool `json:"allow_trailing_wildcard,omitempty"`

	re *regexp.Regexp
}

// ExpectedShape describes the accepted value shape for clarification
// messages. The text is built from admin-authored fields only.
func (p *Param) ExpectedShape() string {
	var parts []string
	if p.AllowlistRef != "" {
		parts = append(parts, "value from the "+p.AllowlistRef+" allowlist")
	}
	if p.Pattern != "" {
		parts = append(parts, "matching "+p.Pattern)
	}
	if len(parts) == 0 {
		parts = append(parts, string(p.Type))
	}
	s := strings.Join(parts, ", ")
	if p.AllowTrailingWildcard {
		s += " (a trailing wildcard is applied automatically; do not include '*')"
	}
	return s
}

// MatchHints steer the rules and LLM matchers (section 5.4). They are
// advisory: nothing in a hint reaches an emitted policy.
type MatchHints struct {
	Keywords        []string `json:"keywords,omitempty"`
	ServicePrefixes []string `json:"service_prefixes,omitempty"`
	Examples        []string `json:"examples,omitempty"`
}

// ResourceTemplate renders one Resource ARN pattern for a subset of the
// capability's actions.
type ResourceTemplate struct {
	// Template is the ARN skeleton with {param} placeholders. Only
	// admin-authored text plus validated param values ever render.
	Template string `json:"template"`
	// ForActions lists the actions the template applies to. Empty
	// means every action of the capability.
	ForActions []string `json:"for_actions,omitempty"`
}

// AppliesTo reports whether the template applies to the action.
func (r *ResourceTemplate) AppliesTo(action string) bool {
	if len(r.ForActions) == 0 {
		return true
	}
	for _, a := range r.ForActions {
		if strings.EqualFold(a, action) {
			return true
		}
	}
	return false
}

// ConditionTemplate renders one policy condition for a subset of the
// capability's actions. The key and operator are admin-fixed; only the
// value may carry {param} placeholders.
type ConditionTemplate struct {
	// ForActions lists the actions the condition attaches to. Empty
	// means every action of the capability.
	ForActions []string `json:"for_actions,omitempty"`
	Key        string   `json:"key"`
	Op         string   `json:"op"`
	Value      string   `json:"value"`
}

// AppliesTo reports whether the condition applies to the action.
func (c *ConditionTemplate) AppliesTo(action string) bool {
	if len(c.ForActions) == 0 {
		return true
	}
	for _, a := range c.ForActions {
		if strings.EqualFold(a, action) {
			return true
		}
	}
	return false
}

// Capability is one compiled catalog entry. Instances are immutable
// after load; treat every slice and map as read-only.
type Capability struct {
	ID      string     `json:"id"`
	Version int        `json:"version"`
	Summary string     `json:"summary"`
	Match   MatchHints `json:"match"`
	// Actions is the enumerated action list in canonical dataset
	// spelling, sorted. Never a wildcard (invariant I2).
	Actions       []string            `json:"actions"`
	AccessCeiling dataset.AccessLevel `json:"access_ceiling"`
	Params        map[string]*Param   `json:"params,omitempty"`
	Resources     []ResourceTemplate  `json:"resources"`
	Conditions    []ConditionTemplate `json:"conditions,omitempty"`
	// MaxDurationSeconds caps grant duration for this entry, within
	// 900..3600. Defaults to 900 when the YAML omits it.
	MaxDurationSeconds int  `json:"max_duration_seconds"`
	RequiresApproval   bool `json:"requires_approval"`
	// ManagedPolicy marks the entry eligible for PolicyArns offload
	// (reduction ladder step 4). When true, ManagedPolicyARN names the
	// pre-provisioned customer managed policy.
	ManagedPolicy    bool   `json:"managed_policy"`
	ManagedPolicyARN string `json:"managed_policy_arn,omitempty"`
	// Agents restricts visibility to the listed agent ids. Empty means
	// every agent.
	Agents []string `json:"agents,omitempty"`

	// SourceFile records the catalog file the entry came from, for
	// error messages and audit. Excluded from the snapshot hash.
	SourceFile string `json:"-"`
}

// VisibleTo reports whether the capability is visible to the agent.
func (c *Capability) VisibleTo(agentID string) bool {
	if len(c.Agents) == 0 {
		return true
	}
	for _, a := range c.Agents {
		if a == agentID {
			return true
		}
	}
	return false
}

// ParamNames returns the declared parameter names, sorted.
func (c *Capability) ParamNames() []string {
	names := make([]string, 0, len(c.Params))
	for name := range c.Params {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Services returns the distinct service prefixes of the capability's
// actions, sorted.
func (c *Capability) Services() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, a := range c.Actions {
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
