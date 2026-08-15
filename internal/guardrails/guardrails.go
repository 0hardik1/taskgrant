// Package guardrails implements the IAM-semantics guardrail evaluator
// of architecture section 6. One evaluator, one implementation, used
// twice: inside the synthesizer at compile time and by the broker on
// the concrete policy document returned across the synthesizer seam.
// The broker run is authoritative and assumes nothing about the
// synthesizer implementation.
//
// The evaluator is dataset-driven: every action pattern expands against
// the pinned iam-dataset artifact (unknown actions fail closed) and all
// later checks run on the expansion, so a wildcard that spans an
// escalation action cannot hide behind its literal string (G1).
//
// Every check reports a verdict even on pass; the decision log stores
// passes too. Policy bytes and all strings inside them are hostile
// input: details rendered from them are control-stripped and
// length-capped.
package guardrails

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/domain"
)

// Verdict is the outcome of one guardrail check.
type Verdict string

const (
	Pass          Verdict = "pass"
	Warn          Verdict = "warn"
	Fail          Verdict = "fail"
	NeedsApproval Verdict = "needs_approval"
)

// Valid reports whether v is a known verdict.
func (v Verdict) Valid() bool {
	switch v {
	case Pass, Warn, Fail, NeedsApproval:
		return true
	}
	return false
}

// String returns the wire form of the verdict.
func (v Verdict) String() string { return string(v) }

// Check names, ordered G0 through G8. G8 reports as three entries
// (capability count, rate limit, creep) so each durable control has its
// own verdict in the log.
const (
	CheckStructure         = "G0.structure"
	CheckExistence         = "G1.existence"
	CheckAccessLevels      = "G2.access-levels"
	CheckServiceDenylist   = "G3.service-denylist"
	CheckResourceAllowlist = "G4.resource-allowlist"
	CheckConditions        = "G5.mandatory-conditions"
	CheckSizeBudget        = "G6.size-budget"
	CheckDurationClamp     = "G7.duration-clamp"
	CheckCapabilityCount   = "G8.capability-count"
	CheckRateLimit         = "G8.rate-limit"
	CheckCreep             = "G8.capability-creep"
)

// Numeric limits per architecture sections 6 and 7.
const (
	// DefaultMaxPolicyChars is the G6 budget when neither the Input nor
	// the Config sets one: 2048 minus about 300 chars of session tag
	// headroom (section 7.1).
	DefaultMaxPolicyChars = 2048 - 300
	// DurationFloorSeconds is the G7 floor and default.
	DurationFloorSeconds = 900
	// GlobalDurationCapSeconds is the G7 global cap absent config.
	GlobalDurationCapSeconds = 3600
	// ChainedDurationCapSeconds is the hard ceiling when the broker
	// itself runs on session credentials (role chaining).
	ChainedDurationCapSeconds = 3600
	// MaxCapabilitiesPerGrant caps how many capabilities one grant may
	// bundle (G8).
	MaxCapabilitiesPerGrant = 3
	// RateTokensPerHour documents the per (agent, capability) token
	// bucket rate. Enforcement lives in the durable StateStore; the
	// constant is exported so the store and the evaluator agree.
	RateTokensPerHour = 30
	// CreepAlertThreshold is the 24 h distinct-capability count that
	// raises a warn verdict (G8).
	CreepAlertThreshold = 5
	// CreepHardCap is the 24 h distinct-capability count that requires
	// a human override (needs_approval verdict, G8).
	CreepHardCap = 10
)

// mandatoryDenyServices is the never-shrinkable service denylist core
// (G3). Config can only extend it.
var mandatoryDenyServices = []string{
	"iam", "sts", "organizations", "account", "aws-portal", "billing",
	"payments", "invoicing", "ce", "cur", "tax", "sso", "sso-directory",
	"signin",
}

// MandatoryDenyServices returns the mandatory core of the G3 service
// denylist. Fresh copy on every call.
func MandatoryDenyServices() []string {
	return append([]string(nil), mandatoryDenyServices...)
}

// defaultGlobalServiceExemptions lists services whose actions are
// global and therefore exempt from the aws:RequestedRegion requirement
// (G5). Applied when Config.GlobalServiceExemptions is nil.
var defaultGlobalServiceExemptions = []string{
	"cloudfront", "globalaccelerator", "route53", "route53domains",
	"shield", "support", "trustedadvisor", "waf", "wafv2",
}

// defaultGlobalNamespaceServices lists services with a globally shared
// resource namespace, where a matching-named resource in a foreign
// account turns a grant into an exfiltration channel unless
// aws:ResourceAccount pins the account (G5).
var defaultGlobalNamespaceServices = []string{"s3"}

// Check is one guardrail verdict. Detail is human-facing, already
// control-stripped and length-capped.
type Check struct {
	Name    string  `json:"name"`
	Verdict Verdict `json:"verdict"`
	Detail  string  `json:"detail"`
}

// Result is the ordered outcome of one full evaluation.
type Result struct {
	// Checks holds every check in G0..G8 order, passes included.
	Checks []Check `json:"checks"`
	// Overall is the worst verdict across Checks
	// (fail > needs_approval > warn > pass).
	Overall Verdict `json:"overall"`
	// ExpandedActions is the enumerated action list of the policy,
	// sorted and deduplicated; the decision record keeps it for the
	// feedback loop.
	ExpandedActions []string `json:"expanded_actions,omitempty"`
	// EffectiveDurationSeconds is the G7 clamp output.
	EffectiveDurationSeconds int `json:"effective_duration_seconds"`
	// PolicyChars is the length of the evaluated policy bytes.
	PolicyChars int `json:"policy_chars"`
}

// OK reports whether the evaluation allows the grant to proceed
// without a human gate: overall pass or warn.
func (r Result) OK() bool { return r.Overall == Pass || r.Overall == Warn }

// Check returns the named check when present.
func (r Result) Check(name string) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

// FailedChecks returns the checks whose verdict is fail.
func (r Result) FailedChecks() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Verdict == Fail {
			out = append(out, c)
		}
	}
	return out
}

// StateStore is the durable security-state consumer interface the
// broker injects for G8 (invariant I5: rate ledgers and creep counters
// persist in SQLite and rebuild fail-closed on restart). The store
// package satisfies it; the evaluator only consumes it.
type StateStore interface {
	// TakeToken consumes one token from the per (agent, capability)
	// rate bucket (RateTokensPerHour). It returns false when the bucket
	// is exhausted.
	TakeToken(ctx context.Context, agentID, capabilityID string) (bool, error)
	// DistinctCapabilityCount returns the number of distinct
	// capabilities the agent would have used in the trailing 24 hours
	// with includeIDs counted in.
	DistinctCapabilityCount(ctx context.Context, agentID string, includeIDs []string) (int, error)
}

// CapabilityMeta is the guardrail-relevant metadata of one selected
// catalog capability. The caller resolves it from the catalog snapshot;
// the evaluator never reads the catalog itself.
type CapabilityMeta struct {
	// ID is the catalog capability id.
	ID string
	// MaxDurationSeconds is the capability duration cap; 0 means no
	// capability-level cap.
	MaxDurationSeconds int
	// TaggingOptIn marks a capability the admin opted into
	// Tagging-level actions (G2).
	TaggingOptIn bool
	// ResourceStarOptIn marks a capability the admin opted into
	// Resource "*" statements for resource-free actions (G4).
	ResourceStarOptIn bool
	// WildcardAllowlistResource marks a capability whose resource
	// pattern came from a wildcard allowlist entry, which makes
	// aws:ResourceAccount mandatory (G5).
	WildcardAllowlistResource bool
}

// Config is the evaluator-level configuration, fixed at construction.
type Config struct {
	// AllowedAccessLevels is the default grantable access-level set
	// when the Input carries no profile-resolved set. Defaults to
	// [Read, List]. "Permissions management" is rejected at
	// construction: G2 denies it unconditionally with no override.
	AllowedAccessLevels []string
	// ExtraDenyServices extends the mandatory G3 core. Nothing can
	// shrink the core.
	ExtraDenyServices []string
	// ResourceAllowlist holds the admin ARN allowlist patterns every
	// rendered Resource must match (G4). Globs never cross ARN
	// partition or account fields.
	ResourceAllowlist []string
	// GlobalServiceExemptions overrides the built-in list of global
	// services exempt from aws:RequestedRegion (G5). nil applies the
	// defaults; an empty non-nil slice disables all exemptions.
	GlobalServiceExemptions []string
	// GlobalNamespaceServices overrides the built-in list of services
	// with a globally shared resource namespace that always require
	// aws:ResourceAccount (G5). nil applies the default ([s3]).
	GlobalNamespaceServices []string
	// Accounts is the configured aws.accounts list; every
	// aws:ResourceAccount condition value must be in it when the list
	// is non-empty (G5).
	Accounts []string
	// MaxPolicyChars is the G6 budget when the Input does not set one.
	// 0 applies DefaultMaxPolicyChars.
	MaxPolicyChars int
	// GlobalMaxDurationSeconds is the G7 global cap. 0 applies
	// GlobalDurationCapSeconds (3600).
	GlobalMaxDurationSeconds int
}

// Input is the evaluation context for one concrete policy document.
type Input struct {
	// PolicyJSON is the concrete policy document, treated as hostile
	// bytes (a non-conforming synthesizer could emit anything).
	PolicyJSON []byte
	// AgentID keys the G8 rate and creep state.
	AgentID string
	// Profile names the profile for log detail only.
	Profile string
	// AllowedAccessLevels is the profile-resolved grantable set; nil
	// falls back to the Config default.
	AllowedAccessLevels []string
	// RequestedDurationSeconds is the agent-requested duration; 0
	// applies the 900 s default (G7).
	RequestedDurationSeconds int
	// ProfileMaxDurationSeconds is the profile duration cap; 0 means
	// no profile cap.
	ProfileMaxDurationSeconds int
	// Capabilities carries the guardrail metadata of the selected
	// capabilities.
	Capabilities []CapabilityMeta
	// RequireResourceAccount forces the aws:ResourceAccount condition
	// on every statement regardless of the built-in triggers (G5).
	RequireResourceAccount bool
	// BrokerChained is true when the broker itself runs on session
	// credentials; G7 then clamps to 3600 s.
	BrokerChained bool
	// MaxPolicyChars overrides the G6 budget for this evaluation; 0
	// falls back to the Config value.
	MaxPolicyChars int
	// State is the durable G8 state. nil (the synthesizer-side run)
	// reports warn verdicts for the rate and creep checks; the
	// authoritative broker run must inject it.
	State StateStore
}

// Evaluator is the guardrail evaluator. Immutable after New; safe for
// concurrent use.
type Evaluator struct {
	ds  *dataset.Dataset
	cfg Config

	denyServices     map[string]struct{}
	globalExempt     map[string]struct{}
	globalNamespace  map[string]struct{}
	defaultLevels    map[string]struct{}
	accounts         map[string]struct{}
	maxPolicyChars   int
	globalMaxSeconds int
}

// New builds an Evaluator over the pinned dataset. It applies defaults
// and rejects configuration that would weaken a guardrail.
func New(ds *dataset.Dataset, cfg Config) (*Evaluator, error) {
	if ds == nil {
		return nil, errors.New("guardrails: dataset is required")
	}
	e := &Evaluator{
		ds:              ds,
		cfg:             cfg,
		denyServices:    make(map[string]struct{}),
		globalExempt:    make(map[string]struct{}),
		globalNamespace: make(map[string]struct{}),
		defaultLevels:   make(map[string]struct{}),
		accounts:        make(map[string]struct{}),
	}

	for _, svc := range mandatoryDenyServices {
		e.denyServices[svc] = struct{}{}
	}
	for _, svc := range cfg.ExtraDenyServices {
		e.denyServices[strings.ToLower(strings.TrimSpace(svc))] = struct{}{}
	}

	exempt := cfg.GlobalServiceExemptions
	if exempt == nil {
		exempt = defaultGlobalServiceExemptions
	}
	for _, svc := range exempt {
		e.globalExempt[strings.ToLower(strings.TrimSpace(svc))] = struct{}{}
	}

	globalNS := cfg.GlobalNamespaceServices
	if globalNS == nil {
		globalNS = defaultGlobalNamespaceServices
	}
	for _, svc := range globalNS {
		e.globalNamespace[strings.ToLower(strings.TrimSpace(svc))] = struct{}{}
	}

	levels := cfg.AllowedAccessLevels
	if len(levels) == 0 {
		levels = []string{string(dataset.AccessRead), string(dataset.AccessList)}
	}
	set, err := accessLevelSet(levels)
	if err != nil {
		return nil, fmt.Errorf("guardrails: %w", err)
	}
	e.defaultLevels = set

	for _, acct := range cfg.Accounts {
		e.accounts[strings.TrimSpace(acct)] = struct{}{}
	}

	e.maxPolicyChars = cfg.MaxPolicyChars
	if e.maxPolicyChars <= 0 {
		e.maxPolicyChars = DefaultMaxPolicyChars
	}
	e.globalMaxSeconds = cfg.GlobalMaxDurationSeconds
	if e.globalMaxSeconds <= 0 {
		e.globalMaxSeconds = GlobalDurationCapSeconds
	}
	if e.globalMaxSeconds < DurationFloorSeconds {
		return nil, fmt.Errorf("guardrails: global max duration %d is under the %d floor",
			e.globalMaxSeconds, DurationFloorSeconds)
	}
	return e, nil
}

// accessLevelSet validates level names against the grantable set. The
// "Permissions management" level is never grantable (G2, no override).
func accessLevelSet(levels []string) (map[string]struct{}, error) {
	set := make(map[string]struct{}, len(levels))
	for _, lvl := range levels {
		l := dataset.AccessLevel(lvl)
		if !l.Valid() {
			return nil, fmt.Errorf("unknown access level %q", lvl)
		}
		if l == dataset.AccessPermissionsManagement {
			return nil, errors.New("access level \"Permissions management\" is denied unconditionally and cannot be configured")
		}
		set[lvl] = struct{}{}
	}
	return set, nil
}

// maxDetailLen caps a check detail string. Untrusted policy content
// flows into details; the cap bounds log noise from hostile input.
const maxDetailLen = 700

// newCheck builds a Check with a sanitized, length-capped detail.
func newCheck(name string, v Verdict, detail string) Check {
	d := domain.SanitizeForDisplay(detail)
	if len(d) > maxDetailLen {
		d = d[:maxDetailLen] + "..."
	}
	return Check{Name: name, Verdict: v, Detail: d}
}

// aggregate returns the worst verdict across checks.
func aggregate(checks []Check) Verdict {
	rank := map[Verdict]int{Pass: 0, Warn: 1, NeedsApproval: 2, Fail: 3}
	worst := Pass
	for _, c := range checks {
		if rank[c.Verdict] > rank[worst] {
			worst = c.Verdict
		}
	}
	return worst
}

// joinCapped joins up to max items with "; " and summarizes the rest.
func joinCapped(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, "; ")
	}
	return strings.Join(items[:max], "; ") + fmt.Sprintf("; and %d more", len(items)-max)
}
