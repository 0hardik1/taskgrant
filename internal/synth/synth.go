// Package synth defines the synthesizer seam (architecture section 14):
// the request and result types the broker exchanges with any
// intent-to-policy synthesizer implementation, and the Synthesizer
// interface itself. This package holds types only; implementations live
// in synth/catalog, synth/match, and synth/compile. The broker imports
// only this interface and re-verifies every Result with the guardrail
// evaluator; it never trusts the implementation behind the seam.
package synth

import (
	"context"
	"time"
)

// Verdict is the outcome class of one synthesis run.
type Verdict string

const (
	// VerdictPolicy: a policy compiled and passed the synthesizer's own
	// guardrail run. The broker still re-verifies it.
	VerdictPolicy Verdict = "policy"
	// VerdictDeny: the request is denied; DenialCode says why.
	VerdictDeny Verdict = "deny"
	// VerdictNeedsClarification: the agent must answer a structured
	// clarification and retry with the returned token.
	VerdictNeedsClarification Verdict = "needs_clarification"
	// VerdictPendingApproval: the selection is valid but a human must
	// approve before any mint.
	VerdictPendingApproval Verdict = "pending_approval"
)

// Valid reports whether v is a known verdict.
func (v Verdict) Valid() bool {
	switch v {
	case VerdictPolicy, VerdictDeny, VerdictNeedsClarification, VerdictPendingApproval:
		return true
	}
	return false
}

// String returns the wire form of the verdict.
func (v Verdict) String() string { return string(v) }

// ProfileInfo is the broker-resolved profile context a synthesis run
// operates under. The synthesizer never reads raw config.
type ProfileInfo struct {
	Name               string   `json:"name"`
	RoleARN            string   `json:"role_arn"`
	Region             string   `json:"region"`
	MaxDurationSeconds int      `json:"max_duration_seconds"`
	PolicyARNs         []string `json:"policy_arns,omitempty"`
}

// CapabilityHint is one structured capability request from the agent
// (the preferred path, section 5.4). Params are hostile bytes until
// they pass grammar and allowlist validation.
type CapabilityHint struct {
	ID     string            `json:"id"`
	Params map[string]string `json:"params,omitempty"`
}

// Hints carries the structured portion of a request_grant call.
// Services, Resources, and Access are coarse matcher hints; agents
// never name raw IAM actions.
type Hints struct {
	Capabilities    []CapabilityHint `json:"capabilities,omitempty"`
	Services        []string         `json:"services,omitempty"`
	Resources       []string         `json:"resources,omitempty"`
	Access          string           `json:"access,omitempty"`
	DurationSeconds int              `json:"duration_seconds,omitempty"`
}

// Request is one synthesis request. Task and Reason are untrusted
// agent bytes, already length-capped at the MCP boundary.
type Request struct {
	GrantID string
	AgentID string
	Profile ProfileInfo
	Task    string
	Reason  string
	Hints   Hints
	// RetryToken carries a clarification round back (section 5.6).
	// Empty on the first round.
	RetryToken string
	// MaxPolicyChars is the broker-computed size budget for the
	// minified policy JSON (section 7.1).
	MaxPolicyChars int
}

// CapabilityRef pins one catalog entry by id and version.
type CapabilityRef struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

// StatementExplanation explains one policy statement. The Explanation's
// Statements slice is index-parallel to the policy document's Statement
// array: Statements[i] explains Statement[i], and the mapping survives
// Sid removal under size pressure.
type StatementExplanation struct {
	CapabilityID      string            `json:"capability_id"`
	CapabilityVersion int               `json:"capability_version"`
	Params            map[string]string `json:"params,omitempty"`
	// Reason is rendered from an admin-authored template, never
	// LLM-generated.
	Reason string `json:"reason"`
}

// Explanation traces every statement of a compiled policy back to the
// capability and validated params that produced it.
type Explanation struct {
	Statements []StatementExplanation `json:"statements"`
}

// MissingParam names one missing or invalid parameter with enough
// shape information for a competent agent to retry successfully in one
// round.
type MissingParam struct {
	Capability string `json:"capability"`
	Name       string `json:"name"`
	// ExpectedShape describes the accepted grammar or allowlist, for
	// example "bucket name from the s3-buckets allowlist".
	ExpectedShape string   `json:"expected_shape"`
	Examples      []string `json:"examples,omitempty"`
}

// CandidateCapability is one catalog entry the agent can confirm by id.
type CandidateCapability struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

// Clarification is the structured payload of a needs_clarification
// outcome (section 5.6).
type Clarification struct {
	// Code is the machine-readable reason, one of the domain denial
	// codes such as MISSING_PARAM or AMBIGUOUS_MATCH.
	Code          string                `json:"code"`
	Questions     []string              `json:"questions,omitempty"`
	MissingParams []MissingParam        `json:"missing_params,omitempty"`
	Candidates    []CandidateCapability `json:"candidates,omitempty"`
	// RetryToken is signed and self-contained (grant ULID, intent
	// hash, round counter), so it survives broker restarts.
	RetryToken string `json:"retry_token"`
	// Round counts clarification rounds on this grant, starting at 1.
	// Maximum 2, then CLARIFICATION_EXHAUSTED.
	Round int `json:"round"`
}

// Result is the outcome of one synthesis run.
type Result struct {
	Verdict Verdict
	// PolicyJSON is the minified session policy document. Set only
	// when Verdict is VerdictPolicy or VerdictPendingApproval.
	PolicyJSON []byte
	// PolicyArns lists managed session policies offloaded under size
	// pressure (reduction ladder step 4).
	PolicyArns []string
	// EffectiveDuration respects per-capability caps (G7 clamps
	// further at the broker).
	EffectiveDuration time.Duration
	Explanation       Explanation
	Clarification     *Clarification
	// DenialCode is set when Verdict is VerdictDeny; one of the domain
	// denial codes.
	DenialCode string
	// Capabilities pins the selected catalog entries with versions.
	Capabilities []CapabilityRef
	// ExpandedActions is the full enumerated action list of the
	// policy, kept for the feedback loop (section 13).
	ExpandedActions []string
	// Hashes pin the exact inputs of this compilation (invariant I6).
	CatalogHash string
	DatasetHash string
	ConfigHash  string
}

// Synthesizer converts declared intent into a policy, a clarification,
// an approval requirement, or a denial. Implementations must be
// deterministic for identical inputs (invariant I6): same capability
// set, params, catalog hash, dataset hash, and config hash produce
// byte-identical PolicyJSON.
type Synthesizer interface {
	// Synthesize runs the full pipeline of section 5.4 for one grant.
	Synthesize(ctx context.Context, req Request) (Result, error)

	// Compact re-renders the SAME capability selection under a tighter
	// budget. Deterministic; never re-matches; no LLM involvement.
	// The broker calls it once on PackedPolicyTooLarge with a budget
	// 20 percent under the previous one (section 7.3).
	Compact(ctx context.Context, prev Result, maxChars int) (Result, error)
}
