package mcpserver

// This file defines the wire structs of the five MCP tools. The shapes
// mirror architecture section 4.2 exactly. Input structs carry hostile
// bytes; boundary.go caps them before anything else runs. Output
// structs carry only broker-rendered or sanitized values.

// Boundary caps applied to request_grant inputs (section 4.2 and 12.5).
const (
	MaxTaskChars       = 4096
	MaxReasonChars     = 1024
	MaxNoteChars       = 1024
	MaxProfileChars    = 64
	MaxAccessChars     = 32
	MaxServiceChars    = 64
	MaxServices        = 16
	MaxResourceChars   = 2048
	MaxResources       = 32
	MaxCapabilities    = 16
	MaxCapabilityID    = 128
	MaxParamsPerCap    = 32
	MaxParamNameChars  = 64
	MaxParamValueChars = 1024
	MaxIdemKeyChars    = 128
	MaxRetryTokenChars = 4096
)

// Enumerated error codes for status "error" results. Denials use the
// domain denial codes; these cover boundary and transport failures.
// Raw internal errors are logged, never returned.
const (
	CodeInvalidArgument = "INVALID_ARGUMENT"
	CodeNotFound        = "NOT_FOUND"
	CodeRateLimited     = "RATE_LIMITED"
	CodeInternal        = "INTERNAL"
)

// Release outcome values accepted by release_grant.
const (
	ReleaseSucceeded = "succeeded"
	ReleaseFailed    = "failed"
	ReleaseAbandoned = "abandoned"
)

// CapabilityHintInput is one structured capability request.
type CapabilityHintInput struct {
	ID     string            `json:"id" jsonschema:"catalog capability id, for example s3.read-prefix; discover ids with list_capabilities"`
	Params map[string]string `json:"params,omitempty" jsonschema:"capability parameter values; each value is validated against the capability grammar and admin allowlists"`
}

// RequestGrantInput mirrors the request_grant JSON of section 4.2.
type RequestGrantInput struct {
	Task            string                `json:"task" jsonschema:"what the agent is about to do, in plain language; required, at most 4096 characters, logged verbatim"`
	Reason          string                `json:"reason,omitempty" jsonschema:"why the task needs credentials, for example a ticket reference; at most 1024 characters, logged verbatim"`
	Profile         string                `json:"profile,omitempty" jsonschema:"profile name to mint under; defaults to the agent's default profile"`
	Capabilities    []CapabilityHintInput `json:"capabilities,omitempty" jsonschema:"structured capability requests; the preferred path over free text"`
	Services        []string              `json:"services,omitempty" jsonschema:"coarse service hints for the matcher, for example s3"`
	Resources       []string              `json:"resources,omitempty" jsonschema:"coarse resource ARN hints for the matcher"`
	Access          string                `json:"access,omitempty" jsonschema:"coarse access hint, one of read, list, write, tagging"`
	DurationSeconds int                   `json:"duration_seconds,omitempty" jsonschema:"requested credential lifetime in seconds; clamped by capability, profile, and global caps"`
	CallerRef       string                `json:"caller_ref,omitempty" jsonschema:"agent-local correlation id; sanitized and capped at 64 characters; never part of any authorization decision"`
	IdempotencyKey  string                `json:"idempotency_key,omitempty" jsonschema:"repeat-safe key; a repeated key within its window returns the existing grant's current state instead of minting again"`
	WaitSeconds     int                   `json:"wait_seconds,omitempty" jsonschema:"seconds to block waiting for a human approval before returning a poll hint; capped by server configuration"`
	RetryToken      string                `json:"retry_token,omitempty" jsonschema:"token from a needs_clarification response; attaches this retry to the same grant"`
}

// GetGrantInput is the get_grant argument.
type GetGrantInput struct {
	GrantID string `json:"grant_id" jsonschema:"the grant ULID returned by request_grant"`
}

// ExplainGrantInput is the explain_grant argument.
type ExplainGrantInput struct {
	GrantID string `json:"grant_id" jsonschema:"the grant ULID to explain; own grants only"`
}

// ListCapabilitiesInput is the empty list_capabilities argument.
type ListCapabilitiesInput struct{}

// ReleaseGrantInput is the release_grant argument.
type ReleaseGrantInput struct {
	GrantID string `json:"grant_id" jsonschema:"the grant ULID to release"`
	Outcome string `json:"outcome" jsonschema:"how the task ended: succeeded, failed, or abandoned"`
	Note    string `json:"note,omitempty" jsonschema:"optional free-text note for the audit trail; at most 1024 characters"`
}

// CredentialsOutput carries minted credentials to the requesting agent.
// This is the only path minted secrets take across the MCP boundary,
// and each grant's secret crosses it exactly once by default.
type CredentialsOutput struct {
	AccessKeyID     string `json:"access_key_id" jsonschema:"temporary AWS access key id"`
	SecretAccessKey string `json:"secret_access_key" jsonschema:"temporary AWS secret access key; delivered exactly once"`
	SessionToken    string `json:"session_token" jsonschema:"temporary AWS session token; delivered exactly once"`
	Expiration      string `json:"expiration" jsonschema:"RFC 3339 credential expiry"`
}

// StatementExplanationOutput explains one policy statement; the slice
// in ExplanationOutput is index-parallel to the policy's Statement
// array.
type StatementExplanationOutput struct {
	CapabilityID      string            `json:"capability_id" jsonschema:"catalog entry that produced this statement"`
	CapabilityVersion int               `json:"capability_version" jsonschema:"catalog entry version"`
	Params            map[string]string `json:"params,omitempty" jsonschema:"validated parameter values rendered into the statement"`
	Reason            string            `json:"reason" jsonschema:"template-rendered reason for the statement"`
}

// ExplanationOutput traces every statement of the minted policy.
type ExplanationOutput struct {
	Statements []StatementExplanationOutput `json:"statements" jsonschema:"one entry per policy statement, in statement order"`
}

// MissingParamOutput names one missing or invalid parameter.
type MissingParamOutput struct {
	Capability    string   `json:"capability" jsonschema:"capability id the parameter belongs to"`
	Name          string   `json:"name" jsonschema:"parameter name"`
	ExpectedShape string   `json:"expected_shape" jsonschema:"accepted grammar or allowlist description"`
	Examples      []string `json:"examples,omitempty" jsonschema:"allowlist-derived example values"`
}

// CandidateCapabilityOutput is one catalog entry to confirm by id.
type CandidateCapabilityOutput struct {
	ID      string `json:"id" jsonschema:"capability id to confirm"`
	Summary string `json:"summary" jsonschema:"one-line capability summary"`
}

// ClarificationOutput is the structured needs_clarification payload.
type ClarificationOutput struct {
	Code          string                      `json:"code" jsonschema:"machine-readable clarification code, for example MISSING_PARAM"`
	Questions     []string                    `json:"questions,omitempty" jsonschema:"questions to answer in the retry"`
	MissingParams []MissingParamOutput        `json:"missing_params,omitempty" jsonschema:"exact missing or invalid parameters with expected shapes"`
	Candidates    []CandidateCapabilityOutput `json:"candidates,omitempty" jsonschema:"candidate capabilities to confirm by id"`
	RetryToken    string                      `json:"retry_token" jsonschema:"pass this back in request_grant.retry_token to attach the retry to the same grant"`
	Round         int                         `json:"round" jsonschema:"clarification round number, at most 2"`
}

// GrantOutput is the shared result shape of request_grant and
// get_grant. Which fields are present depends on status, exactly as
// section 4.2 lists the outputs by status.
type GrantOutput struct {
	GrantID                string               `json:"grant_id,omitempty" jsonschema:"grant ULID; the correlation identity for this request"`
	Status                 string               `json:"status" jsonschema:"one of active, pending_approval, needs_clarification, denied, error, released, expired"`
	Credentials            *CredentialsOutput   `json:"credentials,omitempty" jsonschema:"minted credentials; present exactly once per grant"`
	ExpiresAt              string               `json:"expires_at,omitempty" jsonschema:"RFC 3339 credential expiry when active"`
	ScopeSummary           string               `json:"scope_summary,omitempty" jsonschema:"human-readable summary of the granted scope"`
	Explanation            *ExplanationOutput   `json:"explanation,omitempty" jsonschema:"statement-by-statement trace of the minted policy"`
	PollAfterSeconds       int                  `json:"poll_after_seconds,omitempty" jsonschema:"suggested seconds to wait before polling get_grant again"`
	PendingExpiresAt       string               `json:"pending_expires_at,omitempty" jsonschema:"RFC 3339 deadline after which a pending approval expires"`
	Clarification          *ClarificationOutput `json:"clarification,omitempty" jsonschema:"structured clarification when status is needs_clarification"`
	DenialCode             string               `json:"denial_code,omitempty" jsonschema:"machine-readable denial code when status is denied"`
	Detail                 string               `json:"detail,omitempty" jsonschema:"template-rendered explanation of a denial or error"`
	HumanApprovalAvailable bool                 `json:"human_approval_available,omitempty" jsonschema:"true when a human approval path exists for a denied request"`
	ErrorCode              string               `json:"error_code,omitempty" jsonschema:"sanitized enumerated code when status is error"`
}

// CapabilityRefOutput pins one catalog entry by id and version.
type CapabilityRefOutput struct {
	ID      string `json:"id" jsonschema:"capability id"`
	Version int    `json:"version" jsonschema:"capability version"`
}

// GuardrailVerdictOutput is one guardrail check result.
type GuardrailVerdictOutput struct {
	Name    string `json:"name" jsonschema:"guardrail name, for example G4-resource-allowlist"`
	Verdict string `json:"verdict" jsonschema:"pass, warn, or fail"`
	Detail  string `json:"detail,omitempty" jsonschema:"template-rendered verdict detail"`
}

// ExplainGrantOutput is the explain_grant result.
type ExplainGrantOutput struct {
	GrantID      string                   `json:"grant_id,omitempty" jsonschema:"grant ULID"`
	Status       string                   `json:"status" jsonschema:"current grant status, or error"`
	Task         string                   `json:"task,omitempty" jsonschema:"the declared task, control sequences stripped"`
	Reason       string                   `json:"reason,omitempty" jsonschema:"the declared reason, control sequences stripped"`
	Capabilities []CapabilityRefOutput    `json:"capabilities,omitempty" jsonschema:"matched capabilities with versions"`
	Guardrails   []GuardrailVerdictOutput `json:"guardrails,omitempty" jsonschema:"every guardrail verdict, including passes"`
	PolicyJSON   string                   `json:"policy_json,omitempty" jsonschema:"the final minified session policy document"`
	Outcome      string                   `json:"outcome,omitempty" jsonschema:"decision outcome for this grant"`
	Approver     string                   `json:"approver,omitempty" jsonschema:"approver as a role, human or auto, never a name"`
	DenialCode   string                   `json:"denial_code,omitempty" jsonschema:"denial code when the grant was denied"`
	ErrorCode    string                   `json:"error_code,omitempty" jsonschema:"sanitized enumerated code when status is error"`
	Detail       string                   `json:"detail,omitempty" jsonschema:"explanation of an error result"`
}

// ParamShapeOutput describes one capability parameter.
type ParamShapeOutput struct {
	Name          string   `json:"name" jsonschema:"parameter name"`
	ExpectedShape string   `json:"expected_shape" jsonschema:"accepted grammar or allowlist description"`
	Examples      []string `json:"examples,omitempty" jsonschema:"example values"`
}

// CapabilitySummaryOutput is one catalog entry visible to the agent.
type CapabilitySummaryOutput struct {
	ID      string             `json:"id" jsonschema:"capability id to use in request_grant"`
	Summary string             `json:"summary" jsonschema:"one-line capability summary"`
	Params  []ParamShapeOutput `json:"params,omitempty" jsonschema:"parameters the capability expects"`
}

// ListCapabilitiesOutput is the list_capabilities result.
type ListCapabilitiesOutput struct {
	Profiles       []string                  `json:"profiles" jsonschema:"profiles this agent may mint under"`
	DefaultProfile string                    `json:"default_profile,omitempty" jsonschema:"profile used when request_grant omits one"`
	Capabilities   []CapabilitySummaryOutput `json:"capabilities" jsonschema:"catalog entries visible to this agent"`
	ErrorCode      string                    `json:"error_code,omitempty" jsonschema:"sanitized enumerated code on failure"`
	Detail         string                    `json:"detail,omitempty" jsonschema:"explanation of an error result"`
}

// ReleaseGrantOutput is the release_grant result.
type ReleaseGrantOutput struct {
	GrantID           string `json:"grant_id,omitempty" jsonschema:"grant ULID"`
	Status            string `json:"status" jsonschema:"released, or error"`
	Outcome           string `json:"outcome,omitempty" jsonschema:"recorded release outcome"`
	ReleasedAt        string `json:"released_at,omitempty" jsonschema:"RFC 3339 release time"`
	RevocationWritten bool   `json:"revocation_written,omitempty" jsonschema:"true when revoke_on_release wrote a targeted deny"`
	ErrorCode         string `json:"error_code,omitempty" jsonschema:"sanitized enumerated code on failure"`
	Detail            string `json:"detail,omitempty" jsonschema:"explanation of an error result"`
}
