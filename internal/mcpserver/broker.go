// Package mcpserver exposes the five MCP tools of architecture section
// 4.2 over the stdio and streamable HTTP transports (section 4.3). It
// is the untrusted-input boundary: every byte an agent sends is
// length-capped here, and every human-facing render of agent text is
// control-sequence-stripped. The grant machinery itself lives behind
// the Broker interface; the concrete broker is injected at wiring time.
package mcpserver

import (
	"context"
	"errors"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/synth"
)

// Sentinel errors a Broker implementation returns. The tool layer maps
// both ErrNotFound and ErrForbidden to a NOT_FOUND result: cross-agent
// lookups must never confirm that a grant exists (section 4.1).
var (
	// ErrNotFound: the grant does not exist, or belongs to another
	// agent. The tool layer renders NOT_FOUND for it.
	ErrNotFound = errors.New("mcpserver: grant not found")
	// ErrForbidden exists so a defensive broker can distinguish the
	// cases internally. It still surfaces as NOT_FOUND on the wire,
	// never FORBIDDEN.
	ErrForbidden = errors.New("mcpserver: access to grant forbidden")
)

// Transport names recorded on grant requests.
const (
	TransportStdio = "stdio"
	TransportHTTP  = "http"
)

// GrantRequest is one boundary-validated request_grant call, handed to
// the broker. Task, Reason, and RetryToken are raw agent bytes within
// their length caps; CallerRef is already sanitized to the session tag
// charset; WaitSeconds is already clamped by config.
type GrantRequest struct {
	Task            string
	Reason          string
	Profile         string
	Capabilities    []synth.CapabilityHint
	Services        []string
	Resources       []string
	Access          string
	DurationSeconds int
	CallerRef       string
	IdempotencyKey  string
	WaitSeconds     int
	RetryToken      string

	// Transport is TransportStdio or TransportHTTP, set by the tool
	// layer for the decision record.
	Transport string
	// TokenFingerprint is the 8-hex-char fingerprint of the bearer
	// token that authenticated this call; empty on stdio.
	TokenFingerprint string
	// RemoteAddr is the broker-observed peer address of the HTTP request
	// that carried this call (section 9.1, 12.4). It is empty on the
	// stdio and local-socket transports, which have no remote peer. Set
	// by the tool layer from the transport, never from an agent field, so
	// an agent cannot forge or override it.
	RemoteAddr string
}

// Credentials is one minted credential set in transit between the
// broker and the tool layer. It redacts itself in String and
// MarshalJSON (invariant I4); delivery to the agent goes through the
// explicit CredentialsOutput conversion only.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// String implements fmt.Stringer with the secret fields redacted.
func (Credentials) String() string { return "Credentials{REDACTED}" }

// MarshalJSON redacts the secret fields so accidental logging or
// serialization of the internal type never leaks them.
func (c Credentials) MarshalJSON() ([]byte, error) {
	return []byte(`{"access_key_id":"` + c.AccessKeyID + `","secret":"REDACTED"}`), nil
}

// GrantView is the broker's answer to request_grant and get_grant: the
// grant's current state rendered for one agent's eyes. Credentials is
// non-nil only when the broker considers them deliverable; the tool
// layer still enforces the once-delivery rule before anything crosses
// the MCP boundary.
type GrantView struct {
	GrantID string
	// Status is the wire status: active, pending_approval,
	// needs_clarification, denied, error, released, or expired.
	Status string

	// Active fields.
	Credentials  *Credentials
	ExpiresAt    time.Time
	ScopeSummary string
	Explanation  *synth.Explanation

	// Pending-approval fields.
	PollAfterSeconds int
	PendingExpiresAt time.Time

	// Clarification round (section 5.6).
	Clarification *synth.Clarification

	// Denial fields. Detail is template-rendered by the broker, never
	// raw STS or LLM output.
	DenialCode             domain.DenialCode
	Detail                 string
	HumanApprovalAvailable bool

	// ErrorCode is set when Status is "error": a sanitized enumerated
	// code such as STS_ERROR. Raw STS errors never reach this struct.
	ErrorCode string
}

// GuardrailVerdict is one guardrail check result rendered for
// explain_grant: pass, warn, or fail, with template-rendered detail.
type GuardrailVerdict struct {
	Name    string
	Verdict string
	Detail  string
}

// GrantExplanation is the decision record redacted for agent eyes
// (explain_grant, section 4.2): the approver appears as a role such as
// "human", never a name.
type GrantExplanation struct {
	GrantID      string
	Status       string
	Task         string
	Reason       string
	Capabilities []synth.CapabilityRef
	Guardrails   []GuardrailVerdict
	PolicyJSON   string
	Outcome      string
	// ApproverRole is "human", "auto", or empty when no decision was
	// made yet. Broker implementations must never put a name here.
	ApproverRole string
	DenialCode   domain.DenialCode
}

// ParamShape describes one capability parameter for list_capabilities.
type ParamShape struct {
	Name          string
	ExpectedShape string
	Examples      []string
}

// CapabilitySummary is one catalog entry visible to the calling agent.
type CapabilitySummary struct {
	ID      string
	Summary string
	Params  []ParamShape
}

// CapabilityListing is the agent's profile-filtered catalog view.
type CapabilityListing struct {
	Profiles       []string
	DefaultProfile string
	Capabilities   []CapabilitySummary
}

// ReleaseView is the broker's answer to release_grant.
type ReleaseView struct {
	GrantID           string
	Outcome           string
	ReleasedAt        time.Time
	RevocationWritten bool
}

// Broker is the consumer-side seam onto the grant machinery. Every
// method is scoped by the verified agent identity: a broker must treat
// agentID as the caller and answer ErrNotFound for any grant that does
// not belong to it. The concrete implementation lives in
// internal/broker and is injected at wiring time.
type Broker interface {
	// RequestGrant runs one request_grant call end to end, blocking up
	// to req.WaitSeconds for an approval when asked to.
	RequestGrant(ctx context.Context, agentID string, req GrantRequest) (*GrantView, error)
	// GetGrant returns the grant's current state for its owning agent.
	GetGrant(ctx context.Context, agentID, grantID string) (*GrantView, error)
	// ExplainGrant returns the agent-redacted decision record.
	ExplainGrant(ctx context.Context, agentID, grantID string) (*GrantExplanation, error)
	// ListCapabilities returns the agent's profile-filtered catalog.
	ListCapabilities(ctx context.Context, agentID string) (*CapabilityListing, error)
	// ReleaseGrant appends a release record; outcome is one of
	// succeeded, failed, or abandoned, validated at the boundary.
	ReleaseGrant(ctx context.Context, agentID, grantID, outcome, note string) (*ReleaseView, error)
}
