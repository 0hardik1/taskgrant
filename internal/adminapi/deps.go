// Package adminapi is the human-side surface of taskgrant (sections
// 4.1 and 11): a unix-socket JSON API for the CLI and an optional
// bearer-authed HTTP binding for shared deployments. One mux serves
// both listeners; only the way approver identity is established
// differs. No MCP tool can reach anything in this package.
//
// Every response passes through a JSON sanitizer that strips ANSI/C0
// control sequences from every string (section 12.5), because approval
// and audit payloads embed hostile agent bytes such as task and reason.
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Sentinel errors dependency implementations return; the HTTP layer
// maps them to status codes.
var (
	// ErrNotFound: no such approval, grant, agent, or profile.
	ErrNotFound = errors.New("adminapi: not found")
	// ErrAlreadyDecided: the approval was already approved or denied.
	ErrAlreadyDecided = errors.New("adminapi: approval already decided")
	// ErrExpired: the pending approval passed its TTL.
	ErrExpired = errors.New("adminapi: approval expired")
)

// Approver identity methods, recorded on approval records (section 11:
// the unix socket carries the OS peer, HTTP carries the bearer
// principal).
const (
	MethodCLI = "cli"
	MethodAPI = "api"
)

// Approver is the verified identity behind an approve or deny call.
type Approver struct {
	// Method is MethodCLI (unix socket peer credentials) or MethodAPI
	// (HTTP bearer principal).
	Method string `json:"method"`
	// Principal is the resolved identity: a username or bearer
	// principal name.
	Principal string `json:"principal"`
	// UID is the socket peer's uid; -1 when unknown (HTTP).
	UID int `json:"uid"`
	// PID is the socket peer's pid; 0 when unknown.
	PID int `json:"pid"`
}

// PendingApproval is one grant parked in pending_approval. Task and
// Reason are raw agent bytes; the response writer sanitizes them.
type PendingApproval struct {
	ID           string    `json:"id"`
	GrantID      string    `json:"grant_id"`
	AgentID      string    `json:"agent_id"`
	Profile      string    `json:"profile"`
	Task         string    `json:"task"`
	Reason       string    `json:"reason"`
	Capabilities []string  `json:"capabilities"`
	AccessLevels []string  `json:"access_levels"`
	PolicyJSON   string    `json:"policy_json"`
	RequestedAt  time.Time `json:"requested_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ApprovalDecision is the outcome of an approve or deny call. On
// approve the broker mints at that moment (section 11); MintOutcome
// reports how that went in sanitized enumerated form, never raw STS
// text and never any secret.
type ApprovalDecision struct {
	ID          string    `json:"id"`
	GrantID     string    `json:"grant_id"`
	Decision    string    `json:"decision"` // approved | denied
	DecidedAt   time.Time `json:"decided_at"`
	MintOutcome string    `json:"mint_outcome,omitempty"` // minted | mint_failed
}

// ApprovalsBroker is the consumer-side seam onto the durable approval
// queue and the mint-on-approve flow.
type ApprovalsBroker interface {
	ListPending(ctx context.Context) ([]PendingApproval, error)
	GetPending(ctx context.Context, id string) (*PendingApproval, error)
	Approve(ctx context.Context, id string, by Approver, note string) (*ApprovalDecision, error)
	Deny(ctx context.Context, id string, by Approver, note string) (*ApprovalDecision, error)
}

// AuditQuery filters an audit list call (section 9.4).
type AuditQuery struct {
	Agent    string
	Profile  string
	Outcome  string
	Resource string
	Since    time.Time
	Until    time.Time
	Limit    int
}

// AuditRecord is one decision log record with its promoted columns and
// the full canonical body.
type AuditRecord struct {
	RecordID  string          `json:"record_id"`
	GrantID   string          `json:"grant_id"`
	Kind      string          `json:"kind"`
	AgentID   string          `json:"agent_id"`
	Timestamp time.Time       `json:"ts"`
	Outcome   string          `json:"outcome,omitempty"`
	Body      json.RawMessage `json:"body,omitempty"`
}

// ChainVerification is the result of an audit verify run (section 9.3).
type ChainVerification struct {
	OK             bool   `json:"ok"`
	RecordsChecked int    `json:"records_checked"`
	BrokenAt       string `json:"broken_at,omitempty"`
	AnchorChecked  bool   `json:"anchor_checked"`
	AnchorOK       bool   `json:"anchor_ok"`
	Detail         string `json:"detail,omitempty"`
}

// ScopeReport is the union of one agent's live-window grants (creep
// review, section 9.4).
type ScopeReport struct {
	AgentID      string    `json:"agent_id"`
	Since        time.Time `json:"since"`
	Until        time.Time `json:"until"`
	GrantCount   int       `json:"grant_count"`
	Capabilities []string  `json:"capabilities"`
	Actions      []string  `json:"actions"`
	Resources    []string  `json:"resources"`
}

// AuditStore is the consumer-side seam onto the decision log.
type AuditStore interface {
	ListRecords(ctx context.Context, q AuditQuery) ([]AuditRecord, error)
	GrantRecords(ctx context.Context, grantID string) ([]AuditRecord, error)
	Search(ctx context.Context, query string, limit int) ([]AuditRecord, error)
	Scope(ctx context.Context, agentID string) (*ScopeReport, error)
	Verify(ctx context.Context) (*ChainVerification, error)
}

// RevocationResult reports one revocation write (section 8.5).
type RevocationResult struct {
	Mechanism string    `json:"mechanism"`
	Profile   string    `json:"profile,omitempty"`
	GrantID   string    `json:"grant_id,omitempty"`
	AppliedAt time.Time `json:"applied_at"`
	Detail    string    `json:"detail,omitempty"`
}

// Revoker triggers best-effort revocation. Nil when revocation is
// disabled in config.
type Revoker interface {
	RevokeProfile(ctx context.Context, profile string) (*RevocationResult, error)
	RevokeGrant(ctx context.Context, grantID string) (*RevocationResult, error)
}

// ConfigReloader triggers a config/catalog hot reload. Nil disables
// the endpoint.
type ConfigReloader interface {
	Reload(ctx context.Context) error
}

// ReadyChecker gates readiness. Nil means always ready once serving.
type ReadyChecker interface {
	Ready(ctx context.Context) error
}

// AdminTokenVerifier authenticates the HTTP admin binding and names
// the principal that lands in approval records.
type AdminTokenVerifier interface {
	VerifyAdminToken(token string) (principal string, err error)
}

// CredsCapability is one structured capability hint on a creds
// request. Params are hostile bytes until they pass grammar and
// allowlist validation downstream.
type CredsCapability struct {
	ID     string            `json:"id"`
	Params map[string]string `json:"params,omitempty"`
}

// CredsRequest is one `taskgrant creds` grant request over the local
// admin socket (section 4.3): the credential_process delivery path that
// keeps secrets out of an agent's context window.
type CredsRequest struct {
	Agent           string            `json:"agent,omitempty"`
	Profile         string            `json:"profile,omitempty"`
	Task            string            `json:"task"`
	Reason          string            `json:"reason,omitempty"`
	Capabilities    []CredsCapability `json:"capabilities,omitempty"`
	DurationSeconds int               `json:"duration_seconds,omitempty"`
	IdempotencyKey  string            `json:"idempotency_key,omitempty"`
	WaitSeconds     int               `json:"wait_seconds,omitempty"`
}

// CredsResponse reports the grant outcome. On status "active" it
// carries the plaintext credentials exactly once; the CLI renders them
// as credential_process JSON and they are never stored or logged.
type CredsResponse struct {
	Status          string `json:"status"`
	GrantID         string `json:"grant_id,omitempty"`
	Version         int    `json:"version,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	Expiration      string `json:"expiration,omitempty"`
	DenialCode      string `json:"denial_code,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

// CredsBroker serves the `taskgrant creds` helper. Nil disables the
// endpoint.
type CredsBroker interface {
	RequestCredentials(ctx context.Context, req CredsRequest) (*CredsResponse, error)
}
