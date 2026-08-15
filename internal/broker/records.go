package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/guardrails"
	"github.com/0hardik1/taskgrant/internal/mcpserver"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/stsmint"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/synthesizer"
)

// recordSchemaVersion versions the decision record body layout.
const recordSchemaVersion = 1

// hintsBody mirrors the request hints for the decision record.
type hintsBody struct {
	Capabilities []capabilityHintBody `json:"capabilities,omitempty"`
	Services     []string             `json:"services,omitempty"`
	Resources    []string             `json:"resources,omitempty"`
	Access       string               `json:"access,omitempty"`
}

type capabilityHintBody struct {
	ID     string            `json:"id"`
	Params map[string]string `json:"params,omitempty"`
}

// matcherBody is the section 9.1 matcher trace.
type matcherBody struct {
	Matcher            string          `json:"matcher,omitempty"`
	Structured         bool            `json:"structured,omitempty"`
	CacheHit           bool            `json:"cache_hit,omitempty"`
	IntentHash         string          `json:"intent_hash,omitempty"`
	Candidates         []candidateBody `json:"candidates,omitempty"`
	ModelID            string          `json:"model_id,omitempty"`
	PromptTemplateHash string          `json:"prompt_template_hash,omitempty"`
	Notes              []string        `json:"notes,omitempty"`
	ApprovalReasons    []string        `json:"approval_reasons,omitempty"`
	FirstUse           []string        `json:"first_use_capabilities,omitempty"`
}

type candidateBody struct {
	CapabilityID string  `json:"capability_id"`
	Confidence   float64 `json:"confidence"`
	// Rationale is log-only LLM output; it never reaches an agent.
	Rationale string `json:"rationale,omitempty"`
}

// capabilityBody pins one selected capability with validated params.
// Scope queries read the "id" field (store/query.go capabilityID).
type capabilityBody struct {
	ID      string            `json:"id"`
	Version int               `json:"version"`
	Params  map[string]string `json:"params,omitempty"`
}

type statementExplBody struct {
	CapabilityID      string            `json:"capability_id"`
	CapabilityVersion int               `json:"capability_version"`
	Params            map[string]string `json:"params,omitempty"`
	Reason            string            `json:"reason"`
}

// guardrailCheckBody records one guardrail verdict, passes included.
type guardrailCheckBody struct {
	Name    string `json:"name"`
	Verdict string `json:"verdict"`
	Detail  string `json:"detail,omitempty"`
}

// approvalBody records the approval context on approval-kind records.
type approvalBody struct {
	Decision   string `json:"decision"` // approved | denied | expired_pending
	Approver   string `json:"approver,omitempty"`
	Method     string `json:"method,omitempty"`
	Note       string `json:"note,omitempty"`
	RequiredBy string `json:"required_by,omitempty"`
}

// stsBody is the section 9.1 STS block, null unless minted. The secret
// and session token never appear; the access key id only.
type stsBody struct {
	RoleARN                 string            `json:"role_arn"`
	RoleSessionName         string            `json:"role_session_name"`
	SourceIdentity          string            `json:"source_identity"`
	SessionTags             map[string]string `json:"session_tags"`
	TransitiveTagKeys       []string          `json:"transitive_tag_keys"`
	AssumedRoleARN          string            `json:"assumed_role_arn,omitempty"`
	AccessKeyID             string            `json:"access_key_id"`
	Expiration              string            `json:"expiration"`
	PackedPolicySizePercent int               `json:"packed_policy_size_percent"`
	STSRequestID            string            `json:"sts_request_id,omitempty"`
}

type mintAttemptBody struct {
	PolicyChars    int    `json:"policy_chars"`
	PolicyARNCount int    `json:"policy_arn_count"`
	Message        string `json:"message,omitempty"`
}

type clarificationBody struct {
	Code            string   `json:"code"`
	Round           int      `json:"round"`
	Questions       []string `json:"questions,omitempty"`
	MissingParams   []string `json:"missing_params,omitempty"`
	Candidates      []string `json:"candidates,omitempty"`
	RetryTokenSHA   string   `json:"retry_token_sha256_8,omitempty"`
	IntentHash      string   `json:"intent_hash,omitempty"`
	ExhaustionLimit int      `json:"exhaustion_limit,omitempty"`
}

type releaseBody struct {
	Outcome    string `json:"outcome"`
	Note       string `json:"note,omitempty"`
	ReleasedAt string `json:"released_at"`
}

type revocationBody struct {
	Mechanism string `json:"mechanism"` // role-wide | grant
	Role      string `json:"role"`
	Profile   string `json:"profile,omitempty"`
	Sid       string `json:"sid,omitempty"`
	Document  string `json:"document,omitempty"`
	AppliedAt string `json:"applied_at"`
}

// decisionBody is the full section 9.1 record body. Fields absent from
// a given record kind stay omitted.
type decisionBody struct {
	SchemaVersion int    `json:"schema_version"`
	RecordID      string `json:"record_id"`
	GrantID       string `json:"grant_id"`
	Kind          string `json:"kind"`

	ReceivedAt string `json:"received_at,omitempty"`
	DecidedAt  string `json:"decided_at,omitempty"`
	MintedAt   string `json:"minted_at,omitempty"`

	AgentID          string     `json:"agent_id"`
	Transport        string     `json:"transport,omitempty"`
	AuthMethod       string     `json:"auth_method,omitempty"`
	TokenFingerprint string     `json:"token_fingerprint,omitempty"`
	RemoteAddr       string     `json:"remote_addr,omitempty"`
	Task             string     `json:"task,omitempty"`
	Reason           string     `json:"reason,omitempty"`
	CallerRef        string     `json:"caller_ref,omitempty"`
	IdempotencyKey   string     `json:"idempotency_key,omitempty"`
	Profile          string     `json:"profile,omitempty"`
	Hints            *hintsBody `json:"hints,omitempty"`

	RequestedDurationSeconds int `json:"requested_duration_seconds,omitempty"`
	GrantedDurationSeconds   int `json:"granted_duration_seconds,omitempty"`

	Matcher         *matcherBody        `json:"matcher,omitempty"`
	Capabilities    []capabilityBody    `json:"capabilities,omitempty"`
	PolicyJSON      string              `json:"policy_json,omitempty"`
	PolicyChars     int                 `json:"policy_chars,omitempty"`
	PolicyArns      []string            `json:"policy_arns,omitempty"`
	MaxPolicyChars  int                 `json:"max_policy_chars,omitempty"`
	ExpandedActions []string            `json:"expanded_actions,omitempty"`
	Explanation     []statementExplBody `json:"explanation,omitempty"`
	CatalogHash     string              `json:"catalog_hash,omitempty"`
	DatasetHash     string              `json:"dataset_hash,omitempty"`
	ConfigHash      string              `json:"config_hash,omitempty"`
	SynthVersion    string              `json:"synth_version,omitempty"`

	Guardrails []guardrailCheckBody `json:"guardrails,omitempty"`

	Outcome      string   `json:"outcome"`
	DeniedBy     string   `json:"denied_by,omitempty"`
	DenialCode   string   `json:"denial_code,omitempty"`
	DenialDetail []string `json:"denial_detail,omitempty"`

	Approval     *approvalBody      `json:"approval,omitempty"`
	STS          *stsBody           `json:"sts,omitempty"`
	Expiration   string             `json:"expiration,omitempty"`
	MintAttempts []mintAttemptBody  `json:"mint_attempts,omitempty"`
	Clar         *clarificationBody `json:"clarification,omitempty"`
	Release      *releaseBody       `json:"release,omitempty"`
	Revocation   *revocationBody    `json:"revocation,omitempty"`
}

// rfc3339 renders a time for record bodies; zero renders empty.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// baseBody builds the shared envelope portion of a record body.
func (b *Broker) baseBody(e *grantEntry, kind domain.RecordKind, recordID string) decisionBody {
	body := decisionBody{
		SchemaVersion:    recordSchemaVersion,
		RecordID:         recordID,
		GrantID:          e.grant.GrantID,
		Kind:             string(kind),
		ReceivedAt:       rfc3339(e.grant.ReceivedAt),
		DecidedAt:        rfc3339(e.grant.DecidedAt),
		MintedAt:         rfc3339(e.grant.MintedAt),
		AgentID:          e.grant.AgentID,
		Transport:        e.req.Transport,
		TokenFingerprint: e.req.TokenFingerprint,
		RemoteAddr:       e.req.RemoteAddr,
		Task:             e.req.Task,
		Reason:           e.req.Reason,
		CallerRef:        e.req.CallerRef,
		IdempotencyKey:   e.req.IdempotencyKey,
		Profile:          e.grant.Profile,
	}
	switch e.req.Transport {
	case mcpserver.TransportHTTP:
		body.AuthMethod = "bearer"
	case mcpserver.TransportStdio:
		body.AuthMethod = "process"
	case "creds":
		body.AuthMethod = "socket"
	}
	if len(e.req.Capabilities) > 0 || len(e.req.Services) > 0 ||
		len(e.req.Resources) > 0 || e.req.Access != "" {
		h := &hintsBody{
			Services:  e.req.Services,
			Resources: e.req.Resources,
			Access:    e.req.Access,
		}
		for _, c := range e.req.Capabilities {
			h.Capabilities = append(h.Capabilities, capabilityHintBody{ID: c.ID, Params: c.Params})
		}
		body.Hints = h
	}
	body.RequestedDurationSeconds = e.req.DurationSeconds
	return body
}

// synthesisBody fills the synthesis section from the seam result and
// trace.
func fillSynthesis(body *decisionBody, res synth.Result, trace *synthesizer.Trace) {
	for _, ref := range res.Capabilities {
		body.Capabilities = append(body.Capabilities, capabilityBody{
			ID: ref.ID, Version: ref.Version, Params: capabilityParams(res.Explanation, ref.ID),
		})
	}
	body.PolicyJSON = string(res.PolicyJSON)
	body.PolicyChars = len(res.PolicyJSON)
	body.PolicyArns = res.PolicyArns
	body.ExpandedActions = res.ExpandedActions
	for _, st := range res.Explanation.Statements {
		body.Explanation = append(body.Explanation, statementExplBody{
			CapabilityID:      st.CapabilityID,
			CapabilityVersion: st.CapabilityVersion,
			Params:            st.Params,
			Reason:            st.Reason,
		})
	}
	body.CatalogHash = res.CatalogHash
	body.DatasetHash = res.DatasetHash
	body.ConfigHash = res.ConfigHash
	body.SynthVersion = synthesizer.Version
	if trace != nil {
		m := &matcherBody{
			Matcher:            trace.Matcher,
			Structured:         trace.Structured,
			CacheHit:           trace.CacheHit,
			IntentHash:         trace.IntentHash,
			ModelID:            trace.ModelID,
			PromptTemplateHash: trace.PromptTemplateHash,
			Notes:              trace.Notes,
			ApprovalReasons:    trace.ApprovalReasons,
			FirstUse:           trace.FirstUseCapabilities,
		}
		for _, c := range trace.Candidates {
			m.Candidates = append(m.Candidates, candidateBody{
				CapabilityID: c.CapabilityID, Confidence: c.Confidence, Rationale: c.Rationale,
			})
		}
		body.Matcher = m
		body.DenialDetail = trace.DenialDetail
	}
}

// capabilityParams pulls the merged validated params of one capability
// out of the explanation.
func capabilityParams(expl synth.Explanation, capID string) map[string]string {
	var out map[string]string
	for _, st := range expl.Statements {
		if st.CapabilityID != capID {
			continue
		}
		for k, v := range st.Params {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	return out
}

// fillGuardrails records every check, passes included (section 9.1).
func fillGuardrails(body *decisionBody, res *guardrails.Result) {
	if res == nil {
		return
	}
	for _, c := range res.Checks {
		body.Guardrails = append(body.Guardrails, guardrailCheckBody{
			Name: c.Name, Verdict: string(c.Verdict), Detail: c.Detail,
		})
	}
	if len(res.ExpandedActions) > 0 {
		// The broker's authoritative expansion wins over the seam's.
		body.ExpandedActions = res.ExpandedActions
	}
}

// fillSTS records the mint block and the top-level expiration used by
// scope queries.
func fillSTS(body *decisionBody, m *stsmint.Minted, roleARN string) {
	if m == nil {
		return
	}
	body.STS = &stsBody{
		RoleARN:                 roleARN,
		RoleSessionName:         m.RoleSessionName,
		SourceIdentity:          m.SourceIdentity,
		SessionTags:             m.SessionTags,
		TransitiveTagKeys:       m.TransitiveTagKeys,
		AssumedRoleARN:          m.AssumedRoleARN,
		AccessKeyID:             m.Credentials.AccessKeyID(),
		Expiration:              rfc3339(m.Credentials.Expiration()),
		PackedPolicySizePercent: m.PackedPolicySizePercent,
		STSRequestID:            m.STSRequestID,
	}
	body.Expiration = rfc3339(m.Credentials.Expiration())
}

// appendRecord canonicalizes the body and appends it with the promoted
// envelope columns filled. The explanation column joins the statement
// reasons for FTS.
func (b *Broker) appendRecord(ctx context.Context, e *grantEntry, kind domain.RecordKind, body decisionBody) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var explParts []string
	for _, st := range body.Explanation {
		explParts = append(explParts, st.Reason)
	}
	rec := &store.Record{
		RecordID:    body.RecordID,
		GrantID:     e.grant.GrantID,
		AgentID:     e.grant.AgentID,
		TS:          b.now(),
		Kind:        kind,
		Outcome:     body.Outcome,
		Profile:     e.grant.Profile,
		Task:        e.req.Task,
		Reason:      e.req.Reason,
		Explanation: strings.Join(explParts, "\n"),
		Resources:   policyResources([]byte(body.PolicyJSON)),
		Body:        raw,
	}
	if body.STS != nil {
		rec.SourceIdentity = body.STS.SourceIdentity
		rec.AccessKeyID = body.STS.AccessKeyID
	}
	if err := b.log.Append(ctx, rec); err != nil {
		b.logger.Error("broker: decision record append failed",
			"grant_id", e.grant.GrantID, "kind", string(kind), "err", err)
		return err
	}
	return nil
}

// policyResources extracts the Resource ARNs of a policy document for
// the record_resources side table. The bytes are broker-verified policy
// JSON; a parse failure just yields no resources.
func policyResources(policyJSON []byte) []string {
	if len(policyJSON) == 0 {
		return nil
	}
	var doc struct {
		Statement []struct {
			Resource any `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(policyJSON, &doc); err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(v any) {
		if s, ok := v.(string); ok && s != "" {
			if _, dup := seen[s]; !dup {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	for _, st := range doc.Statement {
		switch r := st.Resource.(type) {
		case string:
			add(r)
		case []any:
			for _, v := range r {
				add(v)
			}
		}
	}
	return out
}

// sha8 returns the first 8 hex chars of the SHA-256 of s, the log-safe
// fingerprint form for secrets-adjacent strings such as retry tokens.
func sha8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}
