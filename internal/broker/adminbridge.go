package broker

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0hardik1/taskgrant/internal/adminapi"
	"github.com/0hardik1/taskgrant/internal/approvals"
	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/mcpserver"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/synth"
)

// AdminBridge adapts the broker to the adminapi consumer interfaces:
// the approvals surface, the revoker, and the creds helper. One value
// serves all three.
type AdminBridge struct {
	B *Broker
}

var (
	_ adminapi.ApprovalsBroker = AdminBridge{}
	_ adminapi.Revoker         = AdminBridge{}
	_ adminapi.CredsBroker     = AdminBridge{}
)

// ListPending implements adminapi.ApprovalsBroker.
func (a AdminBridge) ListPending(ctx context.Context) ([]adminapi.PendingApproval, error) {
	rows, err := a.B.approvals.List(ctx, store.StatusPending)
	if err != nil {
		return nil, err
	}
	out := make([]adminapi.PendingApproval, 0, len(rows))
	for _, row := range rows {
		out = append(out, a.pendingView(row))
	}
	return out, nil
}

// GetPending implements adminapi.ApprovalsBroker.
func (a AdminBridge) GetPending(ctx context.Context, id string) (*adminapi.PendingApproval, error) {
	row, err := a.B.approvals.Get(ctx, id)
	if err != nil {
		if isStoreNotFound(err) {
			return nil, adminapi.ErrNotFound
		}
		return nil, err
	}
	v := a.pendingView(row)
	return &v, nil
}

// pendingView renders one queue row. Raw agent bytes stay raw; the
// adminapi response writer sanitizes every string on the way out.
func (a AdminBridge) pendingView(row store.PendingApproval) adminapi.PendingApproval {
	return adminapi.PendingApproval{
		ID:           row.GrantID,
		GrantID:      row.GrantID,
		AgentID:      row.AgentID,
		Profile:      row.Profile,
		Task:         row.Task,
		Reason:       row.Reason,
		Capabilities: append([]string(nil), row.Capabilities...),
		AccessLevels: a.policyAccessLevels(row.PolicyJSON),
		PolicyJSON:   row.PolicyJSON,
		RequestedAt:  row.ReceivedAt,
		ExpiresAt:    row.ExpiresAt,
	}
}

// policyAccessLevels resolves the distinct dataset access levels of a
// stored policy document for the approver view.
func (a AdminBridge) policyAccessLevels(policyJSON string) []string {
	actions := policyActions([]byte(policyJSON))
	set := a.B.accessLevels(actions)
	out := make([]string, 0, len(set))
	for lvl := range set {
		out = append(out, lvl)
	}
	sort.Strings(out)
	return out
}

// Approve implements adminapi.ApprovalsBroker: decision plus the
// mint-at-approval flow.
func (a AdminBridge) Approve(ctx context.Context, id string, by adminapi.Approver, note string) (*adminapi.ApprovalDecision, error) {
	out, err := a.B.ApproveGrant(ctx, id, identityFrom(by), note)
	if err != nil {
		return nil, a.mapDecisionError(ctx, id, err)
	}
	return &adminapi.ApprovalDecision{
		ID: id, GrantID: id, Decision: "approved",
		DecidedAt: out.DecidedAt, MintOutcome: out.MintOutcome,
	}, nil
}

// Deny implements adminapi.ApprovalsBroker.
func (a AdminBridge) Deny(ctx context.Context, id string, by adminapi.Approver, note string) (*adminapi.ApprovalDecision, error) {
	out, err := a.B.DenyGrant(ctx, id, identityFrom(by), note)
	if err != nil {
		return nil, a.mapDecisionError(ctx, id, err)
	}
	return &adminapi.ApprovalDecision{
		ID: id, GrantID: id, Decision: "denied", DecidedAt: out.DecidedAt,
	}, nil
}

// identityFrom converts the adminapi approver to the approvals
// identity recorded on decisions.
func identityFrom(by adminapi.Approver) approvals.Identity {
	method := approvals.MethodCLI
	if by.Method == adminapi.MethodAPI {
		method = approvals.MethodAPI
	}
	return approvals.Identity{Approver: by.Principal, Method: method}
}

// mapDecisionError maps queue errors to the adminapi sentinels.
func (a AdminBridge) mapDecisionError(ctx context.Context, id string, err error) error {
	switch {
	case isStoreNotFound(err):
		return adminapi.ErrNotFound
	case errors.Is(err, approvals.ErrNotPending), errors.Is(err, store.ErrAlreadyDecided):
		if row, gerr := a.B.approvals.Get(ctx, id); gerr == nil && row.Status == store.StatusExpiredPending {
			return adminapi.ErrExpired
		}
		return adminapi.ErrAlreadyDecided
	default:
		return err
	}
}

// RevokeProfile implements adminapi.Revoker.
func (a AdminBridge) RevokeProfile(ctx context.Context, profile string) (*adminapi.RevocationResult, error) {
	out, err := a.B.RevokeProfile(ctx, profile)
	if err != nil {
		return nil, mapRevokeError(err)
	}
	return &adminapi.RevocationResult{
		Mechanism: out.Mechanism, Profile: out.Profile,
		AppliedAt: out.AppliedAt, Detail: out.Detail,
	}, nil
}

// RevokeGrant implements adminapi.Revoker.
func (a AdminBridge) RevokeGrant(ctx context.Context, grantID string) (*adminapi.RevocationResult, error) {
	out, err := a.B.RevokeGrantByID(ctx, grantID)
	if err != nil {
		return nil, mapRevokeError(err)
	}
	return &adminapi.RevocationResult{
		Mechanism: out.Mechanism, GrantID: out.GrantID, Profile: out.Profile,
		AppliedAt: out.AppliedAt, Detail: out.Detail,
	}, nil
}

func mapRevokeError(err error) error {
	if isStoreNotFound(err) {
		return adminapi.ErrNotFound
	}
	return err
}

// RequestCredentials implements adminapi.CredsBroker: the `taskgrant
// creds` helper's grant request over the admin socket (section 4.3).
// Inputs are hostile bytes and are capped here because this path does
// not cross the MCP boundary caps.
func (a AdminBridge) RequestCredentials(ctx context.Context, req adminapi.CredsRequest) (*adminapi.CredsResponse, error) {
	agentID := req.Agent
	if agentID == "" {
		agentID = a.B.cfg.Server.DefaultAgent
	}
	if err := domain.ValidateAgentID(agentID); err != nil {
		return &adminapi.CredsResponse{Status: "error", Detail: "agent: invalid or missing agent id"}, nil
	}
	if req.Task == "" {
		return &adminapi.CredsResponse{Status: "error", Detail: "task: required"}, nil
	}
	if utf8.RuneCountInString(req.Task) > mcpserver.MaxTaskChars {
		return &adminapi.CredsResponse{Status: "error", Detail: "task: too long"}, nil
	}
	if utf8.RuneCountInString(req.Reason) > mcpserver.MaxReasonChars {
		return &adminapi.CredsResponse{Status: "error", Detail: "reason: too long"}, nil
	}
	if len(req.Capabilities) > mcpserver.MaxCapabilities {
		return &adminapi.CredsResponse{Status: "error", Detail: "capabilities: too many"}, nil
	}
	wait := req.WaitSeconds
	if wait < 0 {
		wait = 0
	}
	if wait > a.B.cfg.Server.MaxWaitSeconds {
		wait = a.B.cfg.Server.MaxWaitSeconds
	}
	gr := mcpserver.GrantRequest{
		Task:            req.Task,
		Reason:          req.Reason,
		Profile:         req.Profile,
		DurationSeconds: req.DurationSeconds,
		IdempotencyKey:  req.IdempotencyKey,
		WaitSeconds:     wait,
		Transport:       "creds",
	}
	for _, c := range req.Capabilities {
		if c.ID == "" || utf8.RuneCountInString(c.ID) > mcpserver.MaxCapabilityID {
			return &adminapi.CredsResponse{Status: "error", Detail: "capabilities: invalid id"}, nil
		}
		params := make(map[string]string, len(c.Params))
		for k, v := range c.Params {
			if utf8.RuneCountInString(k) > mcpserver.MaxParamNameChars ||
				utf8.RuneCountInString(v) > mcpserver.MaxParamValueChars {
				return &adminapi.CredsResponse{Status: "error", Detail: "capabilities: param too long"}, nil
			}
			params[k] = v
		}
		gr.Capabilities = append(gr.Capabilities, synth.CapabilityHint{ID: c.ID, Params: params})
	}

	view, err := a.B.RequestGrant(ctx, agentID, gr)
	if err != nil {
		return nil, err
	}
	resp := &adminapi.CredsResponse{Status: view.Status, GrantID: view.GrantID}
	switch view.Status {
	case "active":
		if view.Credentials == nil {
			resp.Status = "error"
			resp.Detail = "credentials were already delivered for this grant"
			return resp, nil
		}
		resp.Version = 1
		resp.AccessKeyID = view.Credentials.AccessKeyID
		resp.SecretAccessKey = view.Credentials.SecretAccessKey
		resp.SessionToken = view.Credentials.SessionToken
		resp.Expiration = view.Credentials.Expiration.UTC().Format(time.RFC3339)
	case "denied":
		resp.DenialCode = string(view.DenialCode)
		resp.Detail = view.Detail
	case "needs_clarification":
		if view.Clarification != nil {
			resp.Detail = "clarification required: " + view.Clarification.Code + "; " +
				strings.Join(view.Clarification.Questions, " ")
		}
	case "pending_approval":
		resp.Detail = "approval pending; approve with: taskgrant approve " + view.GrantID
	case "error":
		resp.Detail = view.Detail
	}
	return resp, nil
}

// AuditBridge adapts the store to the adminapi audit surface.
type AuditBridge struct {
	Store *store.Store
	Clock func() time.Time
}

var _ adminapi.AuditStore = AuditBridge{}

func (a AuditBridge) now() time.Time {
	if a.Clock != nil {
		return a.Clock().UTC()
	}
	return time.Now().UTC()
}

// ListRecords implements adminapi.AuditStore.
func (a AuditBridge) ListRecords(ctx context.Context, q adminapi.AuditQuery) ([]adminapi.AuditRecord, error) {
	recs, err := a.Store.List(ctx, store.ListFilter{
		Agent:           q.Agent,
		Profile:         q.Profile,
		Outcome:         q.Outcome,
		ResourcePattern: q.Resource,
		Since:           q.Since,
		Until:           q.Until,
		Limit:           q.Limit,
	})
	if err != nil {
		return nil, err
	}
	return auditRecords(recs), nil
}

// GrantRecords implements adminapi.AuditStore.
func (a AuditBridge) GrantRecords(ctx context.Context, grantID string) ([]adminapi.AuditRecord, error) {
	recs, err := a.Store.GrantChain(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, adminapi.ErrNotFound
	}
	return auditRecords(recs), nil
}

// Search implements adminapi.AuditStore.
func (a AuditBridge) Search(ctx context.Context, query string, limit int) ([]adminapi.AuditRecord, error) {
	recs, err := a.Store.Search(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	return auditRecords(recs), nil
}

// Scope implements adminapi.AuditStore.
func (a AuditBridge) Scope(ctx context.Context, agentID string) (*adminapi.ScopeReport, error) {
	rep, err := a.Store.Scope(ctx, agentID, a.now())
	if err != nil {
		return nil, err
	}
	now := a.now()
	return &adminapi.ScopeReport{
		AgentID:      rep.Agent,
		Since:        now.Add(-13 * time.Hour),
		Until:        now,
		GrantCount:   len(rep.LiveGrants),
		Capabilities: rep.Capabilities,
		Actions:      rep.Actions,
		Resources:    rep.Resources,
	}, nil
}

// Verify implements adminapi.AuditStore.
func (a AuditBridge) Verify(ctx context.Context) (*adminapi.ChainVerification, error) {
	res, err := a.Store.Verify(ctx)
	if err != nil {
		var chainErr *store.ChainError
		if errors.As(err, &chainErr) {
			return &adminapi.ChainVerification{
				OK:       false,
				BrokenAt: chainErr.RecordID,
				Detail:   chainErr.Reason,
			}, nil
		}
		return nil, err
	}
	return &adminapi.ChainVerification{
		OK:             true,
		RecordsChecked: int(res.Records),
		Detail:         "chain head " + res.HeadHash,
	}, nil
}

// auditRecords converts store records to the adminapi wire shape.
func auditRecords(recs []store.Record) []adminapi.AuditRecord {
	out := make([]adminapi.AuditRecord, 0, len(recs))
	for _, rec := range recs {
		out = append(out, adminapi.AuditRecord{
			RecordID:  rec.RecordID,
			GrantID:   rec.GrantID,
			Kind:      string(rec.Kind),
			AgentID:   rec.AgentID,
			Timestamp: rec.TS,
			Outcome:   rec.Outcome,
			Body:      rec.Body,
		})
	}
	return out
}

// policyActions parses the Action fields of a policy document. The
// bytes are broker-verified but parsed defensively.
func policyActions(policyJSON []byte) []string {
	if len(policyJSON) == 0 {
		return nil
	}
	var doc struct {
		Statement []struct {
			Action any `json:"Action"`
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
		switch a := st.Action.(type) {
		case string:
			add(a)
		case []any:
			for _, v := range a {
				add(v)
			}
		}
	}
	return out
}
