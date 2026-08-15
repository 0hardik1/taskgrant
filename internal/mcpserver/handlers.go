package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/textsafe"
)

// errIdentity is the only error handlers return as a tool error: the
// request reached a handler without a bound identity, which behind the
// auth middleware means server misconfiguration, not agent behavior.
var errIdentity = fmt.Errorf("request is not bound to an agent identity")

// Every denial and error below is a normal tool result (section 4.2),
// so agents can read the structured output and adapt. Raw internal
// errors are logged and replaced with enumerated codes.

func (s *Server) handleRequestGrant(ctx context.Context, req *mcp.CallToolRequest, in RequestGrantInput) (*mcp.CallToolResult, GrantOutput, error) {
	agentID, transport, fingerprint, remoteAddr, err := s.identify(req)
	if err != nil {
		s.logger.Error("mcpserver: request_grant identity", "err", err)
		return nil, GrantOutput{}, errIdentity
	}
	br, badField, badDetail := s.validateGrantRequest(in)
	if badField != "" {
		return nil, GrantOutput{
			Status:    "error",
			ErrorCode: CodeInvalidArgument,
			Detail:    fmt.Sprintf("%s: %s", badField, badDetail),
		}, nil
	}
	br.Transport = transport
	br.TokenFingerprint = fingerprint
	// The remote address is broker-observed at the HTTP boundary and set
	// after validateGrantRequest, so no agent field can populate it.
	br.RemoteAddr = remoteAddr

	view, err := s.broker.RequestGrant(ctx, agentID, br)
	if err != nil {
		return nil, s.grantErrorOutput("request_grant", agentID, err), nil
	}
	return nil, s.grantOutput(view), nil
}

func (s *Server) handleGetGrant(ctx context.Context, req *mcp.CallToolRequest, in GetGrantInput) (*mcp.CallToolResult, GrantOutput, error) {
	agentID, _, _, _, err := s.identify(req)
	if err != nil {
		s.logger.Error("mcpserver: get_grant identity", "err", err)
		return nil, GrantOutput{}, errIdentity
	}
	if !s.limiter.Allow(agentID) {
		s.logger.Warn("mcpserver: get_grant poll rate limited", "agent", agentID)
		return nil, GrantOutput{
			Status:    "error",
			ErrorCode: CodeRateLimited,
			Detail:    "get_grant poll rate exceeded; wait before polling again",
		}, nil
	}
	if _, err := domain.ParseGrantID(in.GrantID); err != nil {
		return nil, GrantOutput{
			Status:    "error",
			ErrorCode: CodeInvalidArgument,
			Detail:    "grant_id: not a valid grant ULID",
		}, nil
	}
	view, err := s.broker.GetGrant(ctx, agentID, in.GrantID)
	if err != nil {
		return nil, s.grantErrorOutput("get_grant", agentID, err), nil
	}
	return nil, s.grantOutput(view), nil
}

func (s *Server) handleExplainGrant(ctx context.Context, req *mcp.CallToolRequest, in ExplainGrantInput) (*mcp.CallToolResult, ExplainGrantOutput, error) {
	agentID, _, _, _, err := s.identify(req)
	if err != nil {
		s.logger.Error("mcpserver: explain_grant identity", "err", err)
		return nil, ExplainGrantOutput{}, errIdentity
	}
	if _, err := domain.ParseGrantID(in.GrantID); err != nil {
		return nil, ExplainGrantOutput{
			Status:    "error",
			ErrorCode: CodeInvalidArgument,
			Detail:    "grant_id: not a valid grant ULID",
		}, nil
	}
	ex, err := s.broker.ExplainGrant(ctx, agentID, in.GrantID)
	if err != nil {
		code, detail := s.mapBrokerError("explain_grant", agentID, err)
		return nil, ExplainGrantOutput{Status: "error", ErrorCode: code, Detail: detail}, nil
	}
	out := ExplainGrantOutput{
		GrantID: ex.GrantID,
		Status:  ex.Status,
		// Task and reason are the agent's own hostile bytes; strip
		// control sequences before they can reach any renderer.
		Task:       textsafe.Sanitize(ex.Task),
		Reason:     textsafe.Sanitize(ex.Reason),
		PolicyJSON: ex.PolicyJSON,
		Outcome:    ex.Outcome,
		Approver:   ex.ApproverRole,
		DenialCode: string(ex.DenialCode),
	}
	for _, c := range ex.Capabilities {
		out.Capabilities = append(out.Capabilities, CapabilityRefOutput{ID: c.ID, Version: c.Version})
	}
	for _, g := range ex.Guardrails {
		out.Guardrails = append(out.Guardrails, GuardrailVerdictOutput{
			Name:    g.Name,
			Verdict: g.Verdict,
			Detail:  textsafe.Sanitize(g.Detail),
		})
	}
	return nil, out, nil
}

func (s *Server) handleListCapabilities(ctx context.Context, req *mcp.CallToolRequest, _ ListCapabilitiesInput) (*mcp.CallToolResult, ListCapabilitiesOutput, error) {
	agentID, _, _, _, err := s.identify(req)
	if err != nil {
		s.logger.Error("mcpserver: list_capabilities identity", "err", err)
		return nil, ListCapabilitiesOutput{}, errIdentity
	}
	listing, err := s.broker.ListCapabilities(ctx, agentID)
	if err != nil {
		code, detail := s.mapBrokerError("list_capabilities", agentID, err)
		return nil, ListCapabilitiesOutput{ErrorCode: code, Detail: detail}, nil
	}
	out := ListCapabilitiesOutput{
		Profiles:       append([]string(nil), listing.Profiles...),
		DefaultProfile: listing.DefaultProfile,
		Capabilities:   make([]CapabilitySummaryOutput, 0, len(listing.Capabilities)),
	}
	if out.Profiles == nil {
		out.Profiles = []string{}
	}
	for _, c := range listing.Capabilities {
		sum := CapabilitySummaryOutput{ID: c.ID, Summary: c.Summary}
		for _, p := range c.Params {
			sum.Params = append(sum.Params, ParamShapeOutput{
				Name:          p.Name,
				ExpectedShape: p.ExpectedShape,
				Examples:      append([]string(nil), p.Examples...),
			})
		}
		out.Capabilities = append(out.Capabilities, sum)
	}
	return nil, out, nil
}

func (s *Server) handleReleaseGrant(ctx context.Context, req *mcp.CallToolRequest, in ReleaseGrantInput) (*mcp.CallToolResult, ReleaseGrantOutput, error) {
	agentID, _, _, _, err := s.identify(req)
	if err != nil {
		s.logger.Error("mcpserver: release_grant identity", "err", err)
		return nil, ReleaseGrantOutput{}, errIdentity
	}
	if _, err := domain.ParseGrantID(in.GrantID); err != nil {
		return nil, ReleaseGrantOutput{
			Status:    "error",
			ErrorCode: CodeInvalidArgument,
			Detail:    "grant_id: not a valid grant ULID",
		}, nil
	}
	switch in.Outcome {
	case ReleaseSucceeded, ReleaseFailed, ReleaseAbandoned:
	default:
		return nil, ReleaseGrantOutput{
			Status:    "error",
			ErrorCode: CodeInvalidArgument,
			Detail:    "outcome: must be succeeded, failed, or abandoned",
		}, nil
	}
	if utf8.RuneCountInString(in.Note) > MaxNoteChars {
		return nil, ReleaseGrantOutput{
			Status:    "error",
			ErrorCode: CodeInvalidArgument,
			Detail:    fmt.Sprintf("note: longer than %d characters", MaxNoteChars),
		}, nil
	}
	view, err := s.broker.ReleaseGrant(ctx, agentID, in.GrantID, in.Outcome, in.Note)
	if err != nil {
		code, detail := s.mapBrokerError("release_grant", agentID, err)
		return nil, ReleaseGrantOutput{Status: "error", ErrorCode: code, Detail: detail}, nil
	}
	out := ReleaseGrantOutput{
		GrantID:           view.GrantID,
		Status:            "released",
		Outcome:           view.Outcome,
		RevocationWritten: view.RevocationWritten,
	}
	if !view.ReleasedAt.IsZero() {
		out.ReleasedAt = view.ReleasedAt.UTC().Format(time.RFC3339)
	}
	return nil, out, nil
}

// validateGrantRequest applies every boundary cap of section 4.2 to
// hostile input. It returns the broker-bound request, or the failing
// field name with a safe detail string.
func (s *Server) validateGrantRequest(in RequestGrantInput) (br GrantRequest, badField, badDetail string) {
	if in.Task == "" {
		return br, "task", "required"
	}
	if utf8.RuneCountInString(in.Task) > MaxTaskChars {
		return br, "task", fmt.Sprintf("longer than %d characters", MaxTaskChars)
	}
	if utf8.RuneCountInString(in.Reason) > MaxReasonChars {
		return br, "reason", fmt.Sprintf("longer than %d characters", MaxReasonChars)
	}
	if utf8.RuneCountInString(in.Profile) > MaxProfileChars {
		return br, "profile", fmt.Sprintf("longer than %d characters", MaxProfileChars)
	}
	if utf8.RuneCountInString(in.Access) > MaxAccessChars {
		return br, "access", fmt.Sprintf("longer than %d characters", MaxAccessChars)
	}
	if utf8.RuneCountInString(in.IdempotencyKey) > MaxIdemKeyChars {
		return br, "idempotency_key", fmt.Sprintf("longer than %d characters", MaxIdemKeyChars)
	}
	if utf8.RuneCountInString(in.RetryToken) > MaxRetryTokenChars {
		return br, "retry_token", fmt.Sprintf("longer than %d characters", MaxRetryTokenChars)
	}
	if in.DurationSeconds < 0 {
		return br, "duration_seconds", "must not be negative"
	}
	if len(in.Services) > MaxServices {
		return br, "services", fmt.Sprintf("more than %d entries", MaxServices)
	}
	for i, svc := range in.Services {
		if utf8.RuneCountInString(svc) > MaxServiceChars {
			return br, fmt.Sprintf("services[%d]", i), fmt.Sprintf("longer than %d characters", MaxServiceChars)
		}
	}
	if len(in.Resources) > MaxResources {
		return br, "resources", fmt.Sprintf("more than %d entries", MaxResources)
	}
	for i, res := range in.Resources {
		if utf8.RuneCountInString(res) > MaxResourceChars {
			return br, fmt.Sprintf("resources[%d]", i), fmt.Sprintf("longer than %d characters", MaxResourceChars)
		}
	}
	if len(in.Capabilities) > MaxCapabilities {
		return br, "capabilities", fmt.Sprintf("more than %d entries", MaxCapabilities)
	}
	caps := make([]synth.CapabilityHint, 0, len(in.Capabilities))
	for i, c := range in.Capabilities {
		if c.ID == "" {
			return br, fmt.Sprintf("capabilities[%d].id", i), "required"
		}
		if utf8.RuneCountInString(c.ID) > MaxCapabilityID {
			return br, fmt.Sprintf("capabilities[%d].id", i), fmt.Sprintf("longer than %d characters", MaxCapabilityID)
		}
		if len(c.Params) > MaxParamsPerCap {
			return br, fmt.Sprintf("capabilities[%d].params", i), fmt.Sprintf("more than %d entries", MaxParamsPerCap)
		}
		var params map[string]string
		if len(c.Params) > 0 {
			params = make(map[string]string, len(c.Params))
			for k, v := range c.Params {
				if utf8.RuneCountInString(k) > MaxParamNameChars {
					return br, fmt.Sprintf("capabilities[%d].params", i), fmt.Sprintf("a key is longer than %d characters", MaxParamNameChars)
				}
				if utf8.RuneCountInString(v) > MaxParamValueChars {
					return br, fmt.Sprintf("capabilities[%d].params[%s]", i, textsafe.Truncate(textsafe.Sanitize(k), 32)), fmt.Sprintf("longer than %d characters", MaxParamValueChars)
				}
				params[k] = v
			}
		}
		caps = append(caps, synth.CapabilityHint{ID: c.ID, Params: params})
	}

	wait := in.WaitSeconds
	if wait < 0 {
		wait = 0
	}
	if wait > s.opts.MaxWaitSeconds {
		wait = s.opts.MaxWaitSeconds
	}

	return GrantRequest{
		Task:            in.Task,
		Reason:          in.Reason,
		Profile:         in.Profile,
		Capabilities:    caps,
		Services:        append([]string(nil), in.Services...),
		Resources:       append([]string(nil), in.Resources...),
		Access:          in.Access,
		DurationSeconds: in.DurationSeconds,
		CallerRef:       domain.SanitizeCallerRef(in.CallerRef),
		IdempotencyKey:  in.IdempotencyKey,
		WaitSeconds:     wait,
		RetryToken:      in.RetryToken,
	}, "", ""
}

// grantOutput converts a broker view to the wire shape, enforcing the
// once-delivery rule on credentials.
func (s *Server) grantOutput(view *GrantView) GrantOutput {
	out := GrantOutput{
		GrantID:                view.GrantID,
		Status:                 view.Status,
		ScopeSummary:           view.ScopeSummary,
		PollAfterSeconds:       view.PollAfterSeconds,
		DenialCode:             string(view.DenialCode),
		Detail:                 view.Detail,
		HumanApprovalAvailable: view.HumanApprovalAvailable,
		ErrorCode:              view.ErrorCode,
	}
	if !view.ExpiresAt.IsZero() {
		out.ExpiresAt = view.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if !view.PendingExpiresAt.IsZero() {
		out.PendingExpiresAt = view.PendingExpiresAt.UTC().Format(time.RFC3339)
	}
	if view.Explanation != nil {
		eo := &ExplanationOutput{Statements: make([]StatementExplanationOutput, 0, len(view.Explanation.Statements))}
		for _, st := range view.Explanation.Statements {
			eo.Statements = append(eo.Statements, StatementExplanationOutput{
				CapabilityID:      st.CapabilityID,
				CapabilityVersion: st.CapabilityVersion,
				Params:            sanitizeParams(st.Params),
				Reason:            st.Reason,
			})
		}
		out.Explanation = eo
	}
	if view.Clarification != nil {
		out.Clarification = clarificationOutput(view.Clarification)
	}
	if view.Credentials != nil && s.deliverable(view.GrantID) {
		out.Credentials = &CredentialsOutput{
			AccessKeyID:     view.Credentials.AccessKeyID,
			SecretAccessKey: view.Credentials.SecretAccessKey,
			SessionToken:    view.Credentials.SessionToken,
			Expiration:      view.Credentials.Expiration.UTC().Format(time.RFC3339),
		}
	}
	return out
}

// deliverable decides whether this response may carry the grant's
// secret. With credential_redelivery on, always; otherwise only the
// first delivery per grant, across every tool (invariant I4).
func (s *Server) deliverable(grantID string) bool {
	if s.opts.CredentialRedelivery {
		return true
	}
	return s.delivered.FirstDelivery(grantID)
}

// clarificationOutput renders a synth clarification for the wire.
// Echoed parameter names and questions may quote agent bytes upstream,
// so every string passes the sanitizer.
func clarificationOutput(c *synth.Clarification) *ClarificationOutput {
	out := &ClarificationOutput{
		Code:       c.Code,
		RetryToken: c.RetryToken,
		Round:      c.Round,
	}
	for _, q := range c.Questions {
		out.Questions = append(out.Questions, textsafe.Sanitize(q))
	}
	for _, mp := range c.MissingParams {
		out.MissingParams = append(out.MissingParams, MissingParamOutput{
			Capability:    mp.Capability,
			Name:          textsafe.Sanitize(mp.Name),
			ExpectedShape: mp.ExpectedShape,
			Examples:      append([]string(nil), mp.Examples...),
		})
	}
	for _, cand := range c.Candidates {
		out.Candidates = append(out.Candidates, CandidateCapabilityOutput{
			ID:      cand.ID,
			Summary: cand.Summary,
		})
	}
	return out
}

// sanitizeParams strips control sequences from echoed parameter values.
func sanitizeParams(params map[string]string) map[string]string {
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]string, len(params))
	for k, v := range params {
		out[textsafe.Sanitize(k)] = textsafe.Sanitize(v)
	}
	return out
}

// grantErrorOutput maps a broker error to a GrantOutput error result.
func (s *Server) grantErrorOutput(tool, agentID string, err error) GrantOutput {
	code, detail := s.mapBrokerError(tool, agentID, err)
	return GrantOutput{Status: "error", ErrorCode: code, Detail: detail}
}

// mapBrokerError collapses broker errors to the enumerated codes.
// ErrNotFound and ErrForbidden both surface as NOT_FOUND so existence
// is never confirmed across agents; everything else is logged in full
// and surfaces as INTERNAL with no detail from the underlying error.
func (s *Server) mapBrokerError(tool, agentID string, err error) (code, detail string) {
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrForbidden):
		return CodeNotFound, "no such grant"
	default:
		s.logger.Error("mcpserver: broker error", "tool", tool, "agent", agentID, "err", err)
		return CodeInternal, "internal error; the incident is logged"
	}
}
