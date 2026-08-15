package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/mcpserver"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/synth"
)

// buildView renders the entry's current state for its owning agent,
// without credentials. Callers on the delivery path use
// viewWithDelivery instead.
func (b *Broker) buildView(e *grantEntry) *mcpserver.GrantView {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buildViewLocked(e)
}

func (b *Broker) buildViewLocked(e *grantEntry) *mcpserver.GrantView {
	v := &mcpserver.GrantView{GrantID: e.grant.GrantID}
	if e.released {
		v.Status = "released"
		return v
	}
	switch e.grant.State {
	case domain.StateActive, domain.StateMinted:
		v.Status = "active"
		v.ExpiresAt = e.grant.ExpiresAt
		v.ScopeSummary = scopeSummary(e.result, e.grant.ExpiresAt)
		expl := e.result.Explanation
		v.Explanation = &expl
	case domain.StatePendingApproval:
		v.Status = "pending_approval"
		v.PollAfterSeconds = defaultPollAfterSeconds
		v.PendingExpiresAt = e.grant.DecidedAt.Add(b.approvals.TTL())
	case domain.StateNeedsClarification:
		v.Status = "needs_clarification"
		v.Clarification = e.result.Clarification
	case domain.StateDenied:
		v.Status = "denied"
		v.DenialCode = e.denial
		v.Detail = e.detail
		v.HumanApprovalAvailable = e.denial == domain.DenyApprovalTimeout
	case domain.StateExpiredPending:
		v.Status = "denied"
		v.DenialCode = domain.DenyApprovalTimeout
		v.Detail = "the pending approval expired before a human decided; resubmit the request"
		v.HumanApprovalAvailable = true
	case domain.StateExpired:
		v.Status = "expired"
	default:
		// Pre-decision states are only observable in a race with the
		// request call; report them as still pending.
		v.Status = "pending_approval"
		v.PollAfterSeconds = 1
	}
	if e.errorCode != "" {
		v.Status = "error"
		v.ErrorCode = e.errorCode
		v.Detail = "internal error; the incident is logged"
	}
	return v
}

// viewWithDelivery builds the view and attaches the plaintext
// credentials exactly once (invariant I4). With credential redelivery
// enabled the plaintext stays attached while the grant is active.
func (b *Broker) viewWithDelivery(e *grantEntry) *mcpserver.GrantView {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.buildViewLocked(e)
	if v.Status != "active" || e.delivery == nil {
		return v
	}
	if e.delivered && !b.redelivery {
		return v
	}
	v.Credentials = &mcpserver.Credentials{
		AccessKeyID:     e.delivery.AccessKeyID,
		SecretAccessKey: e.delivery.SecretAccessKey,
		SessionToken:    e.delivery.SessionToken,
		Expiration:      e.delivery.Expiration,
	}
	e.delivered = true
	if !b.redelivery {
		// The plaintext leaves the broker exactly once.
		e.delivery = nil
	}
	return v
}

// scopeSummary renders a short human-readable scope line from the
// synthesis result. Template material only, no agent bytes.
func scopeSummary(res synth.Result, expiry time.Time) string {
	ids := make([]string, 0, len(res.Capabilities))
	for _, ref := range res.Capabilities {
		ids = append(ids, fmt.Sprintf("%s v%d", ref.ID, ref.Version))
	}
	s := fmt.Sprintf("%s; %d actions", strings.Join(ids, ", "), len(res.ExpandedActions))
	if !expiry.IsZero() {
		s += "; expires " + expiry.UTC().Format(time.RFC3339)
	}
	return s
}

// GetGrant returns the grant's current state for its owning agent.
// Cross-agent lookups return ErrNotFound, never a forbidden signal.
func (b *Broker) GetGrant(ctx context.Context, agentID, grantID string) (*mcpserver.GrantView, error) {
	if _, err := domain.ParseGrantID(grantID); err != nil {
		return nil, errNotFound
	}
	if e, ok := b.entry(grantID); ok {
		if e.grant.AgentID != agentID {
			return nil, errNotFound
		}
		b.refreshEntry(ctx, e)
		return b.viewWithDelivery(e), nil
	}
	return b.reconstructView(ctx, agentID, grantID)
}

// refreshEntry applies time-driven transitions before a read: active
// grants past expiry become expired, pending grants follow the durable
// approval row.
func (b *Broker) refreshEntry(ctx context.Context, e *grantEntry) {
	now := b.now()
	b.mu.Lock()
	if (e.grant.State == domain.StateActive || e.grant.State == domain.StateMinted) &&
		!e.grant.ExpiresAt.IsZero() && now.After(e.grant.ExpiresAt) {
		if e.grant.State == domain.StateMinted {
			b.setStateLocked(e, domain.StateExpired)
		} else {
			b.setStateLocked(e, domain.StateExpired)
		}
		e.delivery = nil
		e.markTerminal(now)
		b.incOutcome("expired")
	}
	pending := e.grant.State == domain.StatePendingApproval
	b.mu.Unlock()

	if pending {
		row, err := b.approvals.Get(ctx, e.grant.GrantID)
		if err != nil {
			return
		}
		switch row.Status {
		case store.StatusExpiredPending:
			b.finalizeExpiredPending(ctx, e)
		case store.StatusDenied:
			b.mu.Lock()
			if e.grant.State == domain.StatePendingApproval {
				b.setStateLocked(e, domain.StateDenied)
				e.denial = domain.DenyApprovalDenied
				e.detail = "a human denied the request"
				e.markTerminal(b.now())
			}
			b.mu.Unlock()
		}
	}
}

// reconstructView rebuilds a view from the decision log for grants no
// longer (or never) in memory, for example after a broker restart.
// Credentials are never reconstructable: they exist in memory only.
func (b *Broker) reconstructView(ctx context.Context, agentID, grantID string) (*mcpserver.GrantView, error) {
	recs, err := b.log.GrantChain(ctx, grantID)
	if err != nil || len(recs) == 0 {
		return nil, errNotFound
	}
	if recs[0].AgentID != agentID {
		return nil, errNotFound
	}
	v := &mcpserver.GrantView{GrantID: grantID}
	now := b.now()

	status := ""
	for _, rec := range recs {
		var body decisionBody
		if err := json.Unmarshal(rec.Body, &body); err != nil {
			continue
		}
		switch rec.Kind {
		case domain.RecordRelease:
			status = "released"
		case domain.RecordClarification:
			status = "needs_clarification"
			v.DenialCode, v.Detail = "", ""
		case domain.RecordApproval:
			switch approvalDecision(body) {
			case "approved":
				status = activeOrExpired(body, now, v)
			case "denied":
				status = "denied"
				v.DenialCode = domain.DenyApprovalDenied
				v.Detail = "a human denied the request"
			case "expired_pending":
				status = "denied"
				v.DenialCode = domain.DenyApprovalTimeout
				v.Detail = "the pending approval expired before a human decided; resubmit the request"
				v.HumanApprovalAvailable = true
			}
		case domain.RecordGrantDecision:
			switch body.Outcome {
			case "auto_approved":
				status = activeOrExpired(body, now, v)
			case "pending_approval":
				status = "pending_approval"
				v.PollAfterSeconds = defaultPollAfterSeconds
			case "denied":
				status = "denied"
				v.DenialCode = domain.DenialCode(body.DenialCode)
				if len(body.DenialDetail) > 0 {
					v.Detail = strings.Join(body.DenialDetail, "; ")
				}
			case "error":
				status = "error"
				v.ErrorCode = mcpserver.CodeInternal
			}
		}
	}
	if status == "" {
		return nil, errNotFound
	}
	if status == "pending_approval" {
		// The durable queue is authoritative for pending grants.
		if row, err := b.approvals.Get(ctx, grantID); err == nil {
			switch row.Status {
			case store.StatusPending:
				v.PendingExpiresAt = row.ExpiresAt
			case store.StatusDenied:
				status = "denied"
				v.DenialCode = domain.DenyApprovalDenied
				v.Detail = "a human denied the request"
			case store.StatusExpiredPending:
				status = "denied"
				v.DenialCode = domain.DenyApprovalTimeout
				v.Detail = "the pending approval expired before a human decided; resubmit the request"
				v.HumanApprovalAvailable = true
			}
		}
	}
	v.Status = status
	return v, nil
}

// approvalDecision extracts the decision of an approval record body.
func approvalDecision(body decisionBody) string {
	if body.Approval != nil && body.Approval.Decision != "" {
		return body.Approval.Decision
	}
	return body.Outcome
}

// activeOrExpired classifies a minted record by its recorded expiry.
func activeOrExpired(body decisionBody, now time.Time, v *mcpserver.GrantView) string {
	exp := parseRFC3339(body.Expiration)
	if exp.IsZero() && body.STS != nil {
		exp = parseRFC3339(body.STS.Expiration)
	}
	if !exp.IsZero() {
		v.ExpiresAt = exp
		if now.After(exp) {
			return "expired"
		}
	}
	return "active"
}

func parseRFC3339(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

// ExplainGrant returns the decision record redacted for agent eyes
// (section 4.2): the approver appears as a role, never a name.
func (b *Broker) ExplainGrant(ctx context.Context, agentID, grantID string) (*mcpserver.GrantExplanation, error) {
	if _, err := domain.ParseGrantID(grantID); err != nil {
		return nil, errNotFound
	}
	recs, err := b.log.GrantChain(ctx, grantID)
	if err != nil || len(recs) == 0 {
		return nil, errNotFound
	}
	if recs[0].AgentID != agentID {
		return nil, errNotFound
	}

	ex := &mcpserver.GrantExplanation{GrantID: grantID}
	view, verr := b.GetGrant(ctx, agentID, grantID)
	if verr == nil {
		ex.Status = view.Status
	}
	for _, rec := range recs {
		var body decisionBody
		if err := json.Unmarshal(rec.Body, &body); err != nil {
			continue
		}
		if body.Task != "" {
			ex.Task = body.Task
		}
		if body.Reason != "" {
			ex.Reason = body.Reason
		}
		if len(body.Capabilities) > 0 {
			ex.Capabilities = ex.Capabilities[:0]
			for _, c := range body.Capabilities {
				ex.Capabilities = append(ex.Capabilities, synth.CapabilityRef{ID: c.ID, Version: c.Version})
			}
		}
		if len(body.Guardrails) > 0 {
			ex.Guardrails = ex.Guardrails[:0]
			for _, g := range body.Guardrails {
				ex.Guardrails = append(ex.Guardrails, mcpserver.GuardrailVerdict{
					Name: g.Name, Verdict: g.Verdict, Detail: g.Detail,
				})
			}
		}
		if body.PolicyJSON != "" {
			ex.PolicyJSON = body.PolicyJSON
		}
		switch rec.Kind {
		case domain.RecordGrantDecision:
			ex.Outcome = body.Outcome
			if body.Outcome == "auto_approved" {
				ex.ApproverRole = "auto"
			}
			ex.DenialCode = domain.DenialCode(body.DenialCode)
		case domain.RecordApproval:
			switch approvalDecision(body) {
			case "approved":
				ex.Outcome = "approved"
				ex.ApproverRole = "human"
				ex.DenialCode = ""
			case "denied":
				ex.Outcome = "denied"
				ex.ApproverRole = "human"
				ex.DenialCode = domain.DenyApprovalDenied
			case "expired_pending":
				ex.Outcome = "expired_pending"
				ex.DenialCode = domain.DenyApprovalTimeout
			}
		}
	}
	if ex.Status == "" {
		ex.Status = ex.Outcome
	}
	return ex, nil
}

// ListCapabilities returns the agent's profiles and its
// profile-filtered catalog view (section 4.2).
func (b *Broker) ListCapabilities(ctx context.Context, agentID string) (*mcpserver.CapabilityListing, error) {
	agent, ok := b.cfg.Agents[agentID]
	if !ok {
		return nil, errNotFound
	}
	listing := &mcpserver.CapabilityListing{
		Profiles:       append([]string(nil), agent.Profiles...),
		DefaultProfile: agent.DefaultProfile,
	}
	snap := b.catalog.SnapshotForAgent(agentID)
	if snap == nil {
		return listing, nil
	}
	for _, c := range snap.Capabilities() {
		sum := mcpserver.CapabilitySummary{ID: c.ID, Summary: c.Summary}
		names := c.ParamNames()
		for _, name := range names {
			p := c.Params[name]
			sum.Params = append(sum.Params, mcpserver.ParamShape{
				Name:          name,
				ExpectedShape: p.ExpectedShape(),
				Examples:      snap.ParamExamples(c.ID, name, 3),
			})
		}
		listing.Capabilities = append(listing.Capabilities, sum)
	}
	sort.Slice(listing.Capabilities, func(i, j int) bool {
		return listing.Capabilities[i].ID < listing.Capabilities[j].ID
	})
	return listing, nil
}

// ReleaseGrant appends a release record so the audit trail shows when
// the task actually ended, and optionally writes the targeted deny
// (revocation.revoke_on_release, section 8.5).
func (b *Broker) ReleaseGrant(ctx context.Context, agentID, grantID, outcome, note string) (*mcpserver.ReleaseView, error) {
	if _, err := domain.ParseGrantID(grantID); err != nil {
		return nil, errNotFound
	}
	e, ok := b.entry(grantID)
	if ok && e.grant.AgentID != agentID {
		return nil, errNotFound
	}
	if !ok {
		// Restart path: verify ownership through the log and build a
		// minimal entry for the release record.
		recs, err := b.log.GrantChain(ctx, grantID)
		if err != nil || len(recs) == 0 || recs[0].AgentID != agentID {
			return nil, errNotFound
		}
		e = &grantEntry{grant: domain.Grant{
			GrantID: grantID,
			AgentID: agentID,
			Profile: recs[0].Profile,
			State:   domain.StateExpired,
		}}
		e.grant.ExpiresAt = expiryFromRecords(recs)
		b.putEntry(e)
	}

	now := b.now()
	b.mu.Lock()
	alreadyReleased := e.released
	if !alreadyReleased {
		e.released = true
		e.releaseOutcome = outcome
		e.releasedAt = now
		e.markTerminal(now)
	}
	rv := &mcpserver.ReleaseView{
		GrantID:           grantID,
		Outcome:           e.releaseOutcome,
		ReleasedAt:        e.releasedAt,
		RevocationWritten: e.revocationWritten,
	}
	b.mu.Unlock()
	if alreadyReleased {
		return rv, nil
	}

	body := b.baseBody(e, domain.RecordRelease, domain.NewGrantID())
	body.Outcome = "released"
	body.Release = &releaseBody{Outcome: outcome, Note: note, ReleasedAt: rfc3339(now)}
	_ = b.appendRecord(ctx, e, domain.RecordRelease, body)
	b.incOutcome("released")

	if b.revoker != nil && b.cfg.Revocation.RevokeOnRelease {
		if written := b.revokeOnRelease(ctx, e); written {
			b.mu.Lock()
			e.revocationWritten = true
			b.mu.Unlock()
			rv.RevocationWritten = true
		}
	}
	return rv, nil
}

// revokeOnRelease writes the targeted per-grant deny for a released
// grant whose credentials are still live.
func (b *Broker) revokeOnRelease(ctx context.Context, e *grantEntry) bool {
	expiry := e.grant.ExpiresAt
	if expiry.IsZero() || !expiry.After(b.now()) {
		return false
	}
	roleARN := b.roleARN(e.grant.Profile)
	roleName, err := roleNameFromARN(roleARN)
	if err != nil {
		b.logger.Error("broker: revoke_on_release role resolution failed",
			"grant_id", e.grant.GrantID, "profile", e.grant.Profile, "err", err)
		return false
	}
	res, err := b.revoker.RevokeGrant(ctx, roleName, e.grant.GrantID, expiry)
	if err != nil {
		b.logger.Error("broker: revoke_on_release failed",
			"grant_id", e.grant.GrantID, "role", roleName, "err", err)
		return false
	}
	body := b.baseBody(e, domain.RecordRevocation, domain.NewGrantID())
	body.Outcome = "revoked"
	body.Revocation = &revocationBody{
		Mechanism: "grant",
		Role:      roleName,
		Profile:   e.grant.Profile,
		Sid:       res.Sid,
		AppliedAt: rfc3339(b.now()),
	}
	_ = b.appendRecord(ctx, e, domain.RecordRevocation, body)
	return true
}

// expiryFromRecords pulls the latest recorded credential expiry.
func expiryFromRecords(recs []store.Record) time.Time {
	var out time.Time
	for _, rec := range recs {
		var body decisionBody
		if err := json.Unmarshal(rec.Body, &body); err != nil {
			continue
		}
		if t := parseRFC3339(body.Expiration); !t.IsZero() {
			out = t
		}
	}
	return out
}
