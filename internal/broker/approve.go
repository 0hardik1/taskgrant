package broker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/0hardik1/taskgrant/internal/approvals"
	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/mcpserver"
	"github.com/0hardik1/taskgrant/internal/revoke"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/synth"
)

// Mint outcomes reported on approval decisions.
const (
	MintOutcomeMinted = "minted"
	MintOutcomeFailed = "mint_failed"
)

// ApprovalOutcome reports one approve or deny decision driven through
// the broker.
type ApprovalOutcome struct {
	GrantID     string
	Decision    string // approved | denied
	DecidedAt   time.Time
	MintOutcome string // minted | mint_failed | empty on deny
}

// ApproveGrant records a human approval, mints at that moment (section
// 11 step 5), appends the approval record with the STS block, and wakes
// any blocked request_grant call.
func (b *Broker) ApproveGrant(ctx context.Context, grantID string, by approvals.Identity, note string) (*ApprovalOutcome, error) {
	d, err := b.approvals.Approve(ctx, grantID, by, note)
	if err != nil {
		return nil, err
	}
	if b.metrics != nil {
		if row, gerr := b.approvals.Get(ctx, grantID); gerr == nil && !row.ReceivedAt.IsZero() {
			b.metrics.ObserveApprovalLatency(d.DecidedAt.Sub(row.ReceivedAt))
		}
	}

	e := b.entryForApproval(ctx, grantID)
	b.mu.Lock()
	b.setStateLocked(e, domain.StateApproved)
	done := e.mintDone
	b.mu.Unlock()

	outcome := &ApprovalOutcome{GrantID: grantID, Decision: "approved", DecidedAt: d.DecidedAt}

	minted, attempts, mintErr := b.mintGrant(ctx, e)
	if mintErr != nil {
		code, deniedBy, detail := classifyMintError(mintErr)
		b.mu.Lock()
		e.grant.DecidedAt = d.DecidedAt
		e.denial = code
		e.detail = detail
		b.setStateLocked(e, domain.StateDenied)
		e.markTerminal(b.now())
		b.mu.Unlock()

		body := b.baseBody(e, domain.RecordApproval, domain.NewGrantID())
		fillSynthesis(&body, e.result, e.trace)
		fillGuardrails(&body, e.guard)
		body.Outcome = "denied"
		body.DeniedBy = deniedBy
		body.DenialCode = code.String()
		body.MintAttempts = attempts
		body.Approval = &approvalBody{
			Decision: "approved", Approver: d.Approver, Method: d.Method,
			Note: d.Note, RequiredBy: e.requiredBy,
		}
		_ = b.appendRecord(ctx, e, domain.RecordApproval, body)
		b.incOutcome("denied")
		outcome.MintOutcome = MintOutcomeFailed
		if done != nil {
			close(done)
		}
		b.logger.Error("broker: mint after approval failed", "grant_id", grantID, "err", mintErr)
		return outcome, nil
	}

	b.mu.Lock()
	b.setStateLocked(e, domain.StateMinted)
	e.grant.MintedAt = b.now()
	e.grant.ExpiresAt = minted.Credentials.Expiration()
	e.minted = minted
	del := minted.Credentials.Delivery()
	e.delivery = &del
	b.setStateLocked(e, domain.StateActive)
	b.mu.Unlock()

	b.afterMint(ctx, e)

	body := b.baseBody(e, domain.RecordApproval, domain.NewGrantID())
	fillSynthesis(&body, e.result, e.trace)
	fillGuardrails(&body, e.guard)
	body.Outcome = "approved"
	body.GrantedDurationSeconds = e.effectiveSeconds
	body.MintAttempts = attempts
	body.Approval = &approvalBody{
		Decision: "approved", Approver: d.Approver, Method: d.Method,
		Note: d.Note, RequiredBy: e.requiredBy,
	}
	fillSTS(&body, minted, b.roleARN(e.grant.Profile))
	_ = b.appendRecord(ctx, e, domain.RecordApproval, body)
	b.incOutcome("approved")
	if b.metrics != nil && minted.PackedPolicySizePercent >= 0 {
		b.metrics.ObservePackedPolicySize(minted.PackedPolicySizePercent)
	}

	outcome.MintOutcome = MintOutcomeMinted
	if done != nil {
		close(done)
	}
	return outcome, nil
}

// DenyGrant records a human denial and wakes any blocked call.
func (b *Broker) DenyGrant(ctx context.Context, grantID string, by approvals.Identity, note string) (*ApprovalOutcome, error) {
	d, err := b.approvals.Deny(ctx, grantID, by, note)
	if err != nil {
		return nil, err
	}
	e := b.entryForApproval(ctx, grantID)
	b.mu.Lock()
	e.grant.DecidedAt = d.DecidedAt
	e.denial = domain.DenyApprovalDenied
	e.detail = "a human denied the request"
	b.setStateLocked(e, domain.StateDenied)
	e.markTerminal(b.now())
	done := e.mintDone
	e.mintDone = nil
	b.mu.Unlock()
	if done != nil {
		close(done)
	}

	body := b.baseBody(e, domain.RecordApproval, domain.NewGrantID())
	fillSynthesis(&body, e.result, e.trace)
	body.Outcome = "denied"
	body.DeniedBy = "approver"
	body.DenialCode = domain.DenyApprovalDenied.String()
	body.Approval = &approvalBody{
		Decision: "denied", Approver: d.Approver, Method: d.Method,
		Note: d.Note, RequiredBy: e.requiredBy,
	}
	_ = b.appendRecord(ctx, e, domain.RecordApproval, body)
	b.incOutcome("denied")

	return &ApprovalOutcome{GrantID: grantID, Decision: "denied", DecidedAt: d.DecidedAt}, nil
}

// entryForApproval finds the in-memory entry for a decided grant, or
// rebuilds a minimal one from the durable pending row (approve after a
// broker restart, section 11 step 5). The rebuilt entry mints with the
// stored policy and the configured default duration.
func (b *Broker) entryForApproval(ctx context.Context, grantID string) *grantEntry {
	if e, ok := b.entry(grantID); ok {
		return e
	}
	e := &grantEntry{grant: domain.Grant{
		GrantID: grantID,
		State:   domain.StatePendingApproval,
	}}
	if row, err := b.approvals.Get(ctx, grantID); err == nil {
		e.grant.AgentID = row.AgentID
		e.grant.Profile = row.Profile
		e.grant.ReceivedAt = row.ReceivedAt
		e.requiredBy = row.RequiredBy
		e.req = mcpserver.GrantRequest{Task: row.Task, Reason: row.Reason, Profile: row.Profile}
		e.result = synth.Result{
			Verdict:    synth.VerdictPendingApproval,
			PolicyJSON: []byte(row.PolicyJSON),
		}
		for _, id := range row.Capabilities {
			e.result.Capabilities = append(e.result.Capabilities, synth.CapabilityRef{ID: id})
		}
	}
	b.putEntry(e)
	return e
}

// roleNameFromARN resolves the IAM role name out of a role ARN.
func roleNameFromARN(arn string) (string, error) {
	return revoke.RoleNameFromARN(arn)
}

// RevokeProfile writes the documented role-wide deny for a profile's
// base role (section 8.5) and appends a revocation record.
func (b *Broker) RevokeProfile(ctx context.Context, profile string) (*revocationOutcome, error) {
	if b.revoker == nil {
		return nil, errRevocationDisabled
	}
	p, ok := b.cfg.Profiles[profile]
	if !ok {
		return nil, store.ErrNotFound
	}
	roleName, err := roleNameFromARN(p.RoleARN)
	if err != nil {
		return nil, err
	}
	res, err := b.revoker.RevokeRole(ctx, roleName)
	if err != nil {
		return nil, err
	}
	now := b.now()
	e := &grantEntry{grant: domain.Grant{
		GrantID: domain.NewGrantID(), // revocation event id: role-wide has no grant
		AgentID: "",
		Profile: profile,
		State:   domain.StateReceived,
	}}
	body := b.baseBody(e, domain.RecordRevocation, domain.NewGrantID())
	body.AgentID = "admin"
	body.Outcome = "revoked"
	body.Revocation = &revocationBody{
		Mechanism: "role-wide",
		Role:      roleName,
		Profile:   profile,
		Sid:       res.Sid,
		AppliedAt: rfc3339(now),
	}
	rec := &store.Record{
		GrantID: e.grant.GrantID,
		AgentID: "admin",
		TS:      now,
		Kind:    domain.RecordRevocation,
		Outcome: "revoked",
		Profile: profile,
	}
	raw, merr := json.Marshal(body)
	if merr == nil {
		rec.Body = raw
		if aerr := b.log.Append(ctx, rec); aerr != nil {
			b.logger.Error("broker: revocation record append failed", "profile", profile, "err", aerr)
		}
	}
	return &revocationOutcome{
		Mechanism: "role-wide",
		Profile:   profile,
		AppliedAt: now,
		Detail:    "deny attached as sid " + res.Sid,
	}, nil
}

// RevokeGrantByID writes the best-effort targeted deny for one grant,
// keyed only on the broker-authored ULID (invariant I3).
func (b *Broker) RevokeGrantByID(ctx context.Context, grantID string) (*revocationOutcome, error) {
	if b.revoker == nil {
		return nil, errRevocationDisabled
	}
	if _, err := domain.ParseGrantID(grantID); err != nil {
		return nil, store.ErrNotFound
	}
	recs, err := b.log.GrantChain(ctx, grantID)
	if err != nil || len(recs) == 0 {
		return nil, store.ErrNotFound
	}
	profile := recs[0].Profile
	p, ok := b.cfg.Profiles[profile]
	if !ok {
		return nil, store.ErrNotFound
	}
	roleName, err := roleNameFromARN(p.RoleARN)
	if err != nil {
		return nil, err
	}
	expiry := expiryFromRecords(recs)
	if expiry.IsZero() {
		expiry = b.now().Add(time.Duration(b.cfg.AWS.MaxDurationSeconds) * time.Second)
	}
	res, err := b.revoker.RevokeGrant(ctx, roleName, grantID, expiry)
	if err != nil {
		return nil, err
	}
	now := b.now()
	e := &grantEntry{grant: domain.Grant{
		GrantID: grantID,
		AgentID: recs[0].AgentID,
		Profile: profile,
		State:   domain.StateReceived,
	}}
	body := b.baseBody(e, domain.RecordRevocation, domain.NewGrantID())
	body.Outcome = "revoked"
	body.Revocation = &revocationBody{
		Mechanism: "grant",
		Role:      roleName,
		Profile:   profile,
		Sid:       res.Sid,
		AppliedAt: rfc3339(now),
	}
	_ = b.appendRecord(ctx, e, domain.RecordRevocation, body)
	return &revocationOutcome{
		Mechanism: "grant",
		GrantID:   grantID,
		Profile:   profile,
		AppliedAt: now,
		Detail:    "deny attached as sid " + res.Sid,
	}, nil
}

// revocationOutcome reports one revocation write.
type revocationOutcome struct {
	Mechanism string
	Profile   string
	GrantID   string
	AppliedAt time.Time
	Detail    string
}

// errRevocationDisabled marks revocation attempts with no revoker
// wired (revocation.enabled false).
var errRevocationDisabled = errors.New("broker: revocation is disabled")
