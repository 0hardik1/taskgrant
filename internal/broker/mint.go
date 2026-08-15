package broker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/guardrails"
	"github.com/0hardik1/taskgrant/internal/stsmint"
	"github.com/0hardik1/taskgrant/internal/synth"
)

// configProfile aliases the config profile shape used through the
// pipeline.
type configProfile = config.ProfileConfig

// errCompactRejected marks a Compact retry whose re-render was denied
// or failed re-verification; the mint then fails POLICY_TOO_LARGE.
var errCompactRejected = errors.New("broker: compact re-render rejected")

// mintGrant performs the STS mint for the entry's current policy with
// the section 7.3 Compact protocol: one retry on PackedPolicyTooLarge
// under a 20 percent tighter budget, same grant ULID, both attempts
// recorded.
func (b *Broker) mintGrant(ctx context.Context, e *grantEntry) (*stsmint.Minted, []mintAttemptBody, error) {
	profile, ok := b.cfg.Profiles[e.grant.Profile]
	if !ok {
		return nil, nil, fmt.Errorf("broker: profile %q vanished from config", e.grant.Profile)
	}
	seconds := e.effectiveSeconds
	if seconds <= 0 {
		seconds = b.fallbackDuration(profile)
	}
	req := stsmint.MintRequest{
		GrantID:         e.grant.GrantID,
		AgentID:         e.grant.AgentID,
		Profile:         e.grant.Profile,
		RoleARN:         profile.RoleARN,
		Region:          b.cfg.ProfileRegion(e.grant.Profile),
		PolicyJSON:      e.result.PolicyJSON,
		PolicyARNs:      combinedPolicyARNs(profile.PolicyARNs, e.result.PolicyArns),
		DurationSeconds: seconds,
		CallerRef:       e.req.CallerRef,
		ExternalID:      profile.ExternalID,
	}

	var attempts []mintAttemptBody
	compact := func(cctx context.Context, maxChars int) ([]byte, []string, error) {
		prev := e.result
		res, err := b.synth.Compact(cctx, prev, maxChars)
		if err != nil {
			return nil, nil, err
		}
		if res.Verdict != synth.VerdictPolicy || len(res.PolicyJSON) == 0 {
			return nil, nil, fmt.Errorf("%w: verdict %s code %s", errCompactRejected, res.Verdict, res.DenialCode)
		}
		// Authoritative re-verification of the compacted policy. The
		// durable G8 state is not re-consumed: the request already paid
		// its rate token; this run checks policy content only.
		gres := b.evaluator.Evaluate(cctx, guardrails.Input{
			PolicyJSON:                res.PolicyJSON,
			AgentID:                   e.grant.AgentID,
			Profile:                   e.grant.Profile,
			RequestedDurationSeconds:  seconds,
			ProfileMaxDurationSeconds: profile.MaxDurationSeconds,
			Capabilities:              metaOnly(res.Capabilities, b, res),
			BrokerChained:             b.chained,
		})
		if gres.Overall == guardrails.Fail {
			return nil, nil, fmt.Errorf("%w: compacted policy failed guardrails", errCompactRejected)
		}
		b.mu.Lock()
		e.result = res
		e.budgetChars = maxChars
		b.mu.Unlock()
		return res.PolicyJSON, combinedPolicyARNs(profile.PolicyARNs, res.PolicyArns), nil
	}

	minted, err := b.minter.MintWithCompact(ctx, req, compact)
	if err != nil {
		var tooLarge *stsmint.PolicyTooLargeError
		if errors.As(err, &tooLarge) {
			for _, a := range tooLarge.Attempts {
				attempts = append(attempts, mintAttemptBody{
					PolicyChars:    a.PolicyChars,
					PolicyARNCount: a.PolicyARNCount,
					Message:        a.Message,
				})
			}
		}
		return nil, attempts, err
	}
	return minted, attempts, nil
}

// fallbackDuration clamps the configured default when no guardrail
// result is available (approve-after-restart path).
func (b *Broker) fallbackDuration(profile config.ProfileConfig) int {
	seconds := b.cfg.AWS.DefaultDurationSeconds
	if seconds <= 0 {
		seconds = guardrails.DurationFloorSeconds
	}
	if cap := profile.MaxDurationSeconds; cap > 0 && seconds > cap {
		seconds = cap
	}
	if b.chained && seconds > guardrails.ChainedDurationCapSeconds {
		seconds = guardrails.ChainedDurationCapSeconds
	}
	if seconds < guardrails.DurationFloorSeconds {
		seconds = guardrails.DurationFloorSeconds
	}
	return seconds
}

// classifyMintError maps a mint failure to the sanitized denial the
// agent sees. Raw STS errors stay internal (section 4.2).
func classifyMintError(err error) (domain.DenialCode, string, string) {
	var tooLarge *stsmint.PolicyTooLargeError
	if errors.As(err, &tooLarge) {
		return domain.DenyPolicyTooLarge, "policy_too_large",
			"the session policy exceeded the STS packed size limit even after one compact retry; split the task"
	}
	if errors.Is(err, errCompactRejected) {
		return domain.DenyPolicyTooLarge, "policy_too_large",
			"the session policy exceeded the STS packed size limit and could not be compacted; split the task"
	}
	return domain.DenySTSError, "sts",
		"the STS call failed; the incident is logged"
}

// metaOnly builds minimal capability meta for the compact
// re-verification.
func metaOnly(refs []synth.CapabilityRef, b *Broker, res synth.Result) []guardrails.CapabilityMeta {
	meta, _ := b.capabilityMeta(res)
	if len(meta) > 0 {
		return meta
	}
	out := make([]guardrails.CapabilityMeta, 0, len(refs))
	for _, ref := range refs {
		out = append(out, guardrails.CapabilityMeta{ID: ref.ID})
	}
	return out
}

// mintExpiry returns the credential expiry of a minted entry, zero when
// not minted.
func (e *grantEntry) mintExpiry() time.Time {
	if e.minted == nil {
		return time.Time{}
	}
	return e.minted.Credentials.Expiration()
}
