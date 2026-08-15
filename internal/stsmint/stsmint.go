// Package stsmint owns the sts:AssumeRole call (architecture section
// 8). It is the only package that can reach the broker's parent AWS
// credentials (invariant I4): New loads the default credential chain
// here and nothing exports it. Everything else in the package is
// construction and hygiene: the canonical RoleSessionName, the frozen
// session tag schema, SourceIdentity, redacting credential types, the
// PackedPolicyTooLarge compact-retry protocol, and the slog scrubber.
package stsmint

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// PackedPolicySize thresholds (percent of the undisclosed packed
// limit). Section 7.3: warn at 70, alert at 85; observed values
// calibrate the limit empirically over time.
const (
	PackedPolicyWarnPercent  = 70
	PackedPolicyAlertPercent = 85
)

// Duration bounds STS accepts for AssumeRole.
const (
	minMintSeconds = 900
	maxMintSeconds = 43200
)

// maxPolicyARNs is the STS ceiling on managed session policies.
const maxPolicyARNs = 10

// PackedPolicySeverity classifies a PackedPolicySize percentage:
// "ok", "warn" (at or over 70), "alert" (at or over 85), or "unknown"
// for a negative value (STS did not report one).
func PackedPolicySeverity(pct int) string {
	switch {
	case pct < 0:
		return "unknown"
	case pct >= PackedPolicyAlertPercent:
		return "alert"
	case pct >= PackedPolicyWarnPercent:
		return "warn"
	default:
		return "ok"
	}
}

// STSAPI is the consumer interface over the STS client, sized for this
// package; tests inject a fake, production uses *sts.Client.
type STSAPI interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Options configures New.
type Options struct {
	// Region is the STS region (aws.sts_region, or a profile region).
	Region string
	// EndpointURL optionally points STS at a stand-in endpoint such as
	// LocalStack (config aws.endpoint_url). Empty uses the real STS.
	EndpointURL string
	// Logger receives package logs. nil disables package logging.
	// Install ScrubAttr on the root handler regardless.
	Logger *slog.Logger
}

// Minter performs AssumeRole calls. Immutable after construction and
// safe for concurrent use.
type Minter struct {
	client STSAPI
	logger *slog.Logger
}

// New constructs a Minter from the default AWS credential chain
// (IRSA, instance profile, environment, shared config). The parent
// credentials live only inside the returned Minter's client; no other
// package can reach them (invariant I4).
func New(ctx context.Context, opts Options) (*Minter, error) {
	var loadOpts []func(*awsconfig.LoadOptions) error
	if opts.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(opts.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws credential chain: %w", err)
	}
	client := sts.NewFromConfig(cfg, func(o *sts.Options) {
		if opts.EndpointURL != "" {
			o.BaseEndpoint = aws.String(opts.EndpointURL)
		}
	})
	return &Minter{client: client, logger: opts.Logger}, nil
}

// NewWithClient injects a pre-built STS API implementation. Tests and
// LocalStack harnesses use it; it never touches the credential chain.
func NewWithClient(client STSAPI, logger *slog.Logger) *Minter {
	return &Minter{client: client, logger: logger}
}

// MintRequest is one AssumeRole construction request. The broker fills
// it from the grant, the profile config, and the guardrail-clamped
// duration; CallerRef is raw agent bytes and is sanitized here.
type MintRequest struct {
	// GrantID is the grant ULID (26-char canonical form).
	GrantID string
	// AgentID is the validated agent slug.
	AgentID string
	// Profile is the profile name, for the taskgrant:profile tag.
	Profile string
	// RoleARN is the profile's role.
	RoleARN string
	// Region optionally overrides the client region for this call
	// (profile region differing from aws.sts_region).
	Region string
	// PolicyJSON is the minified session policy. Optional only for the
	// preflight-style minimal mint; grants always carry one.
	PolicyJSON []byte
	// PolicyARNs are managed session policy ARNs (max 10), from the
	// profile's static ceilings plus any size-budget offload.
	PolicyARNs []string
	// DurationSeconds is the guardrail-clamped effective duration.
	DurationSeconds int
	// CallerRef is the agent-supplied correlation id: hostile bytes,
	// sanitized to the 64-char safe charset before it becomes a tag.
	CallerRef string
	// ExternalID is set for cross-account profiles only.
	ExternalID string
}

// Minted is the outcome of one successful AssumeRole.
type Minted struct {
	// Credentials is the redacting record form; call
	// Credentials.Delivery() exactly once at the delivery boundary.
	Credentials Credentials
	// AssumedRoleARN is the assumed-role user ARN from STS.
	AssumedRoleARN string
	// RoleSessionName is the exact session name sent.
	RoleSessionName string
	// SourceIdentity is the exact SourceIdentity sent (tg-<ulid>).
	SourceIdentity string
	// SessionTags is the exact tag set sent, for the decision record.
	SessionTags map[string]string
	// TransitiveTagKeys is the exact transitive key list sent.
	TransitiveTagKeys []string
	// PackedPolicySizePercent is the packed-size percentage STS
	// reported, or -1 when absent.
	PackedPolicySizePercent int
	// STSRequestID is the AssumeRole request id, an assume-time
	// CloudTrail join key.
	STSRequestID string
}

// PackedPolicySeverity classifies this mint's packed size.
func (m *Minted) PackedPolicySeverity() string {
	return PackedPolicySeverity(m.PackedPolicySizePercent)
}

// BuildAssumeRoleInput constructs the AssumeRole input exactly per
// section 8.2: canonical RoleSessionName (62-char safe, the grant ULID
// always intact), the frozen four-tag schema of 8.3 with caller_ref
// sanitized, exactly two transitive tag keys, SourceIdentity tg-<ulid>,
// ExternalId only when configured, and PolicyArns passed through.
func BuildAssumeRoleInput(req MintRequest) (*sts.AssumeRoleInput, error) {
	if _, err := domain.ParseGrantID(req.GrantID); err != nil {
		return nil, fmt.Errorf("mint request: %w", err)
	}
	if err := domain.ValidateAgentID(req.AgentID); err != nil {
		return nil, fmt.Errorf("mint request: %w", err)
	}
	if req.RoleARN == "" {
		return nil, errors.New("mint request: role arn is required")
	}
	if req.Profile == "" {
		return nil, errors.New("mint request: profile name is required")
	}
	if req.DurationSeconds < minMintSeconds || req.DurationSeconds > maxMintSeconds {
		return nil, fmt.Errorf("mint request: duration %d outside %d..%d",
			req.DurationSeconds, minMintSeconds, maxMintSeconds)
	}
	if len(req.PolicyARNs) > maxPolicyARNs {
		return nil, fmt.Errorf("mint request: %d policy arns exceed the STS maximum of %d",
			len(req.PolicyARNs), maxPolicyARNs)
	}

	tags := []ststypes.Tag{
		{Key: aws.String(domain.TagKeyAgent), Value: aws.String(req.AgentID)},
		{Key: aws.String(domain.TagKeyGrant), Value: aws.String(req.GrantID)},
		{Key: aws.String(domain.TagKeyProfile), Value: aws.String(req.Profile)},
	}
	if ref := domain.SanitizeCallerRef(req.CallerRef); ref != "" {
		tags = append(tags, ststypes.Tag{
			Key:   aws.String(domain.TagKeyCallerRef),
			Value: aws.String(ref),
		})
	}

	input := &sts.AssumeRoleInput{
		RoleArn:           aws.String(req.RoleARN),
		RoleSessionName:   aws.String(domain.RoleSessionName(req.AgentID, req.GrantID)),
		DurationSeconds:   aws.Int32(int32(req.DurationSeconds)),
		Tags:              tags,
		TransitiveTagKeys: domain.TransitiveTagKeys(),
		SourceIdentity:    aws.String(domain.SourceIdentity(req.GrantID)),
	}
	if len(req.PolicyJSON) > 0 {
		input.Policy = aws.String(string(req.PolicyJSON))
	}
	for _, arn := range req.PolicyARNs {
		input.PolicyArns = append(input.PolicyArns,
			ststypes.PolicyDescriptorType{Arn: aws.String(arn)})
	}
	if req.ExternalID != "" {
		input.ExternalId = aws.String(req.ExternalID)
	}
	return input, nil
}

// Mint performs one AssumeRole. On the STS PackedPolicyTooLarge error
// it returns *PackedPolicyTooLargeError so the broker can compact and
// retry; any other STS failure returns a wrapped raw error that must
// stay internal (raw STS errors can leak role ARNs and account ids;
// agents see sanitized codes only).
func (m *Minter) Mint(ctx context.Context, req MintRequest) (*Minted, error) {
	input, err := BuildAssumeRoleInput(req)
	if err != nil {
		return nil, err
	}
	var optFns []func(*sts.Options)
	if req.Region != "" {
		optFns = append(optFns, func(o *sts.Options) { o.Region = req.Region })
	}

	out, err := m.client.AssumeRole(ctx, input, optFns...)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == packedPolicyTooLargeCode {
			return nil, &PackedPolicyTooLargeError{
				PolicyChars:    len(req.PolicyJSON),
				PolicyARNCount: len(req.PolicyARNs),
				Message:        apiErr.ErrorMessage(),
			}
		}
		if m.logger != nil {
			m.logger.LogAttrs(ctx, slog.LevelError, "sts assume role failed",
				slog.String("grant_id", req.GrantID),
				slog.String("agent_id", req.AgentID),
				slog.String("profile", req.Profile),
				slog.String("error", err.Error()),
			)
		}
		return nil, fmt.Errorf("sts assume role: %w", err)
	}
	if out.Credentials == nil || out.Credentials.AccessKeyId == nil ||
		out.Credentials.SecretAccessKey == nil || out.Credentials.SessionToken == nil {
		return nil, errors.New("sts assume role: response carried no credentials")
	}

	pct := -1
	if out.PackedPolicySize != nil {
		pct = int(*out.PackedPolicySize)
	}
	tags := make(map[string]string, len(input.Tags))
	for _, t := range input.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	assumedARN := ""
	if out.AssumedRoleUser != nil {
		assumedARN = aws.ToString(out.AssumedRoleUser.Arn)
	}
	requestID, _ := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)

	minted := &Minted{
		Credentials: NewCredentials(
			aws.ToString(out.Credentials.AccessKeyId),
			aws.ToString(out.Credentials.SecretAccessKey),
			aws.ToString(out.Credentials.SessionToken),
			aws.ToTime(out.Credentials.Expiration),
		),
		AssumedRoleARN:          assumedARN,
		RoleSessionName:         aws.ToString(input.RoleSessionName),
		SourceIdentity:          aws.ToString(input.SourceIdentity),
		SessionTags:             tags,
		TransitiveTagKeys:       append([]string(nil), input.TransitiveTagKeys...),
		PackedPolicySizePercent: pct,
		STSRequestID:            requestID,
	}
	m.logMintOutcome(ctx, req, minted)
	return minted, nil
}

// logMintOutcome records the mint and the packed-size headroom (warn
// at 70 percent, alert at 85). The Credentials LogValue keeps secrets
// out even here.
func (m *Minter) logMintOutcome(ctx context.Context, req MintRequest, minted *Minted) {
	if m.logger == nil {
		return
	}
	attrs := []slog.Attr{
		slog.String("grant_id", req.GrantID),
		slog.String("agent_id", req.AgentID),
		slog.String("profile", req.Profile),
		slog.String("access_key_id", minted.Credentials.AccessKeyID()),
		slog.String("source_identity", minted.SourceIdentity),
		slog.Int("packed_policy_size_percent", minted.PackedPolicySizePercent),
	}
	switch minted.PackedPolicySeverity() {
	case "alert":
		m.logger.LogAttrs(ctx, slog.LevelError, "packed policy size at alert threshold", attrs...)
	case "warn":
		m.logger.LogAttrs(ctx, slog.LevelWarn, "packed policy size at warn threshold", attrs...)
	}
	m.logger.LogAttrs(ctx, slog.LevelInfo, "minted sts session", attrs...)
}

// CompactFunc re-renders the same capability selection under a tighter
// character budget: the synthesizer seam's Compact, adapted by the
// broker. It returns the new minified policy and the (possibly
// extended) managed policy ARN list.
type CompactFunc func(ctx context.Context, maxChars int) (policyJSON []byte, policyARNs []string, err error)

// MintWithCompact runs the section 7.3 mint protocol: mint once; on
// PackedPolicyTooLarge invoke compact exactly once with a budget 20
// percent under the rejected policy's size and retry; a second
// PackedPolicyTooLarge returns *PolicyTooLargeError carrying both
// attempts. The grant ULID never changes across the retry.
func (m *Minter) MintWithCompact(ctx context.Context, req MintRequest, compact CompactFunc) (*Minted, error) {
	minted, err := m.Mint(ctx, req)
	var first *PackedPolicyTooLargeError
	if err == nil || !errors.As(err, &first) {
		return minted, err
	}
	if compact == nil {
		return nil, err
	}

	tighter := len(req.PolicyJSON) * 80 / 100
	if m.logger != nil {
		m.logger.LogAttrs(ctx, slog.LevelWarn, "packed policy too large; compacting once",
			slog.String("grant_id", req.GrantID),
			slog.Int("policy_chars", len(req.PolicyJSON)),
			slog.Int("compact_budget_chars", tighter),
		)
	}
	policyJSON, policyARNs, cerr := compact(ctx, tighter)
	if cerr != nil {
		return nil, fmt.Errorf("compact after %s: %w", packedPolicyTooLargeCode, cerr)
	}
	retry := req
	retry.PolicyJSON = policyJSON
	if policyARNs != nil {
		retry.PolicyARNs = policyARNs
	}

	minted, err = m.Mint(ctx, retry)
	var second *PackedPolicyTooLargeError
	if err != nil && errors.As(err, &second) {
		return nil, &PolicyTooLargeError{Attempts: [2]MintAttempt{
			{PolicyChars: first.PolicyChars, PolicyARNCount: first.PolicyARNCount, Message: first.Message},
			{PolicyChars: second.PolicyChars, PolicyARNCount: second.PolicyARNCount, Message: second.Message},
		}}
	}
	return minted, err
}

// BrokerIdentity is the broker's own caller identity at startup.
type BrokerIdentity struct {
	ARN     string
	Account string
	UserID  string
	// Chained is true when the broker itself runs on session
	// credentials (the ARN names an assumed role). Every mint is then
	// role chaining and G7 clamps all grants to 3600 seconds.
	Chained bool
}

// CallerIdentity resolves and logs the broker's caller identity
// (section 8.7). The broker calls it at startup and feeds Chained into
// the guardrail evaluator's G7 input.
func (m *Minter) CallerIdentity(ctx context.Context) (BrokerIdentity, error) {
	out, err := m.client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return BrokerIdentity{}, fmt.Errorf("sts get caller identity: %w", err)
	}
	id := BrokerIdentity{
		ARN:     aws.ToString(out.Arn),
		Account: aws.ToString(out.Account),
		UserID:  aws.ToString(out.UserId),
	}
	id.Chained = strings.Contains(id.ARN, ":assumed-role/")
	if m.logger != nil {
		if id.Chained {
			m.logger.LogAttrs(ctx, slog.LevelWarn,
				"broker runs on session credentials; every mint is role chaining and grant durations clamp to 3600 seconds",
				slog.String("caller_arn", id.ARN))
		} else {
			m.logger.LogAttrs(ctx, slog.LevelInfo, "broker caller identity",
				slog.String("caller_arn", id.ARN))
		}
	}
	return id, nil
}
