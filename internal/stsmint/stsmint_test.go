package stsmint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"

	"github.com/0hardik1/taskgrant/internal/domain"
)

const (
	testSecret = "wJalrXUtnFEMI-K7MDENG-bPxRfiCY-SECRETKEY"
	testToken  = "FwoGZXIvYXdzE-SESSIONTOKEN-abcdef"
)

// fakeSTS is a scripted STSAPI: each AssumeRole call consumes the next
// response.
type fakeSTS struct {
	responses []func() (*sts.AssumeRoleOutput, error)
	inputs    []*sts.AssumeRoleInput
	callerARN string
}

func (f *fakeSTS) AssumeRole(_ context.Context, params *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.inputs = append(f.inputs, params)
	if len(f.responses) == 0 {
		return nil, errors.New("fakeSTS: no scripted response")
	}
	next := f.responses[0]
	f.responses = f.responses[1:]
	return next()
}

func (f *fakeSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{
		Arn:     aws.String(f.callerARN),
		Account: aws.String("111111111111"),
		UserId:  aws.String("AROAEXAMPLE:session"),
	}, nil
}

func successOutput(packedPct int32) func() (*sts.AssumeRoleOutput, error) {
	return func() (*sts.AssumeRoleOutput, error) {
		exp := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Second)
		return &sts.AssumeRoleOutput{
			AssumedRoleUser: &ststypes.AssumedRoleUser{
				Arn:           aws.String("arn:aws:sts::222222222222:assumed-role/taskgrant-s3-archiver/tg-invoice-bot-x"),
				AssumedRoleId: aws.String("AROAEXAMPLE:tg-invoice-bot-x"),
			},
			Credentials: &ststypes.Credentials{
				AccessKeyId:     aws.String("ASIAEXAMPLEKEY"),
				SecretAccessKey: aws.String(testSecret),
				SessionToken:    aws.String(testToken),
				Expiration:      &exp,
			},
			PackedPolicySize: aws.Int32(packedPct),
		}, nil
	}
}

func packedTooLarge() func() (*sts.AssumeRoleOutput, error) {
	return func() (*sts.AssumeRoleOutput, error) {
		return nil, &smithy.GenericAPIError{
			Code:    "PackedPolicyTooLarge",
			Message: "serialized policy document exceeds the maximum allowed size",
		}
	}
}

func testRequest() MintRequest {
	return MintRequest{
		GrantID:         domain.NewGrantID(),
		AgentID:         "invoice-bot",
		Profile:         "s3-archiver",
		RoleARN:         "arn:aws:iam::222222222222:role/taskgrant-s3-archiver",
		PolicyJSON:      []byte(`{"Version":"2012-10-17","Statement":[]}`),
		DurationSeconds: 900,
		CallerRef:       "run-4412-step-3",
	}
}

func TestBuildAssumeRoleInput(t *testing.T) {
	req := testRequest()
	req.PolicyARNs = []string{"arn:aws:iam::222222222222:policy/ceiling"}
	req.ExternalID = "ext-id-1"

	input, err := BuildAssumeRoleInput(req)
	if err != nil {
		t.Fatalf("BuildAssumeRoleInput: %v", err)
	}
	if got := aws.ToString(input.RoleSessionName); got != "tg-invoice-bot-"+req.GrantID {
		t.Errorf("RoleSessionName = %q", got)
	}
	if got := aws.ToString(input.SourceIdentity); got != "tg-"+req.GrantID {
		t.Errorf("SourceIdentity = %q", got)
	}
	if got := aws.ToString(input.Policy); got != string(req.PolicyJSON) {
		t.Errorf("Policy = %q", got)
	}
	if got := aws.ToInt32(input.DurationSeconds); got != 900 {
		t.Errorf("DurationSeconds = %d", got)
	}
	if got := aws.ToString(input.ExternalId); got != "ext-id-1" {
		t.Errorf("ExternalId = %q", got)
	}
	if len(input.PolicyArns) != 1 || aws.ToString(input.PolicyArns[0].Arn) != req.PolicyARNs[0] {
		t.Errorf("PolicyArns = %+v", input.PolicyArns)
	}

	// Frozen tag schema: exactly four tags in the 8.3 shape, exactly
	// two transitive keys.
	wantTags := map[string]string{
		domain.TagKeyAgent:     "invoice-bot",
		domain.TagKeyGrant:     req.GrantID,
		domain.TagKeyProfile:   "s3-archiver",
		domain.TagKeyCallerRef: "run-4412-step-3",
	}
	if len(input.Tags) != len(wantTags) {
		t.Fatalf("got %d tags, want %d", len(input.Tags), len(wantTags))
	}
	for _, tag := range input.Tags {
		k, v := aws.ToString(tag.Key), aws.ToString(tag.Value)
		if wantTags[k] != v {
			t.Errorf("tag %q = %q, want %q", k, v, wantTags[k])
		}
	}
	wantTransitive := []string{domain.TagKeyAgent, domain.TagKeyGrant}
	if len(input.TransitiveTagKeys) != 2 ||
		input.TransitiveTagKeys[0] != wantTransitive[0] ||
		input.TransitiveTagKeys[1] != wantTransitive[1] {
		t.Errorf("TransitiveTagKeys = %v, want %v", input.TransitiveTagKeys, wantTransitive)
	}
}

func TestBuildAssumeRoleInputValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*MintRequest)
	}{
		{"bad_grant_id", func(r *MintRequest) { r.GrantID = "not-a-ulid" }},
		{"bad_agent_id", func(r *MintRequest) { r.AgentID = "Bad Agent!" }},
		{"no_role", func(r *MintRequest) { r.RoleARN = "" }},
		{"no_profile", func(r *MintRequest) { r.Profile = "" }},
		{"duration_low", func(r *MintRequest) { r.DurationSeconds = 899 }},
		{"duration_high", func(r *MintRequest) { r.DurationSeconds = 43201 }},
		{"too_many_policy_arns", func(r *MintRequest) {
			for i := 0; i < 11; i++ {
				r.PolicyARNs = append(r.PolicyARNs, fmt.Sprintf("arn:aws:iam::222222222222:policy/p%d", i))
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := testRequest()
			tc.mutate(&req)
			if _, err := BuildAssumeRoleInput(req); err == nil {
				t.Error("BuildAssumeRoleInput accepted an invalid request")
			}
		})
	}
}

func TestRoleSessionNameTruncationSafe(t *testing.T) {
	grantID := domain.NewGrantID()

	// The longest valid agent id fits exactly in 62 chars.
	longest := "a" + strings.Repeat("b", 31)
	req := testRequest()
	req.GrantID = grantID
	req.AgentID = longest
	input, err := BuildAssumeRoleInput(req)
	if err != nil {
		t.Fatalf("BuildAssumeRoleInput: %v", err)
	}
	name := aws.ToString(input.RoleSessionName)
	if len(name) != domain.MaxRoleSessionNameChars {
		t.Errorf("len = %d, want %d (%q)", len(name), domain.MaxRoleSessionNameChars, name)
	}
	if !strings.HasSuffix(name, grantID) {
		t.Errorf("session name %q lost the grant ULID", name)
	}

	// Hostile over-long input to the underlying builder still keeps
	// the ULID whole and the length under the cap.
	hostile := domain.RoleSessionName(strings.Repeat("x", 100), grantID)
	if len(hostile) > domain.MaxRoleSessionNameChars {
		t.Errorf("hostile name is %d chars, cap is %d", len(hostile), domain.MaxRoleSessionNameChars)
	}
	if !strings.HasSuffix(hostile, "-"+grantID) {
		t.Errorf("hostile name %q truncated the grant ULID", hostile)
	}
}

func TestCallerRefSanitization(t *testing.T) {
	req := testRequest()
	req.CallerRef = "evil\x1b[31m;ref\x00" + strings.Repeat("A", 100)
	input, err := BuildAssumeRoleInput(req)
	if err != nil {
		t.Fatalf("BuildAssumeRoleInput: %v", err)
	}
	var got string
	for _, tag := range input.Tags {
		if aws.ToString(tag.Key) == domain.TagKeyCallerRef {
			got = aws.ToString(tag.Value)
		}
	}
	if len(got) > domain.CallerRefMaxLen {
		t.Errorf("caller_ref is %d chars, cap is %d", len(got), domain.CallerRefMaxLen)
	}
	if strings.ContainsAny(got, "\x1b\x00;") {
		t.Errorf("caller_ref %q kept unsafe bytes", got)
	}
	if !strings.HasPrefix(got, "evil31mref") {
		t.Errorf("caller_ref %q lost the safe charset content", got)
	}

	// An all-hostile ref produces no tag at all rather than an empty
	// value.
	req.CallerRef = "\x1b\x00\x07"
	input, err = BuildAssumeRoleInput(req)
	if err != nil {
		t.Fatalf("BuildAssumeRoleInput: %v", err)
	}
	for _, tag := range input.Tags {
		if aws.ToString(tag.Key) == domain.TagKeyCallerRef {
			t.Errorf("empty caller_ref still produced a tag with value %q", aws.ToString(tag.Value))
		}
	}
}

func TestMintSuccess(t *testing.T) {
	fake := &fakeSTS{responses: []func() (*sts.AssumeRoleOutput, error){successOutput(42)}}
	m := NewWithClient(fake, nil)
	req := testRequest()

	minted, err := m.Mint(context.Background(), req)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if minted.Credentials.AccessKeyID() != "ASIAEXAMPLEKEY" {
		t.Errorf("AccessKeyID = %q", minted.Credentials.AccessKeyID())
	}
	if minted.PackedPolicySizePercent != 42 {
		t.Errorf("PackedPolicySizePercent = %d, want 42", minted.PackedPolicySizePercent)
	}
	if minted.SourceIdentity != "tg-"+req.GrantID {
		t.Errorf("SourceIdentity = %q", minted.SourceIdentity)
	}
	if minted.SessionTags[domain.TagKeyGrant] != req.GrantID {
		t.Errorf("SessionTags = %v", minted.SessionTags)
	}
	d := minted.Credentials.Delivery()
	if d.SecretAccessKey != testSecret || d.SessionToken != testToken {
		t.Error("Delivery lost the plaintext credentials")
	}
}

func TestCredentialsRedaction(t *testing.T) {
	c := NewCredentials("ASIAEXAMPLEKEY", testSecret, testToken, time.Now().UTC())
	minted := &Minted{Credentials: c}

	renders := map[string]string{
		"String":       c.String(),
		"Sprintf_v":    fmt.Sprintf("%v", c),
		"Sprintf_plus": fmt.Sprintf("%+v", c),
		"Sprintf_s":    fmt.Sprintf("%s", c),
		"Sprintf_hash": fmt.Sprintf("%#v", c),
		"Minted_plus":  fmt.Sprintf("%+v", minted),
		"Minted_v":     fmt.Sprintf("%v", *minted),
	}
	jsonBytes, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal(Credentials): %v", err)
	}
	renders["json_credentials"] = string(jsonBytes)
	jsonBytes, err = json.Marshal(minted)
	if err != nil {
		t.Fatalf("json.Marshal(Minted): %v", err)
	}
	renders["json_minted"] = string(jsonBytes)

	for name, out := range renders {
		if strings.Contains(out, testSecret) || strings.Contains(out, testToken) {
			t.Errorf("%s leaked a secret: %s", name, out)
		}
		if name != "json_minted" && !strings.Contains(out, "ASIAEXAMPLEKEY") {
			t.Errorf("%s dropped the access key id: %s", name, out)
		}
	}

	// The delivery struct is the one deliberate plaintext surface.
	d, err := json.Marshal(c.Delivery())
	if err != nil {
		t.Fatalf("json.Marshal(Delivery): %v", err)
	}
	if !bytes.Contains(d, []byte(testSecret)) {
		t.Error("Delivery must carry the plaintext for the one-time hand-off")
	}
}

func TestMintPackedPolicyTooLarge(t *testing.T) {
	fake := &fakeSTS{responses: []func() (*sts.AssumeRoleOutput, error){packedTooLarge()}}
	m := NewWithClient(fake, nil)

	_, err := m.Mint(context.Background(), testRequest())
	var ppe *PackedPolicyTooLargeError
	if !errors.As(err, &ppe) {
		t.Fatalf("err = %v, want *PackedPolicyTooLargeError", err)
	}
	if ppe.PolicyChars != len(testRequest().PolicyJSON) {
		t.Errorf("PolicyChars = %d", ppe.PolicyChars)
	}
}

func TestMintWithCompactRecovers(t *testing.T) {
	fake := &fakeSTS{responses: []func() (*sts.AssumeRoleOutput, error){
		packedTooLarge(),
		successOutput(69),
	}}
	m := NewWithClient(fake, nil)
	req := testRequest()

	compactCalls := 0
	compacted := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"c"}]}`)
	compact := func(_ context.Context, maxChars int) ([]byte, []string, error) {
		compactCalls++
		want := len(req.PolicyJSON) * 80 / 100
		if maxChars != want {
			t.Errorf("compact budget = %d, want 20 percent under previous (%d)", maxChars, want)
		}
		return compacted, []string{"arn:aws:iam::222222222222:policy/offload"}, nil
	}

	minted, err := m.MintWithCompact(context.Background(), req, compact)
	if err != nil {
		t.Fatalf("MintWithCompact: %v", err)
	}
	if compactCalls != 1 {
		t.Errorf("compact called %d times, want exactly once", compactCalls)
	}
	if minted.PackedPolicySizePercent != 69 {
		t.Errorf("PackedPolicySizePercent = %d", minted.PackedPolicySizePercent)
	}
	if len(fake.inputs) != 2 {
		t.Fatalf("AssumeRole called %d times, want 2", len(fake.inputs))
	}
	if got := aws.ToString(fake.inputs[1].Policy); got != string(compacted) {
		t.Errorf("retry policy = %q, want the compacted document", got)
	}
	if len(fake.inputs[1].PolicyArns) != 1 {
		t.Errorf("retry PolicyArns = %+v, want the offloaded arn", fake.inputs[1].PolicyArns)
	}
	// The grant identity never changes across the retry.
	if aws.ToString(fake.inputs[0].SourceIdentity) != aws.ToString(fake.inputs[1].SourceIdentity) {
		t.Error("SourceIdentity changed across the compact retry")
	}
}

func TestMintWithCompactSecondFailureIsTerminal(t *testing.T) {
	fake := &fakeSTS{responses: []func() (*sts.AssumeRoleOutput, error){
		packedTooLarge(),
		packedTooLarge(),
	}}
	m := NewWithClient(fake, nil)
	req := testRequest()

	compacted := []byte(`{"Version":"2012-10-17"}`)
	compact := func(_ context.Context, _ int) ([]byte, []string, error) {
		return compacted, nil, nil
	}

	_, err := m.MintWithCompact(context.Background(), req, compact)
	var terminal *PolicyTooLargeError
	if !errors.As(err, &terminal) {
		t.Fatalf("err = %v, want *PolicyTooLargeError", err)
	}
	if terminal.DenialCode() != domain.DenyPolicyTooLarge {
		t.Errorf("DenialCode = %s, want %s", terminal.DenialCode(), domain.DenyPolicyTooLarge)
	}
	if terminal.Attempts[0].PolicyChars != len(req.PolicyJSON) {
		t.Errorf("attempt 1 chars = %d, want %d", terminal.Attempts[0].PolicyChars, len(req.PolicyJSON))
	}
	if terminal.Attempts[1].PolicyChars != len(compacted) {
		t.Errorf("attempt 2 chars = %d, want %d", terminal.Attempts[1].PolicyChars, len(compacted))
	}
}

func TestMintOtherErrorsPassThrough(t *testing.T) {
	fake := &fakeSTS{responses: []func() (*sts.AssumeRoleOutput, error){
		func() (*sts.AssumeRoleOutput, error) {
			return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "nope"}
		},
	}}
	m := NewWithClient(fake, nil)
	_, err := m.Mint(context.Background(), testRequest())
	if err == nil {
		t.Fatal("Mint returned nil error")
	}
	var ppe *PackedPolicyTooLargeError
	if errors.As(err, &ppe) {
		t.Error("a non-packed error must not classify as PackedPolicyTooLarge")
	}
}

func TestCallerIdentityChained(t *testing.T) {
	cases := []struct {
		arn  string
		want bool
	}{
		{"arn:aws:sts::111111111111:assumed-role/taskgrant-broker/i-abc", true},
		{"arn:aws:iam::111111111111:role/taskgrant-broker", false},
		{"arn:aws:iam::111111111111:user/dev", false},
	}
	for _, tc := range cases {
		m := NewWithClient(&fakeSTS{callerARN: tc.arn}, nil)
		id, err := m.CallerIdentity(context.Background())
		if err != nil {
			t.Fatalf("CallerIdentity: %v", err)
		}
		if id.Chained != tc.want {
			t.Errorf("Chained(%q) = %t, want %t", tc.arn, id.Chained, tc.want)
		}
	}
}

func TestPackedPolicySeverity(t *testing.T) {
	cases := []struct {
		pct  int
		want string
	}{
		{-1, "unknown"}, {0, "ok"}, {69, "ok"}, {70, "warn"},
		{84, "warn"}, {85, "alert"}, {120, "alert"},
	}
	for _, tc := range cases {
		if got := PackedPolicySeverity(tc.pct); got != tc.want {
			t.Errorf("PackedPolicySeverity(%d) = %q, want %q", tc.pct, got, tc.want)
		}
	}
}

func TestScrubAttr(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: ScrubAttr}))
	logger.Info("minted",
		"grant_id", "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"session_token", testToken,
		"SecretAccessKey", testSecret,
		"Authorization", "Bearer hunter2",
		"access_key_id", "ASIAEXAMPLEKEY",
	)
	out := buf.String()
	for _, leaked := range []string{testToken, testSecret, "hunter2", "session_token", "SecretAccessKey", "Authorization"} {
		if strings.Contains(out, leaked) {
			t.Errorf("scrubbed log leaked %q: %s", leaked, out)
		}
	}
	for _, kept := range []string{"grant_id", "access_key_id", "ASIAEXAMPLEKEY"} {
		if !strings.Contains(out, kept) {
			t.Errorf("scrubbed log dropped safe attr %q: %s", kept, out)
		}
	}
}

func TestMintLoggingNeverLeaksSecrets(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: ScrubAttr}))
	fake := &fakeSTS{responses: []func() (*sts.AssumeRoleOutput, error){successOutput(90)}}
	m := NewWithClient(fake, logger)

	if _, err := m.Mint(context.Background(), testRequest()); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, testSecret) || strings.Contains(out, testToken) {
		t.Errorf("mint logging leaked a secret: %s", out)
	}
	if !strings.Contains(out, "alert") && !strings.Contains(out, "packed policy size") {
		t.Errorf("packed size at 90 percent should have logged the alert: %s", out)
	}
}
