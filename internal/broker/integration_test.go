package broker

// Integration-style tests over the real seams (section 14): the real
// dataset artifact, the starter catalog, the real synthesizer and
// compiler, the shared guardrail evaluator, and the real stsmint
// Minter over a capturing fake STS client. Two end-to-end properties:
//
//  1. The catalog's max_duration_seconds is honored all the way into
//     the AssumeRole input, past a larger requested duration and a
//     larger profile cap.
//  2. The CloudTrail join: the SourceIdentity, session tags, and
//     RoleSessionName recomputed from a decision record alone match
//     the exact AssumeRole input STS received.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/0hardik1/taskgrant/internal/approvals"
	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/guardrails"
	"github.com/0hardik1/taskgrant/internal/mcpserver"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/stsmint"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
	"github.com/0hardik1/taskgrant/internal/synth/compile"
	"github.com/0hardik1/taskgrant/internal/synth/match"
	"github.com/0hardik1/taskgrant/internal/synth/synthesizer"
)

const (
	integrationDatasetPath = "../../testdata/iam-dataset.json"
	integrationCatalogDir  = "../../examples/catalog"
)

// captureSTSClient implements stsmint.STSAPI and records every
// AssumeRole input, standing in for what CloudTrail's AssumeRole event
// would capture in requestParameters.
type captureSTSClient struct {
	mu     sync.Mutex
	inputs []*sts.AssumeRoleInput
}

func (c *captureSTSClient) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inputs = append(c.inputs, in)
	exp := time.Now().Add(time.Duration(aws.ToInt32(in.DurationSeconds)) * time.Second).UTC()
	return &sts.AssumeRoleOutput{
		AssumedRoleUser: &ststypes.AssumedRoleUser{
			Arn:           aws.String("arn:aws:sts::222222222222:assumed-role/tg-p1/" + aws.ToString(in.RoleSessionName)),
			AssumedRoleId: aws.String("AROAINTEGRATION:" + aws.ToString(in.RoleSessionName)),
		},
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("ASIAINTEGRATIONTEST"),
			SecretAccessKey: aws.String("integration-secret"),
			SessionToken:    aws.String("integration-session-token"),
			Expiration:      aws.Time(exp),
		},
		PackedPolicySize: aws.Int32(37),
	}, nil
}

func (c *captureSTSClient) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{
		Arn:     aws.String("arn:aws:iam::111111111111:role/taskgrant-broker"),
		Account: aws.String("111111111111"),
	}, nil
}

func (c *captureSTSClient) last(t *testing.T) *sts.AssumeRoleInput {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.inputs) == 0 {
		t.Fatal("no AssumeRole call was captured")
	}
	return c.inputs[len(c.inputs)-1]
}

// The consumer-side adapters below mirror cmd/taskgrant/adapters.go:
// test-local wiring of the concrete foundation packages onto the
// synthesizer seams.

type itSnapshotView struct{ snap *catalog.Snapshot }

var _ match.Snapshot = itSnapshotView{}

func (v itSnapshotView) Hash() string {
	if v.snap == nil {
		return ""
	}
	return v.snap.CatalogHash()
}

func (v itSnapshotView) Capabilities() []match.Capability {
	if v.snap == nil {
		return nil
	}
	caps := v.snap.Capabilities()
	out := make([]match.Capability, 0, len(caps))
	for _, c := range caps {
		out = append(out, v.convert(c))
	}
	return out
}

func (v itSnapshotView) Lookup(id string) (match.Capability, bool) {
	if v.snap == nil {
		return match.Capability{}, false
	}
	c, ok := v.snap.Capability(id)
	if !ok {
		return match.Capability{}, false
	}
	return v.convert(c), true
}

func (v itSnapshotView) convert(c *catalog.Capability) match.Capability {
	out := match.Capability{
		ID:                 c.ID,
		Version:            c.Version,
		Summary:            c.Summary,
		Keywords:           c.Match.Keywords,
		ServicePrefixes:    c.Match.ServicePrefixes,
		Examples:           c.Match.Examples,
		RequiresApproval:   c.RequiresApproval,
		MaxDurationSeconds: c.MaxDurationSeconds,
	}
	for _, name := range c.ParamNames() {
		p := c.Params[name]
		out.Params = append(out.Params, match.ParamSpec{
			Name:          name,
			Required:      true,
			ExpectedShape: p.ExpectedShape(),
			Examples:      v.snap.ParamExamples(c.ID, name, 3),
		})
	}
	return out
}

type itCatalogAdapter struct{ store *catalog.Store }

var _ synthesizer.Catalog = itCatalogAdapter{}

func (a itCatalogAdapter) SnapshotFor(agentID string) match.Snapshot {
	return itSnapshotView{snap: a.store.SnapshotForAgent(agentID)}
}

type itParamsAdapter struct{ store *catalog.Store }

var _ synthesizer.ParamValidator = itParamsAdapter{}

func (a itParamsAdapter) ValidateParams(capabilityID string, params map[string]string) []synthesizer.ParamError {
	snap := a.store.Current()
	if snap == nil {
		return []synthesizer.ParamError{{Capability: capabilityID, Reason: "catalog unavailable"}}
	}
	_, err := snap.ValidateParams(capabilityID, params)
	if err == nil {
		return nil
	}
	if perr, ok := err.(*catalog.ParamError); ok {
		return []synthesizer.ParamError{{
			Capability: perr.Capability,
			Name:       perr.Param,
			Reason:     perr.Reason,
		}}
	}
	return []synthesizer.ParamError{{Capability: capabilityID, Reason: "unknown capability"}}
}

type itCompilerAdapter struct {
	store    *catalog.Store
	compiler *compile.Compiler
	region   string
	accounts []string
}

var _ synthesizer.Compiler = itCompilerAdapter{}

func (a itCompilerAdapter) Compile(_ context.Context, in synthesizer.CompileInput) (synthesizer.CompileResult, error) {
	snap := a.store.Current()
	if snap == nil {
		return synthesizer.CompileResult{}, fmt.Errorf("compile: catalog unavailable")
	}
	sels := make([]compile.Selection, 0, len(in.Capabilities))
	for _, sc := range in.Capabilities {
		c, ok := snap.Capability(sc.ID)
		if !ok {
			return synthesizer.CompileResult{}, fmt.Errorf("compile: capability %q is not in the catalog", sc.ID)
		}
		validated, err := snap.ValidateParams(sc.ID, sc.Params)
		if err != nil {
			return synthesizer.CompileResult{}, fmt.Errorf("compile: capability %s params: %w", sc.ID, err)
		}
		sels = append(sels, compile.Selection{Capability: c, Params: validated})
	}
	out, err := a.compiler.Compile(compile.Input{
		Selections:          sels,
		Region:              a.region,
		Accounts:            a.accounts,
		MaxPolicyChars:      in.MaxChars,
		ForceDropSids:       in.Options.DropSids,
		ForceOffloadManaged: in.Options.OffloadManaged,
	})
	if err != nil {
		return synthesizer.CompileResult{}, err
	}
	return synthesizer.CompileResult{
		PolicyJSON:         out.PolicyJSON,
		PolicyArns:         out.PolicyArns,
		Explanation:        out.Explanation,
		ExpandedActions:    out.ExpandedActions,
		PerCapabilityChars: out.Attribution,
	}, nil
}

type itGuardrailAdapter struct {
	evaluator *guardrails.Evaluator
	store     *catalog.Store
}

var _ synthesizer.GuardrailEvaluator = itGuardrailAdapter{}

func (a itGuardrailAdapter) Evaluate(ctx context.Context, policyJSON []byte, meta synthesizer.GuardrailMeta) ([]synthesizer.GuardrailVerdict, error) {
	in := guardrails.Input{
		PolicyJSON:                policyJSON,
		AgentID:                   meta.AgentID,
		Profile:                   meta.Profile.Name,
		ProfileMaxDurationSeconds: meta.Profile.MaxDurationSeconds,
		Capabilities:              a.capabilityMeta(meta.Capabilities),
	}
	res := a.evaluator.Evaluate(ctx, in)
	out := make([]synthesizer.GuardrailVerdict, 0, len(res.Checks))
	for _, c := range res.Checks {
		verdict := string(c.Verdict)
		if c.Verdict == guardrails.NeedsApproval {
			verdict = synthesizer.GuardrailWarn
		}
		out = append(out, synthesizer.GuardrailVerdict{Check: c.Name, Result: verdict, Detail: c.Detail})
	}
	return out, nil
}

func (a itGuardrailAdapter) capabilityMeta(refs []synth.CapabilityRef) []guardrails.CapabilityMeta {
	snap := a.store.Current()
	out := make([]guardrails.CapabilityMeta, 0, len(refs))
	for _, ref := range refs {
		m := guardrails.CapabilityMeta{ID: ref.ID}
		if snap != nil {
			if c, ok := snap.Capability(ref.ID); ok {
				m.MaxDurationSeconds = c.MaxDurationSeconds
				m.TaggingOptIn = c.AccessCeiling == "Tagging"
			}
		}
		out = append(out, m)
	}
	return out
}

// integrationHarness is one fully wired broker over real components,
// with only the STS wire call faked.
type integrationHarness struct {
	b   *Broker
	st  *store.Store
	sts *captureSTSClient
}

func newIntegrationHarness(t *testing.T) *integrationHarness {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ds, err := dataset.Load(integrationDatasetPath)
	if err != nil {
		t.Fatalf("dataset.Load: %v", err)
	}
	snap, err := catalog.Load(integrationCatalogDir, ds, catalog.WithoutGitCommit())
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	catStore := catalog.NewStore(snap)

	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "it.db"), Logger: logger})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	appr, err := approvals.New(st, 900*time.Second, approvals.Options{Logger: logger})
	if err != nil {
		t.Fatalf("approvals.New: %v", err)
	}

	cfg := testConfig()

	evaluator, err := guardrails.New(ds, guardrails.Config{
		AllowedAccessLevels:      []string{"Read", "List"},
		ResourceAllowlist:        snap.ResourcePatterns(),
		Accounts:                 cfg.AWS.Accounts,
		GlobalMaxDurationSeconds: cfg.AWS.MaxDurationSeconds,
	})
	if err != nil {
		t.Fatalf("guardrails.New: %v", err)
	}

	compiler, err := compile.New(ds)
	if err != nil {
		t.Fatalf("compile.New: %v", err)
	}

	synthImpl, err := synthesizer.New(synthesizer.Deps{
		Catalog: itCatalogAdapter{store: catStore},
		Compiler: itCompilerAdapter{
			store:    catStore,
			compiler: compiler,
			region:   cfg.AWS.STSRegion,
			accounts: cfg.AWS.Accounts,
		},
		Guardrails:  itGuardrailAdapter{evaluator: evaluator, store: catStore},
		Params:      itParamsAdapter{store: catStore},
		Cache:       synthesizer.NewMemoryCache(0),
		DatasetHash: ds.Hash(),
		ConfigHash:  cfg.ConfigHash(),
	})
	if err != nil {
		t.Fatalf("synthesizer.New: %v", err)
	}

	stsClient := &captureSTSClient{}
	minter := stsmint.NewWithClient(stsClient, logger)

	b, err := New(Deps{
		Config:    cfg,
		Synth:     synthImpl,
		Evaluator: evaluator,
		Approvals: appr,
		Minter:    minter,
		Log:       st,
		Catalog:   catStore,
		Dataset:   ds,
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}
	return &integrationHarness{b: b, st: st, sts: stsClient}
}

// integrationRecordBody is the decision-record subset these tests read.
type integrationRecordBody struct {
	GrantID                  string `json:"grant_id"`
	AgentID                  string `json:"agent_id"`
	Profile                  string `json:"profile"`
	Outcome                  string `json:"outcome"`
	RequestedDurationSeconds int    `json:"requested_duration_seconds"`
	GrantedDurationSeconds   int    `json:"granted_duration_seconds"`
	CallerRef                string `json:"caller_ref"`
	STS                      *struct {
		RoleARN           string            `json:"role_arn"`
		RoleSessionName   string            `json:"role_session_name"`
		SourceIdentity    string            `json:"source_identity"`
		SessionTags       map[string]string `json:"session_tags"`
		TransitiveTagKeys []string          `json:"transitive_tag_keys"`
		AccessKeyID       string            `json:"access_key_id"`
	} `json:"sts"`
}

// mintedRecordBody finds the auto_approved decision record of a grant
// and decodes the fields under test.
func mintedRecordBody(t *testing.T, st *store.Store, grantID string) integrationRecordBody {
	t.Helper()
	recs, err := st.GrantChain(context.Background(), grantID)
	if err != nil {
		t.Fatalf("GrantChain: %v", err)
	}
	for _, r := range recs {
		var body integrationRecordBody
		if err := json.Unmarshal(r.Body, &body); err != nil {
			t.Fatalf("record body decode: %v", err)
		}
		if body.Outcome == "auto_approved" {
			return body
		}
	}
	t.Fatalf("no auto_approved decision record for grant %s (%d records)", grantID, len(recs))
	return integrationRecordBody{}
}

// integrationGrantReq is a structured-hints request for the starter
// catalog's s3.read-prefix entry (capability cap 900 s), asking for
// more duration than the capability allows.
func integrationGrantReq() mcpserver.GrantRequest {
	return mcpserver.GrantRequest{
		Task:   "download the 2026 invoices from the archive bucket",
		Reason: "monthly archive job, ticket OPS-4412",
		Capabilities: []synth.CapabilityHint{{
			ID:     "s3.read-prefix",
			Params: map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"},
		}},
		DurationSeconds: 1800,
		Transport:       mcpserver.TransportStdio,
	}
}

func TestIntegrationCatalogMaxDurationHonoredEndToEnd(t *testing.T) {
	h := newIntegrationHarness(t)
	ctx := context.Background()

	// The request asks for 1800 s; the profile allows 1800 and the
	// global cap is 3600. The catalog entry caps at 900, and that cap
	// must win all the way into the AssumeRole input.
	view, err := h.b.RequestGrant(ctx, "bot", integrationGrantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "active" {
		t.Fatalf("status = %q (detail %q, code %q), want active", view.Status, view.Detail, view.DenialCode)
	}

	input := h.sts.last(t)
	if got := aws.ToInt32(input.DurationSeconds); got != 900 {
		t.Fatalf("AssumeRole DurationSeconds = %d, want 900 (the catalog max_duration_seconds)", got)
	}

	body := mintedRecordBody(t, h.st, view.GrantID)
	if body.RequestedDurationSeconds != 1800 {
		t.Errorf("record requested_duration_seconds = %d, want 1800", body.RequestedDurationSeconds)
	}
	if body.GrantedDurationSeconds != 900 {
		t.Errorf("record granted_duration_seconds = %d, want 900", body.GrantedDurationSeconds)
	}
}

func TestIntegrationCloudTrailJoinRecomputation(t *testing.T) {
	h := newIntegrationHarness(t)
	ctx := context.Background()

	const rawCallerRef = "run 4412/step<3>\x1b[31m"
	req := integrationGrantReq()
	req.CallerRef = rawCallerRef

	view, err := h.b.RequestGrant(ctx, "bot", req)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "active" {
		t.Fatalf("status = %q (detail %q, code %q), want active", view.Status, view.Detail, view.DenialCode)
	}

	input := h.sts.last(t)
	body := mintedRecordBody(t, h.st, view.GrantID)
	if body.STS == nil {
		t.Fatal("decision record has no STS block")
	}
	if body.GrantID != view.GrantID {
		t.Fatalf("record grant_id = %q, want %q", body.GrantID, view.GrantID)
	}

	// Recompute the broker-authored join fields from the decision
	// record alone, then require agreement with both the record's STS
	// block and the exact AssumeRole input (what a synthetic CloudTrail
	// AssumeRole event would carry in requestParameters).
	wantSourceIdentity := domain.SourceIdentity(body.GrantID)
	wantSessionName := domain.RoleSessionName(body.AgentID, body.GrantID)
	wantTags := map[string]string{
		domain.TagKeyAgent:     body.AgentID,
		domain.TagKeyGrant:     body.GrantID,
		domain.TagKeyProfile:   body.Profile,
		domain.TagKeyCallerRef: domain.SanitizeCallerRef(body.CallerRef),
	}

	if body.STS.SourceIdentity != wantSourceIdentity {
		t.Errorf("record source_identity = %q, recomputed %q", body.STS.SourceIdentity, wantSourceIdentity)
	}
	if got := aws.ToString(input.SourceIdentity); got != wantSourceIdentity {
		t.Errorf("AssumeRole SourceIdentity = %q, recomputed %q", got, wantSourceIdentity)
	}
	if body.STS.RoleSessionName != wantSessionName {
		t.Errorf("record role_session_name = %q, recomputed %q", body.STS.RoleSessionName, wantSessionName)
	}
	if got := aws.ToString(input.RoleSessionName); got != wantSessionName {
		t.Errorf("AssumeRole RoleSessionName = %q, recomputed %q", got, wantSessionName)
	}

	// The frozen four-tag schema (section 8.3), record and wire.
	inputTags := make(map[string]string, len(input.Tags))
	for _, tag := range input.Tags {
		inputTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	for key, want := range wantTags {
		if got := body.STS.SessionTags[key]; got != want {
			t.Errorf("record session tag %s = %q, recomputed %q", key, got, want)
		}
		if got := inputTags[key]; got != want {
			t.Errorf("AssumeRole tag %s = %q, recomputed %q", key, got, want)
		}
	}
	if len(inputTags) != len(wantTags) {
		t.Errorf("AssumeRole carried %d tags %v, want exactly %d", len(inputTags), inputTags, len(wantTags))
	}
	// The raw hostile caller_ref bytes must not reach the wire.
	if inputTags[domain.TagKeyCallerRef] == rawCallerRef {
		t.Error("caller_ref reached STS unsanitized")
	}

	// Transitive keys: exactly the two broker-authored identity tags.
	wantTransitive := domain.TransitiveTagKeys()
	if len(input.TransitiveTagKeys) != len(wantTransitive) {
		t.Fatalf("transitive keys = %v, want %v", input.TransitiveTagKeys, wantTransitive)
	}
	for i, k := range wantTransitive {
		if input.TransitiveTagKeys[i] != k {
			t.Errorf("transitive key [%d] = %q, want %q", i, input.TransitiveTagKeys[i], k)
		}
		if body.STS.TransitiveTagKeys[i] != k {
			t.Errorf("record transitive key [%d] = %q, want %q", i, body.STS.TransitiveTagKeys[i], k)
		}
	}

	// The join inversion: a CloudTrail sourceIdentity resolves back to
	// exactly this grant's decision record.
	back, err := domain.GrantIDFromSourceIdentity(aws.ToString(input.SourceIdentity))
	if err != nil {
		t.Fatalf("GrantIDFromSourceIdentity: %v", err)
	}
	if back != view.GrantID {
		t.Errorf("join inversion returned %q, want %q", back, view.GrantID)
	}

	// The log stores the access key id, never the secret (I4).
	if body.STS.AccessKeyID != "ASIAINTEGRATIONTEST" {
		t.Errorf("record access_key_id = %q, want the minted key id", body.STS.AccessKeyID)
	}
}
