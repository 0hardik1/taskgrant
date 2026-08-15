package synthesizer

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/match"
)

// fakeSnapshot implements match.Snapshot.
type fakeSnapshot struct {
	caps []match.Capability
	hash string
}

func (f fakeSnapshot) Capabilities() []match.Capability { return f.caps }

func (f fakeSnapshot) Lookup(id string) (match.Capability, bool) {
	for _, c := range f.caps {
		if c.ID == id {
			return c, true
		}
	}
	return match.Capability{}, false
}

func (f fakeSnapshot) Hash() string { return f.hash }

// fakeCatalog implements Catalog with one snapshot for every agent.
type fakeCatalog struct {
	snap fakeSnapshot
}

func (f fakeCatalog) SnapshotFor(string) match.Snapshot { return f.snap }

func testCapabilities() []match.Capability {
	return []match.Capability{
		{
			ID:              "s3.read-prefix",
			Version:         3,
			Summary:         "Read objects under one prefix of an allowlisted bucket",
			Keywords:        []string{"read", "download", "fetch", "get", "list"},
			ServicePrefixes: []string{"s3"},
			Params: []match.ParamSpec{
				{Name: "bucket", Required: true, ExpectedShape: "bucket name from the s3-buckets allowlist", Examples: []string{"acme-invoices-prod"}},
				{Name: "prefix", Required: false, ExpectedShape: "path prefix"},
			},
			MaxDurationSeconds: 1200,
		},
		{
			ID:               "s3.write-prefix",
			Version:          1,
			Summary:          "Write objects under one prefix of an allowlisted bucket",
			Keywords:         []string{"write", "upload", "put", "archive"},
			ServicePrefixes:  []string{"s3"},
			Params:           []match.ParamSpec{{Name: "bucket", Required: true, ExpectedShape: "bucket name"}},
			RequiresApproval: true,
		},
		{
			ID:              "sqs.consume",
			Version:         2,
			Summary:         "Consume messages from one allowlisted queue",
			Keywords:        []string{"consume", "receive", "poll", "dequeue"},
			ServicePrefixes: []string{"sqs"},
			Params:          []match.ParamSpec{{Name: "queue", Required: true, ExpectedShape: "queue name"}},
		},
	}
}

// fakeCompiler is a deterministic Compiler: canonical JSON over the
// sorted capability selection, byte-stable for identical inputs. It
// records inputs so tests can assert what reached compilation.
type fakeCompiler struct {
	managed map[string]bool
	calls   int
	inputs  []CompileInput
}

type fakeStatement struct {
	Sid      string `json:"Sid,omitempty"`
	Effect   string `json:"Effect"`
	Action   string `json:"Action"`
	Resource string `json:"Resource"`
}

type fakePolicy struct {
	Version   string          `json:"Version"`
	Statement []fakeStatement `json:"Statement"`
}

func (f *fakeCompiler) Compile(_ context.Context, in CompileInput) (CompileResult, error) {
	f.calls++
	f.inputs = append(f.inputs, in)

	caps := append([]SelectedCapability(nil), in.Capabilities...)
	sort.SliceStable(caps, func(i, j int) bool { return caps[i].ID < caps[j].ID })

	var (
		stmts   []fakeStatement
		expl    []synth.StatementExplanation
		arns    []string
		actions []string
	)
	perCap := map[string]int{}
	for i, c := range caps {
		if in.Options.OffloadManaged && f.managed[c.ID] {
			arns = append(arns, "arn:aws:iam::222222222222:policy/tg-"+c.ID)
			actions = append(actions, c.ID+":Managed")
			continue
		}
		paramsJSON, err := json.Marshal(c.Params)
		if err != nil {
			return CompileResult{}, err
		}
		st := fakeStatement{
			Effect:   "Allow",
			Action:   "cap:" + c.ID,
			Resource: "arn:fake:" + c.ID + ":" + string(paramsJSON),
		}
		if !in.Options.DropSids {
			st.Sid = fmt.Sprintf("tg%d", i)
		}
		b, err := json.Marshal(st)
		if err != nil {
			return CompileResult{}, err
		}
		perCap[c.ID] = len(b)
		stmts = append(stmts, st)
		expl = append(expl, synth.StatementExplanation{
			CapabilityID:      c.ID,
			CapabilityVersion: c.Version,
			Params:            c.Params,
			Reason:            "template reason for " + c.ID,
		})
		actions = append(actions, c.ID+":Action")
	}
	policy, err := json.Marshal(fakePolicy{Version: "2012-10-17", Statement: stmts})
	if err != nil {
		return CompileResult{}, err
	}
	return CompileResult{
		PolicyJSON:         policy,
		PolicyArns:         arns,
		Explanation:        synth.Explanation{Statements: expl},
		ExpandedActions:    actions,
		PerCapabilityChars: perCap,
	}, nil
}

// renderSize compiles the selection standalone and returns the policy
// length, letting tests pick exact ladder budgets.
func (f *fakeCompiler) renderSize(caps []SelectedCapability, opts CompileOptions) int {
	clone := &fakeCompiler{managed: f.managed}
	res, err := clone.Compile(context.Background(), CompileInput{Capabilities: caps, Options: opts})
	if err != nil {
		panic(err)
	}
	return len(res.PolicyJSON)
}

// fakeGuardrails implements GuardrailEvaluator.
type fakeGuardrails struct {
	fail       bool
	err        error
	calls      int
	lastPolicy []byte
	lastMeta   GuardrailMeta
}

func (f *fakeGuardrails) Evaluate(_ context.Context, policyJSON []byte, meta GuardrailMeta) ([]GuardrailVerdict, error) {
	f.calls++
	f.lastPolicy = append([]byte(nil), policyJSON...)
	f.lastMeta = meta
	if f.err != nil {
		return nil, f.err
	}
	if f.fail {
		return []GuardrailVerdict{
			{Check: "G0", Result: GuardrailPass, Detail: "structure ok"},
			{Check: "G2", Result: GuardrailFail, Detail: "access level not permitted"},
		}, nil
	}
	return []GuardrailVerdict{
		{Check: "G0", Result: GuardrailPass, Detail: "structure ok"},
		{Check: "G2", Result: GuardrailPass, Detail: "levels ok"},
	}, nil
}

// fakeValidator rejects values containing wildcard or template bytes,
// mirroring the section 5.2 grammar stance.
type fakeValidator struct{}

func (fakeValidator) ValidateParams(capabilityID string, params map[string]string) []ParamError {
	var errs []ParamError
	for name, val := range params {
		if val == "" || strings.ContainsAny(val, "*?") || strings.Contains(val, "${") ||
			strings.ContainsAny(val, " \t\n") {
			errs = append(errs, ParamError{
				Capability:    capabilityID,
				Name:          name,
				Reason:        "value fails the declared grammar",
				ExpectedShape: "letters, digits, dashes, slashes",
				Examples:      []string{"acme-invoices-prod"},
			})
		}
	}
	return errs
}

// env bundles a synthesizer with its observable fakes.
type env struct {
	synth      *Synthesizer
	compiler   *fakeCompiler
	guardrails *fakeGuardrails
	cache      *MemoryCache
	classifier *match.StubClassifier
	firstUsed  map[string]bool
}

// newEnv builds a default test environment; mut customizes the Deps
// before construction.
func newEnv(t interface{ Fatalf(string, ...any) }, mut func(*Deps, *env)) *env {
	e := &env{
		compiler:   &fakeCompiler{managed: map[string]bool{"sqs.consume": true}},
		guardrails: &fakeGuardrails{},
		firstUsed:  map[string]bool{},
	}
	deps := Deps{
		Catalog:     fakeCatalog{snap: fakeSnapshot{caps: testCapabilities(), hash: "cat-hash"}},
		Compiler:    e.compiler,
		Guardrails:  e.guardrails,
		Params:      fakeValidator{},
		ConfigHash:  "cfg-hash",
		DatasetHash: "ds-hash",
		FirstUse: func(agentID, capabilityID string) (bool, error) {
			return !e.firstUsed[agentID+"|"+capabilityID], nil
		},
	}
	if mut != nil {
		mut(&deps, e)
	}
	s, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.synth = s
	return e
}

// baseRequest is a structured-hint request that proceeds cleanly.
func baseRequest(grantID string) synth.Request {
	return synth.Request{
		GrantID: grantID,
		AgentID: "invoice-bot",
		Profile: synth.ProfileInfo{Name: "s3-archiver", RoleARN: "arn:aws:iam::222222222222:role/tg", MaxDurationSeconds: 1800},
		Task:    "Archive the invoices older than 90 days",
		Reason:  "Monthly archive job, ticket OPS-4412",
		Hints: synth.Hints{Capabilities: []synth.CapabilityHint{{
			ID:     "s3.read-prefix",
			Params: map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"},
		}}},
		MaxPolicyChars: DefaultMaxPolicyChars,
	}
}
