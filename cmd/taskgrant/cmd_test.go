package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
)

// testConfigYAML is a complete valid config for CLI tests. The %s slots
// are the catalog path and the dataset path.
const testConfigYAML = `
version: 1

server:
  transport: http
  listen: 127.0.0.1:8443
  admin_socket: /tmp/taskgrant-test.sock
  max_wait_seconds: 60

aws:
  sts_region: us-east-1
  default_duration_seconds: 900
  max_duration_seconds: 3600
  accounts: ["222222222222"]

agents:
  invoice-bot:
    token_sha256: "9F8A000000000000000000000000000000000000000000000000000000000000"
    token_expires: 2026-08-15T00:00:00Z
    profiles: [s3-archiver]

profiles:
  s3-archiver:
    role_arn: arn:aws:iam::222222222222:role/taskgrant-s3-archiver
    max_duration_seconds: 1800
    region: us-east-1
    external_id: cross-acct-42

synth:
  catalog_path: %s
  dataset_path: %s

guardrails:
  access_levels: [Read, List]
  first_use_approval: true

approvals:
  pending_ttl_seconds: 900

revocation:
  enabled: true

log:
  path: /var/lib/taskgrant/decisions.db
`

// exampleCatalogDir and exampleDatasetPath point at the shared test
// fixtures other packages already validate against.
const (
	exampleCatalogDir  = "../../examples/catalog"
	exampleDatasetPath = "../../testdata/iam-dataset.json"
)

func writeTestConfig(t *testing.T) string {
	t.Helper()
	catDir, err := filepath.Abs(exampleCatalogDir)
	if err != nil {
		t.Fatal(err)
	}
	dsPath, err := filepath.Abs(exampleDatasetPath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(testConfigYAML, catDir, dsPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadExampleSnapshot(t *testing.T) (*config.Config, *dataset.Dataset, *catalog.Snapshot) {
	t.Helper()
	cfg, ds, snap, err := loadCore(writeTestConfig(t))
	if err != nil {
		t.Fatalf("loadCore: %v", err)
	}
	return cfg, ds, snap
}

func TestTrimUpstream(t *testing.T) {
	upstream := `[
	  {
	    "prefix": "s3",
	    "privileges": [
	      {"privilege": "GetObject", "access_level": "Read",
	       "resource_types": [{"resource_type": "object*", "condition_keys": ["s3:ExistingObjectTag/<key>"]}]},
	      {"privilege": "ListBucket", "access_level": "List",
	       "resource_types": [{"resource_type": "bucket", "condition_keys": ["s3:prefix"]},
	                          {"resource_type": "", "condition_keys": ["s3:prefix", "aws:ResourceTag/${TagKey}"]}]},
	      {"privilege": "WeirdAction", "access_level": "Mystery", "resource_types": []}
	    ]
	  }
	]`
	artifact, skipped, err := trimUpstream([]byte(upstream), "commit-1")
	if err != nil {
		t.Fatalf("trimUpstream: %v", err)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (the Mystery access level)", skipped)
	}
	if len(artifact.Actions) != 2 {
		t.Fatalf("actions = %d, want 2", len(artifact.Actions))
	}
	get := artifact.Actions["s3:GetObject"]
	if get.AccessLevel != "Read" || len(get.ResourceTypes) != 1 || get.ResourceTypes[0] != "object" {
		t.Fatalf("s3:GetObject trimmed wrong: %+v", get)
	}
	list := artifact.Actions["s3:ListBucket"]
	if len(list.ConditionKeys) != 2 {
		t.Fatalf("s3:ListBucket condition keys not unioned: %+v", list.ConditionKeys)
	}

	// The artifact must load through the dataset package unchanged.
	data, err := json.MarshalIndent(artifact, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	ds, err := dataset.LoadBytes(data)
	if err != nil {
		t.Fatalf("trimmed artifact does not load: %v", err)
	}
	if ds.SourceCommit() != "commit-1" || ds.Len() != 2 {
		t.Fatalf("loaded dataset wrong: commit %q len %d", ds.SourceCommit(), ds.Len())
	}
}

func TestTrimUpstreamRejectsGarbage(t *testing.T) {
	for _, bad := range []string{`{}`, `[]`, `not json`, `[{"prefix":"s3","privileges":[]}]`} {
		if _, _, err := trimUpstream([]byte(bad), "c"); err == nil {
			t.Errorf("trimUpstream(%q) accepted garbage", bad)
		}
	}
}

func TestParsePolicyARN(t *testing.T) {
	cases := []struct {
		arn     string
		account string
		path    string
		name    string
		wantErr bool
	}{
		{"arn:aws:iam::222222222222:policy/taskgrant-logs-read", "222222222222", "/", "taskgrant-logs-read", false},
		{"arn:aws:iam::222222222222:policy/taskgrant/nested/name", "222222222222", "/taskgrant/nested/", "name", false},
		{"arn:aws:iam::222222222222:role/some-role", "", "", "", true},
		{"not-an-arn", "", "", "", true},
		{"arn:aws:iam::222222222222:policy/", "", "", "", true},
	}
	for _, tc := range cases {
		account, path, name, err := parsePolicyARN(tc.arn)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parsePolicyARN(%q) accepted", tc.arn)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePolicyARN(%q): %v", tc.arn, err)
			continue
		}
		if account != tc.account || path != tc.path || name != tc.name {
			t.Errorf("parsePolicyARN(%q) = %q %q %q, want %q %q %q",
				tc.arn, account, path, name, tc.account, tc.path, tc.name)
		}
	}
}

func TestProvisionSid(t *testing.T) {
	cases := []struct {
		id   string
		ord  int
		want string
	}{
		{"logs.read", 0, "TgLogsRead0"},
		{"s3.read-prefix", 2, "TgS3ReadPrefix2"},
		{"lambda.invoke", 1, "TgLambdaInvoke1"},
	}
	for _, tc := range cases {
		if got := provisionSid(tc.id, tc.ord); got != tc.want {
			t.Errorf("provisionSid(%q, %d) = %q, want %q", tc.id, tc.ord, got, tc.want)
		}
	}
}

func TestCollapseStars(t *testing.T) {
	cases := map[string]string{
		"a/**":     "a/*",
		"a/*b*":    "a/*b*",
		"***":      "*",
		"no-stars": "no-stars",
	}
	for in, want := range cases {
		if got := collapseStars(in); got != want {
			t.Errorf("collapseStars(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderManagedPolicy(t *testing.T) {
	cfg, _, snap := loadExampleSnapshot(t)
	c, ok := snap.Capability("logs.read")
	if !ok {
		t.Fatal("logs.read is not in the example catalog")
	}
	if !c.ManagedPolicy {
		t.Fatal("logs.read is not managed_policy in the example catalog")
	}
	doc, err := renderManagedPolicy(cfg, snap, c)
	if err != nil {
		t.Fatalf("renderManagedPolicy: %v", err)
	}

	var parsed struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid       string                    `json:"Sid"`
			Effect    string                    `json:"Effect"`
			Action    []string                  `json:"Action"`
			Resource  []string                  `json:"Resource"`
			Condition map[string]map[string]any `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("rendered document is not JSON: %v\n%s", err, doc)
	}
	if parsed.Version != "2012-10-17" || len(parsed.Statement) == 0 {
		t.Fatalf("document malformed: %s", doc)
	}

	// Worst case: every allowlisted log group appears; no live action
	// wildcards; region and account conditions injected.
	text := string(doc)
	for _, group := range []string{"/aws/lambda/invoice-processor", "/ecs/invoice-api"} {
		if !strings.Contains(text, group) {
			t.Errorf("allowlisted log group %q missing from the render", group)
		}
	}
	for _, st := range parsed.Statement {
		if st.Effect != "Allow" {
			t.Errorf("statement effect %q", st.Effect)
		}
		for _, a := range st.Action {
			if strings.Contains(a, "*") {
				t.Errorf("live action wildcard %q in a managed policy (I2)", a)
			}
		}
		cond := st.Condition["StringEquals"]
		if cond == nil {
			t.Fatalf("statement lacks the injected StringEquals conditions: %s", doc)
		}
		if _, ok := cond["aws:RequestedRegion"]; !ok {
			t.Errorf("aws:RequestedRegion not injected: %s", doc)
		}
	}
}

func TestProvisionDryRunAgainstExamples(t *testing.T) {
	cfgPath := writeTestConfig(t)
	var stdout, stderr bytes.Buffer
	code := cmdProvision([]string{"--config", cfgPath, "--dry-run", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("provision --dry-run exited %d: %s", code, stderr.String())
	}
	var out struct {
		Records map[string]provisionRecord `json:"records"`
		DryRun  bool                       `json:"dry_run"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("json output: %v\n%s", err, stdout.String())
	}
	rec, ok := out.Records["logs.read"]
	if !ok || rec.SHA256 == "" || rec.PolicyARN == "" {
		t.Fatalf("logs.read record missing: %+v", out.Records)
	}
	if rec.PolicyARN != "arn:aws:iam::222222222222:policy/taskgrant-logs-read" {
		t.Fatalf("policy arn = %q, want the catalog-pinned one", rec.PolicyARN)
	}
}

// fakeIAM is a minimal IAM Query API stand-in.
type fakeIAM struct {
	t            *testing.T
	existing     bool
	currentDoc   string
	created      int
	newVersions  int
	lastDocument string
}

func (f *fakeIAM) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		action := r.Form.Get("Action")
		switch action {
		case "CreatePolicy":
			if f.existing {
				w.WriteHeader(409)
				fmt.Fprint(w, `<ErrorResponse><Error><Code>EntityAlreadyExists</Code><Message>exists</Message></Error></ErrorResponse>`)
				return
			}
			f.created++
			f.lastDocument = r.Form.Get("PolicyDocument")
			fmt.Fprint(w, `<CreatePolicyResponse><CreatePolicyResult><Policy><Arn>arn:aws:iam::222222222222:policy/test</Arn></Policy></CreatePolicyResult></CreatePolicyResponse>`)
		case "GetPolicy":
			fmt.Fprint(w, `<GetPolicyResponse><GetPolicyResult><Policy><DefaultVersionId>v1</DefaultVersionId></Policy></GetPolicyResult></GetPolicyResponse>`)
		case "GetPolicyVersion":
			fmt.Fprintf(w, `<GetPolicyVersionResponse><GetPolicyVersionResult><PolicyVersion><Document>%s</Document></PolicyVersion></GetPolicyVersionResult></GetPolicyVersionResponse>`,
				strings.ReplaceAll(f.currentDoc, "&", "&amp;"))
		case "CreatePolicyVersion":
			f.newVersions++
			f.lastDocument = r.Form.Get("PolicyDocument")
			fmt.Fprint(w, `<CreatePolicyVersionResponse></CreatePolicyVersionResponse>`)
		default:
			f.t.Errorf("unexpected IAM action %q", action)
			w.WriteHeader(400)
		}
	})
}

func TestEnsureManagedPolicy(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	ctx := t.Context()

	t.Run("created", func(t *testing.T) {
		f := &fakeIAM{t: t}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		client, err := newIAMClient(srv.URL, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		arn, status, err := ensureManagedPolicy(ctx, client, "arn:x", "test", "/", "logs.read", `{"a":1}`)
		if err != nil || status != "created" || f.created != 1 {
			t.Fatalf("created path: %v %q created=%d", err, status, f.created)
		}
		if arn != "arn:aws:iam::222222222222:policy/test" {
			t.Fatalf("arn = %q, want the CreatePolicy answer", arn)
		}
	})

	t.Run("unchanged", func(t *testing.T) {
		f := &fakeIAM{t: t, existing: true, currentDoc: `{"a": 1}`}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		client, err := newIAMClient(srv.URL, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		_, status, err := ensureManagedPolicy(ctx, client, "arn:x", "test", "/", "logs.read", `{"a":1}`)
		if err != nil || status != "unchanged" || f.newVersions != 0 {
			t.Fatalf("unchanged path: %v %q versions=%d", err, status, f.newVersions)
		}
	})

	t.Run("updated", func(t *testing.T) {
		f := &fakeIAM{t: t, existing: true, currentDoc: `{"a":2}`}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		client, err := newIAMClient(srv.URL, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		_, status, err := ensureManagedPolicy(ctx, client, "arn:x", "test", "/", "logs.read", `{"a":1}`)
		if err != nil || status != "updated" || f.newVersions != 1 {
			t.Fatalf("updated path: %v %q versions=%d", err, status, f.newVersions)
		}
	})
}

func TestConfigTrustPolicy(t *testing.T) {
	cfgPath := writeTestConfig(t)
	var stdout, stderr bytes.Buffer
	code := cmdConfig([]string{"trust-policy", "--config", cfgPath,
		"--broker-arn", "arn:aws:iam::111111111111:role/my-broker", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("trust-policy exited %d: %s", code, stderr.String())
	}
	var out map[string]struct {
		RoleARN string `json:"role_arn"`
		Policy  struct {
			Version   string `json:"Version"`
			Statement []struct {
				Effect    string         `json:"Effect"`
				Principal map[string]any `json:"Principal"`
				Action    []string       `json:"Action"`
				Condition map[string]any `json:"Condition"`
			} `json:"Statement"`
		} `json:"trust_policy"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout.String())
	}
	entry, ok := out["s3-archiver"]
	if !ok {
		t.Fatalf("profile missing from output: %s", stdout.String())
	}
	st := entry.Policy.Statement[0]
	if st.Principal["AWS"] != "arn:aws:iam::111111111111:role/my-broker" {
		t.Fatalf("principal = %v", st.Principal)
	}
	if len(st.Action) != 3 || st.Action[1] != "sts:TagSession" || st.Action[2] != "sts:SetSourceIdentity" {
		t.Fatalf("actions = %v; TagSession and SetSourceIdentity are mandatory", st.Action)
	}
	sl, _ := st.Condition["StringLike"].(map[string]any)
	if sl["sts:SourceIdentity"] != "tg-*" {
		t.Fatalf("SourceIdentity condition missing: %v", st.Condition)
	}
	se, _ := st.Condition["StringEquals"].(map[string]any)
	if se["sts:ExternalId"] != "cross-acct-42" {
		t.Fatalf("cross-account profile lacks the sts:ExternalId condition: %v", st.Condition)
	}
}

func TestConfigBrokerPolicy(t *testing.T) {
	cfgPath := writeTestConfig(t)
	var stdout, stderr bytes.Buffer
	code := cmdConfig([]string{"broker-policy", "--config", cfgPath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("broker-policy exited %d: %s", code, stderr.String())
	}
	var doc brokerPolicyDoc
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout.String())
	}
	if len(doc.Statement) != 2 {
		t.Fatalf("want mint + revocation statements (revocation.enabled), got %d", len(doc.Statement))
	}
	mint := doc.Statement[0]
	if len(mint.Resource) != 1 || mint.Resource[0] != "arn:aws:iam::222222222222:role/taskgrant-s3-archiver" {
		t.Fatalf("mint statement not scoped to the configured roles: %v", mint.Resource)
	}
	if doc.Statement[1].Action[0] != "iam:PutRolePolicy" {
		t.Fatalf("revocation statement = %v", doc.Statement[1])
	}
}

func TestConfigValidateCommand(t *testing.T) {
	cfgPath := writeTestConfig(t)
	var stdout, stderr bytes.Buffer
	code := cmdConfig([]string{"validate", "--config", cfgPath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate exited %d: %s", code, stderr.String())
	}
	var out struct {
		Valid       bool   `json:"valid"`
		ConfigHash  string `json:"config_hash"`
		CatalogHash string `json:"catalog_hash"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !out.Valid || out.ConfigHash == "" || out.CatalogHash == "" {
		t.Fatalf("validate output incomplete: %+v", out)
	}
}

func TestAgentTokenIssue(t *testing.T) {
	cfgPath := writeTestConfig(t)
	var stdout, stderr bytes.Buffer
	code := cmdAgent([]string{"token", "issue", "new-bot", "--config", cfgPath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("token issue exited %d: %s", code, stderr.String())
	}
	var out struct {
		Token       string `json:"token"`
		TokenSHA256 string `json:"token_sha256"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !strings.HasPrefix(out.Token, "tgt_") || len(out.TokenSHA256) != 64 || len(out.Fingerprint) != 8 {
		t.Fatalf("token output malformed: %+v", out)
	}
}

func TestAgentTokenRotateUnknownAgentFails(t *testing.T) {
	cfgPath := writeTestConfig(t)
	var stdout, stderr bytes.Buffer
	if code := cmdAgent([]string{"token", "rotate", "ghost-bot", "--config", cfgPath}, &stdout, &stderr); code == 0 {
		t.Fatal("rotate accepted an unknown agent")
	}
}

func TestDatasetShowHash(t *testing.T) {
	cfgPath := writeTestConfig(t)
	var stdout, stderr bytes.Buffer
	code := cmdDataset([]string{"show-hash", "--config", cfgPath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show-hash exited %d: %s", code, stderr.String())
	}
	var out struct {
		Hash    string `json:"hash"`
		Actions int    `json:"actions"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(out.Hash) != 64 || out.Actions == 0 {
		t.Fatalf("show-hash output malformed: %+v", out)
	}
}

func TestDiffDatasets(t *testing.T) {
	dir := t.TempDir()
	current := `{"schema_version":1,"source_commit":"old","actions":{
	  "s3:GetObject":{"access_level":"Read","resource_types":["object"],"condition_keys":[]},
	  "s3:OldAction":{"access_level":"Read","resource_types":[],"condition_keys":[]}}}`
	currentPath := filepath.Join(dir, "dataset.json")
	if err := os.WriteFile(currentPath, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := dataset.LoadBytes([]byte(`{"schema_version":1,"source_commit":"new","actions":{
	  "s3:GetObject":{"access_level":"Write","resource_types":["object"],"condition_keys":[]},
	  "s3:NewAction":{"access_level":"Read","resource_types":[],"condition_keys":[]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Synth: config.SynthConfig{CatalogPath: filepath.Join(dir, "no-catalog")}}
	d := diffDatasets(cfg, currentPath, next)
	if !d.haveCurrent {
		t.Fatal("current artifact not loaded")
	}
	if len(d.added) != 1 || d.added[0] != "s3:NewAction" {
		t.Fatalf("added = %v", d.added)
	}
	if len(d.removed) != 1 || d.removed[0] != "s3:OldAction" {
		t.Fatalf("removed = %v", d.removed)
	}
	if len(d.levelChanges) != 1 || !strings.Contains(d.levelChanges[0], "Read -> Write") {
		t.Fatalf("levelChanges = %v", d.levelChanges)
	}
}
