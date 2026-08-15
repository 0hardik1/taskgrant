package config

import (
	"strings"
	"testing"
	"time"
)

// validYAML is a complete config that passes validation.
const validYAML = `
version: 1

server:
  transport: http
  listen: 127.0.0.1:8443
  admin_socket: /var/run/taskgrant/admin.sock
  max_wait_seconds: 60

aws:
  sts_region: us-east-1
  default_duration_seconds: 900
  max_duration_seconds: 3600
  accounts: ["222222222222"]
  endpoint_url: http://localhost:4566

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

synth:
  catalog_path: /etc/taskgrant/capabilities/
  dataset_path: /var/lib/taskgrant/iam-dataset.json

guardrails:
  access_levels: [Read, List]
  extra_deny_services: []
  first_use_approval: true

approvals:
  pending_ttl_seconds: 900
  rules:
    - match: {access_level: Write}
      action: require_approval

revocation:
  enabled: false

log:
  path: /var/lib/taskgrant/decisions.db
  anchor: {type: s3-object-lock, bucket: acme-taskgrant-anchor, interval: 1h}
`

func mustLoad(t *testing.T, yamlText string) *Config {
	t.Helper()
	cfg, err := Load([]byte(yamlText))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	return cfg
}

func TestLoadValidConfig(t *testing.T) {
	cfg := mustLoad(t, validYAML)
	if cfg.Server.Transport != TransportHTTP {
		t.Errorf("transport = %q", cfg.Server.Transport)
	}
	if cfg.AWS.EndpointURL != "http://localhost:4566" {
		t.Errorf("endpoint_url = %q", cfg.AWS.EndpointURL)
	}
	agent := cfg.Agents["invoice-bot"]
	if agent.DefaultProfile != "s3-archiver" {
		t.Errorf("single profile did not become default: %q", agent.DefaultProfile)
	}
	if agent.TokenSHA256 != strings.ToLower(agent.TokenSHA256) {
		t.Errorf("token hash not normalized: %q", agent.TokenSHA256)
	}
	if cfg.Log.Anchor.Interval.Std() != time.Hour {
		t.Errorf("anchor interval = %v", cfg.Log.Anchor.Interval.Std())
	}
	if !cfg.Guardrails.FirstUseApproval {
		t.Error("first_use_approval lost")
	}
	if cfg.EffectiveMaxDurationSeconds("s3-archiver") != 1800 {
		t.Errorf("effective max = %d", cfg.EffectiveMaxDurationSeconds("s3-archiver"))
	}
	if cfg.EffectiveMaxDurationSeconds("missing") != 3600 {
		t.Errorf("fallback max = %d", cfg.EffectiveMaxDurationSeconds("missing"))
	}
}

func TestFirstUseApprovalDefaultsTrue(t *testing.T) {
	yamlText := strings.Replace(validYAML, "  first_use_approval: true\n", "", 1)
	cfg := mustLoad(t, yamlText)
	if !cfg.Guardrails.FirstUseApproval {
		t.Error("first_use_approval should default to true")
	}
	yamlText = strings.Replace(validYAML, "first_use_approval: true", "first_use_approval: false", 1)
	cfg = mustLoad(t, yamlText)
	if cfg.Guardrails.FirstUseApproval {
		t.Error("explicit false was overridden")
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	yamlText := validYAML + "\nsurprise_field: 1\n"
	if _, err := Load([]byte(yamlText)); err == nil {
		t.Fatal("unknown top-level field accepted")
	}
	yamlText = strings.Replace(validYAML, "sts_region: us-east-1",
		"sts_region: us-east-1\n  extra_thing: yes", 1)
	if _, err := Load([]byte(yamlText)); err == nil {
		t.Fatal("unknown nested field accepted")
	}
}

func TestEnvInterpolation(t *testing.T) {
	t.Setenv("TG_TEST_EXTID", "shared-secret-42")
	yamlText := strings.Replace(validYAML, "\n    region: us-east-1\n",
		"\n    region: us-east-1\n    external_id: ${TG_TEST_EXTID}\n", 1)
	cfg := mustLoad(t, yamlText)
	if cfg.Profiles["s3-archiver"].ExternalID != "shared-secret-42" {
		t.Errorf("external_id = %q", cfg.Profiles["s3-archiver"].ExternalID)
	}
}

func TestEnvInterpolationMissingVarFails(t *testing.T) {
	yamlText := strings.Replace(validYAML, "\n    region: us-east-1\n",
		"\n    region: us-east-1\n    external_id: ${TG_DEFINITELY_UNSET_VAR}\n", 1)
	_, err := Load([]byte(yamlText))
	if err == nil || !strings.Contains(err.Error(), "TG_DEFINITELY_UNSET_VAR") {
		t.Fatalf("want missing-variable error, got %v", err)
	}
}

func TestValidationFailures(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			"bad version",
			func(s string) string { return strings.Replace(s, "version: 1", "version: 2", 1) },
			"version must be 1",
		},
		{
			"bad transport",
			func(s string) string { return strings.Replace(s, "transport: http", "transport: grpc", 1) },
			"transport",
		},
		{
			"stdio without default agent",
			func(s string) string { return strings.Replace(s, "transport: http", "transport: stdio", 1) },
			"default_agent",
		},
		{
			"http without listen",
			func(s string) string { return strings.Replace(s, "  listen: 127.0.0.1:8443\n", "", 1) },
			"server.listen",
		},
		{
			"duration under floor",
			func(s string) string {
				return strings.Replace(s, "default_duration_seconds: 900", "default_duration_seconds: 300", 1)
			},
			"default_duration_seconds",
		},
		{
			"duration over cap",
			func(s string) string {
				return strings.Replace(s, "max_duration_seconds: 3600\n  accounts", "max_duration_seconds: 7200\n  accounts", 1)
			},
			"max_duration_seconds",
		},
		{
			"profile cap over global",
			func(s string) string {
				return strings.Replace(s, "max_duration_seconds: 1800", "max_duration_seconds: 3601", 1)
			},
			"max_duration_seconds",
		},
		{
			"bad agent slug",
			func(s string) string { return strings.Replace(s, "invoice-bot:", "Invoice-Bot:", 1) },
			"agent",
		},
		{
			"bad token hex",
			func(s string) string {
				return strings.Replace(s,
					"9F8A000000000000000000000000000000000000000000000000000000000000", "zz-not-hex", 1)
			},
			"token_sha256",
		},
		{
			"missing token expiry",
			func(s string) string {
				return strings.Replace(s, "    token_expires: 2026-08-15T00:00:00Z\n", "", 1)
			},
			"token_expires",
		},
		{
			"http agent without token",
			func(s string) string {
				return strings.Replace(s,
					"    token_sha256: \"9F8A000000000000000000000000000000000000000000000000000000000000\"\n    token_expires: 2026-08-15T00:00:00Z\n", "", 1)
			},
			"token_sha256",
		},
		{
			"unresolved profile reference",
			func(s string) string { return strings.Replace(s, "profiles: [s3-archiver]", "profiles: [ghost]", 1) },
			"does not exist",
		},
		{
			"bad role arn",
			func(s string) string {
				return strings.Replace(s, "arn:aws:iam::222222222222:role/taskgrant-s3-archiver", "not-an-arn", 1)
			},
			"role_arn",
		},
		{
			"bad account id",
			func(s string) string { return strings.Replace(s, `["222222222222"]`, `["1234"]`, 1) },
			"12-digit",
		},
		{
			"permissions management level",
			func(s string) string {
				return strings.Replace(s, "access_levels: [Read, List]", "access_levels: [Read, \"Permissions management\"]", 1)
			},
			"access_levels",
		},
		{
			"bad approval action",
			func(s string) string { return strings.Replace(s, "action: require_approval", "action: shrug", 1) },
			"action",
		},
		{
			"bad anchor type",
			func(s string) string { return strings.Replace(s, "type: s3-object-lock", "type: carrier-pigeon", 1) },
			"anchor",
		},
		{
			"anchor without bucket",
			func(s string) string {
				return strings.Replace(s, "anchor: {type: s3-object-lock, bucket: acme-taskgrant-anchor, interval: 1h}",
					"anchor: {type: s3-object-lock, interval: 1h}", 1)
			},
			"bucket",
		},
		{
			"missing log path",
			func(s string) string { return strings.Replace(s, "  path: /var/lib/taskgrant/decisions.db\n", "", 1) },
			"log.path",
		},
		{
			"missing dataset path",
			func(s string) string {
				return strings.Replace(s, "  dataset_path: /var/lib/taskgrant/iam-dataset.json\n", "", 1)
			},
			"dataset_path",
		},
		{
			"bad endpoint url",
			func(s string) string {
				return strings.Replace(s, "endpoint_url: http://localhost:4566", "endpoint_url: ftp;//broken", 1)
			},
			"endpoint_url",
		},
		{
			"default profile not in list",
			func(s string) string {
				return strings.Replace(s, "profiles: [s3-archiver]", "profiles: [s3-archiver]\n    default_profile: other", 1)
			},
			"default_profile",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load([]byte(tt.mutate(validYAML)))
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not mention %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestAllowLongSessions(t *testing.T) {
	yamlText := strings.Replace(validYAML, "max_duration_seconds: 3600\n  accounts",
		"max_duration_seconds: 7200\n  allow_long_sessions: true\n  accounts", 1)
	cfg := mustLoad(t, yamlText)
	if cfg.AWS.MaxDurationSeconds != 7200 {
		t.Fatalf("max duration = %d", cfg.AWS.MaxDurationSeconds)
	}
}

func TestConfigHashStableAndSensitive(t *testing.T) {
	a := mustLoad(t, validYAML)
	b := mustLoad(t, validYAML)
	if a.ConfigHash() != b.ConfigHash() {
		t.Fatal("equal configs hash differently")
	}
	if len(a.ConfigHash()) != 64 {
		t.Fatalf("hash length = %d", len(a.ConfigHash()))
	}
	changed := mustLoad(t, strings.Replace(validYAML, "pending_ttl_seconds: 900", "pending_ttl_seconds: 600", 1))
	if a.ConfigHash() == changed.ConfigHash() {
		t.Fatal("changed config hashes identically")
	}
}

func TestDurationForms(t *testing.T) {
	yamlText := strings.Replace(validYAML, "interval: 1h", "interval: 900", 1)
	cfg := mustLoad(t, yamlText)
	if cfg.Log.Anchor.Interval.Std() != 900*time.Second {
		t.Fatalf("integer seconds interval = %v", cfg.Log.Anchor.Interval.Std())
	}
	yamlText = strings.Replace(validYAML, "interval: 1h", "interval: 90m", 1)
	cfg = mustLoad(t, yamlText)
	if cfg.Log.Anchor.Interval.Std() != 90*time.Minute {
		t.Fatalf("duration string interval = %v", cfg.Log.Anchor.Interval.Std())
	}
	yamlText = strings.Replace(validYAML, "interval: 1h", "interval: soon", 1)
	if _, err := Load([]byte(yamlText)); err == nil {
		t.Fatal("bad duration accepted")
	}
}

func TestEmptyConfigFails(t *testing.T) {
	if _, err := Load(nil); err == nil {
		t.Fatal("empty config accepted")
	}
}

func TestSortedEnumerations(t *testing.T) {
	cfg := mustLoad(t, validYAML)
	if got := cfg.AgentIDs(); len(got) != 1 || got[0] != "invoice-bot" {
		t.Fatalf("AgentIDs = %v", got)
	}
	if got := cfg.ProfileNames(); len(got) != 1 || got[0] != "s3-archiver" {
		t.Fatalf("ProfileNames = %v", got)
	}
	if cfg.ProfileRegion("s3-archiver") != "us-east-1" {
		t.Fatalf("ProfileRegion = %q", cfg.ProfileRegion("s3-archiver"))
	}
}
