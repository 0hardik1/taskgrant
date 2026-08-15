package catalog

import (
	"strings"
	"testing"
)

// baseAllowlists is a minimal valid allowlists file for invariant
// tests.
const baseAllowlists = `
allowlists:
  b: [acme-invoices-prod]
resource_patterns:
  - arn:aws:s3:::acme-invoices-prod
  - arn:aws:s3:::acme-invoices-prod/*
`

// baseCapability is a minimal valid capability; each test case rewrites
// one aspect of it to violate exactly one load-time invariant.
const baseCapability = `
id: t.cap
version: 1
summary: test capability
actions: [s3:GetObject, s3:ListBucket]
access_ceiling: List
params:
  bucket: {type: arn_component, allowlist_ref: b}
  prefix: {type: path_prefix, pattern: '^[A-Za-z0-9_/.=-]{1,512}$', allow_trailing_wildcard: true}
resources:
  - {template: 'arn:aws:s3:::{bucket}', for_actions: [s3:ListBucket]}
  - {template: 'arn:aws:s3:::{bucket}/{prefix}*', for_actions: [s3:GetObject]}
conditions:
  - {for_actions: [s3:ListBucket], key: s3:prefix, op: StringLike, value: '{prefix}*'}
max_duration_seconds: 900
`

func TestLoadBaseCapabilityIsValid(t *testing.T) {
	ds := loadTestDataset(t)
	dir := t.TempDir()
	writeFile(t, dir, "allowlists.yaml", baseAllowlists)
	writeFile(t, dir, "cap.yaml", baseCapability)
	if _, err := Load(dir, ds, WithoutGitCommit()); err != nil {
		t.Fatalf("base capability should load: %v", err)
	}
}

func TestLoadInvariantViolations(t *testing.T) {
	tests := []struct {
		name       string
		capability string // replaces baseCapability when set
		allowlists string // replaces baseAllowlists when set
		wantSubstr string
	}{
		{
			name:       "action not in dataset",
			capability: strings.Replace(baseCapability, "actions: [s3:GetObject, s3:ListBucket]", "actions: [s3:FrobObject, s3:ListBucket]", 1),
			wantSubstr: "does not exist in the pinned dataset",
		},
		{
			name:       "wildcard action",
			capability: strings.Replace(baseCapability, "actions: [s3:GetObject, s3:ListBucket]", "actions: ['s3:Get*', s3:ListBucket]", 1),
			wantSubstr: "wildcard",
		},
		{
			name:       "action above access ceiling",
			capability: strings.Replace(baseCapability, "actions: [s3:GetObject, s3:ListBucket]", "actions: [s3:PutObject, s3:GetObject, s3:ListBucket]", 1),
			wantSubstr: "above the ceiling",
		},
		{
			name:       "ceiling permissions management",
			capability: strings.Replace(baseCapability, "access_ceiling: List", "access_ceiling: Permissions management", 1),
			wantSubstr: "never grantable",
		},
		{
			name:       "denied service",
			capability: strings.Replace(baseCapability, "actions: [s3:GetObject, s3:ListBucket]", "actions: [iam:GetRole, s3:GetObject, s3:ListBucket]", 1),
			wantSubstr: "denied service",
		},
		{
			name: "escalation denylist action",
			capability: strings.Replace(
				strings.Replace(baseCapability, "actions: [s3:GetObject, s3:ListBucket]", "actions: [lambda:AddPermission, s3:GetObject, s3:ListBucket]", 1),
				"access_ceiling: List", "access_ceiling: Tagging", 1),
			wantSubstr: "escalation denylist",
		},
		{
			name:       "undeclared param in resource template",
			capability: strings.Replace(baseCapability, "arn:aws:s3:::{bucket}/{prefix}*", "arn:aws:s3:::{bucket}/{mystery}*", 1),
			wantSubstr: "undeclared param {mystery}",
		},
		{
			name: "declared param never used",
			capability: strings.Replace(baseCapability,
				"params:", "params:\n  orphan: {type: identifier, pattern: '^[a-z]{1,8}$'}", 1),
			wantSubstr: "used in no resource or condition template",
		},
		{
			name:       "unanchored pattern",
			capability: strings.Replace(baseCapability, "pattern: '^[A-Za-z0-9_/.=-]{1,512}$'", "pattern: '[A-Za-z0-9_/.=-]{1,512}'", 1),
			wantSubstr: "anchored",
		},
		{
			name:       "grammar accepts star",
			capability: strings.Replace(baseCapability, "pattern: '^[A-Za-z0-9_/.=-]{1,512}$'", "pattern: '^[A-Za-z0-9*_/.=-]{1,512}$'", 1),
			wantSubstr: "forbidden probe",
		},
		{
			name:       "grammar accepts question mark",
			capability: strings.Replace(baseCapability, "pattern: '^[A-Za-z0-9_/.=-]{1,512}$'", "pattern: '^[A-Za-z0-9?_/.=-]{1,512}$'", 1),
			wantSubstr: "forbidden probe",
		},
		{
			name:       "grammar accepts whitespace",
			capability: strings.Replace(baseCapability, "pattern: '^[A-Za-z0-9_/.=-]{1,512}$'", "pattern: '^[A-Za-z0-9 _/.=-]{1,512}$'", 1),
			wantSubstr: "forbidden probe",
		},
		{
			name:       "grammar accepts dollar brace",
			capability: strings.Replace(baseCapability, "pattern: '^[A-Za-z0-9_/.=-]{1,512}$'", `pattern: '^[A-Za-z0-9${}_/.=-]{1,512}$'`, 1),
			wantSubstr: "forbidden probe",
		},
		{
			name:       "param with neither pattern nor allowlist",
			capability: strings.Replace(baseCapability, "bucket: {type: arn_component, allowlist_ref: b}", "bucket: {type: arn_component}", 1),
			wantSubstr: "anchored pattern or an allowlist_ref",
		},
		{
			name:       "unknown allowlist ref",
			capability: strings.Replace(baseCapability, "allowlist_ref: b}", "allowlist_ref: ghost}", 1),
			wantSubstr: `allowlist_ref "ghost" is not defined`,
		},
		{
			name: "worst-case render off allowlist",
			allowlists: strings.Replace(baseAllowlists,
				"b: [acme-invoices-prod]", "b: [acme-invoices-prod, rogue-bucket]", 1),
			wantSubstr: "matches no admin resource pattern",
		},
		{
			name: "condition key unsupported by action",
			capability: strings.Replace(baseCapability,
				"key: s3:prefix", "key: dynamodb:LeadingKeys", 1),
			wantSubstr: "not supported by action",
		},
		{
			name:       "condition op outside the closed set",
			capability: strings.Replace(baseCapability, "op: StringLike", "op: StringNotEquals", 1),
			wantSubstr: "not allowed",
		},
		{
			name:       "condition key with placeholder",
			capability: strings.Replace(baseCapability, "key: s3:prefix", "key: 's3:{prefix}'", 1),
			wantSubstr: "not a fixed condition key",
		},
		{
			name:       "duration below floor",
			capability: strings.Replace(baseCapability, "max_duration_seconds: 900", "max_duration_seconds: 899", 1),
			wantSubstr: "must be within 900..3600",
		},
		{
			name:       "duration above cap",
			capability: strings.Replace(baseCapability, "max_duration_seconds: 900", "max_duration_seconds: 3601", 1),
			wantSubstr: "must be within 900..3600",
		},
		{
			name: "action covered by no resource template",
			capability: strings.Replace(baseCapability,
				"actions: [s3:GetObject, s3:ListBucket]",
				"actions: [s3:GetObject, s3:GetObjectVersion, s3:ListBucket]", 1),
			wantSubstr: "covered by no resource template",
		},
		{
			name:       "managed policy without arn",
			capability: baseCapability + "\nmanaged_policy: true\n",
			wantSubstr: "managed_policy_arn",
		},
		{
			name:       "managed policy arn without flag",
			capability: baseCapability + "\nmanaged_policy_arn: arn:aws:iam::222222222222:policy/x\n",
			wantSubstr: "managed_policy is false",
		},
		{
			name:       "invalid agent slug",
			capability: baseCapability + "\nagents: ['Bad Agent!']\n",
			wantSubstr: "agents",
		},
		{
			name:       "version below one",
			capability: strings.Replace(baseCapability, "version: 1", "version: 0", 1),
			wantSubstr: "version",
		},
		{
			name:       "empty summary",
			capability: strings.Replace(baseCapability, "summary: test capability", "summary: ''", 1),
			wantSubstr: "summary",
		},
		{
			name:       "unknown yaml field rejected",
			capability: baseCapability + "\nsurprise_field: 1\n",
			wantSubstr: "parse",
		},
		{
			name:       "extra denied service via option",
			capability: baseCapability, // s3 denied below via option
			wantSubstr: "denied service",
		},
	}

	ds := loadTestDataset(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			al := baseAllowlists
			if tt.allowlists != "" {
				al = tt.allowlists
			}
			c := baseCapability
			if tt.capability != "" {
				c = tt.capability
			}
			writeFile(t, dir, "allowlists.yaml", al)
			writeFile(t, dir, "cap.yaml", c)
			opts := []Option{WithoutGitCommit()}
			if tt.name == "extra denied service via option" {
				opts = append(opts, WithExtraDeniedServices("s3"))
			}
			_, err := Load(dir, ds, opts...)
			if err == nil {
				t.Fatalf("load succeeded, want error containing %q", tt.wantSubstr)
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSubstr)
			}
			// Errors must name the offending file.
			if !strings.Contains(err.Error(), ".yaml") {
				t.Errorf("error %q does not name a file", err.Error())
			}
		})
	}
}

func TestLoadDuplicateCapabilityID(t *testing.T) {
	ds := loadTestDataset(t)
	dir := t.TempDir()
	writeFile(t, dir, "allowlists.yaml", baseAllowlists)
	writeFile(t, dir, "a.yaml", baseCapability)
	writeFile(t, dir, "b.yaml", baseCapability)
	_, err := Load(dir, ds, WithoutGitCommit())
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("want duplicate id error, got %v", err)
	}
}

func TestLoadEmptyDir(t *testing.T) {
	ds := loadTestDataset(t)
	dir := t.TempDir()
	if _, err := Load(dir, ds, WithoutGitCommit()); err == nil {
		t.Fatal("empty catalog dir must refuse to load")
	}
}

func TestLoadDurationDefaultsTo900(t *testing.T) {
	ds := loadTestDataset(t)
	dir := t.TempDir()
	writeFile(t, dir, "allowlists.yaml", baseAllowlists)
	writeFile(t, dir, "cap.yaml", strings.Replace(baseCapability, "max_duration_seconds: 900\n", "", 1))
	snap, err := Load(dir, ds, WithoutGitCommit())
	if err != nil {
		t.Fatal(err)
	}
	c, _ := snap.Capability("t.cap")
	if c.MaxDurationSeconds != 900 {
		t.Errorf("default duration = %d, want 900", c.MaxDurationSeconds)
	}
}
