package dataset

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func loadFixture(t *testing.T) *Dataset {
	t.Helper()
	d, err := Load(filepath.Join("testdata", "iam-dataset.json"))
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return d
}

func TestLoadFixture(t *testing.T) {
	d := loadFixture(t)
	if d.SchemaVersion() != 1 {
		t.Errorf("schema version = %d", d.SchemaVersion())
	}
	if d.SourceCommit() == "" {
		t.Error("source commit empty")
	}
	if len(d.Hash()) != 64 {
		t.Errorf("hash length = %d", len(d.Hash()))
	}
	if d.Len() == 0 {
		t.Error("no actions loaded")
	}
	// The hash must be the hash of the raw bytes.
	raw, err := os.ReadFile(filepath.Join("testdata", "iam-dataset.json"))
	if err != nil {
		t.Fatal(err)
	}
	d2, err := LoadBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Hash() != d.Hash() {
		t.Error("Load and LoadBytes hash differently for the same bytes")
	}
}

func TestLookup(t *testing.T) {
	d := loadFixture(t)
	tests := []struct {
		action    string
		found     bool
		wantLevel AccessLevel
	}{
		{"s3:GetObject", true, AccessRead},
		{"s3:getobject", true, AccessRead}, // case-insensitive like IAM
		{"S3:GETOBJECT", true, AccessRead},
		{"s3:ListBucket", true, AccessList},
		{"s3:PutObject", true, AccessWrite},
		{"s3:PutBucketPolicy", true, AccessPermissionsManagement},
		{"iam:PassRole", true, AccessWrite},
		{"lambda:InvokeFunction", true, AccessWrite},
		{"s3:TeleportObject", false, ""},
		{"", false, ""},
	}
	for _, tt := range tests {
		info, ok := d.Lookup(tt.action)
		if ok != tt.found {
			t.Errorf("Lookup(%q) found = %v, want %v", tt.action, ok, tt.found)
			continue
		}
		if ok && info.AccessLevel != tt.wantLevel {
			t.Errorf("Lookup(%q) level = %q, want %q", tt.action, info.AccessLevel, tt.wantLevel)
		}
	}
	// Canonical name survives case-insensitive lookup.
	info, _ := d.Lookup("s3:getobject")
	if info.Action != "s3:GetObject" {
		t.Errorf("canonical name = %q", info.Action)
	}
}

func TestLookupReturnsCopies(t *testing.T) {
	d := loadFixture(t)
	a, _ := d.Lookup("s3:ListBucket")
	a.ConditionKeys[0] = "tampered"
	b, _ := d.Lookup("s3:ListBucket")
	if b.ConditionKeys[0] == "tampered" {
		t.Fatal("Lookup shares backing storage with the dataset")
	}
}

func TestExpand(t *testing.T) {
	d := loadFixture(t)
	tests := []struct {
		name    string
		pattern string
		want    []string
		wantErr error
	}{
		{
			"literal action",
			"s3:GetObject",
			[]string{"s3:GetObject"}, nil,
		},
		{
			"literal case-insensitive returns canonical",
			"s3:getobjectversion",
			[]string{"s3:GetObjectVersion"}, nil,
		},
		{
			"prefix wildcard",
			"s3:Get*",
			[]string{"s3:GetObject", "s3:GetObjectVersion"}, nil,
		},
		{
			"service wildcard spans escalation actions",
			"iam:*",
			[]string{
				"iam:AttachRolePolicy", "iam:CreateAccessKey", "iam:GetRole",
				"iam:ListRoles", "iam:PassRole", "iam:PutRolePolicy",
			}, nil,
		},
		{
			"question mark wildcard",
			"sqs:???Message",
			nil, ErrNoMatch, // Send has 4 letters before Message in SendMessage? No: Send is 4. Receive is 7. None are 3.
		},
		{
			"question marks matching",
			"sqs:????Message",
			[]string{"sqs:SendMessage"}, nil,
		},
		{
			"unknown literal fails closed",
			"s3:TeleportObject",
			nil, ErrUnknownAction,
		},
		{
			"unknown service wildcard fails closed",
			"quantum:*",
			nil, ErrNoMatch,
		},
		{
			"empty pattern fails",
			"",
			nil, nil, // any error accepted
		},
		{
			"hostile charset fails",
			"s3:Get*; DROP TABLE",
			nil, nil, // any error accepted
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Expand(tt.pattern)
			if tt.want != nil {
				if err != nil {
					t.Fatalf("Expand(%q) error: %v", tt.pattern, err)
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Fatalf("Expand(%q) = %v, want %v", tt.pattern, got, tt.want)
				}
				if !sort.StringsAreSorted(got) {
					t.Fatalf("Expand(%q) result not sorted: %v", tt.pattern, got)
				}
				return
			}
			if err == nil {
				t.Fatalf("Expand(%q) = %v, want error", tt.pattern, got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("Expand(%q) error = %v, want %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

func TestExpandAll(t *testing.T) {
	d := loadFixture(t)
	got, err := d.ExpandAll([]string{"s3:Get*", "s3:GetObject", "s3:ListBucket"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandAll = %v, want %v", got, want)
	}
	// One unknown pattern fails the whole call.
	if _, err := d.ExpandAll([]string{"s3:GetObject", "nope:Nope"}); err == nil {
		t.Fatal("ExpandAll accepted an unknown action")
	}
}

func TestSupportsConditionKey(t *testing.T) {
	d := loadFixture(t)
	tests := []struct {
		action string
		key    string
		want   bool
	}{
		{"s3:ListBucket", "s3:prefix", true},
		{"s3:ListBucket", "S3:PREFIX", true},
		{"s3:ListBucket", "s3:versionid", false},
		{"s3:GetObject", "aws:RequestedRegion", true},          // global key
		{"iam:GetRole", "aws:ResourceAccount", true},           // global key on trimmed list
		{"lambda:InvokeFunction", "aws:ResourceTag/env", true}, // templated ${TagKey}
		{"s3:GetObject", "s3:ExistingObjectTag/team", true},    // templated <key>
		{"s3:GetObject", "s3:ExistingObjectTag/", false},       // template needs a tail
		{"logs:GetLogEvents", "aws:ResourceTag/env", false},    // not supported by this action
		{"sts:AssumeRole", "aws:PrincipalTag/env", true},       // principal tags always available
		{"nope:Nope", "aws:RequestedRegion", false},            // unknown action fails closed
	}
	for _, tt := range tests {
		if got := d.SupportsConditionKey(tt.action, tt.key); got != tt.want {
			t.Errorf("SupportsConditionKey(%q, %q) = %v, want %v", tt.action, tt.key, got, tt.want)
		}
	}
}

func TestDenylist(t *testing.T) {
	required := []string{
		"iam:PassRole", "lambda:AddPermission", "kms:PutKeyPolicy",
		"s3:PutBucketPolicy", "sts:AssumeRole", "iam:CreateAccessKey",
		"iam:AttachRolePolicy", "iam:PutRolePolicy", "ec2:ModifyInstanceAttribute",
	}
	for _, a := range required {
		if !IsEscalationAction(a) {
			t.Errorf("required denylist entry missing: %s", a)
		}
		if !IsEscalationAction(strings.ToUpper(a)) {
			t.Errorf("denylist match not case-insensitive: %s", a)
		}
	}
	if IsEscalationAction("s3:GetObject") {
		t.Error("s3:GetObject wrongly denylisted")
	}
	list := EscalationDenylist()
	if !sort.StringsAreSorted(list) {
		t.Error("EscalationDenylist not sorted")
	}
	if len(list) < len(required) {
		t.Errorf("denylist too small: %d", len(list))
	}
	if DenylistVersion < 1 {
		t.Error("denylist version must start at 1")
	}
	// The mislabel defense: iam:PassRole is Write in the dataset but
	// still denylisted.
	d := loadFixture(t)
	info, ok := d.Lookup("iam:PassRole")
	if !ok || info.AccessLevel != AccessWrite {
		t.Fatalf("fixture should label iam:PassRole Write, got %v %v", ok, info.AccessLevel)
	}
	if !IsEscalationAction("iam:PassRole") {
		t.Fatal("iam:PassRole must stay denylisted regardless of its dataset label")
	}
}

func TestEscalationActionsIn(t *testing.T) {
	got := EscalationActionsIn([]string{
		"s3:GetObject", "IAM:PASSROLE", "iam:PassRole", "sts:AssumeRole",
	})
	want := []string{"iam:PassRole", "sts:AssumeRole"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EscalationActionsIn = %v, want %v", got, want)
	}
}

func TestLoadBytesRejectsBadArtifacts(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"not json", "hello"},
		{"wrong schema version", `{"schema_version": 2, "source_commit": "abc", "actions": {"s3:GetObject": {"access_level": "Read", "resource_types": [], "condition_keys": []}}}`},
		{"empty source commit", `{"schema_version": 1, "source_commit": "", "actions": {"s3:GetObject": {"access_level": "Read", "resource_types": [], "condition_keys": []}}}`},
		{"no actions", `{"schema_version": 1, "source_commit": "abc", "actions": {}}`},
		{"bad access level", `{"schema_version": 1, "source_commit": "abc", "actions": {"s3:GetObject": {"access_level": "Root", "resource_types": [], "condition_keys": []}}}`},
		{"action without service", `{"schema_version": 1, "source_commit": "abc", "actions": {"GetObject": {"access_level": "Read", "resource_types": [], "condition_keys": []}}}`},
		{"unknown field", `{"schema_version": 1, "source_commit": "abc", "surprise": true, "actions": {"s3:GetObject": {"access_level": "Read", "resource_types": [], "condition_keys": []}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(tt.data)); err == nil {
				t.Fatal("bad artifact accepted")
			}
		})
	}
}

func TestRootFixtureCopyStaysInSync(t *testing.T) {
	local, err := os.ReadFile(filepath.Join("testdata", "iam-dataset.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join("..", "..", "testdata", "iam-dataset.json"))
	if err != nil {
		t.Fatalf("root testdata copy missing: %v", err)
	}
	dl, err := LoadBytes(local)
	if err != nil {
		t.Fatal(err)
	}
	dr, err := LoadBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	if dl.Hash() != dr.Hash() {
		t.Fatal("internal/dataset/testdata and repo testdata fixtures differ")
	}
}
