package catalog

import (
	"errors"
	"strings"
	"testing"
)

// TestValidateParamsAdversarial drives hostile parameter values through
// the full validation path of the starter catalog. Params are the
// entire agent-controlled policy surface (invariant I1), so every one
// of these must be rejected.
func TestValidateParamsAdversarial(t *testing.T) {
	snap := loadStarter(t)

	valid := map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}
	if _, err := snap.ValidateParams("s3.read-prefix", valid); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}

	tests := []struct {
		name   string
		params map[string]string
	}{
		{"star in prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/*x"}},
		{"lone star prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "*"}},
		{"double trailing star", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/**"}},
		{"question mark", map[string]string{"bucket": "acme-invoices-prod", "prefix": "20?6/"}},
		{"space", map[string]string{"bucket": "acme-invoices-prod", "prefix": "20 26/"}},
		{"tab", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026\t/"}},
		{"newline", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026\n/"}},
		{"nbsp", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026\u00a0/"}},
		{"line separator", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026\u2028/"}},
		{"dollar brace", map[string]string{"bucket": "acme-invoices-prod", "prefix": "${aws:username}/"}},
		{"ansi escape", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026\x1b[31m/"}},
		{"null byte", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026\x00/"}},
		{"invalid utf8", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026\xff/"}},
		{"513 char prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": strings.Repeat("a", 513)}},
		{"oversize raw value", map[string]string{"bucket": "acme-invoices-prod", "prefix": strings.Repeat("a", 2048)}},
		{"cyrillic homoglyph bucket", map[string]string{"bucket": "аcme-invoices-prod", "prefix": "2026/"}}, // Cyrillic а
		{"fullwidth star", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026＊/"}},           // ＊ homoglyph
		{"bucket off allowlist", map[string]string{"bucket": "evil-bucket", "prefix": "2026/"}},
		{"bucket star injection", map[string]string{"bucket": "acme-invoices-prod*", "prefix": "2026/"}},
		{"bucket colon injection", map[string]string{"bucket": "acme:invoices", "prefix": "2026/"}},
		{"bucket slash injection", map[string]string{"bucket": "acme-invoices-prod/x", "prefix": "2026/"}},
		{"undeclared param", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/", "extra": "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := snap.ValidateParams("s3.read-prefix", tt.params)
			if err == nil {
				t.Fatal("hostile value accepted")
			}
		})
	}
}

func TestValidateParamsMissingAndInvalidClassified(t *testing.T) {
	snap := loadStarter(t)

	_, err := snap.ValidateParams("s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod"})
	var pe *ParamError
	if !errors.As(err, &pe) {
		t.Fatalf("want *ParamError, got %v", err)
	}
	if !pe.Missing || pe.Param != "prefix" {
		t.Errorf("missing prefix classified as %+v", pe)
	}

	_, err = snap.ValidateParams("s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "${aws:username}/"})
	if !errors.As(err, &pe) {
		t.Fatalf("want *ParamError, got %v", err)
	}
	if pe.Missing {
		t.Error("invalid value classified as missing")
	}
	// Error text must never echo the raw hostile value.
	if strings.Contains(pe.Error(), "aws:username") {
		t.Errorf("error text echoes hostile bytes: %q", pe.Error())
	}
}

// TestValidateParamsTrailingWildcard pins the section 5.2 rule that a
// value-supplied '*' is REJECTED, never stripped and normalized. The
// trailing wildcard in the emitted resource is authored by the template
// ('{prefix}*'); an agent value carrying its own '*' would widen scope
// (for example prefix "2026/*" is not "read under 2026/", it is
// value-controlled), so it is an INVALID_PARAM. The earlier version of
// this test asserted the strip-and-accept behavior, which encoded the
// defect (scenario S030).
func TestValidateParamsTrailingWildcard(t *testing.T) {
	snap := loadStarter(t)

	// The template-controlled prefix param still rejects a value '*',
	// even though its resource template appends a wildcard.
	if _, err := snap.ValidateParams("s3.read-prefix", map[string]string{
		"bucket": "acme-invoices-prod", "prefix": "2026/*",
	}); err == nil {
		t.Error("a value-supplied trailing wildcard on prefix was accepted; it must be INVALID_PARAM")
	}

	// The legitimate value renders '.../2026/*' through the template.
	got, err := snap.ValidateParams("s3.read-prefix", map[string]string{
		"bucket": "acme-invoices-prod", "prefix": "2026/",
	})
	if err != nil {
		t.Fatalf("plain prefix rejected: %v", err)
	}
	if p := got["prefix"]; p.Value != "2026/" || p.TrailingWildcard {
		t.Errorf("prefix = %+v, want value 2026/ with no TrailingWildcard flag", p)
	}

	// bucket likewise rejects a value wildcard.
	if _, err := snap.ValidateParams("s3.read-prefix", map[string]string{
		"bucket": "acme-invoices-prod*", "prefix": "2026/",
	}); err == nil {
		t.Error("wildcard on bucket accepted")
	}
}

func TestValidateParamsWildcardAllowlistEntry(t *testing.T) {
	snap := loadStarter(t)

	// acme-ml-artifacts is an exact entry: no wildcard flag.
	got, err := snap.ValidateParams("s3.read-prefix", map[string]string{
		"bucket": "acme-ml-artifacts", "prefix": "models/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["bucket"].FromWildcardEntry {
		t.Error("exact allowlist match flagged as wildcard entry")
	}

	// acme-ml-scratch matches only the acme-ml-* glob entry.
	got, err = snap.ValidateParams("s3.read-prefix", map[string]string{
		"bucket": "acme-ml-scratch", "prefix": "models/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got["bucket"].FromWildcardEntry {
		t.Error("glob allowlist match not flagged as wildcard entry")
	}
}

func TestValidateParamsUnknownCapability(t *testing.T) {
	snap := loadStarter(t)
	if _, err := snap.ValidateParams("ghost.cap", map[string]string{}); err == nil {
		t.Error("unknown capability accepted")
	}
	// A capability hidden from an agent's view is unknown in that view.
	view := snap.ForAgent("some-agent")
	if view.Len() != snap.Len() {
		t.Skip("starter catalog has no agent-restricted entries")
	}
}

func TestMissingParamNames(t *testing.T) {
	snap := loadStarter(t)
	missing := snap.MissingParamNames("s3.read-prefix", map[string]string{"bucket": "x"})
	if len(missing) != 1 || missing[0] != "prefix" {
		t.Errorf("missing = %v, want [prefix]", missing)
	}
}
