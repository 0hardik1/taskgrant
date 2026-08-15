package identity

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
)

func testConfig(t *testing.T, tokenHash string, expires time.Time) *config.Config {
	t.Helper()
	return &config.Config{
		Agents: map[string]config.AgentConfig{
			"invoice-bot": {
				TokenSHA256:    tokenHash,
				TokenExpires:   expires,
				Profiles:       []string{"s3-archiver"},
				DefaultProfile: "s3-archiver",
			},
		},
		Profiles: map[string]config.ProfileConfig{
			"s3-archiver": {RoleARN: "arn:aws:iam::222222222222:role/taskgrant-s3-archiver"},
		},
	}
}

func TestGenerateAndVerifyToken(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Plaintext, TokenPrefix) {
		t.Errorf("plaintext lacks prefix: %q", tok.Plaintext)
	}
	if len(tok.SHA256Hex) != 64 {
		t.Errorf("hash length = %d", len(tok.SHA256Hex))
	}
	if tok.Fingerprint != tok.SHA256Hex[:8] {
		t.Errorf("fingerprint = %q", tok.Fingerprint)
	}
	if HashToken(tok.Plaintext) != tok.SHA256Hex {
		t.Error("HashToken disagrees with GenerateToken")
	}

	expires := time.Now().Add(24 * time.Hour)
	reg, err := NewRegistry(testConfig(t, tok.SHA256Hex, expires))
	if err != nil {
		t.Fatal(err)
	}
	info, err := reg.VerifyToken(tok.Plaintext)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if info.AgentID != "invoice-bot" {
		t.Errorf("agent id = %q", info.AgentID)
	}
	if info.Fingerprint != tok.Fingerprint {
		t.Errorf("fingerprint = %q, want %q", info.Fingerprint, tok.Fingerprint)
	}
	if !info.ExpiresAt.Equal(expires) {
		t.Errorf("expiry = %v", info.ExpiresAt)
	}
}

func TestVerifyTokenRejections(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	reg, err := NewRegistry(testConfig(t, tok.SHA256Hex, future))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		token   string
		at      time.Time
		wantErr error
	}{
		{"wrong token", "tgt_wrong", time.Now(), ErrInvalidToken},
		{"empty token", "", time.Now(), ErrInvalidToken},
		{"oversized token", strings.Repeat("a", 5000), time.Now(), ErrInvalidToken},
		{"hash presented instead of token", tok.SHA256Hex, time.Now(), ErrInvalidToken},
		{"expired token", tok.Plaintext, future.Add(time.Second), ErrExpiredToken},
		{"expiry instant is expired", tok.Plaintext, future, ErrExpiredToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := reg.VerifyTokenAt(tt.token, tt.at)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}

	// Still valid one second before expiry.
	if _, err := reg.VerifyTokenAt(tok.Plaintext, future.Add(-time.Second)); err != nil {
		t.Fatalf("token rejected before expiry: %v", err)
	}
}

func TestNewRegistryRejectsBadConfig(t *testing.T) {
	tok, _ := GenerateToken()
	future := time.Now().Add(time.Hour)

	tests := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{
			"bad agent slug",
			func(c *config.Config) {
				c.Agents["Bad-Agent"] = c.Agents["invoice-bot"]
			},
		},
		{
			"token without expiry",
			func(c *config.Config) {
				a := c.Agents["invoice-bot"]
				a.TokenExpires = time.Time{}
				c.Agents["invoice-bot"] = a
			},
		},
		{
			"malformed token hash",
			func(c *config.Config) {
				a := c.Agents["invoice-bot"]
				a.TokenSHA256 = "zz"
				c.Agents["invoice-bot"] = a
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t, tok.SHA256Hex, future)
			tt.mutate(cfg)
			if _, err := NewRegistry(cfg); err == nil {
				t.Fatal("bad config accepted")
			}
		})
	}
	if _, err := NewRegistry(nil); err == nil {
		t.Fatal("nil config accepted")
	}
}

func TestRegistryLookups(t *testing.T) {
	tok, _ := GenerateToken()
	reg, err := NewRegistry(testConfig(t, tok.SHA256Hex, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	agent, ok := reg.Agent("invoice-bot")
	if !ok {
		t.Fatal("agent missing")
	}
	if !agent.AllowsProfile("s3-archiver") {
		t.Error("profile allowlist broken")
	}
	if agent.AllowsProfile("other") {
		t.Error("profile allowlist too permissive")
	}
	if agent.DefaultProfile != "s3-archiver" {
		t.Errorf("default profile = %q", agent.DefaultProfile)
	}
	if !agent.HasToken() {
		t.Error("HasToken = false")
	}
	if _, ok := reg.Agent("ghost"); ok {
		t.Error("ghost agent found")
	}
	if ids := reg.AgentIDs(); len(ids) != 1 || ids[0] != "invoice-bot" {
		t.Errorf("AgentIDs = %v", ids)
	}
}

func TestAgentWithoutTokenNeverAuthenticates(t *testing.T) {
	cfg := testConfig(t, "", time.Time{})
	reg, err := NewRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.VerifyToken("anything"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidToken)
	}
}

func TestFingerprintHelper(t *testing.T) {
	if got := Fingerprint("abcdef0123456789"); got != "abcdef01" {
		t.Errorf("Fingerprint = %q", got)
	}
	if got := Fingerprint("abc"); got != "abc" {
		t.Errorf("short Fingerprint = %q", got)
	}
}

func TestGeneratedTokensAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.Plaintext] {
			t.Fatal("duplicate token generated")
		}
		seen[tok.Plaintext] = true
	}
}
