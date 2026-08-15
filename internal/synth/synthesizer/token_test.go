package synthesizer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// signRawRetryToken signs arbitrary payload bytes with the production
// HMAC scheme, letting tests craft structurally hostile payloads.
func signRawRetryToken(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestRetryTokenRoundTrip(t *testing.T) {
	key := deriveTokenKey("cfg-hash")
	p := retryTokenPayload{GrantID: "01J0GRANT", AgentID: "invoice-bot", IntentHash: strings.Repeat("a", 64), Round: 1}
	token := signRetryToken(key, p)

	got, err := verifyRetryToken(key, token, "invoice-bot")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != p {
		t.Fatalf("payload = %+v, want %+v", got, p)
	}
}

func TestRetryTokenSurvivesRestart(t *testing.T) {
	// The key derives deterministically from the config hash, so a
	// token signed before a restart verifies after one.
	before := deriveTokenKey("cfg-hash")
	after := deriveTokenKey("cfg-hash")
	token := signRetryToken(before, retryTokenPayload{GrantID: "g", AgentID: "bot", IntentHash: "i", Round: 2})
	if _, err := verifyRetryToken(after, token, "bot"); err != nil {
		t.Fatalf("token must survive a restart with the same config: %v", err)
	}
	// A different config derives a different key.
	other := deriveTokenKey("other-config")
	if _, err := verifyRetryToken(other, token, "bot"); !errors.Is(err, ErrInvalidRetryToken) {
		t.Fatalf("a different config hash must reject the token, got %v", err)
	}
}

// TestRetryTokenAgentBinding is the token-layer regression for the
// cross-agent isolation hole: a valid token presented under a different
// agent identity must be rejected (section 4.1). Before the AgentID
// binding this returned the payload with no error.
func TestRetryTokenAgentBinding(t *testing.T) {
	key := deriveTokenKey("cfg-hash")
	token := signRetryToken(key, retryTokenPayload{GrantID: "g", AgentID: "agent-051", IntentHash: "i", Round: 1})

	if _, err := verifyRetryToken(key, token, "agent-051"); err != nil {
		t.Fatalf("issuing agent must verify its own token: %v", err)
	}
	if _, err := verifyRetryToken(key, token, "agent-201"); !errors.Is(err, ErrInvalidRetryToken) {
		t.Fatalf("another agent's presentation must be rejected, got %v", err)
	}
	// A legacy token carrying no agent binding is rejected outright.
	legacy := signRetryToken(key, retryTokenPayload{GrantID: "g", IntentHash: "i", Round: 1})
	if _, err := verifyRetryToken(key, legacy, "agent-051"); !errors.Is(err, ErrInvalidRetryToken) {
		t.Fatalf("an unbound token must be rejected, got %v", err)
	}
}

func TestRetryTokenRejections(t *testing.T) {
	key := deriveTokenKey("cfg-hash")
	valid := signRetryToken(key, retryTokenPayload{GrantID: "g", AgentID: "bot", IntentHash: "i", Round: 1})

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no separator", strings.ReplaceAll(valid, ".", "_")},
		{"tampered mac", valid[:len(valid)-2] + "zz"},
		{"tampered body", "AAAA" + valid},
		{"not base64", "!!!.!!!"},
		{"oversized", strings.Repeat("A", 2048) + "." + strings.Repeat("A", 43)},
		{"round zero", signRetryToken(key, retryTokenPayload{GrantID: "g", AgentID: "bot", Round: 0})},
		{"round beyond max", signRetryToken(key, retryTokenPayload{GrantID: "g", AgentID: "bot", Round: MaxClarificationRounds + 1})},
		{"empty grant", signRetryToken(key, retryTokenPayload{AgentID: "bot", Round: 1})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := verifyRetryToken(key, tt.token, "bot"); !errors.Is(err, ErrInvalidRetryToken) {
				t.Fatalf("err = %v, want ErrInvalidRetryToken", err)
			}
		})
	}
}

func TestRetryTokenUnknownFieldRejected(t *testing.T) {
	// A token whose payload smuggles extra fields fails strict
	// decoding even with a valid signature over those bytes.
	key := deriveTokenKey("cfg-hash")
	body := []byte(`{"g":"grant","a":"bot","i":"hash","r":1,"admin":true}`)
	token := signRawRetryToken(key, body)
	if _, err := verifyRetryToken(key, token, "bot"); !errors.Is(err, ErrInvalidRetryToken) {
		t.Fatalf("err = %v, want ErrInvalidRetryToken", err)
	}
}
