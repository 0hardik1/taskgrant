package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// TokenPrefix marks taskgrant bearer tokens so secret scanners can
// recognize them.
const TokenPrefix = "tgt_"

// tokenEntropyBytes is the random payload size of a generated token.
const tokenEntropyBytes = 32

// GeneratedToken is the one-time output of GenerateToken. Plaintext is
// shown exactly once by the CLI and never stored; only SHA256Hex goes
// into config.
type GeneratedToken struct {
	// Plaintext is the bearer token to hand to the agent, once.
	Plaintext string
	// SHA256Hex is the value for the agent's token_sha256 config field.
	SHA256Hex string
	// Fingerprint is the first 8 hex characters of SHA256Hex, the form
	// the decision log records.
	Fingerprint string
}

// GenerateToken mints a new bearer token from crypto/rand for the
// `taskgrant agent token issue|rotate` commands.
func GenerateToken() (GeneratedToken, error) {
	buf := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return GeneratedToken{}, fmt.Errorf("identity: token entropy: %w", err)
	}
	plaintext := TokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	hash := HashToken(plaintext)
	return GeneratedToken{
		Plaintext:   plaintext,
		SHA256Hex:   hash,
		Fingerprint: Fingerprint(hash),
	}, nil
}

// HashToken returns the lowercase SHA-256 hex of a plaintext token,
// the form stored in config.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// Fingerprint returns the first 8 characters of a token's SHA-256 hex.
// It accepts the full hash; shorter inputs return themselves.
func Fingerprint(sha256Hex string) string {
	if len(sha256Hex) <= FingerprintLen {
		return sha256Hex
	}
	return sha256Hex[:FingerprintLen]
}
