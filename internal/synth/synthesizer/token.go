package synthesizer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MaxClarificationRounds bounds the clarification loop (section 5.6):
// after two rounds the grant denies CLARIFICATION_EXHAUSTED.
const MaxClarificationRounds = 2

// ErrInvalidRetryToken is returned when a presented retry token fails
// signature verification, belongs to a different grant, or carries an
// out-of-range round. Retry tokens are agent-presented bytes; a bad
// one is a protocol violation, surfaced as a sanitized error by the
// broker, never as a policy outcome.
var ErrInvalidRetryToken = errors.New("synthesizer: invalid retry token")

// retryTokenPayload is the signed, self-contained clarification state:
// grant ULID, the agent the token was issued to, the intent hash of the
// round that issued it, and the round counter. Self-containment is what
// lets tokens survive broker restarts (section 5.6). The AgentID binding
// keeps a retry token usable only by its issuing agent, so it can never
// resolve another agent's grant (section 4.1, trust model section 3).
type retryTokenPayload struct {
	GrantID    string `json:"g"`
	AgentID    string `json:"a"`
	IntentHash string `json:"i"`
	Round      int    `json:"r"`
}

// deriveTokenKey derives a stable HMAC key from the config hash when
// no explicit key is configured. Stability across restarts is the
// requirement; the config hash covers secrets (token hashes) and is
// not agent-observable.
func deriveTokenKey(configHash string) []byte {
	sum := sha256.Sum256([]byte("taskgrant/retry-token/v1|" + configHash))
	return sum[:]
}

// signRetryToken renders base64url(payload) + "." + base64url(HMAC).
func signRetryToken(key []byte, p retryTokenPayload) string {
	body, err := json.Marshal(p)
	if err != nil {
		// retryTokenPayload holds only JSON-serializable fields.
		panic(fmt.Sprintf("synthesizer: retry token serialization failed: %v", err))
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyRetryToken parses and authenticates an agent-presented token.
// The HMAC comparison is constant time. expectedAgentID is the verified
// identity of the caller presenting the token; the token's own AgentID
// must equal it, so one agent's token can never drive another agent's
// grant (section 4.1).
func verifyRetryToken(key []byte, token, expectedAgentID string) (retryTokenPayload, error) {
	var p retryTokenPayload
	// Length cap at the boundary: a well-formed token is small.
	if len(token) > 1024 {
		return p, ErrInvalidRetryToken
	}
	body64, mac64, ok := strings.Cut(token, ".")
	if !ok {
		return p, ErrInvalidRetryToken
	}
	body, err := base64.RawURLEncoding.DecodeString(body64)
	if err != nil {
		return p, ErrInvalidRetryToken
	}
	presented, err := base64.RawURLEncoding.DecodeString(mac64)
	if err != nil {
		return p, ErrInvalidRetryToken
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	if !hmac.Equal(presented, mac.Sum(nil)) {
		return p, ErrInvalidRetryToken
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, ErrInvalidRetryToken
	}
	if p.GrantID == "" || p.Round < 1 || p.Round > MaxClarificationRounds {
		return p, ErrInvalidRetryToken
	}
	// Agent binding (section 4.1): a token is valid only for the agent it
	// was issued to. A mismatch (or a legacy token with no agent) is a
	// protocol violation, not a policy outcome.
	if p.AgentID == "" || p.AgentID != expectedAgentID {
		return p, ErrInvalidRetryToken
	}
	return p, nil
}
