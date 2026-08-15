// Package identity maps presented credentials to agent identities: the
// AgentRegistry built from config, static bearer token verification
// (v1), and token generation for the CLI. The v2 OIDC verifier swaps in
// behind the same registry without touching the MCP layer.
package identity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/domain"
)

// maxPresentedTokenLen caps the bytes accepted from the wire before any
// hashing. Presented tokens are untrusted input.
const maxPresentedTokenLen = 1024

// FingerprintLen is the length of a token fingerprint: the first 8 hex
// characters of the token's SHA-256 (section 9.1).
const FingerprintLen = 8

// Verification errors. The MCP layer decides how much of this reaches
// the wire; internally the two cases stay distinct for logging.
var (
	ErrInvalidToken = errors.New("identity: token does not match any agent")
	ErrExpiredToken = errors.New("identity: token expired")
)

// ValidateAgentID reports whether id is a valid agent slug. It is the
// domain rule re-exported where identity callers expect it.
func ValidateAgentID(id string) error { return domain.ValidateAgentID(id) }

// TokenInfo is the verified identity behind a presented token. The MCP
// layer copies AgentID into the SDK's TokenInfo.UserID so the session
// binds to the agent (anti-hijack), and the decision log records the
// fingerprint.
type TokenInfo struct {
	AgentID     string
	Fingerprint string
	ExpiresAt   time.Time
}

// Agent is one registered agent with its profile allowlist.
type Agent struct {
	ID             string
	Profiles       []string
	DefaultProfile string
	TokenExpires   time.Time

	tokenHash []byte // 32 bytes when a token is configured, else nil
}

// HasToken reports whether the agent has a bearer token configured.
func (a *Agent) HasToken() bool { return len(a.tokenHash) == 32 }

// AllowsProfile reports whether the agent's allowlist contains name.
func (a *Agent) AllowsProfile(name string) bool {
	for _, p := range a.Profiles {
		if p == name {
			return true
		}
	}
	return false
}

// Registry resolves agent ids and verifies bearer tokens. It is
// immutable after construction and safe for concurrent use.
type Registry struct {
	agents map[string]*Agent
}

// NewRegistry builds the registry from validated config. It re-checks
// the security-relevant rules instead of assuming the config was
// validated (fail closed): agent id slugs, token hash shape, and the
// mandatory expiry on every configured token.
func NewRegistry(cfg *config.Config) (*Registry, error) {
	if cfg == nil {
		return nil, errors.New("identity: nil config")
	}
	r := &Registry{agents: make(map[string]*Agent, len(cfg.Agents))}
	for id, ac := range cfg.Agents {
		if err := domain.ValidateAgentID(id); err != nil {
			return nil, fmt.Errorf("identity: %w", err)
		}
		agent := &Agent{
			ID:             id,
			Profiles:       append([]string(nil), ac.Profiles...),
			DefaultProfile: ac.DefaultProfile,
			TokenExpires:   ac.TokenExpires,
		}
		if ac.TokenSHA256 != "" {
			hash, err := hex.DecodeString(ac.TokenSHA256)
			if err != nil || len(hash) != sha256.Size {
				return nil, fmt.Errorf("identity: agent %q: token_sha256 is not a 64-char hex SHA-256", id)
			}
			if ac.TokenExpires.IsZero() {
				return nil, fmt.Errorf("identity: agent %q: token_expires is mandatory when a token is configured", id)
			}
			agent.tokenHash = hash
		}
		r.agents[id] = agent
	}
	return r, nil
}

// Agent returns the registered agent for id.
func (r *Registry) Agent(id string) (*Agent, bool) {
	a, ok := r.agents[id]
	return a, ok
}

// AgentIDs returns every registered agent id, sorted.
func (r *Registry) AgentIDs() []string {
	ids := make([]string, 0, len(r.agents))
	for id := range r.agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// VerifyToken verifies a presented bearer token against the registry
// at the current time.
func (r *Registry) VerifyToken(presented string) (TokenInfo, error) {
	return r.VerifyTokenAt(presented, time.Now())
}

// VerifyTokenAt verifies a presented bearer token at a given instant.
// The presented token is hashed with SHA-256 and compared against every
// stored hash in constant time, with no early exit on match. Expiry is
// checked unconditionally: a matching token past its expiry never
// authenticates.
func (r *Registry) VerifyTokenAt(presented string, now time.Time) (TokenInfo, error) {
	if presented == "" || len(presented) > maxPresentedTokenLen {
		return TokenInfo{}, ErrInvalidToken
	}
	sum := sha256.Sum256([]byte(presented))

	var matched *Agent
	for _, agent := range r.agents {
		if !agent.HasToken() {
			continue
		}
		if subtle.ConstantTimeCompare(sum[:], agent.tokenHash) == 1 {
			matched = agent
			// No break: every stored hash is compared on every call so
			// timing does not reveal which agent matched.
		}
	}
	if matched == nil {
		return TokenInfo{}, ErrInvalidToken
	}
	if matched.TokenExpires.IsZero() || !now.Before(matched.TokenExpires) {
		return TokenInfo{}, ErrExpiredToken
	}
	return TokenInfo{
		AgentID:     matched.ID,
		Fingerprint: hex.EncodeToString(sum[:])[:FingerprintLen],
		ExpiresAt:   matched.TokenExpires,
	}, nil
}
