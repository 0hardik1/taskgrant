package domain

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// SourceIdentityPrefix is the fixed prefix of every broker-authored
// SourceIdentity (section 8.4).
const SourceIdentityPrefix = "tg-"

// MaxRoleSessionNameChars is the ceiling taskgrant applies to
// RoleSessionName (section 8.2). STS allows 64; taskgrant stays at 62
// for margin.
const MaxRoleSessionNameChars = 62

// AgentIDPattern is the config-validated agent id slug (section 4.3).
// It guarantees the id fits the RoleSessionName charset, session tag
// value limits, and log columns.
const AgentIDPattern = `^[a-z0-9][a-z0-9_-]{1,31}$`

var agentIDRE = regexp.MustCompile(AgentIDPattern)

// ValidateAgentID returns nil when id matches AgentIDPattern.
func ValidateAgentID(id string) error {
	if !agentIDRE.MatchString(id) {
		return fmt.Errorf("agent id %q does not match %s", id, AgentIDPattern)
	}
	return nil
}

// Grant is the core grant record shared across packages. One grant is
// identified by one ULID minted at request receipt; the ULID never
// changes across clarification rounds, approvals, or retries.
type Grant struct {
	GrantID        string    // 26-char ULID string, the correlation identity
	AgentID        string    // validated slug
	Profile        string    // profile name the grant runs under
	State          State     // current state machine node
	IdempotencyKey string    // agent-supplied; repeated key replays this grant
	ReceivedAt     time.Time // request receipt (ULID mint time)
	DecidedAt      time.Time // decision (auto_approved, denied, ...) time
	MintedAt       time.Time // STS mint time; zero unless minted
	ExpiresAt      time.Time // credential expiry; zero unless minted
}

// SetState validates the transition from the grant's current state and
// applies it. It returns a *TransitionError when the edge is illegal.
func (g *Grant) SetState(next State) error {
	if err := ValidateTransition(g.State, next); err != nil {
		return err
	}
	g.State = next
	return nil
}

// SourceIdentity returns the grant's broker-authored SourceIdentity.
func (g *Grant) SourceIdentity() string { return SourceIdentity(g.GrantID) }

// grant id entropy: monotonic within one millisecond, seeded from
// crypto/rand, guarded by a mutex for concurrent use.
var (
	grantIDMu      sync.Mutex
	grantIDEntropy = ulid.Monotonic(rand.Reader, 0)
)

// NewGrantID mints a new grant ULID and returns its canonical 26-char
// string form. Safe for concurrent use.
func NewGrantID() string {
	grantIDMu.Lock()
	defer grantIDMu.Unlock()
	for {
		id, err := ulid.New(ulid.Timestamp(time.Now().UTC()), grantIDEntropy)
		if err == nil {
			return id.String()
		}
		if errors.Is(err, ulid.ErrMonotonicOverflow) {
			// Practically unreachable; wait for the next millisecond.
			time.Sleep(time.Millisecond)
			continue
		}
		// crypto/rand does not fail on supported platforms.
		panic(fmt.Sprintf("domain: grant id entropy failure: %v", err))
	}
}

// ParseGrantID validates a grant id string strictly (canonical 26-char
// ULID form) and returns the parsed ULID. Use it on every
// agent-supplied grant_id before any lookup.
func ParseGrantID(s string) (ulid.ULID, error) {
	id, err := ulid.ParseStrict(s)
	if err != nil {
		return ulid.ULID{}, fmt.Errorf("invalid grant id: %w", err)
	}
	return id, nil
}

// SourceIdentity returns "tg-" + grantID, the broker-authored session
// SourceIdentity and the primary CloudTrail join key (section 8.4).
func SourceIdentity(grantID string) string {
	return SourceIdentityPrefix + grantID
}

// GrantIDFromSourceIdentity inverts SourceIdentity. It returns an error
// when the value does not carry the taskgrant prefix or a valid ULID.
func GrantIDFromSourceIdentity(sourceIdentity string) (string, error) {
	rest, ok := strings.CutPrefix(sourceIdentity, SourceIdentityPrefix)
	if !ok {
		return "", fmt.Errorf("source identity %q lacks prefix %q", sourceIdentity, SourceIdentityPrefix)
	}
	if _, err := ParseGrantID(rest); err != nil {
		return "", err
	}
	return rest, nil
}

// RoleSessionName builds "tg-<agentID>-<grantID>" and keeps the result
// at or under MaxRoleSessionNameChars. When the name would run long the
// agent id portion is truncated; the grant ULID is never touched, so
// the correlation identity always survives whole. Characters outside
// the STS session name charset are replaced with "-" defensively; a
// validated agent id never needs it.
func RoleSessionName(agentID, grantID string) string {
	agent := sanitizeSessionNameComponent(agentID)
	if agent == "" {
		agent = "a"
	}
	// "tg-" + agent + "-" + grantID
	budget := MaxRoleSessionNameChars - len(SourceIdentityPrefix) - 1 - len(grantID)
	if budget < 1 {
		budget = 1
	}
	if len(agent) > budget {
		agent = agent[:budget]
	}
	return SourceIdentityPrefix + agent + "-" + grantID
}

// sanitizeSessionNameComponent maps a string onto the RoleSessionName
// charset [A-Za-z0-9_+=,.@-]. Any other byte becomes "-".
func sanitizeSessionNameComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '_' || c == '+' || c == '=' || c == ',' || c == '.' || c == '@' || c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
