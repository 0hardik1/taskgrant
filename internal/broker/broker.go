// Package broker is the grant state machine and orchestration core of
// taskgrant (architecture sections 2 and 5.4). Every credential request
// becomes a grant identified by one ULID minted at receipt. The broker
// drives the pipeline: synthesize through the synth seam, re-verify the
// returned policy with the guardrail evaluator (the broker never trusts
// the seam, anchor rule 2), park approvals durably, mint through
// stsmint at approval or auto-approve time (never at request time,
// anchor rule 1), and append every decision to the tamper-evident log.
//
// Credentials appear exactly once: the broker hands the plaintext to
// the transport a single time and the decision log stores only the
// access key id (invariant I4).
package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/0hardik1/taskgrant/internal/approvals"
	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/guardrails"
	"github.com/0hardik1/taskgrant/internal/mcpserver"
	"github.com/0hardik1/taskgrant/internal/revoke"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/stsmint"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
	"github.com/0hardik1/taskgrant/internal/synth/synthesizer"
)

// Tunables.
const (
	// PolicyBudgetChars is the synthesizer size budget: the 2,048 char
	// STS plaintext limit minus the session tag headroom margin
	// (section 7.1).
	PolicyBudgetChars = guardrails.DefaultMaxPolicyChars
	// IdempotencyWindow is how long a repeated idempotency key replays
	// the existing grant instead of minting again.
	IdempotencyWindow = time.Hour
	// entryRetention keeps terminal grants in memory for fast get_grant
	// answers before the store fallback takes over.
	entryRetention = time.Hour
	// maxEntries bounds the in-memory grant registry.
	maxEntries = 4096
	// defaultPollAfterSeconds is the poll hint on pending answers.
	defaultPollAfterSeconds = 5
	// mintWaitCeiling bounds how long an approval waiter waits for the
	// approve-time mint to finish after the decision lands.
	mintWaitCeiling = 30 * time.Second
)

// DecisionLog is the persistence surface the broker needs from the
// store. *store.Store satisfies it.
type DecisionLog interface {
	Append(ctx context.Context, rec *store.Record) error
	GrantChain(ctx context.Context, grantID string) ([]store.Record, error)
	PutIdempotencyKey(ctx context.Context, agent, key, grantID string, now, expiresAt time.Time) (string, bool, error)
	DeleteExpiredIdempotencyKeys(ctx context.Context, now time.Time) (int64, error)
	TakeToken(ctx context.Context, agent, capability string, ratePerHour, burst float64, now time.Time) (bool, error)
	DistinctCapabilities24h(ctx context.Context, agent string, now time.Time) (int, error)
	RecordCapabilityUse(ctx context.Context, agent, capability string, now time.Time) error
	FirstUseSeen(ctx context.Context, agent, capability string) (seen, approved bool, err error)
	MarkFirstUse(ctx context.Context, agent, capability string, now time.Time, approved bool) error
}

var _ DecisionLog = (*store.Store)(nil)

// ApprovalQueue is the durable approval surface. *approvals.Manager
// satisfies it.
type ApprovalQueue interface {
	Submit(ctx context.Context, p store.PendingApproval) (store.PendingApproval, error)
	Get(ctx context.Context, grantID string) (store.PendingApproval, error)
	List(ctx context.Context, status store.PendingStatus) ([]store.PendingApproval, error)
	WaitDecision(ctx context.Context, grantID string) (approvals.Decision, error)
	Approve(ctx context.Context, grantID string, by approvals.Identity, note string) (approvals.Decision, error)
	Deny(ctx context.Context, grantID string, by approvals.Identity, note string) (approvals.Decision, error)
	SweepOnce(ctx context.Context) (int, error)
	TTL() time.Duration
}

var _ ApprovalQueue = (*approvals.Manager)(nil)

// Minter performs the STS mint. *stsmint.Minter satisfies it.
type Minter interface {
	MintWithCompact(ctx context.Context, req stsmint.MintRequest, compact stsmint.CompactFunc) (*stsmint.Minted, error)
}

var _ Minter = (*stsmint.Minter)(nil)

// GuardrailEvaluator is the authoritative policy verifier.
// *guardrails.Evaluator satisfies it.
type GuardrailEvaluator interface {
	Evaluate(ctx context.Context, in guardrails.Input) guardrails.Result
}

var _ GuardrailEvaluator = (*guardrails.Evaluator)(nil)

// Catalog provides the current snapshot and per-agent views.
// *catalog.Store satisfies it.
type Catalog interface {
	Current() *catalog.Snapshot
	SnapshotForAgent(agentID string) *catalog.Snapshot
}

var _ Catalog = (*catalog.Store)(nil)

// GrantRevoker writes best-effort deny statements (section 8.5).
// *revoke.Revoker satisfies it. Nil when revocation is disabled.
type GrantRevoker interface {
	RevokeRole(ctx context.Context, roleName string) (revoke.Result, error)
	RevokeGrant(ctx context.Context, roleName, grantID string, grantExpiry time.Time) (revoke.Result, error)
	GC(ctx context.Context, roleName string) (revoke.Result, error)
}

var _ GrantRevoker = (*revoke.Revoker)(nil)

// MetricsRecorder receives operational counters. *adminapi.Metrics
// satisfies it. Nil disables recording.
type MetricsRecorder interface {
	IncGrantOutcome(outcome string)
	ObservePackedPolicySize(percent int)
	ObserveApprovalLatency(d time.Duration)
}

// TracedSynthesizer is the optional richer seam the concrete
// synthesizer implements; the broker type-asserts for the decision
// record's matcher trace.
type TracedSynthesizer interface {
	SynthesizeTraced(ctx context.Context, req synth.Request) (synth.Result, synthesizer.Trace, error)
}

// Deps are the injected collaborators of the broker.
type Deps struct {
	Config    *config.Config
	Synth     synth.Synthesizer
	Evaluator GuardrailEvaluator
	Approvals ApprovalQueue
	Minter    Minter
	Log       DecisionLog
	Catalog   Catalog
	Dataset   *dataset.Dataset
	Revoker   GrantRevoker    // optional
	Metrics   MetricsRecorder // optional
	// Chained is true when the broker itself runs on session
	// credentials; G7 then clamps every grant to 3600 s.
	Chained bool
	// Clock overrides time.Now for tests.
	Clock  func() time.Time
	Logger *slog.Logger
}

// Broker is the grant state machine. Safe for concurrent use.
type Broker struct {
	cfg        *config.Config
	cfgHash    string
	synth      synth.Synthesizer
	evaluator  GuardrailEvaluator
	approvals  ApprovalQueue
	minter     Minter
	log        DecisionLog
	catalog    Catalog
	ds         *dataset.Dataset
	revoker    GrantRevoker
	metrics    MetricsRecorder
	chained    bool
	clock      func() time.Time
	logger     *slog.Logger
	redelivery bool

	mu     sync.Mutex
	grants map[string]*grantEntry
}

// grantEntry is the in-memory record of one live grant. The plaintext
// credential Delivery lives only here, until it is handed to the
// transport exactly once (or until expiry when redelivery is on).
type grantEntry struct {
	grant             domain.Grant
	req               mcpserver.GrantRequest
	result            synth.Result
	budgetChars       int
	trace             *synthesizer.Trace
	guard             *guardrails.Result
	effectiveSeconds  int
	requiredBy        string
	denial            domain.DenialCode
	detail            string
	errorCode         string
	minted            *stsmint.Minted
	delivery          *stsmint.Delivery
	delivered         bool
	mintDone          chan struct{}
	released          bool
	releaseOutcome    string
	releasedAt        time.Time
	revocationWritten bool
	terminalAt        time.Time
}

// New validates dependencies and builds a Broker.
func New(deps Deps) (*Broker, error) {
	var missing []string
	if deps.Config == nil {
		missing = append(missing, "Config")
	}
	if deps.Synth == nil {
		missing = append(missing, "Synth")
	}
	if deps.Evaluator == nil {
		missing = append(missing, "Evaluator")
	}
	if deps.Approvals == nil {
		missing = append(missing, "Approvals")
	}
	if deps.Minter == nil {
		missing = append(missing, "Minter")
	}
	if deps.Log == nil {
		missing = append(missing, "Log")
	}
	if deps.Catalog == nil {
		missing = append(missing, "Catalog")
	}
	if deps.Dataset == nil {
		missing = append(missing, "Dataset")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("broker: missing required dependencies: %v", missing)
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &Broker{
		cfg:        deps.Config,
		cfgHash:    deps.Config.ConfigHash(),
		synth:      deps.Synth,
		evaluator:  deps.Evaluator,
		approvals:  deps.Approvals,
		minter:     deps.Minter,
		log:        deps.Log,
		catalog:    deps.Catalog,
		ds:         deps.Dataset,
		revoker:    deps.Revoker,
		metrics:    deps.Metrics,
		chained:    deps.Chained,
		clock:      deps.Clock,
		logger:     deps.Logger,
		redelivery: deps.Config.Server.CredentialRedelivery,
		grants:     make(map[string]*grantEntry),
	}, nil
}

// Ready implements the adminapi readiness seam.
func (b *Broker) Ready(context.Context) error { return nil }

// now returns the broker clock in UTC.
func (b *Broker) now() time.Time { return b.clock().UTC() }

// incOutcome records a grant outcome metric when metrics are wired.
func (b *Broker) incOutcome(outcome string) {
	if b.metrics != nil {
		b.metrics.IncGrantOutcome(outcome)
	}
}

// entry returns the in-memory entry for grantID.
func (b *Broker) entry(grantID string) (*grantEntry, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.grants[grantID]
	return e, ok
}

// putEntry inserts an entry, evicting old terminal entries beyond the
// registry bound.
func (b *Broker) putEntry(e *grantEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.grants) >= maxEntries {
		b.evictLocked()
	}
	b.grants[e.grant.GrantID] = e
}

// evictLocked drops the oldest terminal entries. Caller holds b.mu.
func (b *Broker) evictLocked() {
	var oldestID string
	var oldest time.Time
	for id, e := range b.grants {
		if e.terminalAt.IsZero() {
			continue
		}
		if oldestID == "" || e.terminalAt.Before(oldest) {
			oldestID, oldest = id, e.terminalAt
		}
	}
	if oldestID != "" {
		delete(b.grants, oldestID)
	}
}

// markTerminal stamps the entry's terminal time once. Caller holds b.mu.
func (e *grantEntry) markTerminal(now time.Time) {
	if e.terminalAt.IsZero() {
		e.terminalAt = now
	}
}

// budget returns the policy budget the entry's current policy was
// rendered under: the default, or the tighter Compact budget.
func (e *grantEntry) budget() int {
	if e.budgetChars > 0 {
		return e.budgetChars
	}
	return PolicyBudgetChars
}

// setState applies a state transition, logging illegal edges instead of
// corrupting state. Caller holds b.mu.
func (b *Broker) setStateLocked(e *grantEntry, next domain.State) {
	if err := e.grant.SetState(next); err != nil {
		b.logger.Error("broker: illegal grant state transition",
			"grant_id", e.grant.GrantID, "from", string(e.grant.State), "to", string(next), "err", err)
	}
}

// resolveProfile validates the agent and resolves the effective
// profile. It returns a denial code when the pair is not permitted.
func (b *Broker) resolveProfile(agentID, requested string) (string, config.ProfileConfig, domain.DenialCode, string) {
	agent, ok := b.cfg.Agents[agentID]
	if !ok {
		return "", config.ProfileConfig{}, domain.DenyAgentNotPermitted,
			"agent is not configured on this broker"
	}
	name := requested
	if name == "" {
		name = agent.DefaultProfile
	}
	if name == "" {
		return "", config.ProfileConfig{}, domain.DenyProfileNotAllowed,
			"no profile requested and the agent has no default profile"
	}
	if !agent.HasProfile(name) {
		return "", config.ProfileConfig{}, domain.DenyProfileNotAllowed,
			"profile is not on the agent's allowlist"
	}
	p, ok := b.cfg.Profiles[name]
	if !ok {
		return "", config.ProfileConfig{}, domain.DenyProfileNotAllowed,
			"profile is not configured"
	}
	return name, p, "", ""
}

// combinedPolicyARNs merges the profile static ceiling ARNs with the
// synthesizer offload ARNs, deduplicated, order preserved.
func combinedPolicyARNs(static, offload []string) []string {
	seen := make(map[string]struct{}, len(static)+len(offload))
	out := make([]string, 0, len(static)+len(offload))
	for _, arn := range append(append([]string(nil), static...), offload...) {
		if arn == "" {
			continue
		}
		if _, dup := seen[arn]; dup {
			continue
		}
		seen[arn] = struct{}{}
		out = append(out, arn)
	}
	return out
}

// errNotFoundFor maps any broker-internal miss onto the mcpserver
// sentinel so cross-agent existence is never confirmed.
var errNotFound = mcpserver.ErrNotFound

// isStoreNotFound reports a store-level miss.
func isStoreNotFound(err error) bool {
	return errors.Is(err, store.ErrNotFound)
}
