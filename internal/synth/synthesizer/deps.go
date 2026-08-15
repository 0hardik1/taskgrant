package synthesizer

import (
	"context"
	"sync"
	"time"

	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/match"
)

// This file holds the consumer-side interfaces the synthesizer needs
// from sibling packages developed in parallel (synth/catalog,
// synth/compile, guardrails, store). The integration step adapts the
// concrete types; the synthesizer never imports them directly.

// Catalog provides agent-filtered snapshots of the capability catalog.
// The concrete type lives in synth/catalog.
type Catalog interface {
	// SnapshotFor returns the immutable capability view visible to
	// the agent. Its Hash is the catalog snapshot hash.
	SnapshotFor(agentID string) match.Snapshot
}

// SelectedCapability is one capability selection handed to the
// compiler: id, pinned version, and validated params only. Task text
// never appears here (invariant I1).
type SelectedCapability struct {
	ID      string
	Version int
	Params  map[string]string
}

// CompileOptions select reduction-ladder behavior (section 7.3).
// Minification and identical-statement merging always happen.
type CompileOptions struct {
	// DropSids removes optional Sids (ladder step 3); the explanation
	// maps statements by index.
	DropSids bool
	// OffloadManaged moves managed_policy:true capabilities out of
	// the inline policy onto PolicyArns (ladder step 4).
	OffloadManaged bool
}

// CompileInput is one deterministic compilation request. Identical
// inputs must produce byte-identical output (invariant I6).
type CompileInput struct {
	Capabilities []SelectedCapability
	MaxChars     int
	Options      CompileOptions
}

// CompileResult is one compiled policy. PolicyJSON is minified and
// canonically ordered.
type CompileResult struct {
	PolicyJSON      []byte
	PolicyArns      []string
	Explanation     synth.Explanation
	ExpandedActions []string
	// PerCapabilityChars attributes minified policy bytes to each
	// capability id, for OVER_BUDGET attribution (ladder step 5).
	PerCapabilityChars map[string]int
}

// Compiler renders capability selections into policy documents. The
// concrete type lives in synth/compile.
type Compiler interface {
	Compile(ctx context.Context, in CompileInput) (CompileResult, error)
}

// Guardrail verdict results.
const (
	GuardrailPass = "pass"
	GuardrailWarn = "warn"
	GuardrailFail = "fail"
)

// GuardrailVerdict is one named check outcome. Every check is
// recorded, passes included (section 9.1).
type GuardrailVerdict struct {
	Check  string
	Result string
	Detail string
}

// GuardrailMeta is the request context the evaluator sees. It carries
// no task text: the guardrail evaluator never reads agent prose
// (section 12.1).
type GuardrailMeta struct {
	AgentID         string
	Profile         synth.ProfileInfo
	Capabilities    []synth.CapabilityRef
	ExpandedActions []string
}

// GuardrailEvaluator is the consumer-side seam to the shared
// IAM-semantics evaluator (section 6). The synthesizer runs it at
// compile time and fails closed on hard failures; the broker's own
// run on the returned policy stays authoritative.
type GuardrailEvaluator interface {
	Evaluate(ctx context.Context, policyJSON []byte, meta GuardrailMeta) ([]GuardrailVerdict, error)
}

// ParamError is one grammar or allowlist violation. Reason and
// ExpectedShape must be admin-authored template text; implementations
// must not echo raw agent bytes (renders are sanitized regardless).
type ParamError struct {
	Capability    string
	Name          string
	Reason        string
	ExpectedShape string
	Examples      []string
}

// ParamValidator validates one capability's params against its
// declared grammars and allowlists. The concrete type lives in
// synth/catalog. ALL params pass through it regardless of origin
// (extracted or hinted).
type ParamValidator interface {
	ValidateParams(capabilityID string, params map[string]string) []ParamError
}

// CacheKey identifies one decision cache entry. It includes the agent
// and profile because snapshots are agent-filtered, and the budget
// because output bytes depend on it.
type CacheKey struct {
	AgentID        string
	Profile        string
	IntentHash     string
	CatalogHash    string
	DatasetHash    string
	ConfigHash     string
	MaxPolicyChars int
}

// CachedDecision is one replayable prior result: only successful
// compilations are cached. Approval requirements are re-derived on
// every hit, never replayed.
type CachedDecision struct {
	PolicyJSON        []byte
	PolicyArns        []string
	EffectiveDuration time.Duration
	Explanation       synth.Explanation
	Capabilities      []synth.CapabilityRef
	ExpandedActions   []string
}

// DecisionCache is the decision cache seam (pipeline step 2). The
// in-process MemoryCache below suffices for v1; a durable variant can
// live behind the same interface.
type DecisionCache interface {
	Get(key CacheKey) (CachedDecision, bool)
	Put(key CacheKey, d CachedDecision)
}

// MemoryCache is a bounded, concurrency-safe, in-process
// DecisionCache with FIFO eviction.
type MemoryCache struct {
	mu      sync.Mutex
	max     int
	entries map[CacheKey]CachedDecision
	order   []CacheKey
}

// DefaultCacheEntries bounds MemoryCache when no size is given.
const DefaultCacheEntries = 1024

// NewMemoryCache returns a MemoryCache holding at most maxEntries
// decisions (DefaultCacheEntries when maxEntries <= 0).
func NewMemoryCache(maxEntries int) *MemoryCache {
	if maxEntries <= 0 {
		maxEntries = DefaultCacheEntries
	}
	return &MemoryCache{
		max:     maxEntries,
		entries: make(map[CacheKey]CachedDecision, maxEntries),
	}
}

// Get implements DecisionCache. The returned decision is a defensive
// copy; callers cannot mutate cached bytes.
func (c *MemoryCache) Get(key CacheKey) (CachedDecision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, ok := c.entries[key]
	if !ok {
		return CachedDecision{}, false
	}
	return copyDecision(d), true
}

// Put implements DecisionCache.
func (c *MemoryCache) Put(key CacheKey, d CachedDecision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		for len(c.order) >= c.max {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
		c.order = append(c.order, key)
	}
	c.entries[key] = copyDecision(d)
}

// copyDecision deep-copies the mutable parts of a cached decision.
func copyDecision(d CachedDecision) CachedDecision {
	out := d
	out.PolicyJSON = append([]byte(nil), d.PolicyJSON...)
	out.PolicyArns = append([]string(nil), d.PolicyArns...)
	out.ExpandedActions = append([]string(nil), d.ExpandedActions...)
	out.Capabilities = append([]synth.CapabilityRef(nil), d.Capabilities...)
	if d.Explanation.Statements != nil {
		stmts := make([]synth.StatementExplanation, len(d.Explanation.Statements))
		for i, s := range d.Explanation.Statements {
			cp := s
			if s.Params != nil {
				cp.Params = make(map[string]string, len(s.Params))
				for k, v := range s.Params {
					cp.Params[k] = v
				}
			}
			stmts[i] = cp
		}
		out.Explanation = synth.Explanation{Statements: stmts}
	}
	return out
}
