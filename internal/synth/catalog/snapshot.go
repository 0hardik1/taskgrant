package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
)

// Snapshot is one compiled, immutable catalog. All accessors are safe
// for concurrent use. A Snapshot may be a per-agent view (ForAgent);
// views share the full snapshot's hash, because the hash pins the
// reviewed catalog content, not the visibility filter.
type Snapshot struct {
	caps             map[string]*Capability
	order            []string // sorted capability ids in this view
	allowlists       map[string][]string
	resourcePatterns []string
	datasetHash      string
	hash             string
	gitCommit        string
	agentFilter      string // empty means the unfiltered snapshot
}

// snapshotModel is the canonical serialization behind the snapshot
// hash. Struct fields serialize in declaration order and map keys
// sort, so equal catalogs hash equally (invariant I6).
type snapshotModel struct {
	Capabilities     []*Capability       `json:"capabilities"`
	Allowlists       map[string][]string `json:"allowlists"`
	ResourcePatterns []string            `json:"resource_patterns"`
	DatasetHash      string              `json:"dataset_hash"`
}

// newSnapshot assembles and hashes a snapshot from compiled parts.
func newSnapshot(caps map[string]*Capability, allowlists map[string][]string, resourcePatterns []string, datasetHash string) (*Snapshot, error) {
	order := make([]string, 0, len(caps))
	for id := range caps {
		order = append(order, id)
	}
	sort.Strings(order)

	capsSorted := make([]*Capability, 0, len(order))
	for _, id := range order {
		capsSorted = append(capsSorted, caps[id])
	}
	model := snapshotModel{
		Capabilities:     capsSorted,
		Allowlists:       allowlists,
		ResourcePatterns: resourcePatterns,
		DatasetHash:      datasetHash,
	}
	data, err := json.Marshal(model)
	if err != nil {
		return nil, fmt.Errorf("catalog: canonical serialization failed: %v", err)
	}
	sum := sha256.Sum256(data)
	return &Snapshot{
		caps:             caps,
		order:            order,
		allowlists:       allowlists,
		resourcePatterns: resourcePatterns,
		datasetHash:      datasetHash,
		hash:             hex.EncodeToString(sum[:]),
	}, nil
}

// Hash returns the SHA-256 hex of the compiled snapshot.
func (s *Snapshot) Hash() string { return s.hash }

// GitCommit returns the git commit SHA governing the catalog
// directory at load time, or empty when none was resolvable.
func (s *Snapshot) GitCommit() string { return s.gitCommit }

// CatalogHash returns the catalog version string for decision records:
// the snapshot SHA-256, plus "+<commit>" when a git commit was
// resolvable (section 5.2).
func (s *Snapshot) CatalogHash() string {
	if s.gitCommit == "" {
		return s.hash
	}
	return s.hash + "+" + s.gitCommit
}

// DatasetHash returns the hash of the dataset the snapshot was
// validated against.
func (s *Snapshot) DatasetHash() string { return s.datasetHash }

// AgentFilter returns the agent id this view is filtered to, or empty
// for the unfiltered snapshot.
func (s *Snapshot) AgentFilter() string { return s.agentFilter }

// Len returns the number of capabilities visible in this view.
func (s *Snapshot) Len() int { return len(s.order) }

// IDs returns the visible capability ids, sorted. Fresh copy.
func (s *Snapshot) IDs() []string {
	return append([]string(nil), s.order...)
}

// Capability returns one visible capability by id.
func (s *Snapshot) Capability(id string) (*Capability, bool) {
	c, ok := s.caps[id]
	return c, ok
}

// Capabilities returns every visible capability, sorted by id. The
// slice is fresh; the entries are the shared immutable capabilities.
func (s *Snapshot) Capabilities() []*Capability {
	out := make([]*Capability, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.caps[id])
	}
	return out
}

// Allowlist returns the entries of one named allowlist set. Fresh
// copy.
func (s *Snapshot) Allowlist(name string) ([]string, bool) {
	entries, ok := s.allowlists[name]
	if !ok {
		return nil, false
	}
	return append([]string(nil), entries...), true
}

// ResourcePatterns returns the admin resource ARN patterns. Fresh
// copy.
func (s *Snapshot) ResourcePatterns() []string {
	return append([]string(nil), s.resourcePatterns...)
}

// ResourceMatchesAllowlist reports whether the concrete resource ARN
// matches at least one admin resource pattern, field-wise so globs do
// not cross ARN partition or account fields (G4).
func (s *Snapshot) ResourceMatchesAllowlist(arn string) bool {
	for _, p := range s.resourcePatterns {
		if arnMatches(p, arn) {
			return true
		}
	}
	return false
}

// ForAgent returns the per-agent view: only capabilities visible to
// agentID remain, so one agent cannot enumerate another's catalog
// scope. The view shares the underlying immutable data and the full
// snapshot's hash.
func (s *Snapshot) ForAgent(agentID string) *Snapshot {
	filtered := make(map[string]*Capability)
	order := make([]string, 0, len(s.order))
	for _, id := range s.order {
		c := s.caps[id]
		if c.VisibleTo(agentID) {
			filtered[id] = c
			order = append(order, id)
		}
	}
	return &Snapshot{
		caps:             filtered,
		order:            order,
		allowlists:       s.allowlists,
		resourcePatterns: s.resourcePatterns,
		datasetHash:      s.datasetHash,
		hash:             s.hash,
		gitCommit:        s.gitCommit,
		agentFilter:      agentID,
	}
}

// ParamExamples returns up to n concrete example values for one
// param, drawn from its allowlist with wildcard entries skipped. Used
// by clarification messages (section 5.6). Nil when the param has no
// allowlist.
func (s *Snapshot) ParamExamples(capID, param string, n int) []string {
	c, ok := s.caps[capID]
	if !ok {
		return nil
	}
	p, ok := c.Params[param]
	if !ok || p.AllowlistRef == "" {
		return nil
	}
	entries := s.allowlists[p.AllowlistRef]
	var out []string
	for _, e := range entries {
		if len(out) >= n {
			break
		}
		if !strings.Contains(e, "*") {
			out = append(out, e)
		}
	}
	return out
}

// Store holds the current snapshot behind an atomic pointer so hot
// reload swaps atomically: in-flight requests keep the snapshot they
// started with, new requests see the new one.
type Store struct {
	cur atomic.Pointer[Snapshot]
}

// NewStore returns a Store holding the given snapshot.
func NewStore(s *Snapshot) *Store {
	st := &Store{}
	if s != nil {
		st.cur.Store(s)
	}
	return st
}

// Current returns the current snapshot, or nil when none was stored.
func (st *Store) Current() *Snapshot { return st.cur.Load() }

// Swap installs next as the current snapshot and returns the previous
// one. It never installs nil.
func (st *Store) Swap(next *Snapshot) *Snapshot {
	if next == nil {
		return st.cur.Load()
	}
	return st.cur.Swap(next)
}

// SnapshotForAgent returns the current snapshot filtered to one
// agent's visibility (section 5.2). Nil when no snapshot is stored.
func (st *Store) SnapshotForAgent(agentID string) *Snapshot {
	cur := st.cur.Load()
	if cur == nil {
		return nil
	}
	return cur.ForAgent(agentID)
}
