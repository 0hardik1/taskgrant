// Package match implements the matching stage of the intent-to-policy
// synthesizer (architecture section 5.4): the rules matcher, the
// optional LLM classifier seam with two implementations, and the
// confidence gate of section 5.5.
//
// The package defines a consumer-side view of the capability catalog
// (Capability, Snapshot) so it builds and tests independently of
// synth/catalog, which is developed in parallel. The integration step
// adapts the concrete catalog snapshot to the Snapshot interface.
//
// Trust stance: task text and every agent-supplied param value are
// hostile bytes. The matchers only ever select admin-approved catalog
// entries (closed world); no matcher output reaches a policy without
// full grammar and allowlist validation downstream.
package match

// Matcher names recorded in the match trace.
const (
	// MatcherRules identifies the deterministic rules matcher.
	MatcherRules = "rules"
	// MatcherLLM identifies the LLM classifier matcher.
	MatcherLLM = "llm"
)

// ParamSpec is the consumer-side view of one declared capability
// parameter, carrying enough shape information for the section 5.6
// clarification contract (name the exact param, its expected shape,
// and allowlist-derived examples).
type ParamSpec struct {
	Name     string
	Required bool
	// ExpectedShape describes the accepted grammar or allowlist in
	// admin-authored words, for example "bucket name from the
	// s3-buckets allowlist".
	ExpectedShape string
	Examples      []string
}

// Capability is the consumer-side view of one catalog entry, already
// filtered to the requesting agent's visibility. All fields are
// admin-authored (trusted) catalog content.
type Capability struct {
	ID      string
	Version int
	Summary string
	// Keywords, ServicePrefixes, and Examples are the catalog match
	// hints (section 5.2).
	Keywords        []string
	ServicePrefixes []string
	Examples        []string
	Params          []ParamSpec
	// RequiresApproval routes every grant of this capability through a
	// human (section 5.5).
	RequiresApproval bool
	// MaxDurationSeconds caps the session duration for grants that
	// include this capability. Zero means no capability-level cap.
	MaxDurationSeconds int
}

// Snapshot is the agent-filtered, immutable capability view the
// matchers score against. The concrete type lives in synth/catalog;
// the integration step adapts it.
type Snapshot interface {
	// Capabilities returns the entries visible to the agent in a
	// stable order.
	Capabilities() []Capability
	// Lookup returns the entry with the given id when it is visible
	// to the agent. A capability that exists but is not permitted for
	// the agent must not be returned (closed world per agent).
	Lookup(id string) (Capability, bool)
	// Hash is the catalog snapshot hash pinned into every decision.
	Hash() string
}

// Candidate is one scored capability selection produced by a matcher.
type Candidate struct {
	CapabilityID string
	// Params are extracted or hinted parameter values. They are
	// hostile bytes until grammar and allowlist validation passes.
	Params     map[string]string
	Confidence float64
	// Rationale goes to the decision log only, never to policy or
	// agent-facing output.
	Rationale string
}

// MatchResult is the outcome of one matcher run, sized for the match
// trace of the decision record (section 9.1).
type MatchResult struct {
	// Matcher is MatcherRules or MatcherLLM.
	Matcher string
	// Structured is true when the candidates come from valid agent
	// capability hints. Structured candidates form a requested set,
	// not competing alternatives, so the gate skips the margin rule.
	Structured bool
	// Abstained is true when the rules matcher found no candidate
	// strong enough to gate on; the pipeline then consults the LLM
	// matcher or denies NEEDS_STRUCTURED_HINTS.
	Abstained bool
	// Candidates are sorted by confidence descending, then id
	// ascending, at most MaxClassifications entries.
	Candidates []Candidate
	// ModelID and PromptTemplateHash are recorded for LLM runs only.
	ModelID            string
	PromptTemplateHash string
	// Notes carry log-only diagnostics such as rejected unknown ids.
	Notes []string
}

// cloneParams returns a fresh copy of a params map so hostile input
// maps are never aliased into results.
func cloneParams(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
