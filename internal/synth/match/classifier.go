package match

import (
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/0hardik1/taskgrant/internal/config"
)

// Schema bounds for classifier output. The classifier response is
// untrusted model output over hostile task bytes; everything is capped
// at this boundary regardless of which Classifier produced it.
const (
	// MaxClassifications is the maximum candidate count (section 5.4).
	MaxClassifications = 3
	// maxParamsPerClassification bounds extracted param maps.
	maxParamsPerClassification = 16
	// maxParamNameLen and maxParamValueLen bound extracted params.
	// Values still face full grammar and allowlist validation later.
	maxParamNameLen  = 64
	maxParamValueLen = 1024
	// maxCapabilityIDLen bounds the id string before closed-world
	// lookup.
	maxCapabilityIDLen = 128
	// maxRationaleRunes truncates the log-only rationale.
	maxRationaleRunes = 512
)

// ClassifierInput is what a classifier sees: the profile-filtered
// catalog summaries and the task text. Implementations must place the
// task in a delimited untrusted-data block and never let it act as an
// instruction.
type ClassifierInput struct {
	// Task is normalized, untrusted agent text.
	Task string
	// Capabilities is the agent-filtered catalog view. The classifier
	// never sees other agents' catalog scope.
	Capabilities []Capability
}

// Classification is one schema-validated classifier candidate.
type Classification struct {
	CapabilityID string            `json:"capability_id"`
	Params       map[string]string `json:"params,omitempty"`
	Confidence   float64           `json:"confidence"`
	Rationale    string            `json:"rationale,omitempty"`
}

// Classifier maps free-text intent onto catalog entries. Output is a
// closed-world selection: unknown capability ids are rejected by
// LLMMatcher, params face full validation downstream, and rationale
// goes to the log only.
type Classifier interface {
	Classify(ctx context.Context, in ClassifierInput) ([]Classification, error)
	// ModelID is recorded in the match trace.
	ModelID() string
	// PromptTemplateHash is the SHA-256 hex of the prompt template,
	// recorded in the match trace.
	PromptTemplateHash() string
}

// NewClassifierFromConfig builds the classifier for the synth.llm
// config block. It returns (nil, nil) when the block is absent, which
// is the fully supported no-LLM mode. Only the anthropic provider is
// implemented in v1.
func NewClassifierFromConfig(cfg *config.LLMConfig, opts ...AnthropicOption) (Classifier, error) {
	if cfg == nil {
		return nil, nil
	}
	switch cfg.Provider {
	case "anthropic":
		return NewAnthropicClassifier(cfg.Model, opts...)
	default:
		return nil, fmt.Errorf("match: unsupported synth.llm provider %q (v1 supports: anthropic)", cfg.Provider)
	}
}

// LLMMatcher wraps a Classifier and enforces the closed-world and
// schema rules on its output no matter which implementation produced
// it.
type LLMMatcher struct {
	Classifier Classifier
}

// Match runs the classifier and converts its output into a
// MatchResult. Unknown capability ids are dropped (closed world) with
// a log note; duplicate ids keep the highest-confidence candidate;
// candidates sort by confidence descending then id ascending.
func (m LLMMatcher) Match(ctx context.Context, snap Snapshot, task string) (MatchResult, error) {
	if m.Classifier == nil {
		return MatchResult{Matcher: MatcherLLM}, fmt.Errorf("match: LLMMatcher has no classifier")
	}
	res := MatchResult{
		Matcher:            MatcherLLM,
		ModelID:            m.Classifier.ModelID(),
		PromptTemplateHash: m.Classifier.PromptTemplateHash(),
	}
	out, err := m.Classifier.Classify(ctx, ClassifierInput{Task: task, Capabilities: snap.Capabilities()})
	if err != nil {
		return res, fmt.Errorf("match: classifier: %w", err)
	}
	out, err = normalizeClassifications(out)
	if err != nil {
		return res, fmt.Errorf("match: classifier output rejected: %w", err)
	}

	best := map[string]Candidate{}
	for _, c := range out {
		if _, ok := snap.Lookup(c.CapabilityID); !ok {
			res.Notes = append(res.Notes,
				fmt.Sprintf("rejected unknown capability_id %q from classifier (closed world)", clip(c.CapabilityID, maxCapabilityIDLen)))
			continue
		}
		cand := Candidate{
			CapabilityID: c.CapabilityID,
			Params:       cloneParams(c.Params),
			Confidence:   c.Confidence,
			Rationale:    c.Rationale,
		}
		if prev, dup := best[c.CapabilityID]; !dup || cand.Confidence > prev.Confidence {
			best[c.CapabilityID] = cand
		}
	}
	for _, cand := range best {
		res.Candidates = append(res.Candidates, cand)
	}
	sort.SliceStable(res.Candidates, func(i, j int) bool {
		if res.Candidates[i].Confidence != res.Candidates[j].Confidence {
			return res.Candidates[i].Confidence > res.Candidates[j].Confidence
		}
		return res.Candidates[i].CapabilityID < res.Candidates[j].CapabilityID
	})
	return res, nil
}

// normalizeClassifications schema-validates classifier output and
// truncates the log-only rationale. It rejects: more than
// MaxClassifications entries, empty or oversized ids, confidences
// outside [0,1] (NaN included), and oversized param maps, names, or
// values.
func normalizeClassifications(cs []Classification) ([]Classification, error) {
	if len(cs) > MaxClassifications {
		return nil, fmt.Errorf("%d candidates exceed the maximum of %d", len(cs), MaxClassifications)
	}
	out := make([]Classification, 0, len(cs))
	for i, c := range cs {
		if c.CapabilityID == "" {
			return nil, fmt.Errorf("candidate %d: empty capability_id", i)
		}
		if len(c.CapabilityID) > maxCapabilityIDLen {
			return nil, fmt.Errorf("candidate %d: capability_id exceeds %d bytes", i, maxCapabilityIDLen)
		}
		if math.IsNaN(c.Confidence) || c.Confidence < 0 || c.Confidence > 1 {
			return nil, fmt.Errorf("candidate %d: confidence %v outside [0,1]", i, c.Confidence)
		}
		if len(c.Params) > maxParamsPerClassification {
			return nil, fmt.Errorf("candidate %d: %d params exceed the maximum of %d", i, len(c.Params), maxParamsPerClassification)
		}
		for k, v := range c.Params {
			if k == "" || len(k) > maxParamNameLen {
				return nil, fmt.Errorf("candidate %d: param name length outside 1..%d", i, maxParamNameLen)
			}
			if len(v) > maxParamValueLen {
				return nil, fmt.Errorf("candidate %d: param %q value exceeds %d bytes", i, k, maxParamValueLen)
			}
		}
		if r := []rune(c.Rationale); len(r) > maxRationaleRunes {
			c.Rationale = string(r[:maxRationaleRunes])
		}
		c.Params = cloneParams(c.Params)
		out = append(out, c)
	}
	return out, nil
}
