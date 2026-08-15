package match

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/taskgrant/internal/synth"
)

// Confidence constants of the matching stage (sections 5.4 and 5.5).
const (
	// StructuredConfidence is assigned when structured capability
	// hints are present and every id exists in the agent-filtered
	// snapshot: the steady-state path for well-behaved agents.
	StructuredConfidence = 1.0
	// KeywordConfidenceCap bounds keyword/service scores so a pure
	// keyword match always passes through one structured confirmation
	// (0.79 is below the 0.80 proceed threshold).
	KeywordConfidenceCap = 0.79
	// AbstainThreshold is the score under which the rules matcher
	// abstains instead of gating on a weak keyword guess. It equals
	// the gate's NO_MATCH threshold.
	AbstainThreshold = 0.50
)

// Keyword scoring weights. A capability scores only when at least one
// keyword or service prefix hits; the score is deterministic in the
// task token set and the hints.
const (
	keywordWeight = 0.65
	serviceWeight = 0.35
)

// RulesMatcher is the always-present deterministic matcher. It needs
// no configuration and no network.
type RulesMatcher struct{}

// Match implements the rules matcher of section 5.4.
//
// Structured path: when capability hints are present and every hinted
// id exists in the agent-filtered snapshot, each hint becomes a
// candidate with confidence 1.0 and Structured is true.
//
// Keyword path: otherwise the task text and coarse hints are scored
// against the catalog match hints, capped at KeywordConfidenceCap.
// When the top score is below AbstainThreshold the matcher abstains;
// the pipeline then consults the LLM matcher or denies
// NEEDS_STRUCTURED_HINTS.
//
// task must already be normalized (trimmed, whitespace collapsed);
// the matcher lowercases and tokenizes it itself.
func (RulesMatcher) Match(snap Snapshot, task string, hints synth.Hints) MatchResult {
	res := MatchResult{Matcher: MatcherRules}

	if len(hints.Capabilities) > 0 {
		if cands, notes, ok := structuredCandidates(snap, hints.Capabilities); ok {
			res.Structured = true
			res.Candidates = cands
			res.Notes = notes
			return res
		} else {
			res.Notes = append(res.Notes, notes...)
		}
	}

	res.Candidates = keywordCandidates(snap, task, hints)
	if len(res.Candidates) == 0 || res.Candidates[0].Confidence < AbstainThreshold {
		res.Abstained = true
	}
	return res
}

// structuredCandidates converts capability hints into candidates. It
// returns ok=false when any hinted id is absent from the agent's
// snapshot (unknown or not permitted; the two are indistinguishable by
// design so existence is not confirmed). Duplicate ids are merged,
// first occurrence winning per param key.
func structuredCandidates(snap Snapshot, hintCaps []synth.CapabilityHint) ([]Candidate, []string, bool) {
	var notes []string
	seen := make(map[string]int, len(hintCaps))
	var cands []Candidate
	for _, h := range hintCaps {
		if _, ok := snap.Lookup(h.ID); !ok {
			notes = append(notes, fmt.Sprintf("capability hint %q is not in the agent-filtered snapshot", clip(h.ID, 128)))
			return nil, notes, false
		}
		if i, dup := seen[h.ID]; dup {
			notes = append(notes, fmt.Sprintf("duplicate capability hint %q merged, first params win", h.ID))
			for k, v := range h.Params {
				if _, exists := cands[i].Params[k]; !exists {
					cands[i].Params[k] = v
				}
			}
			continue
		}
		seen[h.ID] = len(cands)
		cands = append(cands, Candidate{
			CapabilityID: h.ID,
			Params:       cloneParams(h.Params),
			Confidence:   StructuredConfidence,
			Rationale:    "structured capability hint",
		})
	}
	return cands, notes, true
}

// keywordCandidates scores every visible capability against the task
// token set and the coarse service hints. Deterministic: ties break on
// capability id.
func keywordCandidates(snap Snapshot, task string, hints synth.Hints) []Candidate {
	joined := " " + strings.Join(tokenize(task), " ") + " "
	services := make(map[string]bool, len(hints.Services))
	for _, s := range hints.Services {
		services[strings.ToLower(strings.TrimSpace(s))] = true
	}

	var cands []Candidate
	for _, capability := range snap.Capabilities() {
		kwHits := 0
		var hitWords []string
		for _, kw := range capability.Keywords {
			norm := strings.Join(tokenize(kw), " ")
			if norm != "" && strings.Contains(joined, " "+norm+" ") {
				kwHits++
				hitWords = append(hitWords, kw)
			}
		}
		svcHit := false
		var hitSvc string
		for _, p := range capability.ServicePrefixes {
			pl := strings.ToLower(p)
			if services[pl] || strings.Contains(joined, " "+pl+" ") {
				svcHit = true
				hitSvc = p
				break
			}
		}
		if kwHits == 0 && !svcHit {
			continue
		}
		kwScore := 0.0
		if kwHits > 0 {
			kwScore = 0.6 + 0.2*float64(kwHits-1)
			if kwScore > 1.0 {
				kwScore = 1.0
			}
		}
		svcScore := 0.0
		if svcHit {
			svcScore = 1.0
		}
		score := KeywordConfidenceCap * (keywordWeight*kwScore + serviceWeight*svcScore)
		if score > KeywordConfidenceCap {
			score = KeywordConfidenceCap
		}
		cands = append(cands, Candidate{
			CapabilityID: capability.ID,
			Params:       map[string]string{},
			Confidence:   score,
			Rationale:    keywordRationale(hitWords, hitSvc),
		})
	}

	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].Confidence != cands[j].Confidence {
			return cands[i].Confidence > cands[j].Confidence
		}
		return cands[i].CapabilityID < cands[j].CapabilityID
	})
	if len(cands) > MaxClassifications {
		cands = cands[:MaxClassifications]
	}
	return cands
}

// keywordRationale renders a log-only rationale from catalog-authored
// strings only, never from task bytes.
func keywordRationale(keywords []string, service string) string {
	var b strings.Builder
	b.WriteString("keyword match")
	if len(keywords) > 0 {
		b.WriteString(": ")
		b.WriteString(strings.Join(keywords, ", "))
	}
	if service != "" {
		b.WriteString("; service ")
		b.WriteString(service)
	}
	return b.String()
}

// tokenize lowercases s and splits it into alphanumeric tokens.
func tokenize(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return false
		}
		return true
	})
}

// clip bounds a hostile string for a log note without mutating stored
// raw bytes elsewhere.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
