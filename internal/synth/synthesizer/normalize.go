package synthesizer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/taskgrant/internal/synth"
)

// NormalizeTask normalizes untrusted task text for matching and
// hashing: trim plus Unicode-whitespace collapse to single spaces.
//
// NFC normalization is intentionally skipped: golang.org/x/text is not
// among the pinned module dependencies (absent from go.sum) and the
// build rules forbid adding third-party dependencies; the stdlib has
// no NFC implementation. Consequence: two byte-distinct but
// canonically equivalent task strings hash to different intent
// hashes, which only lowers the decision-cache hit rate. It never
// affects correctness or policy bytes, because task text never enters
// a policy (invariant I1).
func NormalizeTask(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// canonicalIntent is the exact serialization behind the intent hash.
// Hints are part of the intent: the same task text with different
// structured hints is a different decision.
type canonicalIntent struct {
	Task         string                `json:"task"`
	Capabilities []canonicalCapability `json:"capabilities,omitempty"`
	Services     []string              `json:"services,omitempty"`
	Resources    []string              `json:"resources,omitempty"`
	Access       string                `json:"access,omitempty"`
	Duration     int                   `json:"duration,omitempty"`
}

type canonicalCapability struct {
	ID     string            `json:"id"`
	Params map[string]string `json:"params,omitempty"`
}

// IntentHash returns the SHA-256 hex of the canonical intent: the
// normalized task plus the hints, with order-insensitive fields
// sorted (capability list by id, services and resources
// lexicographically; JSON map keys sort by encoding/json).
func IntentHash(task string, hints synth.Hints) string {
	ci := canonicalIntent{
		Task:      NormalizeTask(task),
		Services:  sortedCopy(hints.Services),
		Resources: sortedCopy(hints.Resources),
		Access:    hints.Access,
		Duration:  hints.DurationSeconds,
	}
	for _, h := range hints.Capabilities {
		ci.Capabilities = append(ci.Capabilities, canonicalCapability{ID: h.ID, Params: h.Params})
	}
	sort.SliceStable(ci.Capabilities, func(i, j int) bool {
		return ci.Capabilities[i].ID < ci.Capabilities[j].ID
	})
	data, err := json.Marshal(ci)
	if err != nil {
		// canonicalIntent holds only JSON-serializable fields.
		panic(fmt.Sprintf("synthesizer: canonical intent serialization failed: %v", err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
