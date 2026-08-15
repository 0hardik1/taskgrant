package match

import (
	"errors"
	"testing"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/synth"
)

// cand builds a competing (non-structured) candidate.
func cand(id string, conf float64, params map[string]string) Candidate {
	return Candidate{CapabilityID: id, Params: cloneParams(params), Confidence: conf}
}

// TestGateTable mirrors the section 5.5 confidence gate table row by
// row.
func TestGateTable(t *testing.T) {
	snap := testSnapshot()
	resolved := map[string]string{"bucket": "acme-invoices-prod"}

	tests := []struct {
		name             string
		res              MatchResult
		hints            synth.Hints
		firstUse         map[string]bool
		firstUseErr      error
		firstUseApproval bool
		wantOutcome      GateOutcome
		wantDenial       domain.DenialCode
		wantClarify      domain.DenialCode
		wantSelected     []string
		wantMissing      []string // capability.param
	}{
		{
			// Row 1: Top >= 0.80, margin >= 0.20, all required params
			// resolved: proceed.
			name: "row1 proceed",
			res: MatchResult{Matcher: MatcherLLM, Candidates: []Candidate{
				cand("s3.read-prefix", 0.90, resolved),
				cand("sqs.consume", 0.40, nil),
			}},
			wantOutcome:  GateProceed,
			wantSelected: []string{"s3.read-prefix"},
		},
		{
			// Row 2: Top >= 0.80, params missing: clarification naming
			// the params.
			name: "row2 missing params",
			res: MatchResult{Matcher: MatcherLLM, Candidates: []Candidate{
				cand("s3.read-prefix", 0.90, nil),
			}},
			wantOutcome: GateClarify,
			wantClarify: domain.DenyMissingParam,
			wantMissing: []string{"s3.read-prefix.bucket"},
		},
		{
			// Row 3a: Top in [0.50, 0.80): clarification with a
			// candidate list, confirm by id.
			name: "row3 low confidence band",
			res: MatchResult{Matcher: MatcherRules, Candidates: []Candidate{
				cand("s3.read-prefix", 0.79, resolved),
			}},
			wantOutcome: GateClarify,
			wantClarify: domain.DenyAmbiguousMatch,
		},
		{
			// Row 3b: margin < 0.20: ambiguous even above 0.80.
			name: "row3 thin margin",
			res: MatchResult{Matcher: MatcherLLM, Candidates: []Candidate{
				cand("s3.read-prefix", 0.90, resolved),
				cand("s3.write-prefix", 0.85, nil),
			}},
			wantOutcome: GateClarify,
			wantClarify: domain.DenyAmbiguousMatch,
		},
		{
			// Row 4a: Top < 0.50: deny NO_MATCH.
			name: "row4 weak top",
			res: MatchResult{Matcher: MatcherLLM, Candidates: []Candidate{
				cand("s3.read-prefix", 0.49, resolved),
			}},
			wantOutcome: GateDeny,
			wantDenial:  domain.DenyNoMatch,
		},
		{
			// Row 4b: none: deny NO_MATCH.
			name:        "row4 no candidates",
			res:         MatchResult{Matcher: MatcherLLM},
			wantOutcome: GateDeny,
			wantDenial:  domain.DenyNoMatch,
		},
		{
			// Row 5: any capability requires_approval: pending
			// approval.
			name: "row5 requires approval",
			res: MatchResult{Matcher: MatcherRules, Structured: true, Candidates: []Candidate{
				cand("s3.write-prefix", StructuredConfidence, resolved),
			}},
			wantOutcome:  GatePendingApproval,
			wantSelected: []string{"s3.write-prefix"},
		},
		{
			// Row 6: first use of (agent, capability) with
			// first_use_approval on: pending approval.
			name: "row6 first use",
			res: MatchResult{Matcher: MatcherRules, Structured: true, Candidates: []Candidate{
				cand("s3.read-prefix", StructuredConfidence, resolved),
			}},
			firstUse:         map[string]bool{"s3.read-prefix": true},
			firstUseApproval: true,
			wantOutcome:      GatePendingApproval,
			wantSelected:     []string{"s3.read-prefix"},
		},
		{
			// Row 6 inverse: first_use_approval off never parks.
			name: "row6 flag off proceeds",
			res: MatchResult{Matcher: MatcherRules, Structured: true, Candidates: []Candidate{
				cand("s3.read-prefix", StructuredConfidence, resolved),
			}},
			firstUse:         map[string]bool{"s3.read-prefix": true},
			firstUseApproval: false,
			wantOutcome:      GateProceed,
			wantSelected:     []string{"s3.read-prefix"},
		},
		{
			// First-use ledger error fails closed to approval.
			name: "first use error fails closed",
			res: MatchResult{Matcher: MatcherRules, Structured: true, Candidates: []Candidate{
				cand("s3.read-prefix", StructuredConfidence, resolved),
			}},
			firstUseErr:      errors.New("ledger unavailable"),
			firstUseApproval: true,
			wantOutcome:      GatePendingApproval,
		},
		{
			// Structured set: multiple 1.0 candidates are a requested
			// set; the margin rule does not apply.
			name: "structured set skips margin",
			res: MatchResult{Matcher: MatcherRules, Structured: true, Candidates: []Candidate{
				cand("s3.read-prefix", StructuredConfidence, resolved),
				cand("sqs.consume", StructuredConfidence, map[string]string{"queue": "jobs"}),
			}},
			wantOutcome:  GateProceed,
			wantSelected: []string{"s3.read-prefix", "sqs.consume"},
		},
		{
			// G8 mirror: more than three capabilities per grant deny.
			name: "over capability cap",
			res: MatchResult{Matcher: MatcherRules, Structured: true, Candidates: []Candidate{
				cand("s3.read-prefix", 1, resolved),
				cand("s3.write-prefix", 1, resolved),
				cand("sqs.consume", 1, map[string]string{"queue": "jobs"}),
				cand("s3.read-prefix", 1, resolved),
			}},
			wantOutcome: GateDeny,
			wantDenial:  domain.DenyGuardrailViolation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := Gate{
				FirstUseApproval: tt.firstUseApproval,
				FirstUse: func(agentID, capabilityID string) (bool, error) {
					if tt.firstUseErr != nil {
						return false, tt.firstUseErr
					}
					return tt.firstUse[capabilityID], nil
				},
			}
			dec, err := g.Decide("invoice-bot", tt.res, tt.hints, snap)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if dec.Outcome != tt.wantOutcome {
				t.Fatalf("outcome = %q, want %q (decision: %+v)", dec.Outcome, tt.wantOutcome, dec)
			}
			if tt.wantDenial != "" && dec.DenialCode != tt.wantDenial {
				t.Errorf("denial code = %q, want %q", dec.DenialCode, tt.wantDenial)
			}
			if tt.wantClarify != "" {
				if dec.ClarifyCode != tt.wantClarify {
					t.Errorf("clarify code = %q, want %q", dec.ClarifyCode, tt.wantClarify)
				}
				if len(dec.Questions) == 0 {
					t.Error("clarification must carry questions")
				}
				if tt.wantClarify == domain.DenyAmbiguousMatch && len(dec.Candidates) == 0 {
					t.Error("ambiguous clarification must list candidates")
				}
			}
			if tt.wantSelected != nil {
				if len(dec.Selected) != len(tt.wantSelected) {
					t.Fatalf("selected %d capabilities, want %d", len(dec.Selected), len(tt.wantSelected))
				}
				for i, id := range tt.wantSelected {
					if dec.Selected[i].Capability.ID != id {
						t.Errorf("selected[%d] = %q, want %q", i, dec.Selected[i].Capability.ID, id)
					}
				}
			}
			if tt.wantMissing != nil {
				var got []string
				for _, m := range dec.MissingParams {
					got = append(got, m.Capability+"."+m.Name)
					if m.ExpectedShape == "" {
						t.Errorf("missing param %s.%s lacks an expected shape", m.Capability, m.Name)
					}
				}
				if len(got) != len(tt.wantMissing) {
					t.Fatalf("missing params = %v, want %v", got, tt.wantMissing)
				}
				for i := range got {
					if got[i] != tt.wantMissing[i] {
						t.Errorf("missing[%d] = %q, want %q", i, got[i], tt.wantMissing[i])
					}
				}
			}
		})
	}
}

func TestGateHintedParamsWinOverExtracted(t *testing.T) {
	snap := testSnapshot()
	res := MatchResult{Matcher: MatcherLLM, Candidates: []Candidate{
		cand("s3.read-prefix", 0.95, map[string]string{"bucket": "extracted-bucket", "prefix": "x/"}),
	}}
	hints := synth.Hints{Capabilities: []synth.CapabilityHint{
		{ID: "s3.read-prefix", Params: map[string]string{"bucket": "hinted-bucket"}},
	}}
	dec, err := Gate{}.Decide("invoice-bot", res, hints, snap)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if dec.Outcome != GateProceed {
		t.Fatalf("outcome = %q, want proceed", dec.Outcome)
	}
	got := dec.Selected[0].Params
	if got["bucket"] != "hinted-bucket" {
		t.Errorf("bucket = %q, hinted must win on conflict", got["bucket"])
	}
	if got["prefix"] != "x/" {
		t.Errorf("prefix = %q, extracted must survive when unhinted", got["prefix"])
	}
}

func TestGateFirstUseEnabledWithoutDependencyErrors(t *testing.T) {
	snap := testSnapshot()
	res := MatchResult{Matcher: MatcherRules, Structured: true, Candidates: []Candidate{
		cand("s3.read-prefix", 1, map[string]string{"bucket": "b"}),
	}}
	_, err := Gate{FirstUseApproval: true}.Decide("invoice-bot", res, synth.Hints{}, snap)
	if err == nil {
		t.Fatal("expected an error when first-use approval has no FirstUse dependency")
	}
}
