package match

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLLMMatcherClosedWorld(t *testing.T) {
	snap := testSnapshot()
	stub := &StubClassifier{Fn: func(in ClassifierInput) []Classification {
		return []Classification{
			{CapabilityID: "s3.read-prefix", Params: map[string]string{"bucket": "acme"}, Confidence: 0.9, Rationale: "reads a bucket"},
			{CapabilityID: "iam.create-user", Confidence: 0.99, Rationale: "hallucinated"},
		}
	}}
	res, err := LLMMatcher{Classifier: stub}.Match(context.Background(), snap, "read the acme bucket")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1 (unknown id must be dropped)", len(res.Candidates))
	}
	if res.Candidates[0].CapabilityID != "s3.read-prefix" {
		t.Errorf("candidate = %q", res.Candidates[0].CapabilityID)
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "iam.create-user") {
		t.Errorf("expected a rejection note for the unknown id, got %v", res.Notes)
	}
	if res.Matcher != MatcherLLM {
		t.Errorf("matcher = %q, want %q", res.Matcher, MatcherLLM)
	}
	if res.ModelID != "stub" || res.PromptTemplateHash == "" {
		t.Errorf("model id and prompt template hash must be recorded, got %q / %q", res.ModelID, res.PromptTemplateHash)
	}
}

func TestLLMMatcherSchemaViolations(t *testing.T) {
	snap := testSnapshot()
	tests := []struct {
		name string
		out  []Classification
	}{
		{
			name: "too many candidates",
			out: []Classification{
				{CapabilityID: "s3.read-prefix", Confidence: 0.9},
				{CapabilityID: "s3.write-prefix", Confidence: 0.8},
				{CapabilityID: "sqs.consume", Confidence: 0.7},
				{CapabilityID: "s3.read-prefix", Confidence: 0.6},
			},
		},
		{
			name: "confidence above one",
			out:  []Classification{{CapabilityID: "s3.read-prefix", Confidence: 1.5}},
		},
		{
			name: "negative confidence",
			out:  []Classification{{CapabilityID: "s3.read-prefix", Confidence: -0.1}},
		},
		{
			name: "empty capability id",
			out:  []Classification{{CapabilityID: "", Confidence: 0.9}},
		},
		{
			name: "oversized param value",
			out: []Classification{{
				CapabilityID: "s3.read-prefix",
				Confidence:   0.9,
				Params:       map[string]string{"bucket": strings.Repeat("a", maxParamValueLen+1)},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &StubClassifier{Fn: func(ClassifierInput) []Classification { return tt.out }}
			_, err := LLMMatcher{Classifier: stub}.Match(context.Background(), snap, "task")
			if err == nil {
				t.Fatal("expected a schema rejection")
			}
		})
	}
}

func TestLLMMatcherDeduplicatesAndSorts(t *testing.T) {
	snap := testSnapshot()
	stub := &StubClassifier{Fn: func(ClassifierInput) []Classification {
		return []Classification{
			{CapabilityID: "s3.read-prefix", Confidence: 0.6},
			{CapabilityID: "sqs.consume", Confidence: 0.9},
			{CapabilityID: "s3.read-prefix", Confidence: 0.8},
		}
	}}
	res, err := LLMMatcher{Classifier: stub}.Match(context.Background(), snap, "task")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2 after dedupe", len(res.Candidates))
	}
	if res.Candidates[0].CapabilityID != "sqs.consume" || res.Candidates[0].Confidence != 0.9 {
		t.Errorf("top = %+v, want sqs.consume at 0.9", res.Candidates[0])
	}
	if res.Candidates[1].CapabilityID != "s3.read-prefix" || res.Candidates[1].Confidence != 0.8 {
		t.Errorf("second = %+v, want s3.read-prefix keeping its highest confidence 0.8", res.Candidates[1])
	}
}

func TestLLMMatcherRationaleTruncated(t *testing.T) {
	snap := testSnapshot()
	stub := &StubClassifier{Fn: func(ClassifierInput) []Classification {
		return []Classification{{
			CapabilityID: "s3.read-prefix",
			Confidence:   0.9,
			Rationale:    strings.Repeat("r", maxRationaleRunes*2),
		}}
	}}
	res, err := LLMMatcher{Classifier: stub}.Match(context.Background(), snap, "task")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if got := len([]rune(res.Candidates[0].Rationale)); got != maxRationaleRunes {
		t.Errorf("rationale length = %d runes, want truncation to %d", got, maxRationaleRunes)
	}
}

func TestLLMMatcherPropagatesClassifierError(t *testing.T) {
	snap := testSnapshot()
	stub := &StubClassifier{Err: errors.New("api unreachable")}
	_, err := LLMMatcher{Classifier: stub}.Match(context.Background(), snap, "task")
	if err == nil {
		t.Fatal("expected the classifier error to propagate")
	}
}

func TestNewClassifierFromConfigNilBlock(t *testing.T) {
	c, err := NewClassifierFromConfig(nil)
	if err != nil {
		t.Fatalf("nil block must not error: %v", err)
	}
	if c != nil {
		t.Fatal("nil block must produce a nil classifier (no-LLM mode)")
	}
}
