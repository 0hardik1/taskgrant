package match

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// stubTemplate is the fixed "prompt template" identity of the stub, so
// its PromptTemplateHash is stable and distinguishable in traces.
const stubTemplate = "taskgrant-stub-classifier/v1"

// StubClassifier is a deterministic Classifier for tests and offline
// pipelines. It returns exactly what Fn computes from the input, and
// never performs I/O. A nil Fn classifies everything as no match.
type StubClassifier struct {
	// Model is the reported model id; defaults to "stub".
	Model string
	// Fn computes the classifications. It must be deterministic for
	// identical inputs.
	Fn func(in ClassifierInput) []Classification
	// Err, when set, is returned from every Classify call. It lets
	// tests exercise classifier-failure degradation.
	Err error
	// Calls counts Classify invocations, for never-re-matches tests.
	Calls int
}

// Classify implements Classifier.
func (s *StubClassifier) Classify(_ context.Context, in ClassifierInput) ([]Classification, error) {
	s.Calls++
	if s.Err != nil {
		return nil, s.Err
	}
	if s.Fn == nil {
		return nil, nil
	}
	return s.Fn(in), nil
}

// ModelID implements Classifier.
func (s *StubClassifier) ModelID() string {
	if s.Model == "" {
		return "stub"
	}
	return s.Model
}

// PromptTemplateHash implements Classifier.
func (s *StubClassifier) PromptTemplateHash() string {
	sum := sha256.Sum256([]byte(stubTemplate))
	return hex.EncodeToString(sum[:])
}
