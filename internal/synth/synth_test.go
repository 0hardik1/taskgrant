package synth

import (
	"context"
	"testing"
	"time"
)

// stubSynthesizer proves the interface is implementable with the
// published types alone. Real implementations live behind the seam.
type stubSynthesizer struct{}

func (stubSynthesizer) Synthesize(_ context.Context, req Request) (Result, error) {
	return Result{
		Verdict:           VerdictDeny,
		DenialCode:        "NO_MATCH",
		EffectiveDuration: 900 * time.Second,
	}, nil
}

func (stubSynthesizer) Compact(_ context.Context, prev Result, maxChars int) (Result, error) {
	return prev, nil
}

var _ Synthesizer = stubSynthesizer{}

func TestVerdictValid(t *testing.T) {
	tests := []struct {
		v    Verdict
		want bool
	}{
		{VerdictPolicy, true},
		{VerdictDeny, true},
		{VerdictNeedsClarification, true},
		{VerdictPendingApproval, true},
		{Verdict("approved"), false},
		{Verdict(""), false},
	}
	for _, tt := range tests {
		if got := tt.v.Valid(); got != tt.want {
			t.Errorf("Verdict(%q).Valid() = %v, want %v", tt.v, got, tt.want)
		}
	}
}

func TestSeamRoundTrip(t *testing.T) {
	var s Synthesizer = stubSynthesizer{}
	res, err := s.Synthesize(context.Background(), Request{
		GrantID:        "01J4LOCALTESTULID0000000000",
		AgentID:        "invoice-bot",
		Task:           "read the invoices bucket",
		MaxPolicyChars: 1748,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictDeny || res.DenialCode != "NO_MATCH" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
