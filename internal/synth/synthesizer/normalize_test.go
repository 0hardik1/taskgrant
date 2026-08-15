package synthesizer

import (
	"testing"

	"github.com/0hardik1/taskgrant/internal/synth"
)

func TestNormalizeTask(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"trim", "  archive invoices  ", "archive invoices"},
		{"collapse spaces", "archive    invoices", "archive invoices"},
		{"collapse mixed whitespace", "archive\t\n invoices\r\n now", "archive invoices now"},
		{"unicode spaces", "archive invoices", "archive invoices"},
		{"empty", "   \t\n ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeTask(tt.in); got != tt.want {
				t.Fatalf("NormalizeTask(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIntentHash(t *testing.T) {
	hints := synth.Hints{Capabilities: []synth.CapabilityHint{{
		ID:     "s3.read-prefix",
		Params: map[string]string{"bucket": "b", "prefix": "p/"},
	}}}

	t.Run("whitespace variants collide", func(t *testing.T) {
		a := IntentHash("archive  the\tinvoices", hints)
		b := IntentHash(" archive the invoices ", hints)
		if a != b {
			t.Fatal("normalized whitespace variants must hash identically")
		}
	})
	t.Run("different task text differs", func(t *testing.T) {
		if IntentHash("archive invoices", hints) == IntentHash("delete invoices", hints) {
			t.Fatal("different tasks must hash differently")
		}
	})
	t.Run("hints are part of the intent", func(t *testing.T) {
		other := synth.Hints{Capabilities: []synth.CapabilityHint{{
			ID:     "s3.read-prefix",
			Params: map[string]string{"bucket": "b", "prefix": "OTHER/"},
		}}}
		if IntentHash("archive invoices", hints) == IntentHash("archive invoices", other) {
			t.Fatal("different hint params must hash differently")
		}
	})
	t.Run("capability order is canonical", func(t *testing.T) {
		ab := synth.Hints{Capabilities: []synth.CapabilityHint{{ID: "a"}, {ID: "b"}}}
		ba := synth.Hints{Capabilities: []synth.CapabilityHint{{ID: "b"}, {ID: "a"}}}
		if IntentHash("t", ab) != IntentHash("t", ba) {
			t.Fatal("capability hint order must not change the intent hash")
		}
	})
	t.Run("service order is canonical", func(t *testing.T) {
		if IntentHash("t", synth.Hints{Services: []string{"s3", "sqs"}}) !=
			IntentHash("t", synth.Hints{Services: []string{"sqs", "s3"}}) {
			t.Fatal("service hint order must not change the intent hash")
		}
	})
	t.Run("stable across calls", func(t *testing.T) {
		a := IntentHash("archive invoices", hints)
		for i := 0; i < 50; i++ {
			if IntentHash("archive invoices", hints) != a {
				t.Fatal("intent hash is not deterministic")
			}
		}
		if len(a) != 64 {
			t.Fatalf("hash %q is not sha256 hex", a)
		}
	})
}
