package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateTransition(t *testing.T) {
	tests := []struct {
		name string
		from State
		to   State
		ok   bool
	}{
		{"received to synthesized", StateReceived, StateSynthesized, true},
		{"received to denied", StateReceived, StateDenied, true},
		{"received to minted skips stages", StateReceived, StateMinted, false},
		{"synthesized to guardrails", StateSynthesized, StateGuardrails, true},
		{"synthesized to clarification", StateSynthesized, StateNeedsClarification, true},
		{"synthesized to denied", StateSynthesized, StateDenied, true},
		{"synthesized to minted", StateSynthesized, StateMinted, false},
		{"guardrails to auto_approved", StateGuardrails, StateAutoApproved, true},
		{"guardrails to pending_approval", StateGuardrails, StatePendingApproval, true},
		{"guardrails to denied", StateGuardrails, StateDenied, true},
		{"guardrails to active", StateGuardrails, StateActive, false},
		{"auto_approved to minted", StateAutoApproved, StateMinted, true},
		{"auto_approved to denied sts failure", StateAutoApproved, StateDenied, true},
		{"pending to approved", StatePendingApproval, StateApproved, true},
		{"pending to denied", StatePendingApproval, StateDenied, true},
		{"pending to expired_pending", StatePendingApproval, StateExpiredPending, true},
		{"pending to minted skips approval", StatePendingApproval, StateMinted, false},
		{"approved to minted", StateApproved, StateMinted, true},
		{"approved to denied", StateApproved, StateDenied, true},
		{"clarification retry", StateNeedsClarification, StateSynthesized, true},
		{"clarification exhausted", StateNeedsClarification, StateDenied, true},
		{"minted to active", StateMinted, StateActive, true},
		{"minted to expired", StateMinted, StateExpired, true},
		{"active to expired", StateActive, StateExpired, true},
		{"denied is terminal", StateDenied, StateReceived, false},
		{"expired is terminal", StateExpired, StateActive, false},
		{"expired_pending is terminal", StateExpiredPending, StateApproved, false},
		{"unknown from", State("bogus"), StateDenied, false},
		{"unknown to", StateReceived, State("bogus"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTransition(tt.from, tt.to)
			if tt.ok && err != nil {
				t.Fatalf("want legal, got %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("want illegal, got nil error")
			}
		})
	}
}

func TestTransitionErrorType(t *testing.T) {
	err := ValidateTransition(StateDenied, StateActive)
	var te *TransitionError
	if !errors.As(err, &te) {
		t.Fatalf("want *TransitionError, got %T", err)
	}
	if te.From != StateDenied || te.To != StateActive {
		t.Fatalf("wrong fields: %+v", te)
	}
}

func TestTerminalStates(t *testing.T) {
	wantTerminal := map[State]bool{
		StateDenied: true, StateExpired: true, StateExpiredPending: true,
	}
	for _, s := range States() {
		if got := s.Terminal(); got != wantTerminal[s] {
			t.Errorf("state %s: Terminal() = %v, want %v", s, got, wantTerminal[s])
		}
		if !s.Valid() {
			t.Errorf("state %s: Valid() = false", s)
		}
	}
	if State("bogus").Valid() {
		t.Error("bogus state reported valid")
	}
	if State("bogus").Terminal() {
		t.Error("bogus state reported terminal")
	}
}

func TestGrantSetState(t *testing.T) {
	g := &Grant{GrantID: NewGrantID(), AgentID: "invoice-bot", State: StateReceived}
	if err := g.SetState(StateSynthesized); err != nil {
		t.Fatalf("legal transition failed: %v", err)
	}
	if g.State != StateSynthesized {
		t.Fatalf("state not applied: %s", g.State)
	}
	if err := g.SetState(StateActive); err == nil {
		t.Fatal("illegal transition accepted")
	}
	if g.State != StateSynthesized {
		t.Fatalf("state mutated on illegal transition: %s", g.State)
	}
}

func TestNewGrantID(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		id := NewGrantID()
		if len(id) != 26 {
			t.Fatalf("ulid length = %d, want 26", len(id))
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate grant id %s", id)
		}
		seen[id] = struct{}{}
		if _, err := ParseGrantID(id); err != nil {
			t.Fatalf("minted id fails strict parse: %v", err)
		}
	}
}

func TestParseGrantIDRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not-a-ulid", strings.Repeat("Z", 26), strings.Repeat("0", 25)} {
		if _, err := ParseGrantID(bad); err == nil {
			t.Errorf("ParseGrantID(%q) accepted", bad)
		}
	}
}

func TestSourceIdentityRoundTrip(t *testing.T) {
	id := NewGrantID()
	si := SourceIdentity(id)
	if si != "tg-"+id {
		t.Fatalf("SourceIdentity = %q", si)
	}
	back, err := GrantIDFromSourceIdentity(si)
	if err != nil || back != id {
		t.Fatalf("round trip = %q, %v", back, err)
	}
	if _, err := GrantIDFromSourceIdentity("aws-" + id); err == nil {
		t.Error("wrong prefix accepted")
	}
	if _, err := GrantIDFromSourceIdentity("tg-junk"); err == nil {
		t.Error("junk ulid accepted")
	}
}

func TestRoleSessionName(t *testing.T) {
	grantID := NewGrantID()
	tests := []struct {
		name    string
		agentID string
	}{
		{"short agent", "bot"},
		{"max slug agent", "a" + strings.Repeat("b", 31)},
		{"oversized agent", strings.Repeat("x", 100)},
		{"hostile bytes", "evil\x1b[2Jagent!"},
		{"empty agent", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RoleSessionName(tt.agentID, grantID)
			if len(got) > MaxRoleSessionNameChars {
				t.Fatalf("length %d exceeds %d: %q", len(got), MaxRoleSessionNameChars, got)
			}
			if !strings.HasPrefix(got, "tg-") {
				t.Fatalf("missing prefix: %q", got)
			}
			if !strings.HasSuffix(got, "-"+grantID) {
				t.Fatalf("grant ulid truncated or missing: %q", got)
			}
			for i := 0; i < len(got); i++ {
				c := got[i]
				valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
					c >= '0' && c <= '9' || strings.ContainsRune("_+=,.@-", rune(c))
				if !valid {
					t.Fatalf("invalid session name byte %q in %q", c, got)
				}
			}
		})
	}
	// A max-length slug must fit exactly without truncation.
	full := RoleSessionName("a"+strings.Repeat("b", 31), grantID)
	if len(full) != MaxRoleSessionNameChars {
		t.Fatalf("max slug name length = %d, want %d", len(full), MaxRoleSessionNameChars)
	}
}

func TestValidateAgentID(t *testing.T) {
	tests := []struct {
		id string
		ok bool
	}{
		{"invoice-bot", true},
		{"a1", true},
		{"a" + strings.Repeat("b", 31), true},
		{"a", false},
		{"", false},
		{"Invoice-Bot", false},
		{"-leading", false},
		{"has space", false},
		{"a" + strings.Repeat("b", 32), false},
		{"dot.name", false},
	}
	for _, tt := range tests {
		err := ValidateAgentID(tt.id)
		if tt.ok && err != nil {
			t.Errorf("ValidateAgentID(%q) = %v, want nil", tt.id, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("ValidateAgentID(%q) = nil, want error", tt.id)
		}
	}
}

func TestSanitizeCallerRef(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"clean", "run-4412/step-3", "run-4412/step-3"},
		{"strips controls", "run\x1b[31m-1\x07", "run31m-1"},
		{"strips disallowed runes", "a;b|c$d", "abcd"},
		{"caps length", strings.Repeat("a", 100), strings.Repeat("a", 64)},
		{"unicode dropped", "référence", "rfrence"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeCallerRef(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeForDisplay(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain", "hello world", "hello world"},
		{"keeps newline and tab", "a\n\tb", "a\n\tb"},
		{"strips csi", "safe\x1b[2J\x1b[1;31mred", "safered"},
		{"strips osc bel", "x\x1b]0;title\x07y", "xy"},
		{"strips osc st", "x\x1b]8;;http://evil\x1b\\y", "xy"},
		{"strips bare c0", "a\x00\x01\x08b\x7fc", "abc"},
		{"trailing esc", "abc\x1b", "abc"},
		{"unterminated csi", "abc\x1b[12", "abc"},
		{"two byte escape", "a\x1bcb", "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeForDisplay(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDenialCodesAndRecordKinds(t *testing.T) {
	if len(DenialCodes()) != 15 {
		t.Fatalf("denial code count = %d, want 15", len(DenialCodes()))
	}
	for _, c := range DenialCodes() {
		if !c.Valid() {
			t.Errorf("code %s invalid", c)
		}
	}
	if DenialCode("NOPE").Valid() {
		t.Error("unknown denial code reported valid")
	}
	if len(RecordKinds()) != 6 {
		t.Fatalf("record kind count = %d, want 6", len(RecordKinds()))
	}
	for _, k := range RecordKinds() {
		if !k.Valid() {
			t.Errorf("kind %s invalid", k)
		}
	}
	if RecordKind("nope").Valid() {
		t.Error("unknown record kind reported valid")
	}
}

func TestTransitiveTagKeys(t *testing.T) {
	keys := TransitiveTagKeys()
	if len(keys) != 2 || keys[0] != TagKeyAgent || keys[1] != TagKeyGrant {
		t.Fatalf("TransitiveTagKeys = %v", keys)
	}
	// Mutating the returned slice must not affect later calls.
	keys[0] = "tampered"
	again := TransitiveTagKeys()
	if again[0] != TagKeyAgent {
		t.Fatal("TransitiveTagKeys shares backing storage")
	}
}

func TestGrantIDsAreSortable(t *testing.T) {
	a := NewGrantID()
	time.Sleep(2 * time.Millisecond)
	b := NewGrantID()
	if !(a < b) {
		t.Fatalf("ulids not time ordered: %s then %s", a, b)
	}
}
