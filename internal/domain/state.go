package domain

import "fmt"

// State is one node of the grant state machine (architecture section 2).
type State string

// Grant states, exactly the section 2 state machine.
const (
	StateReceived           State = "received"
	StateSynthesized        State = "synthesized"
	StateGuardrails         State = "guardrails"
	StateAutoApproved       State = "auto_approved"
	StatePendingApproval    State = "pending_approval"
	StateApproved           State = "approved"
	StateNeedsClarification State = "needs_clarification"
	StateDenied             State = "denied"
	StateMinted             State = "minted"
	StateActive             State = "active"
	StateExpired            State = "expired"
	StateExpiredPending     State = "expired_pending"
)

// legalTransitions is the edge set of the state machine. The diagram
// edges from section 2 are all present. Three operational edges are
// included on purpose:
//
//   - received to denied: boundary rejections (rate limit, agent not
//     permitted) happen before synthesis.
//   - synthesized to denied: the confidence gate can deny (NO_MATCH)
//     before the guardrail stage.
//   - auto_approved / approved to denied: the STS call at mint time can
//     fail (STS_ERROR).
//
// A clarification retry re-enters synthesis on the same grant, so
// needs_clarification transitions back to synthesized; when the retry
// budget is exhausted the grant is denied (CLARIFICATION_EXHAUSTED).
var legalTransitions = map[State][]State{
	StateReceived:           {StateSynthesized, StateDenied},
	StateSynthesized:        {StateGuardrails, StateNeedsClarification, StateDenied},
	StateGuardrails:         {StateAutoApproved, StatePendingApproval, StateDenied},
	StateAutoApproved:       {StateMinted, StateDenied},
	StatePendingApproval:    {StateApproved, StateDenied, StateExpiredPending},
	StateApproved:           {StateMinted, StateDenied},
	StateNeedsClarification: {StateSynthesized, StateDenied},
	StateMinted:             {StateActive, StateExpired},
	StateActive:             {StateExpired},
	StateDenied:             nil,
	StateExpired:            nil,
	StateExpiredPending:     nil,
}

// Valid reports whether s is a known grant state.
func (s State) Valid() bool {
	_, ok := legalTransitions[s]
	return ok
}

// Terminal reports whether s has no outgoing transitions.
func (s State) Terminal() bool {
	next, ok := legalTransitions[s]
	return ok && len(next) == 0
}

// CanTransitionTo reports whether the edge from s to next is legal.
func (s State) CanTransitionTo(next State) bool {
	for _, t := range legalTransitions[s] {
		if t == next {
			return true
		}
	}
	return false
}

// String returns the wire form of the state.
func (s State) String() string { return string(s) }

// States returns every valid state. The slice is a fresh copy.
func States() []State {
	return []State{
		StateReceived, StateSynthesized, StateGuardrails, StateAutoApproved,
		StatePendingApproval, StateApproved, StateNeedsClarification,
		StateDenied, StateMinted, StateActive, StateExpired, StateExpiredPending,
	}
}

// TransitionError describes an illegal state transition attempt.
type TransitionError struct {
	From State
	To   State
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("illegal grant state transition: %s to %s", e.From, e.To)
}

// ValidateTransition returns nil when the edge from one state to the
// next is legal, and a *TransitionError otherwise. Unknown states are
// always illegal.
func ValidateTransition(from, to State) error {
	if !from.Valid() {
		return fmt.Errorf("unknown grant state %q", string(from))
	}
	if !to.Valid() {
		return fmt.Errorf("unknown grant state %q", string(to))
	}
	if !from.CanTransitionTo(to) {
		return &TransitionError{From: from, To: to}
	}
	return nil
}
