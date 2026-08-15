package domain

// DenialCode is a machine-readable reason for a denied grant, exactly
// the set in architecture section 5.6.
type DenialCode string

const (
	DenyNoMatch                DenialCode = "NO_MATCH"
	DenyAmbiguousMatch         DenialCode = "AMBIGUOUS_MATCH"
	DenyMissingParam           DenialCode = "MISSING_PARAM"
	DenyInvalidParam           DenialCode = "INVALID_PARAM"
	DenyNeedsStructuredHints   DenialCode = "NEEDS_STRUCTURED_HINTS"
	DenyGuardrailViolation     DenialCode = "GUARDRAIL_VIOLATION"
	DenyOverBudget             DenialCode = "OVER_BUDGET"
	DenyRateLimited            DenialCode = "RATE_LIMITED"
	DenyClarificationExhausted DenialCode = "CLARIFICATION_EXHAUSTED"
	DenyApprovalDenied         DenialCode = "APPROVAL_DENIED"
	DenyApprovalTimeout        DenialCode = "APPROVAL_TIMEOUT"
	DenyAgentNotPermitted      DenialCode = "AGENT_NOT_PERMITTED"
	DenyProfileNotAllowed      DenialCode = "PROFILE_NOT_ALLOWED"
	DenyPolicyTooLarge         DenialCode = "POLICY_TOO_LARGE"
	DenySTSError               DenialCode = "STS_ERROR"
)

// denialCodes is the closed set of valid denial codes.
var denialCodes = map[DenialCode]struct{}{
	DenyNoMatch: {}, DenyAmbiguousMatch: {}, DenyMissingParam: {},
	DenyInvalidParam: {}, DenyNeedsStructuredHints: {},
	DenyGuardrailViolation: {}, DenyOverBudget: {}, DenyRateLimited: {},
	DenyClarificationExhausted: {}, DenyApprovalDenied: {},
	DenyApprovalTimeout: {}, DenyAgentNotPermitted: {},
	DenyProfileNotAllowed: {}, DenyPolicyTooLarge: {}, DenySTSError: {},
}

// Valid reports whether c is a known denial code.
func (c DenialCode) Valid() bool {
	_, ok := denialCodes[c]
	return ok
}

// String returns the wire form of the denial code.
func (c DenialCode) String() string { return string(c) }

// DenialCodes returns every valid denial code as a fresh slice, in the
// order the architecture lists them.
func DenialCodes() []DenialCode {
	return []DenialCode{
		DenyNoMatch, DenyAmbiguousMatch, DenyMissingParam, DenyInvalidParam,
		DenyNeedsStructuredHints, DenyGuardrailViolation, DenyOverBudget,
		DenyRateLimited, DenyClarificationExhausted, DenyApprovalDenied,
		DenyApprovalTimeout, DenyAgentNotPermitted, DenyProfileNotAllowed,
		DenyPolicyTooLarge, DenySTSError,
	}
}

// RecordKind is the type tag of one decision log record (section 9.1).
type RecordKind string

const (
	RecordGrantDecision RecordKind = "grant_decision"
	RecordClarification RecordKind = "clarification"
	RecordApproval      RecordKind = "approval"
	RecordRevocation    RecordKind = "revocation"
	RecordRelease       RecordKind = "release"
	RecordPrune         RecordKind = "prune"
)

// recordKinds is the closed set of valid record kinds.
var recordKinds = map[RecordKind]struct{}{
	RecordGrantDecision: {}, RecordClarification: {}, RecordApproval: {},
	RecordRevocation: {}, RecordRelease: {}, RecordPrune: {},
}

// Valid reports whether k is a known record kind.
func (k RecordKind) Valid() bool {
	_, ok := recordKinds[k]
	return ok
}

// String returns the wire form of the record kind.
func (k RecordKind) String() string { return string(k) }

// RecordKinds returns every valid record kind as a fresh slice.
func RecordKinds() []RecordKind {
	return []RecordKind{
		RecordGrantDecision, RecordClarification, RecordApproval,
		RecordRevocation, RecordRelease, RecordPrune,
	}
}
