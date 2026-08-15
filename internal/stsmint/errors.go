package stsmint

import (
	"fmt"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// packedPolicyTooLargeCode is the STS API error code for a session
// whose packed policy plus session tags exceed the undisclosed binary
// limit. It can fire even under 2,048 plaintext chars (section 7.1).
const packedPolicyTooLargeCode = "PackedPolicyTooLarge"

// PackedPolicyTooLargeError marks one AssumeRole rejection for packed
// size. The broker reacts by invoking the synthesizer seam's Compact
// exactly once and retrying the mint (section 7.3);
// Minter.MintWithCompact packages that sequence.
type PackedPolicyTooLargeError struct {
	// PolicyChars is the plaintext length of the rejected policy.
	PolicyChars int
	// PolicyARNCount is the number of managed policy ARNs attached.
	PolicyARNCount int
	// Message is the raw STS error message. It is internal-only
	// material; never surface it to an agent unsanitized.
	Message string
}

// Error implements error.
func (e *PackedPolicyTooLargeError) Error() string {
	return fmt.Sprintf("sts rejected the packed policy as too large (policy %d chars, %d policy arns): %s",
		e.PolicyChars, e.PolicyARNCount, e.Message)
}

// MintAttempt is the metadata of one failed mint attempt, kept for the
// decision record.
type MintAttempt struct {
	PolicyChars    int    `json:"policy_chars"`
	PolicyARNCount int    `json:"policy_arn_count"`
	Message        string `json:"message"`
}

// PolicyTooLargeError is terminal: the single Compact retry also hit
// PackedPolicyTooLarge. It maps to denial code POLICY_TOO_LARGE and
// carries both attempts so the decision log shows the whole sequence.
type PolicyTooLargeError struct {
	// Attempts holds the original attempt first, the compacted retry
	// second.
	Attempts [2]MintAttempt
}

// Error implements error.
func (e *PolicyTooLargeError) Error() string {
	return fmt.Sprintf("policy too large after the single compact retry: attempt 1 was %d chars, attempt 2 was %d chars",
		e.Attempts[0].PolicyChars, e.Attempts[1].PolicyChars)
}

// DenialCode returns the machine-readable denial code for this error.
func (e *PolicyTooLargeError) DenialCode() domain.DenialCode {
	return domain.DenyPolicyTooLarge
}
