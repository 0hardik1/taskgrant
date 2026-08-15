// Package revoke implements the best-effort revocation path of
// architecture section 8.5: deny-by-issue-time inline policies written
// to the base role with iam:PutRolePolicy. STS tokens cannot be
// invalidated; the primary control remains the short TTL. Every write
// serializes through one goroutine to avoid read-modify-write races on
// the inline policy document.
//
// Invariant I3 by construction: revocation conditions key only on the
// broker-authored grant ULID via the taskgrant:grant principal tag.
// There is no API that accepts caller_ref, and grant ids are validated
// as ULIDs before they enter a document.
package revoke

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// PolicyName is the inline role policy that carries every taskgrant
// deny statement for a role.
const PolicyName = "taskgrant-revocations"

// DefaultIssueTimeMargin is added to now in the DateLessThan
// aws:TokenIssueTime condition so in-flight STS mints on the propagation
// boundary are covered (section 8.5).
const DefaultIssueTimeMargin = 30 * time.Second

// MaxInlinePolicyChars is the IAM ceiling for one inline role policy.
const MaxInlinePolicyChars = 10240

// DefaultWarnChars is the accumulated-size warning threshold.
const DefaultWarnChars = 8192

// PolicyVersion is the only accepted IAM policy language version.
const PolicyVersion = "2012-10-17"

// grantTagConditionKey is the only principal-tag condition key
// revocation is allowed to use. It is broker-authored (I3);
// taskgrant:caller_ref must never appear here.
const grantTagConditionKey = "aws:PrincipalTag/" + domain.TagKeyGrant

// Statement is one deny statement of the revocation policy document.
type Statement struct {
	Sid       string                       `json:"Sid"`
	Effect    string                       `json:"Effect"`
	Action    string                       `json:"Action"`
	Resource  string                       `json:"Resource"`
	Condition map[string]map[string]string `json:"Condition"`
}

// Document is the revocation inline policy document.
type Document struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// sidRE parses the two Sid shapes this package writes. The digits after
// E are the unix-seconds moment the statement stops mattering and GC
// may remove it.
var sidRE = regexp.MustCompile(`^tg(All|G[0-9A-HJKMNP-TV-Z]{26})E([0-9]+)$`)

// RoleWideDeny builds the role-wide statement: Deny * on * for every
// session whose token was issued before now plus margin. It stops
// mattering after every pre-cutoff session has expired, bounded by
// maxSessionDuration.
func RoleWideDeny(now time.Time, margin, maxSessionDuration time.Duration) Statement {
	if margin <= 0 {
		margin = DefaultIssueTimeMargin
	}
	cutoff := now.UTC().Add(margin)
	expiry := cutoff.Add(maxSessionDuration)
	return Statement{
		Sid:      "tgAllE" + strconv.FormatInt(expiry.Unix(), 10),
		Effect:   "Deny",
		Action:   "*",
		Resource: "*",
		Condition: map[string]map[string]string{
			"DateLessThan": {
				"aws:TokenIssueTime": cutoff.Format(time.RFC3339),
			},
		},
	}
}

// GrantDeny builds the per-grant statement: the role-wide deny plus a
// StringEquals condition on the broker-authored taskgrant:grant
// principal tag. grantID must be a canonical grant ULID; any other
// value, including anything agent-supplied such as caller_ref, is
// rejected (I3). The statement stops mattering at grantExpiry plus
// margin; a zero grantExpiry falls back to now plus maxSessionDuration.
func GrantDeny(grantID string, now time.Time, margin, maxSessionDuration time.Duration, grantExpiry time.Time) (Statement, error) {
	if _, err := domain.ParseGrantID(grantID); err != nil {
		return Statement{}, fmt.Errorf("revoke: grant deny requires a broker grant ULID: %w", err)
	}
	if margin <= 0 {
		margin = DefaultIssueTimeMargin
	}
	cutoff := now.UTC().Add(margin)
	expiry := grantExpiry.UTC().Add(margin)
	if grantExpiry.IsZero() {
		expiry = now.UTC().Add(maxSessionDuration).Add(margin)
	}
	return Statement{
		Sid:      "tgG" + grantID + "E" + strconv.FormatInt(expiry.Unix(), 10),
		Effect:   "Deny",
		Action:   "*",
		Resource: "*",
		Condition: map[string]map[string]string{
			"DateLessThan": {
				"aws:TokenIssueTime": cutoff.Format(time.RFC3339),
			},
			"StringEquals": {
				grantTagConditionKey: grantID,
			},
		},
	}, nil
}

// sidExpiry extracts the GC moment encoded in one of this package's
// Sids. ok is false for foreign or malformed Sids; GC keeps those
// (fail safe).
func sidExpiry(sid string) (time.Time, bool) {
	m := sidRE.FindStringSubmatch(sid)
	if m == nil {
		return time.Time{}, false
	}
	secs, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(secs, 0).UTC(), true
}

// RoleNameFromARN extracts the role name from an IAM role ARN.
// PutRolePolicy takes the name, not the ARN; role paths are stripped.
func RoleNameFromARN(arn string) (string, error) {
	const marker = ":role/"
	i := strings.Index(arn, marker)
	if !strings.HasPrefix(arn, "arn:") || i < 0 {
		return "", fmt.Errorf("revoke: %q is not an IAM role ARN", arn)
	}
	full := arn[i+len(marker):]
	if full == "" {
		return "", fmt.Errorf("revoke: %q is not an IAM role ARN", arn)
	}
	// The role name is the last path segment.
	if j := strings.LastIndex(full, "/"); j >= 0 {
		full = full[j+1:]
	}
	if full == "" {
		return "", fmt.Errorf("revoke: %q has an empty role name", arn)
	}
	return full, nil
}
