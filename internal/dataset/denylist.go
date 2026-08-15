package dataset

import (
	"sort"
	"strings"
)

// DenylistVersion identifies the shipped escalation-action denylist.
// Bump it on every change to the list; the version is recorded so old
// decisions stay explainable.
const DenylistVersion = 1

// escalationDenylist is the shipped, versioned denylist of known
// privilege-escalation actions (sections 5.3 and G2). It applies
// regardless of the dataset's access level labels, because the dataset
// is a community scrape and can mislabel: iam:PassRole, for example,
// carries the Write level yet hands a role to another service. Keys
// are lowercase; matching is case-insensitive.
var escalationDenylist = map[string]string{
	// Canonical names keyed by lowercase form.
	"iam:passrole":                     "iam:PassRole",
	"iam:createaccesskey":              "iam:CreateAccessKey",
	"iam:attachrolepolicy":             "iam:AttachRolePolicy",
	"iam:putrolepolicy":                "iam:PutRolePolicy",
	"iam:attachuserpolicy":             "iam:AttachUserPolicy",
	"iam:putuserpolicy":                "iam:PutUserPolicy",
	"iam:attachgrouppolicy":            "iam:AttachGroupPolicy",
	"iam:putgrouppolicy":               "iam:PutGroupPolicy",
	"iam:createpolicyversion":          "iam:CreatePolicyVersion",
	"iam:setdefaultpolicyversion":      "iam:SetDefaultPolicyVersion",
	"iam:updateassumerolepolicy":       "iam:UpdateAssumeRolePolicy",
	"iam:createloginprofile":           "iam:CreateLoginProfile",
	"iam:updateloginprofile":           "iam:UpdateLoginProfile",
	"iam:addusertogroup":               "iam:AddUserToGroup",
	"sts:assumerole":                   "sts:AssumeRole",
	"lambda:addpermission":             "lambda:AddPermission",
	"lambda:updatefunctioncode":        "lambda:UpdateFunctionCode",
	"kms:putkeypolicy":                 "kms:PutKeyPolicy",
	"s3:putbucketpolicy":               "s3:PutBucketPolicy",
	"ec2:modifyinstanceattribute":      "ec2:ModifyInstanceAttribute",
	"glue:updatedevendpoint":           "glue:UpdateDevEndpoint",
	"cloudformation:createstack":       "cloudformation:CreateStack",
	"ssm:sendcommand":                  "ssm:SendCommand",
	"ssm:startsession":                 "ssm:StartSession",
	"secretsmanager:putresourcepolicy": "secretsmanager:PutResourcePolicy",
	"sns:addpermission":                "sns:AddPermission",
	"sqs:addpermission":                "sqs:AddPermission",
	"ecr:setrepositorypolicy":          "ecr:SetRepositoryPolicy",
}

// IsEscalationAction reports whether the action sits on the shipped
// escalation denylist. Matching is case-insensitive. The check is
// independent of the dataset artifact: an action stays denied even
// when the dataset labels it Read.
func IsEscalationAction(action string) bool {
	_, ok := escalationDenylist[strings.ToLower(strings.TrimSpace(action))]
	return ok
}

// EscalationDenylist returns the canonical denylisted action names,
// sorted. Fresh copy on every call.
func EscalationDenylist() []string {
	out := make([]string, 0, len(escalationDenylist))
	for _, name := range escalationDenylist {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// EscalationActionsIn returns the subset of actions that sit on the
// denylist, in input order, deduplicated. Convenient for guardrail
// verdict details.
func EscalationActionsIn(actions []string) []string {
	var hits []string
	seen := make(map[string]struct{})
	for _, a := range actions {
		key := strings.ToLower(strings.TrimSpace(a))
		if canonical, ok := escalationDenylist[key]; ok {
			if _, dup := seen[canonical]; !dup {
				seen[canonical] = struct{}{}
				hits = append(hits, canonical)
			}
		}
	}
	return hits
}
