package compile

import (
	"errors"
	"sort"
	"strings"
)

// globalServiceExemptions lists services whose APIs are global:
// aws:RequestedRegion would deaden their statements, so G5 exempts
// them. The list is deliberately short; a service absent here gets the
// region condition.
var globalServiceExemptions = map[string]struct{}{
	"artifact":          {},
	"cloudfront":        {},
	"globalaccelerator": {},
	"health":            {},
	"route53":           {},
	"route53domains":    {},
	"shield":            {},
	"support":           {},
	"trustedadvisor":    {},
	"waf":               {},
}

// GlobalServiceExemptions returns the exemption list, sorted. Fresh
// copy.
func GlobalServiceExemptions() []string {
	out := make([]string, 0, len(globalServiceExemptions))
	for s := range globalServiceExemptions {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// globalNamespaceServices are services with a global resource
// namespace: a matching-named resource can exist in a foreign account,
// so aws:ResourceAccount is mandatory (G5).
var globalNamespaceServices = map[string]struct{}{
	"s3": {},
}

// IsGlobalService reports whether the service is exempt from the
// aws:RequestedRegion injection.
func IsGlobalService(service string) bool {
	_, ok := globalServiceExemptions[strings.ToLower(service)]
	return ok
}

// injectMandatoryConditions applies G5 to one statement:
//
//   - aws:RequestedRegion on every statement, unless every action
//     belongs to a global-service exemption;
//   - aws:ResourceAccount whenever the resource came from a wildcard
//     allowlist entry, belongs to a global-namespace service (s3), or
//     renders with a wildcard account field.
//
// A capability that already pins either key keeps its admin-authored
// condition. Missing configuration fails closed.
func (c *Compiler) injectMandatoryConditions(s *stmt, in Input, wildcardValue bool) error {
	if needsRegionCondition(s) && !s.hasCondKey("aws:RequestedRegion") {
		if in.Region == "" {
			return errors.New("aws:RequestedRegion injection requires a region (G5)")
		}
		s.addCond("StringEquals", "aws:RequestedRegion", in.Region)
	}

	if needsAccountCondition(s, wildcardValue) && !s.hasCondKey("aws:ResourceAccount") {
		if len(in.Accounts) == 0 {
			return errors.New("aws:ResourceAccount injection requires configured accounts (G5)")
		}
		for _, acct := range in.Accounts {
			if strings.TrimSpace(acct) == "" {
				return errors.New("aws:ResourceAccount injection got an empty account id")
			}
			s.addCond("StringEquals", "aws:ResourceAccount", acct)
		}
	}
	return nil
}

// needsRegionCondition reports whether any action's service is
// non-global. A mixed statement gets the condition; the catalog should
// keep global-service actions in their own capabilities.
func needsRegionCondition(s *stmt) bool {
	for _, a := range s.actions {
		svc, _, ok := strings.Cut(a, ":")
		if !ok {
			return true
		}
		if _, exempt := globalServiceExemptions[strings.ToLower(svc)]; !exempt {
			return true
		}
	}
	return false
}

// needsAccountCondition reports whether the statement requires
// aws:ResourceAccount: a param matched a wildcard allowlist entry, a
// resource belongs to a global-namespace service, or a resource
// renders with a wildcard in its account field.
func needsAccountCondition(s *stmt, wildcardValue bool) bool {
	if wildcardValue {
		return true
	}
	for _, r := range s.resources {
		parts := strings.SplitN(r, ":", arnFields)
		if len(parts) != arnFields {
			continue
		}
		if _, global := globalNamespaceServices[strings.ToLower(parts[2])]; global {
			return true
		}
		if strings.Contains(parts[4], "*") {
			return true
		}
	}
	return false
}

// arnFields is the colon-separated field count of an ARN.
const arnFields = 6
