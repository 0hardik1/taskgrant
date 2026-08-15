package main

// provision.go implements `taskgrant provision` (architecture section
// 7.3 step 4): create or update the customer managed session policies
// that back managed_policy capabilities, and record their SHAs. A
// managed session policy is pre-provisioned and static, so it must
// cover the worst-case render of its capability: allowlist parameters
// expand to every allowlisted value and pattern-only parameters widen
// to a wildcard. Intersection semantics keep this safe; the managed
// policy only ever narrows the session further.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
	"github.com/0hardik1/taskgrant/internal/synth/compile"
)

// maxManagedPolicyChars is the IAM managed policy document limit.
const maxManagedPolicyChars = 6144

// maxProvisionCombos bounds worst-case cartesian expansion, mirroring
// the catalog loader's own ceiling.
const maxProvisionCombos = 4096

// provisionRecord is one capability's recorded provisioning state.
type provisionRecord struct {
	PolicyARN string `json:"policy_arn"`
	SHA256    string `json:"sha256"`
	Chars     int    `json:"chars"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
}

func cmdProvision(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	onlyCap := fs.String("capability", "", "provision one capability only")
	dryRun := fs.Bool("dry-run", false, "render and print documents, write nothing to IAM")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, _, snap, err := loadCore(*configPath)
	if err != nil {
		return fail(stderr, "provision: %v", err)
	}

	var managed []*catalog.Capability
	for _, c := range snap.Capabilities() {
		if !c.ManagedPolicy {
			continue
		}
		if *onlyCap != "" && c.ID != *onlyCap {
			continue
		}
		managed = append(managed, c)
	}
	if len(managed) == 0 {
		if *onlyCap != "" {
			return fail(stderr, "provision: capability %q is not a managed_policy catalog entry", *onlyCap)
		}
		fmt.Fprintln(stdout, "no managed_policy capabilities in the catalog; nothing to provision")
		return 0
	}

	var iam *iamClient
	if !*dryRun {
		iam, err = newIAMClient(cfg.AWS.EndpointURL, cfg.AWS.STSRegion)
		if err != nil {
			return fail(stderr, "provision: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	records := map[string]provisionRecord{}
	failures := 0
	for _, c := range managed {
		doc, rerr := renderManagedPolicy(cfg, snap, c)
		if rerr != nil {
			failures++
			fmt.Fprintf(stderr, "provision: %s: %v\n", c.ID, rerr)
			continue
		}
		sum := sha256.Sum256(doc)
		shaHex := hex.EncodeToString(sum[:])

		arn, name, path, aerr := provisionTarget(cfg, c)
		if aerr != nil {
			failures++
			fmt.Fprintf(stderr, "provision: %s: %v\n", c.ID, aerr)
			continue
		}

		status := "rendered"
		if !*dryRun {
			var serr error
			arn, status, serr = ensureManagedPolicy(ctx, iam, arn, name, path, c.ID, string(doc))
			if serr != nil {
				failures++
				fmt.Fprintf(stderr, "provision: %s: %v\n", c.ID, serr)
				continue
			}
		}
		records[c.ID] = provisionRecord{
			PolicyARN: arn,
			SHA256:    shaHex,
			Chars:     len(doc),
			Status:    status,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if !*asJSON {
			fmt.Fprintf(stdout, "%s: %s\n", c.ID, status)
			fmt.Fprintf(stdout, "  policy arn: %s\n", arn)
			fmt.Fprintf(stdout, "  sha256:     %s (%d chars)\n", shaHex, len(doc))
			if c.ManagedPolicyARN == "" {
				fmt.Fprintf(stdout, "  note: set managed_policy_arn: %s in the catalog entry so offload can use it\n", arn)
			}
			if *dryRun {
				fmt.Fprintln(stdout, string(doc))
			}
		}
	}

	if len(records) > 0 && !*dryRun {
		if err := writeProvisionMarker(cfg, records); err != nil {
			fmt.Fprintf(stderr, "warning: could not record provisioned SHAs: %v\n", err)
		}
	}
	if *asJSON {
		jsonOut(stdout, map[string]any{
			"records":  records,
			"failures": failures,
			"dry_run":  *dryRun,
		})
	}
	if failures > 0 {
		return 1
	}
	return 0
}

// provisionTarget resolves the policy ARN, name, and path for one
// capability: the catalog's pinned managed_policy_arn when present,
// otherwise a derived taskgrant-namespaced policy in the first
// configured account.
func provisionTarget(cfg *config.Config, c *catalog.Capability) (arn, name, path string, err error) {
	if c.ManagedPolicyARN != "" {
		acct, p, n, perr := parsePolicyARN(c.ManagedPolicyARN)
		if perr != nil {
			return "", "", "", perr
		}
		_ = acct
		return c.ManagedPolicyARN, n, p, nil
	}
	if len(cfg.AWS.Accounts) == 0 {
		return "", "", "", fmt.Errorf("no managed_policy_arn in the catalog and aws.accounts is empty; cannot derive a policy ARN")
	}
	name = "taskgrant-" + strings.ReplaceAll(c.ID, ".", "-")
	path = "/taskgrant/"
	arn = fmt.Sprintf("arn:aws:iam::%s:policy%s%s", cfg.AWS.Accounts[0], path, name)
	return arn, name, path, nil
}

// parsePolicyARN splits an IAM managed policy ARN into account, path,
// and name.
func parsePolicyARN(arn string) (account, path, name string, err error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || !strings.HasPrefix(parts[5], "policy/") {
		return "", "", "", fmt.Errorf("%q is not an IAM managed policy ARN", arn)
	}
	account = parts[4]
	rest := strings.TrimPrefix(parts[5], "policy")
	i := strings.LastIndex(rest, "/")
	name = rest[i+1:]
	path = rest[:i+1]
	if name == "" {
		return "", "", "", fmt.Errorf("%q has an empty policy name", arn)
	}
	return account, path, name, nil
}

// ensureManagedPolicy creates the policy or writes a new default
// version when the document drifted. Returns the authoritative ARN and
// a status of created, updated, or unchanged.
func ensureManagedPolicy(ctx context.Context, iam *iamClient, arn, name, path, capID, doc string) (string, string, error) {
	desc := "taskgrant managed session policy for capability " + capID + " (worst-case render)"
	createdARN, err := iam.createPolicy(ctx, name, path, doc, desc)
	if err == nil {
		if createdARN != "" {
			arn = createdARN
		}
		return arn, "created", nil
	}
	if iamErrorCode(err) != "EntityAlreadyExists" {
		return arn, "", err
	}

	ver, err := iam.getPolicyDefaultVersion(ctx, arn)
	if err != nil {
		return arn, "", err
	}
	current, err := iam.getPolicyVersionDocument(ctx, arn, ver)
	if err != nil {
		return arn, "", err
	}
	if jsonEquivalent(current, doc) {
		return arn, "unchanged", nil
	}
	err = iam.createPolicyVersion(ctx, arn, doc)
	if iamErrorCode(err) == "LimitExceeded" {
		if derr := iam.deleteOldestNonDefaultVersion(ctx, arn); derr != nil {
			return arn, "", derr
		}
		err = iam.createPolicyVersion(ctx, arn, doc)
	}
	if err != nil {
		return arn, "", err
	}
	return arn, "updated", nil
}

// jsonEquivalent compares two JSON documents structurally.
func jsonEquivalent(a, b string) bool {
	var va, vb any
	if json.Unmarshal([]byte(a), &va) != nil || json.Unmarshal([]byte(b), &vb) != nil {
		return a == b
	}
	ca, errA := json.Marshal(va)
	cb, errB := json.Marshal(vb)
	return errA == nil && errB == nil && string(ca) == string(cb)
}

// provisionMarkerPath stores recorded SHAs next to the decision log,
// like the preflight marker.
func provisionMarkerPath(cfg *config.Config) string {
	return cfg.Log.Path + ".provision.json"
}

// writeProvisionMarker merges the new records into the marker file.
func writeProvisionMarker(cfg *config.Config, records map[string]provisionRecord) error {
	existing := map[string]provisionRecord{}
	if data, err := os.ReadFile(provisionMarkerPath(cfg)); err == nil {
		_ = json.Unmarshal(data, &existing)
	}
	for id, rec := range records {
		existing[id] = rec
	}
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(provisionMarkerPath(cfg), data, 0o640)
}

// managedPolicyDoc is the rendered document, field order fixed for
// review readability.
type managedPolicyDoc struct {
	Version   string             `json:"Version"`
	Statement []managedStatement `json:"Statement"`
}

type managedStatement struct {
	Sid       string                    `json:"Sid"`
	Effect    string                    `json:"Effect"`
	Action    []string                  `json:"Action"`
	Resource  []string                  `json:"Resource"`
	Condition map[string]map[string]any `json:"Condition,omitempty"`
}

// placeholderPattern finds {param} placeholders in templates.
var placeholderPattern = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)

// renderManagedPolicy renders the worst-case policy document for one
// capability.
func renderManagedPolicy(cfg *config.Config, snap *catalog.Snapshot, c *catalog.Capability) ([]byte, error) {
	groups := groupActions(c)
	doc := managedPolicyDoc{Version: compile.PolicyVersion}
	for i, g := range groups {
		resources, err := renderGroupResources(snap, c, g)
		if err != nil {
			return nil, err
		}
		if len(resources) == 0 {
			return nil, fmt.Errorf("actions %v render no resources; managed offload needs a resource template", g.actions)
		}
		cond, err := renderGroupConditions(snap, c, g)
		if err != nil {
			return nil, err
		}
		injectProvisionConditions(cfg, g, resources, cond)
		doc.Statement = append(doc.Statement, managedStatement{
			Sid:       provisionSid(c.ID, i),
			Effect:    "Allow",
			Action:    g.actions,
			Resource:  resources,
			Condition: cond,
		})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > maxManagedPolicyChars {
		return nil, fmt.Errorf("rendered document is %d chars, above the IAM managed policy limit of %d",
			len(data), maxManagedPolicyChars)
	}
	return data, nil
}

// actionGroup is one set of actions sharing resource and condition
// templates.
type actionGroup struct {
	actions    []string
	resources  []catalog.ResourceTemplate
	conditions []catalog.ConditionTemplate
}

// groupActions groups the capability's actions by their applicable
// templates, in deterministic order.
func groupActions(c *catalog.Capability) []actionGroup {
	byKey := map[string]*actionGroup{}
	var order []string
	for _, action := range c.Actions {
		var res []catalog.ResourceTemplate
		var keyParts []string
		for _, rt := range c.Resources {
			if rt.AppliesTo(action) {
				res = append(res, rt)
				keyParts = append(keyParts, "r:"+rt.Template)
			}
		}
		var conds []catalog.ConditionTemplate
		for _, ct := range c.Conditions {
			if ct.AppliesTo(action) {
				conds = append(conds, ct)
				keyParts = append(keyParts, "c:"+ct.Op+"|"+ct.Key+"|"+ct.Value)
			}
		}
		key := strings.Join(keyParts, "\n")
		g, ok := byKey[key]
		if !ok {
			g = &actionGroup{resources: res, conditions: conds}
			byKey[key] = g
			order = append(order, key)
		}
		g.actions = append(g.actions, action)
	}
	out := make([]actionGroup, 0, len(order))
	for _, key := range order {
		g := byKey[key]
		sort.Strings(g.actions)
		out = append(out, *g)
	}
	return out
}

// worstCaseValues returns the worst-case substitutions for one param:
// every allowlisted value, or a bare wildcard for pattern-only params.
func worstCaseValues(snap *catalog.Snapshot, c *catalog.Capability, name string) ([]string, error) {
	p, ok := c.Params[name]
	if !ok {
		return nil, fmt.Errorf("template references undeclared param %q", name)
	}
	if p.AllowlistRef != "" {
		entries, ok := snap.Allowlist(p.AllowlistRef)
		if !ok || len(entries) == 0 {
			return nil, fmt.Errorf("param %q references missing or empty allowlist %q", name, p.AllowlistRef)
		}
		return entries, nil
	}
	return []string{"*"}, nil
}

// renderTemplateWorstCase expands one template across the cartesian
// product of its params' worst-case values.
func renderTemplateWorstCase(snap *catalog.Snapshot, c *catalog.Capability, tpl string) ([]string, error) {
	names := map[string]struct{}{}
	for _, m := range placeholderPattern.FindAllStringSubmatch(tpl, -1) {
		names[m[1]] = struct{}{}
	}
	renders := []string{tpl}
	for name := range names {
		values, err := worstCaseValues(snap, c, name)
		if err != nil {
			return nil, err
		}
		var next []string
		for _, r := range renders {
			for _, v := range values {
				next = append(next, strings.ReplaceAll(r, "{"+name+"}", v))
				if len(next) > maxProvisionCombos {
					return nil, fmt.Errorf("worst-case render combinations exceed %d", maxProvisionCombos)
				}
			}
		}
		renders = next
	}
	for i, r := range renders {
		renders[i] = collapseStars(r)
	}
	return renders, nil
}

// collapseStars folds runs of '*' into one.
func collapseStars(s string) string {
	for strings.Contains(s, "**") {
		s = strings.ReplaceAll(s, "**", "*")
	}
	return s
}

// renderGroupResources renders and deduplicates the group's resources.
func renderGroupResources(snap *catalog.Snapshot, c *catalog.Capability, g actionGroup) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	for _, rt := range g.resources {
		renders, err := renderTemplateWorstCase(snap, c, rt.Template)
		if err != nil {
			return nil, fmt.Errorf("resource template %q: %w", rt.Template, err)
		}
		for _, r := range renders {
			if _, dup := seen[r]; !dup {
				seen[r] = struct{}{}
				out = append(out, r)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// renderGroupConditions renders the group's admin-authored conditions.
// A condition whose worst-case value collapses to a bare wildcard is
// vacuous and dropped.
func renderGroupConditions(snap *catalog.Snapshot, c *catalog.Capability, g actionGroup) (map[string]map[string]any, error) {
	cond := map[string]map[string]any{}
	for _, ct := range g.conditions {
		renders, err := renderTemplateWorstCase(snap, c, ct.Value)
		if err != nil {
			return nil, fmt.Errorf("condition %s %s: %w", ct.Op, ct.Key, err)
		}
		var values []string
		vacuous := false
		for _, r := range renders {
			if r == "*" {
				vacuous = true
				break
			}
			values = append(values, r)
		}
		if vacuous || len(values) == 0 {
			continue
		}
		sort.Strings(values)
		if cond[ct.Op] == nil {
			cond[ct.Op] = map[string]any{}
		}
		cond[ct.Op][ct.Key] = scalarOrSlice(values)
	}
	return cond, nil
}

// injectProvisionConditions mirrors G5 for the pre-provisioned
// document: aws:RequestedRegion unless every service is globally
// exempt, and aws:ResourceAccount for global-namespace services or
// wildcard-bearing resources.
func injectProvisionConditions(cfg *config.Config, g actionGroup, resources []string, cond map[string]map[string]any) {
	services := map[string]struct{}{}
	for _, a := range g.actions {
		if svc, _, ok := strings.Cut(a, ":"); ok {
			services[strings.ToLower(svc)] = struct{}{}
		}
	}
	allGlobal := true
	hasS3 := false
	for svc := range services {
		if !compile.IsGlobalService(svc) {
			allGlobal = false
		}
		if svc == "s3" {
			hasS3 = true
		}
	}

	if !allGlobal && !condHasKey(cond, "aws:RequestedRegion") {
		regions := map[string]struct{}{}
		if cfg.AWS.STSRegion != "" {
			regions[cfg.AWS.STSRegion] = struct{}{}
		}
		for _, p := range cfg.Profiles {
			if p.Region != "" {
				regions[p.Region] = struct{}{}
			}
		}
		if len(regions) > 0 {
			list := make([]string, 0, len(regions))
			for r := range regions {
				list = append(list, r)
			}
			sort.Strings(list)
			if cond["StringEquals"] == nil {
				cond["StringEquals"] = map[string]any{}
			}
			cond["StringEquals"]["aws:RequestedRegion"] = scalarOrSlice(list)
		}
	}

	wildcardResource := false
	for _, r := range resources {
		if strings.Contains(r, "*") {
			wildcardResource = true
			break
		}
	}
	if (hasS3 || wildcardResource) && len(cfg.AWS.Accounts) > 0 && !condHasKey(cond, "aws:ResourceAccount") {
		if cond["StringEquals"] == nil {
			cond["StringEquals"] = map[string]any{}
		}
		cond["StringEquals"]["aws:ResourceAccount"] = scalarOrSlice(append([]string(nil), cfg.AWS.Accounts...))
	}
}

// condHasKey reports whether any operator already carries the key.
func condHasKey(cond map[string]map[string]any, key string) bool {
	for _, kv := range cond {
		for k := range kv {
			if strings.EqualFold(k, key) {
				return true
			}
		}
	}
	return false
}

// scalarOrSlice renders a one-element list as a scalar.
func scalarOrSlice(values []string) any {
	if len(values) == 1 {
		return values[0]
	}
	return values
}

// provisionSid builds a statement Sid from the capability id.
func provisionSid(capID string, ordinal int) string {
	var b strings.Builder
	b.WriteString("Tg")
	upper := true
	for _, r := range capID {
		switch {
		case r >= 'a' && r <= 'z':
			if upper {
				b.WriteRune(r - 32)
				upper = false
			} else {
				b.WriteRune(r)
			}
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			upper = false
		default:
			upper = true
		}
	}
	fmt.Fprintf(&b, "%d", ordinal)
	return b.String()
}
