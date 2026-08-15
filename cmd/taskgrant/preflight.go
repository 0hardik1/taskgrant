package main

// preflight.go implements `taskgrant preflight` (architecture section
// 8.6): a real minimal AssumeRole per profile with tags and
// SourceIdentity, immediately discarded, plus heuristic warnings about
// broad base roles and missing permissions boundaries when the IAM
// read calls are permitted. Endpoint-URL aware, so it works against
// LocalStack.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/revoke"
	"github.com/0hardik1/taskgrant/internal/stsmint"
)

// preflightPolicy is the near-empty session policy for the discarded
// mint: the credentials it yields can do nothing beyond
// sts:GetCallerIdentity, which every principal holds anyway.
const preflightPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}`

// broadPolicyMarkers flag attached managed policies that make the base
// role ceiling broad (precondition 1: taskgrant narrows a role, it does
// not scope a broad account).
var broadPolicyMarkers = []string{"AdministratorAccess", "PowerUserAccess", "FullAccess"}

// preflightResult is one profile's outcome.
type preflightResult struct {
	Profile        string   `json:"profile"`
	RoleARN        string   `json:"role_arn"`
	MintOK         bool     `json:"mint_ok"`
	Error          string   `json:"error,omitempty"`
	AssumedRoleARN string   `json:"assumed_role_arn,omitempty"`
	PackedPercent  int      `json:"packed_policy_size_percent,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	HeuristicsRan  bool     `json:"heuristics_ran"`
}

func cmdPreflight(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	onlyProfile := fs.String("profile", "", "check one profile only")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return fail(stderr, "preflight: %v", err)
	}
	names := cfg.ProfileNames()
	if *onlyProfile != "" {
		if _, ok := cfg.Profiles[*onlyProfile]; !ok {
			return fail(stderr, "preflight: profile %q is not configured", *onlyProfile)
		}
		names = []string{*onlyProfile}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fail(stderr, "preflight: no profiles configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// The minter owns the parent credential chain (I4); preflight logs
	// quietly and never prints minted secrets.
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	minter, err := stsmint.New(ctx, stsmint.Options{
		Region:      cfg.AWS.STSRegion,
		EndpointURL: cfg.AWS.EndpointURL,
		Logger:      quiet,
	})
	if err != nil {
		return fail(stderr, "preflight: %v", err)
	}
	if id, idErr := minter.CallerIdentity(ctx); idErr == nil {
		fmt.Fprintf(stderr, "caller identity: %s\n", id.ARN)
		if id.Chained {
			fmt.Fprintln(stderr, "note: the caller is itself a session; grants will clamp to 3600 seconds (chaining)")
		}
	}

	iam, iamErr := newIAMClient(cfg.AWS.EndpointURL, cfg.AWS.STSRegion)

	results := make([]preflightResult, 0, len(names))
	var passed []string
	for _, name := range names {
		p := cfg.Profiles[name]
		res := preflightResult{Profile: name, RoleARN: p.RoleARN}

		minted, mintErr := minter.Mint(ctx, stsmint.MintRequest{
			GrantID:         domain.NewGrantID(),
			AgentID:         "preflight",
			Profile:         name,
			RoleARN:         p.RoleARN,
			Region:          p.Region,
			PolicyJSON:      []byte(preflightPolicy),
			DurationSeconds: config.MinDurationSeconds,
			CallerRef:       "preflight",
			ExternalID:      p.ExternalID,
		})
		if mintErr != nil {
			res.Error = mintErr.Error()
		} else {
			// Credentials are discarded: only the metadata survives.
			res.MintOK = true
			res.AssumedRoleARN = minted.AssumedRoleARN
			res.PackedPercent = minted.PackedPolicySizePercent
			passed = append(passed, name)
		}

		if iamErr == nil {
			res.Warnings, res.HeuristicsRan = roleHeuristics(ctx, iam, p.RoleARN)
		}
		if !res.HeuristicsRan {
			res.Warnings = append(res.Warnings,
				"IAM read heuristics skipped (GetRole/ListAttachedRolePolicies not permitted or no credentials in the environment)")
		}
		results = append(results, res)
	}

	if len(passed) > 0 {
		if err := writePreflightMarker(cfg, passed); err != nil {
			fmt.Fprintf(stderr, "warning: could not record preflight passes: %v\n", err)
		}
	}

	failures := 0
	for _, r := range results {
		if !r.MintOK {
			failures++
		}
	}
	if *asJSON {
		jsonOut(stdout, map[string]any{
			"results":  results,
			"failures": failures,
		})
	} else {
		printPreflight(stdout, results)
	}
	if failures > 0 {
		return 1
	}
	return 0
}

// roleHeuristics runs the section 8.6 broad-role checks. It returns the
// warnings plus whether the IAM calls were permitted at all.
func roleHeuristics(ctx context.Context, iam *iamClient, roleARN string) ([]string, bool) {
	roleName, err := revoke.RoleNameFromARN(roleARN)
	if err != nil {
		return []string{fmt.Sprintf("role name not parseable from %q", roleARN)}, false
	}
	var warnings []string
	ran := false

	role, err := iam.getRole(ctx, roleName)
	if err == nil {
		ran = true
		if role.PermissionsBoundaryARN == "" {
			warnings = append(warnings,
				"role has no permissions boundary; consider one as a second ceiling (precondition 1)")
		}
	}

	attached, err := iam.listAttachedRolePolicies(ctx, roleName)
	if err == nil {
		ran = true
		for _, ap := range attached {
			for _, marker := range broadPolicyMarkers {
				if strings.Contains(ap.Name, marker) || strings.Contains(ap.ARN, marker) {
					warnings = append(warnings, fmt.Sprintf(
						"attached policy %s looks broad; session policies only narrow, they never grant, so the role ceiling stays broad",
						ap.Name))
					break
				}
			}
		}
	}
	return warnings, ran
}

// printPreflight renders the human-readable report.
func printPreflight(w io.Writer, results []preflightResult) {
	for _, r := range results {
		if r.MintOK {
			fmt.Fprintf(w, "PASS %s\n", r.Profile)
			fmt.Fprintf(w, "     assumed %s (credentials discarded)\n", r.AssumedRoleARN)
			if r.PackedPercent >= 0 {
				fmt.Fprintf(w, "     packed policy size: %d%%\n", r.PackedPercent)
			}
		} else {
			fmt.Fprintf(w, "FAIL %s\n", r.Profile)
			fmt.Fprintf(w, "     %s\n", r.Error)
			fmt.Fprintln(w, "     Check the trust policy (taskgrant config trust-policy) and the broker identity policy (taskgrant config broker-policy).")
		}
		for _, warn := range r.Warnings {
			fmt.Fprintf(w, "     warning: %s\n", warn)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Reminders (outside the session policy's reach):")
	fmt.Fprintln(w, "  - Resource policies naming assumed-role session ARNs bypass session policies; condition them on aws:SourceIdentity (StringLike tg-*).")
	fmt.Fprintln(w, "  - CloudTrail data events (S3 object-level, Lambda invoke) are off by default; without them per-object activity is unobservable.")
}
