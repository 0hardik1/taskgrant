package main

// configcmd.go implements `taskgrant config validate | trust-policy |
// broker-policy` (architecture sections 8.6 and 10). The two policy
// commands emit the generated templates from the spec with the
// configured profile role ARNs filled in.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
)

// placeholderBrokerARN marks an unfilled broker principal in the
// trust-policy template.
const placeholderBrokerARN = "arn:aws:iam::111111111111:role/taskgrant-broker"

func cmdConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: taskgrant config <validate|trust-policy|broker-policy> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "validate":
		return cmdConfigValidate(rest, stdout, stderr)
	case "trust-policy":
		return cmdConfigTrustPolicy(rest, stdout, stderr)
	case "broker-policy":
		return cmdConfigBrokerPolicy(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "taskgrant config: unknown subcommand %q\n", sub)
		return 2
	}
}

// cmdConfigValidate loads and validates the config file, then checks
// the dataset artifact and the catalog when they are present, since a
// config that passes here should also start serving.
func cmdConfigValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		if *asJSON {
			jsonOut(stdout, map[string]any{"valid": false, "error": err.Error()})
		}
		return fail(stderr, "config validate: %v", err)
	}

	var warnings []string
	datasetHash, catalogHash := "", ""
	if _, statErr := os.Stat(cfg.Synth.DatasetPath); statErr != nil {
		warnings = append(warnings,
			fmt.Sprintf("dataset artifact %s is missing; run `taskgrant dataset update` before serving", cfg.Synth.DatasetPath))
	} else {
		ds, dsErr := dataset.Load(cfg.Synth.DatasetPath)
		if dsErr != nil {
			if *asJSON {
				jsonOut(stdout, map[string]any{"valid": false, "error": dsErr.Error()})
			}
			return fail(stderr, "config validate: %v", dsErr)
		}
		datasetHash = ds.Hash()
		snap, catErr := catalog.Load(cfg.Synth.CatalogPath, ds,
			catalog.WithExtraDeniedServices(cfg.Guardrails.ExtraDenyServices...))
		if catErr != nil {
			if *asJSON {
				jsonOut(stdout, map[string]any{"valid": false, "error": catErr.Error()})
			}
			return fail(stderr, "config validate: catalog: %v", catErr)
		}
		catalogHash = snap.CatalogHash()
	}

	if *asJSON {
		return jsonOut(stdout, map[string]any{
			"valid":        true,
			"config_hash":  cfg.ConfigHash(),
			"agents":       cfg.AgentIDs(),
			"profiles":     cfg.ProfileNames(),
			"dataset_hash": datasetHash,
			"catalog_hash": catalogHash,
			"warnings":     warnings,
		})
	}
	fmt.Fprintf(stdout, "config ok: %s\n", *configPath)
	fmt.Fprintf(stdout, "  config hash: %s\n", cfg.ConfigHash())
	fmt.Fprintf(stdout, "  agents: %d, profiles: %d\n", len(cfg.Agents), len(cfg.Profiles))
	if datasetHash != "" {
		fmt.Fprintf(stdout, "  dataset hash: %s\n", datasetHash)
	}
	if catalogHash != "" {
		fmt.Fprintf(stdout, "  catalog hash: %s\n", catalogHash)
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, "warning: "+w)
	}
	return 0
}

// trustPolicyDoc is the target-role trust policy of section 8.6, with
// struct field order matching the spec's JSON.
type trustPolicyDoc struct {
	Version   string                 `json:"Version"`
	Statement []trustPolicyStatement `json:"Statement"`
}

type trustPolicyStatement struct {
	Effect    string         `json:"Effect"`
	Principal map[string]any `json:"Principal"`
	Action    []string       `json:"Action"`
	Condition map[string]any `json:"Condition"`
}

// cmdConfigTrustPolicy emits one trust-policy document per profile
// role. Cross-account profiles (external_id set) add the sts:ExternalId
// condition.
func cmdConfigTrustPolicy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config trust-policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	brokerARN := fs.String("broker-arn", "", "the broker principal ARN for the trust policy Principal")
	onlyProfile := fs.String("profile", "", "emit for one profile only")
	asJSON := fs.Bool("json", false, "JSON output: map of profile to document")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return fail(stderr, "config trust-policy: %v", err)
	}
	principal := *brokerARN
	if principal == "" {
		principal = placeholderBrokerARN
		fmt.Fprintln(stderr, "warning: --broker-arn is unset; the Principal below is a placeholder, replace it with the broker role ARN")
	}

	names := cfg.ProfileNames()
	if *onlyProfile != "" {
		if _, ok := cfg.Profiles[*onlyProfile]; !ok {
			return fail(stderr, "config trust-policy: profile %q is not configured", *onlyProfile)
		}
		names = []string{*onlyProfile}
	}
	sort.Strings(names)

	type entry struct {
		RoleARN string         `json:"role_arn"`
		Policy  trustPolicyDoc `json:"trust_policy"`
	}
	out := map[string]entry{}
	for _, name := range names {
		p := cfg.Profiles[name]
		st := trustPolicyStatement{
			Effect:    "Allow",
			Principal: map[string]any{"AWS": principal},
			Action:    []string{"sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"},
			Condition: map[string]any{
				"StringLike":              map[string]any{"sts:SourceIdentity": "tg-*"},
				"ForAllValues:StringLike": map[string]any{"aws:TagKeys": "taskgrant:*"},
			},
		}
		if p.ExternalID != "" {
			st.Condition["StringEquals"] = map[string]any{"sts:ExternalId": p.ExternalID}
		}
		out[name] = entry{
			RoleARN: p.RoleARN,
			Policy:  trustPolicyDoc{Version: "2012-10-17", Statement: []trustPolicyStatement{st}},
		}
	}

	if *asJSON {
		return jsonOut(stdout, out)
	}
	for _, name := range names {
		e := out[name]
		fmt.Fprintf(stdout, "# profile %s: apply as the trust policy of %s\n", name, e.RoleARN)
		data, mErr := json.MarshalIndent(e.Policy, "", "  ")
		if mErr != nil {
			return fail(stderr, "config trust-policy: %v", mErr)
		}
		fmt.Fprintln(stdout, string(data))
		fmt.Fprintln(stdout)
	}
	fmt.Fprintln(stdout, "# sts:TagSession and sts:SetSourceIdentity are mandatory or mints fail.")
	fmt.Fprintln(stdout, "# Never condition resource policies or ABAC on taskgrant:caller_ref; it is agent-supplied.")
	return 0
}

// brokerPolicyDoc is the broker identity policy of section 8.6.
type brokerPolicyDoc struct {
	Version   string                  `json:"Version"`
	Statement []brokerPolicyStatement `json:"Statement"`
}

type brokerPolicyStatement struct {
	Sid      string   `json:"Sid"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

// cmdConfigBrokerPolicy emits the broker identity policy: the mint
// actions scoped to exactly the configured role ARNs, plus the inline
// policy writes on those roles only when revocation is enabled.
func cmdConfigBrokerPolicy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config broker-policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return fail(stderr, "config broker-policy: %v", err)
	}

	seen := map[string]struct{}{}
	var roleARNs []string
	for _, name := range cfg.ProfileNames() {
		arn := cfg.Profiles[name].RoleARN
		if _, dup := seen[arn]; dup {
			continue
		}
		seen[arn] = struct{}{}
		roleARNs = append(roleARNs, arn)
	}
	sort.Strings(roleARNs)
	if len(roleARNs) == 0 {
		return fail(stderr, "config broker-policy: no profiles configured")
	}

	doc := brokerPolicyDoc{
		Version: "2012-10-17",
		Statement: []brokerPolicyStatement{{
			Sid:      "TaskgrantMint",
			Effect:   "Allow",
			Action:   []string{"sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"},
			Resource: roleARNs,
		}},
	}
	if cfg.Revocation.Enabled {
		doc.Statement = append(doc.Statement, brokerPolicyStatement{
			Sid:      "TaskgrantRevocation",
			Effect:   "Allow",
			Action:   []string{"iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy"},
			Resource: roleARNs,
		})
	}

	if *asJSON {
		return jsonOut(stdout, doc)
	}
	fmt.Fprintln(stdout, "# Attach to the broker principal (IRSA/instance role). Chaining and cross-account")
	fmt.Fprintln(stdout, "# mints require TagSession/SetSourceIdentity in this caller policy, not just the trust policy.")
	data, mErr := json.MarshalIndent(doc, "", "  ")
	if mErr != nil {
		return fail(stderr, "config broker-policy: %v", mErr)
	}
	fmt.Fprintln(stdout, string(data))
	return 0
}
