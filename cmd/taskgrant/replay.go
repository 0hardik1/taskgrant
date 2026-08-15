package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
	"github.com/0hardik1/taskgrant/internal/synth/compile"
)

// replayRecordBody is the subset of a decision body replay reads.
type replayRecordBody struct {
	Outcome      string `json:"outcome"`
	PolicyJSON   string `json:"policy_json"`
	MaxPolicy    int    `json:"max_policy_chars"`
	CatalogHash  string `json:"catalog_hash"`
	DatasetHash  string `json:"dataset_hash"`
	ConfigHash   string `json:"config_hash"`
	Capabilities []struct {
		ID      string            `json:"id"`
		Version int               `json:"version"`
		Params  map[string]string `json:"params"`
	} `json:"capabilities"`
}

// cmdReplay recompiles a grant from its logged inputs through the
// deterministic Compact-free compile path and diffs the bytes against
// the logged policy (section 9.4). Exit codes: 0 match, 1 mismatch or
// error, 3 environment drift made the replay non-comparable.
func cmdReplay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fail(stderr, "replay: exactly one grant id is required")
	}
	grantID := rest[0]

	cfg, ds, snap, err := loadCore(*configPath)
	if err != nil {
		return fail(stderr, "replay: %v", err)
	}
	st, err := store.Open(store.Options{Path: cfg.Log.Path})
	if err != nil {
		return fail(stderr, "replay: %v", err)
	}
	defer st.Close()

	recs, err := st.GrantChain(context.Background(), grantID)
	if err != nil || len(recs) == 0 {
		return fail(stderr, "replay: no records for grant %s", grantID)
	}

	// The last policy-bearing record is the one that governed the mint.
	var body *replayRecordBody
	for _, rec := range recs {
		var candidate replayRecordBody
		if json.Unmarshal(rec.Body, &candidate) != nil {
			continue
		}
		if candidate.PolicyJSON != "" && len(candidate.Capabilities) > 0 {
			c := candidate
			body = &c
		}
	}
	if body == nil {
		return fail(stderr, "replay: grant %s has no policy-bearing record", grantID)
	}

	var warnings []string
	if body.CatalogHash != "" && body.CatalogHash != snap.CatalogHash() {
		warnings = append(warnings, fmt.Sprintf("catalog hash drifted: logged %s, current %s", body.CatalogHash, snap.CatalogHash()))
	}
	if body.DatasetHash != "" && body.DatasetHash != ds.Hash() {
		warnings = append(warnings, fmt.Sprintf("dataset hash drifted: logged %s, current %s", body.DatasetHash, ds.Hash()))
	}
	if body.ConfigHash != "" && body.ConfigHash != cfg.ConfigHash() {
		warnings = append(warnings, fmt.Sprintf("config hash drifted: logged %s, current %s", body.ConfigHash, cfg.ConfigHash()))
	}

	recompiled, err := replayCompile(cfg, ds, snap, body)
	if err != nil {
		return fail(stderr, "replay: recompile: %v", err)
	}

	match := string(recompiled) == body.PolicyJSON
	if *asJSON {
		jsonOut(stdout, map[string]any{
			"grant_id":   grantID,
			"match":      match,
			"logged":     body.PolicyJSON,
			"recompiled": string(recompiled),
			"warnings":   warnings,
		})
	} else {
		for _, w := range warnings {
			fmt.Fprintln(stderr, "warning: "+w)
		}
		if match {
			fmt.Fprintf(stdout, "replay ok: grant %s recompiles byte-identically (%d chars)\n", grantID, len(recompiled))
		} else {
			fmt.Fprintf(stdout, "REPLAY MISMATCH for grant %s\n", grantID)
			fmt.Fprintf(stdout, "logged     (%d chars): %s\n", len(body.PolicyJSON), body.PolicyJSON)
			fmt.Fprintf(stdout, "recompiled (%d chars): %s\n", len(recompiled), string(recompiled))
		}
	}
	if !match {
		if len(warnings) > 0 {
			return 3
		}
		return 1
	}
	return 0
}

// replayCompile re-renders the logged capability selection under the
// logged budget, exactly the way the running synthesizer's compiler
// adapter does (invariant I6 makes this deterministic).
func replayCompile(cfg *config.Config, ds *dataset.Dataset, snap *catalog.Snapshot, body *replayRecordBody) ([]byte, error) {
	compiler, err := compile.New(ds)
	if err != nil {
		return nil, err
	}
	sels := make([]compile.Selection, 0, len(body.Capabilities))
	for _, c := range body.Capabilities {
		capability, ok := snap.Capability(c.ID)
		if !ok {
			return nil, fmt.Errorf("capability %q is no longer in the catalog", c.ID)
		}
		if capability.Version != c.Version {
			return nil, fmt.Errorf("capability %s is version %d now, was %d at grant time",
				c.ID, capability.Version, c.Version)
		}
		params := c.Params
		if params == nil {
			params = map[string]string{}
		}
		validated, err := snap.ValidateParams(c.ID, params)
		if err != nil {
			return nil, fmt.Errorf("capability %s params: %w", c.ID, err)
		}
		sels = append(sels, compile.Selection{Capability: capability, Params: validated})
	}
	budget := body.MaxPolicy
	out, err := compiler.Compile(compile.Input{
		Selections:     sels,
		Region:         cfg.AWS.STSRegion,
		Accounts:       cfg.AWS.Accounts,
		MaxPolicyChars: budget,
		MaxPolicyArns:  offloadARNBudget(cfg),
	})
	if err != nil {
		return nil, err
	}
	return out.PolicyJSON, nil
}
