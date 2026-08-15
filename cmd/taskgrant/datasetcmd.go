package main

// datasetcmd.go implements `taskgrant dataset update` and `taskgrant
// dataset show-hash` (architecture section 5.3). Update fetches the
// upstream iam-dataset definition, trims it to the pinned artifact
// schema, emits a human-readable diff against the current artifact for
// PR review, and writes the new artifact atomically. The running broker
// never fetches anything; only this command does.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
)

// defaultDatasetURL is the upstream trimmed source (section 5.3).
const defaultDatasetURL = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/iam_definition.json"

// datasetCommitURL resolves the upstream commit SHA for source_commit.
const datasetCommitURL = "https://api.github.com/repos/iann0036/iam-dataset/commits/main"

// maxDatasetDownloadBytes bounds the upstream download.
const maxDatasetDownloadBytes = 256 << 20

func cmdDataset(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: taskgrant dataset <update|show-hash> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "update":
		return cmdDatasetUpdate(rest, stdout, stderr)
	case "show-hash":
		return cmdDatasetShowHash(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "taskgrant dataset: unknown subcommand %q\n", sub)
		return 2
	}
}

// cmdDatasetShowHash prints the pinned artifact's identity.
func cmdDatasetShowHash(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dataset show-hash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return fail(stderr, "dataset show-hash: %v", err)
	}
	ds, err := dataset.Load(cfg.Synth.DatasetPath)
	if err != nil {
		return fail(stderr, "dataset show-hash: %v", err)
	}
	if *asJSON {
		return jsonOut(stdout, map[string]any{
			"path":           cfg.Synth.DatasetPath,
			"hash":           ds.Hash(),
			"source_commit":  ds.SourceCommit(),
			"schema_version": ds.SchemaVersion(),
			"actions":        ds.Len(),
		})
	}
	fmt.Fprintf(stdout, "path:           %s\n", cfg.Synth.DatasetPath)
	fmt.Fprintf(stdout, "hash:           %s\n", ds.Hash())
	fmt.Fprintf(stdout, "source commit:  %s\n", ds.SourceCommit())
	fmt.Fprintf(stdout, "schema version: %d\n", ds.SchemaVersion())
	fmt.Fprintf(stdout, "actions:        %d\n", ds.Len())
	return 0
}

// upstreamService is the iam_definition.json wire shape this command
// reads: an array of services, each with privileges.
type upstreamService struct {
	Prefix     string `json:"prefix"`
	Privileges []struct {
		Privilege     string `json:"privilege"`
		AccessLevel   string `json:"access_level"`
		ResourceTypes []struct {
			ResourceType  string   `json:"resource_type"`
			ConditionKeys []string `json:"condition_keys"`
		} `json:"resource_types"`
	} `json:"privileges"`
}

// artifactAction is one trimmed action entry, matching the dataset
// package's artifact schema.
type artifactAction struct {
	AccessLevel   string   `json:"access_level"`
	ResourceTypes []string `json:"resource_types"`
	ConditionKeys []string `json:"condition_keys"`
}

// artifactFile is the artifact wire shape.
type artifactFile struct {
	SchemaVersion int                       `json:"schema_version"`
	SourceCommit  string                    `json:"source_commit"`
	Actions       map[string]artifactAction `json:"actions"`
}

func cmdDatasetUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dataset update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	srcURL := fs.String("url", defaultDatasetURL, "upstream iam_definition.json URL")
	outPath := fs.String("out", "", "artifact output path (default: synth.dataset_path)")
	sourceCommit := fs.String("source-commit", "", "override the recorded source commit")
	dryRun := fs.Bool("dry-run", false, "diff only, write nothing")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return fail(stderr, "dataset update: %v", err)
	}
	target := *outPath
	if target == "" {
		target = cfg.Synth.DatasetPath
	}
	if target == "" {
		return fail(stderr, "dataset update: no output path (set synth.dataset_path or --out)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fmt.Fprintf(stderr, "fetching %s\n", *srcURL)
	raw, err := fetchURL(ctx, *srcURL)
	if err != nil {
		return fail(stderr, "dataset update: fetch: %v", err)
	}
	commit := *sourceCommit
	if commit == "" {
		commit = fetchUpstreamCommit(ctx)
		if commit == "" {
			commit = "main-" + time.Now().UTC().Format("20060102")
			fmt.Fprintf(stderr, "warning: upstream commit lookup failed; recording source_commit %q\n", commit)
		}
	}

	artifact, skipped, err := trimUpstream(raw, commit)
	if err != nil {
		return fail(stderr, "dataset update: %v", err)
	}
	data, err := json.MarshalIndent(artifact, "", " ")
	if err != nil {
		return fail(stderr, "dataset update: encode artifact: %v", err)
	}
	data = append(data, '\n')

	// The artifact must load through the same code path the broker uses
	// before it is allowed on disk.
	newDS, err := dataset.LoadBytes(data)
	if err != nil {
		return fail(stderr, "dataset update: new artifact fails validation: %v", err)
	}

	diff := diffDatasets(cfg, target, newDS)
	if *asJSON {
		jsonOut(stdout, map[string]any{
			"hash":            newDS.Hash(),
			"source_commit":   newDS.SourceCommit(),
			"actions":         newDS.Len(),
			"skipped_actions": skipped,
			"new_actions":     diff.added,
			"removed_actions": diff.removed,
			"level_changes":   diff.levelChanges,
			"catalog_broken":  diff.catalogBroken,
			"written":         !*dryRun,
			"path":            target,
		})
	} else {
		printDatasetDiff(stdout, diff, newDS, skipped)
	}

	if len(diff.catalogBroken) > 0 {
		fmt.Fprintf(stderr, "ERROR: %d catalog action(s) vanish in the new dataset; the broker will refuse to start. Fix the catalog first.\n",
			len(diff.catalogBroken))
		return 1
	}
	if *dryRun {
		fmt.Fprintln(stderr, "dry run: nothing written")
		return 0
	}
	if err := writeFileAtomic(target, data, 0o644); err != nil {
		return fail(stderr, "dataset update: write: %v", err)
	}
	if !*asJSON {
		fmt.Fprintf(stdout, "wrote %s\n", target)
		fmt.Fprintf(stdout, "hash: %s\n", newDS.Hash())
		fmt.Fprintln(stdout, "Commit the artifact and restart the broker to pin the new hash.")
	}
	return 0
}

// trimUpstream converts the upstream definition into the artifact
// schema. Actions with access levels the artifact schema does not
// carry are skipped and counted.
func trimUpstream(raw []byte, sourceCommit string) (*artifactFile, int, error) {
	var services []upstreamService
	if err := json.Unmarshal(raw, &services); err != nil {
		return nil, 0, fmt.Errorf("parse upstream definition (expected a JSON array of services): %w", err)
	}
	if len(services) == 0 {
		return nil, 0, fmt.Errorf("upstream definition holds no services")
	}
	actions := make(map[string]artifactAction)
	skipped := 0
	for _, svc := range services {
		if svc.Prefix == "" {
			continue
		}
		for _, priv := range svc.Privileges {
			if priv.Privilege == "" {
				continue
			}
			if !dataset.AccessLevel(priv.AccessLevel).Valid() {
				skipped++
				continue
			}
			name := svc.Prefix + ":" + priv.Privilege
			var resourceTypes []string
			condKeys := map[string]struct{}{}
			for _, rt := range priv.ResourceTypes {
				rtName := strings.TrimSuffix(rt.ResourceType, "*")
				if rtName != "" {
					resourceTypes = append(resourceTypes, rtName)
				}
				for _, ck := range rt.ConditionKeys {
					if ck != "" {
						condKeys[ck] = struct{}{}
					}
				}
			}
			sort.Strings(resourceTypes)
			keys := make([]string, 0, len(condKeys))
			for k := range condKeys {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if _, dup := actions[name]; dup {
				// Case collisions would refuse to load; keep the first.
				continue
			}
			actions[name] = artifactAction{
				AccessLevel:   priv.AccessLevel,
				ResourceTypes: dedupeSorted(resourceTypes),
				ConditionKeys: keys,
			}
		}
	}
	if len(actions) == 0 {
		return nil, 0, fmt.Errorf("upstream definition trimmed to zero actions")
	}
	return &artifactFile{
		SchemaVersion: dataset.SupportedSchemaVersion,
		SourceCommit:  sourceCommit,
		Actions:       actions,
	}, skipped, nil
}

// dedupeSorted removes adjacent duplicates from a sorted slice.
func dedupeSorted(in []string) []string {
	out := in[:0]
	for i, v := range in {
		if i == 0 || in[i-1] != v {
			out = append(out, v)
		}
	}
	return out
}

// datasetDiff is the review summary of one update.
type datasetDiff struct {
	haveCurrent   bool
	currentHash   string
	added         []string
	removed       []string
	levelChanges  []string
	catalogBroken []string
}

// diffDatasets compares the new dataset against the current artifact
// and checks every catalog action against the new dataset.
func diffDatasets(cfg *config.Config, currentPath string, next *dataset.Dataset) datasetDiff {
	var d datasetDiff
	cur, err := dataset.Load(currentPath)
	if err == nil {
		d.haveCurrent = true
		d.currentHash = cur.Hash()
		curSet := map[string]dataset.AccessLevel{}
		for _, a := range cur.Actions() {
			info, _ := cur.Lookup(a)
			curSet[a] = info.AccessLevel
		}
		nextSet := map[string]dataset.AccessLevel{}
		for _, a := range next.Actions() {
			info, _ := next.Lookup(a)
			nextSet[a] = info.AccessLevel
		}
		for a, lvl := range nextSet {
			if old, ok := curSet[a]; !ok {
				d.added = append(d.added, a)
			} else if old != lvl {
				d.levelChanges = append(d.levelChanges, fmt.Sprintf("%s: %s -> %s", a, old, lvl))
			}
		}
		for a := range curSet {
			if _, ok := nextSet[a]; !ok {
				d.removed = append(d.removed, a)
			}
		}
		sort.Strings(d.added)
		sort.Strings(d.removed)
		sort.Strings(d.levelChanges)

		// Removed actions the catalog still references (section 5.3): a
		// silent removal would refuse the next broker start.
		if snap, cerr := catalog.Load(cfg.Synth.CatalogPath, cur,
			catalog.WithExtraDeniedServices(cfg.Guardrails.ExtraDenyServices...)); cerr == nil {
			for _, id := range snap.IDs() {
				c, _ := snap.Capability(id)
				for _, action := range c.Actions {
					if _, ok := next.Lookup(action); !ok {
						d.catalogBroken = append(d.catalogBroken, fmt.Sprintf("%s (capability %s)", action, id))
					}
				}
			}
			sort.Strings(d.catalogBroken)
		}
	}
	return d
}

// printDatasetDiff renders the human-readable review summary.
func printDatasetDiff(w io.Writer, d datasetDiff, next *dataset.Dataset, skipped int) {
	fmt.Fprintf(w, "new artifact: %d actions, source commit %s\n", next.Len(), next.SourceCommit())
	fmt.Fprintf(w, "new hash:     %s\n", next.Hash())
	if skipped > 0 {
		fmt.Fprintf(w, "skipped:      %d upstream entries with unusable access levels\n", skipped)
	}
	if !d.haveCurrent {
		fmt.Fprintln(w, "no current artifact to diff against (first update)")
		return
	}
	fmt.Fprintf(w, "current hash: %s\n", d.currentHash)
	fmt.Fprintf(w, "diff: %d new, %d removed, %d access-level changes\n",
		len(d.added), len(d.removed), len(d.levelChanges))
	printCapped(w, "  new:", d.added, 20)
	printCapped(w, "  removed:", d.removed, 20)
	printCapped(w, "  level changed:", d.levelChanges, 20)
	if len(d.catalogBroken) > 0 {
		fmt.Fprintf(w, "catalog actions missing from the new dataset (%d):\n", len(d.catalogBroken))
		printCapped(w, " ", d.catalogBroken, 50)
	}
}

// printCapped prints up to n items under a header, then a remainder
// count.
func printCapped(w io.Writer, header string, items []string, n int) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintln(w, header)
	for i, it := range items {
		if i == n {
			fmt.Fprintf(w, "    ... and %d more\n", len(items)-n)
			return
		}
		fmt.Fprintf(w, "    %s\n", it)
	}
}

// fetchURL downloads one URL with a size cap.
func fetchURL(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "taskgrant/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", u, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDatasetDownloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDatasetDownloadBytes {
		return nil, fmt.Errorf("%s exceeds the %d byte download cap", u, maxDatasetDownloadBytes)
	}
	return data, nil
}

// fetchUpstreamCommit resolves the upstream HEAD commit SHA, or "".
func fetchUpstreamCommit(ctx context.Context) string {
	data, err := fetchURL(ctx, datasetCommitURL)
	if err != nil {
		return ""
	}
	var body struct {
		SHA string `json:"sha"`
	}
	if json.Unmarshal(data, &body) != nil {
		return ""
	}
	return body.SHA
}

// writeFileAtomic writes data next to path and renames into place.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
