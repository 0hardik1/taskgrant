package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/textsafe"
)

// cmdAudit dispatches the audit subcommands of section 9.4. The audit
// CLI opens the decision log directly (WAL allows concurrent readers),
// so it works with or without a running broker.
func cmdAudit(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: taskgrant audit list|show|search|trail|scope|verify|export [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return auditList(rest, stdout, stderr)
	case "show":
		return auditShow(rest, stdout, stderr)
	case "search":
		return auditSearch(rest, stdout, stderr)
	case "trail":
		return auditTrail(rest, stdout, stderr)
	case "scope":
		return auditScope(rest, stdout, stderr)
	case "verify":
		return auditVerify(rest, stdout, stderr)
	case "export":
		return auditExport(rest, stdout, stderr)
	default:
		return fail(stderr, "audit: unknown subcommand %q", sub)
	}
}

// openStore opens the decision log read-mostly for audit queries.
func openStore(configPath string) (*config.Config, *store.Store, error) {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(store.Options{Path: cfg.Log.Path})
	if err != nil {
		return nil, nil, err
	}
	return cfg, st, nil
}

func auditList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	agent := fs.String("agent", "", "filter by agent id")
	outcome := fs.String("outcome", "", "filter by outcome")
	profile := fs.String("profile", "", "filter by profile")
	kind := fs.String("kind", "", "filter by record kind")
	resource := fs.String("resource", "", "filter by resource ARN GLOB")
	since := fs.String("since", "", "records at or after (RFC 3339 or YYYY-MM-DD)")
	until := fs.String("until", "", "records before (RFC 3339 or YYYY-MM-DD)")
	limit := fs.Int("limit", 100, "maximum records")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	f := store.ListFilter{
		Agent:           *agent,
		Outcome:         *outcome,
		Profile:         *profile,
		Kind:            domain.RecordKind(*kind),
		ResourcePattern: *resource,
		Limit:           *limit,
	}
	var err error
	if f.Since, err = parseTimeFlag(*since); err != nil {
		return fail(stderr, "audit list: since: %v", err)
	}
	if f.Until, err = parseTimeFlag(*until); err != nil {
		return fail(stderr, "audit list: until: %v", err)
	}

	_, st, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, "audit list: %v", err)
	}
	defer st.Close()
	recs, err := st.List(context.Background(), f)
	if err != nil {
		return fail(stderr, "audit list: %v", err)
	}
	if *asJSON {
		return jsonOut(stdout, recs)
	}
	for _, rec := range recs {
		fmt.Fprintf(stdout, "%s  %-16s %-18s agent=%s grant=%s\n",
			rec.TS.UTC().Format(time.RFC3339), rec.Kind, rec.Outcome, rec.AgentID, rec.GrantID)
	}
	fmt.Fprintf(stdout, "%d records\n", len(recs))
	return 0
}

func auditShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fail(stderr, "audit show: exactly one grant id is required")
	}
	_, st, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, "audit show: %v", err)
	}
	defer st.Close()
	recs, err := st.GrantChain(context.Background(), rest[0])
	if err != nil {
		return fail(stderr, "audit show: %v", err)
	}
	if len(recs) == 0 {
		return fail(stderr, "audit show: no records for grant %s", rest[0])
	}
	if *asJSON {
		return jsonOut(stdout, recs)
	}
	for _, rec := range recs {
		fmt.Fprintf(stdout, "== %s %s (%s) outcome=%s\n",
			rec.TS.UTC().Format(time.RFC3339), rec.Kind, rec.RecordID, rec.Outcome)
		var pretty map[string]any
		if err := json.Unmarshal(rec.Body, &pretty); err == nil {
			data, _ := json.MarshalIndent(textsafe.SanitizeValue(pretty), "", "  ")
			fmt.Fprintln(stdout, string(data))
		}
	}
	return 0
}

func auditSearch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	limit := fs.Int("limit", 100, "maximum records")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fail(stderr, "audit search: exactly one query is required")
	}
	_, st, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, "audit search: %v", err)
	}
	defer st.Close()
	recs, err := st.Search(context.Background(), rest[0], *limit)
	if err != nil {
		return fail(stderr, "audit search: %v", err)
	}
	if *asJSON {
		return jsonOut(stdout, recs)
	}
	for _, rec := range recs {
		fmt.Fprintf(stdout, "%s  %-16s agent=%s grant=%s\n  task: %s\n",
			rec.TS.UTC().Format(time.RFC3339), rec.Kind, rec.AgentID, rec.GrantID,
			textsafe.Truncate(textsafe.Sanitize(rec.Task), 120))
	}
	fmt.Fprintf(stdout, "%d records\n", len(recs))
	return 0
}

// auditTrail prints the CloudTrail join keys of a grant plus an Athena
// query template (section 8.4). It states the observability caveats
// plainly.
func auditTrail(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit trail", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fail(stderr, "audit trail: exactly one grant id is required")
	}
	grantID := rest[0]
	_, st, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, "audit trail: %v", err)
	}
	defer st.Close()
	recs, err := st.GrantChain(context.Background(), grantID)
	if err != nil || len(recs) == 0 {
		return fail(stderr, "audit trail: no records for grant %s", grantID)
	}

	type stsInfo struct {
		RoleSessionName string `json:"role_session_name"`
		SourceIdentity  string `json:"source_identity"`
		AccessKeyID     string `json:"access_key_id"`
		Expiration      string `json:"expiration"`
		STSRequestID    string `json:"sts_request_id"`
	}
	var info stsInfo
	for _, rec := range recs {
		var body struct {
			STS *stsInfo `json:"sts"`
		}
		if json.Unmarshal(rec.Body, &body) == nil && body.STS != nil {
			info = *body.STS
		}
	}
	sourceIdentity := domain.SourceIdentity(grantID)
	athena := fmt.Sprintf(
		"SELECT eventtime, eventsource, eventname, errorcode, requestparameters\n"+
			"FROM cloudtrail_logs\n"+
			"WHERE json_extract_scalar(useridentity.sessioncontext.sourceidentity, '$') = '%s'\n"+
			"ORDER BY eventtime;", sourceIdentity)
	out := map[string]any{
		"grant_id":          grantID,
		"source_identity":   sourceIdentity,
		"role_session_name": info.RoleSessionName,
		"access_key_id":     info.AccessKeyID,
		"sts_request_id":    info.STSRequestID,
		"expiration":        info.Expiration,
		"athena_query":      athena,
		"caveats": []string{
			"CloudTrail data events (S3 object-level, Lambda invoke) are off by default; without them object-level activity leaves no event and is unobservable",
			"SourceIdentity is not captured when an AWS service acts on the session's behalf",
			"session tags appear only on the AssumeRole event (requestParameters.principalTags)",
		},
	}
	if *asJSON {
		return jsonOut(stdout, out)
	}
	fmt.Fprintf(stdout, "grant:             %s\n", grantID)
	fmt.Fprintf(stdout, "source identity:   %s (primary CloudTrail join key)\n", sourceIdentity)
	fmt.Fprintf(stdout, "role session name: %s\n", info.RoleSessionName)
	fmt.Fprintf(stdout, "access key id:     %s\n", info.AccessKeyID)
	fmt.Fprintf(stdout, "sts request id:    %s (assume-time fallback join)\n", info.STSRequestID)
	fmt.Fprintf(stdout, "expiration:        %s\n\n", info.Expiration)
	fmt.Fprintln(stdout, "Athena query:")
	fmt.Fprintln(stdout, athena)
	fmt.Fprintln(stdout, "\nCaveats:")
	fmt.Fprintln(stdout, "- data events (S3 object-level, Lambda invoke) are off by default; without them those actions are UNOBSERVABLE")
	fmt.Fprintln(stdout, "- SourceIdentity is not captured when an AWS service acts on the session's behalf")
	return 0
}

func auditScope(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit scope", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fail(stderr, "audit scope: exactly one agent id is required")
	}
	_, st, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, "audit scope: %v", err)
	}
	defer st.Close()
	report, err := st.Scope(context.Background(), rest[0], time.Now())
	if err != nil {
		return fail(stderr, "audit scope: %v", err)
	}
	if *asJSON {
		return jsonOut(stdout, report)
	}
	fmt.Fprintf(stdout, "agent %s: %d live grants\n", report.Agent, len(report.LiveGrants))
	fmt.Fprintf(stdout, "capabilities: %v\n", report.Capabilities)
	fmt.Fprintf(stdout, "actions (%d): %v\n", len(report.Actions), report.Actions)
	fmt.Fprintf(stdout, "resources (%d): %v\n", len(report.Resources), report.Resources)
	return 0
}

func auditVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, st, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, "audit verify: %v", err)
	}
	defer st.Close()
	res, err := st.Verify(context.Background())
	if err != nil {
		var chainErr *store.ChainError
		if errors.As(err, &chainErr) {
			if *asJSON {
				jsonOut(stdout, map[string]any{
					"ok": false, "broken_at_seq": chainErr.Seq,
					"broken_record": chainErr.RecordID, "reason": chainErr.Reason,
				})
			} else {
				fmt.Fprintf(stdout, "CHAIN BROKEN at seq %d (record %s): %s\n",
					chainErr.Seq, chainErr.RecordID, textsafe.Sanitize(chainErr.Reason))
			}
			return 1
		}
		return fail(stderr, "audit verify: %v", err)
	}
	anchorNote := "no anchor configured"
	if cfg.Log.Anchor != nil {
		anchorNote = "anchor configured (" + cfg.Log.Anchor.Type + "); compare the destination checkpoints against head hash " + res.HeadHash
	}
	if *asJSON {
		return jsonOut(stdout, map[string]any{
			"ok": true, "records": res.Records, "first_seq": res.FirstSeq,
			"head_seq": res.HeadSeq, "head_hash": res.HeadHash, "anchor": anchorNote,
		})
	}
	fmt.Fprintf(stdout, "chain ok: %d records, head seq %d, head hash %s\n", res.Records, res.HeadSeq, res.HeadHash)
	fmt.Fprintln(stdout, anchorNote)
	fmt.Fprintln(stdout, "note: the chain proves internal consistency; a full-file rewrite is detectable only against the external anchor (section 9.3)")
	return 0
}

func auditExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	format := fs.String("format", "jsonl", "export format (jsonl)")
	out := fs.String("out", "", "output file (default stdout)")
	agent := fs.String("agent", "", "filter by agent id")
	since := fs.String("since", "", "records at or after (RFC 3339 or YYYY-MM-DD)")
	until := fs.String("until", "", "records before (RFC 3339 or YYYY-MM-DD)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *format != "jsonl" {
		return fail(stderr, "audit export: unsupported format %q (jsonl)", *format)
	}
	f := store.ListFilter{Agent: *agent, Limit: 1 << 30}
	var err error
	if f.Since, err = parseTimeFlag(*since); err != nil {
		return fail(stderr, "audit export: since: %v", err)
	}
	if f.Until, err = parseTimeFlag(*until); err != nil {
		return fail(stderr, "audit export: until: %v", err)
	}
	_, st, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, "audit export: %v", err)
	}
	defer st.Close()

	var w io.Writer = stdout
	if *out != "" {
		file, ferr := os.Create(*out)
		if ferr != nil {
			return fail(stderr, "audit export: %v", ferr)
		}
		defer file.Close()
		w = file
	}
	n, err := st.ExportJSONL(context.Background(), w, f)
	if err != nil {
		return fail(stderr, "audit export: %v", err)
	}
	fmt.Fprintf(stderr, "exported %d records\n", n)
	return 0
}

// parseTimeFlag accepts RFC 3339 or YYYY-MM-DD; empty yields zero.
func parseTimeFlag(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not RFC 3339 or YYYY-MM-DD", v)
}
