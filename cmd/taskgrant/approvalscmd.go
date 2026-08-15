package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/0hardik1/taskgrant/internal/adminapi"
	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/textsafe"
)

// approvalsListResponse is the GET /v1/approvals body.
type approvalsListResponse struct {
	Pending          []adminapi.PendingApproval `json:"pending"`
	AgentInputNotice string                     `json:"agent_input_notice"`
}

type approvalShowResponse struct {
	Approval         adminapi.PendingApproval `json:"approval"`
	AgentInputNotice string                   `json:"agent_input_notice"`
}

type decisionResponse struct {
	Decision adminapi.ApprovalDecision `json:"decision"`
	Approver adminapi.Approver         `json:"approver"`
}

// cmdApprovals implements `taskgrant approvals list|show <id>`.
func cmdApprovals(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: taskgrant approvals list|show <id> [--json] [--config path]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("approvals "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	client, err := adminClient(*configPath)
	if err != nil {
		return fail(stderr, "approvals: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch sub {
	case "list":
		var resp approvalsListResponse
		if err := client.do(ctx, "GET", "/v1/approvals", nil, &resp); err != nil {
			return fail(stderr, "approvals list: %v", err)
		}
		if *asJSON {
			return jsonOut(stdout, resp)
		}
		if len(resp.Pending) == 0 {
			fmt.Fprintln(stdout, "no pending approvals")
			return 0
		}
		fmt.Fprintln(stdout, "NOTE: task and reason are unverified agent input")
		for _, p := range resp.Pending {
			fmt.Fprintf(stdout, "%s  agent=%s profile=%s expires=%s\n  task: %s\n",
				p.GrantID, p.AgentID, p.Profile,
				p.ExpiresAt.UTC().Format(time.RFC3339),
				textsafe.Truncate(textsafe.Sanitize(p.Task), 120))
		}
		return 0
	case "show":
		rest := fs.Args()
		if len(rest) != 1 {
			return fail(stderr, "approvals show: exactly one grant id is required")
		}
		var resp approvalShowResponse
		if err := client.do(ctx, "GET", "/v1/approvals/"+rest[0], nil, &resp); err != nil {
			return fail(stderr, "approvals show: %v", err)
		}
		if *asJSON {
			return jsonOut(stdout, resp)
		}
		p := resp.Approval
		fmt.Fprintln(stdout, "NOTE: task and reason are unverified agent input")
		fmt.Fprintf(stdout, "grant:        %s\n", p.GrantID)
		fmt.Fprintf(stdout, "agent:        %s\n", p.AgentID)
		fmt.Fprintf(stdout, "profile:      %s\n", p.Profile)
		fmt.Fprintf(stdout, "capabilities: %v\n", p.Capabilities)
		fmt.Fprintf(stdout, "access:       %v\n", p.AccessLevels)
		fmt.Fprintf(stdout, "requested:    %s\n", p.RequestedAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(stdout, "expires:      %s\n", p.ExpiresAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(stdout, "task:         %s\n", textsafe.Sanitize(p.Task))
		if p.Reason != "" {
			fmt.Fprintf(stdout, "reason:       %s\n", textsafe.Sanitize(p.Reason))
		}
		fmt.Fprintf(stdout, "policy:\n%s\n", textsafe.Sanitize(p.PolicyJSON))
		return 0
	default:
		return fail(stderr, "approvals: unknown subcommand %q (list, show)", sub)
	}
}

// cmdApprove implements `taskgrant approve <id>`.
func cmdApprove(args []string, stdout, stderr io.Writer) int {
	return decide(args, stdout, stderr, "approve")
}

// cmdDeny implements `taskgrant deny <id>`.
func cmdDeny(args []string, stdout, stderr io.Writer) int {
	return decide(args, stdout, stderr, "deny")
}

func decide(args []string, stdout, stderr io.Writer, verb string) int {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	note := fs.String("note", "", "note for the approval record")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fail(stderr, "%s: exactly one grant id is required", verb)
	}
	client, err := adminClient(*configPath)
	if err != nil {
		return fail(stderr, "%s: %v", verb, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var resp decisionResponse
	body := map[string]string{"note": *note}
	if err := client.do(ctx, "POST", "/v1/approvals/"+rest[0]+"/"+verb, body, &resp); err != nil {
		return fail(stderr, "%s: %v", verb, err)
	}
	if *asJSON {
		return jsonOut(stdout, resp)
	}
	fmt.Fprintf(stdout, "grant %s: %s", resp.Decision.GrantID, resp.Decision.Decision)
	if resp.Decision.MintOutcome != "" {
		fmt.Fprintf(stdout, " (%s)", resp.Decision.MintOutcome)
	}
	fmt.Fprintf(stdout, " by %s\n", resp.Approver.Principal)
	return 0
}

// cmdRevoke implements `taskgrant revoke --profile <name> | --grant <id>`.
func cmdRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	profile := fs.String("profile", "", "revoke role-wide for this profile")
	grant := fs.String("grant", "", "best-effort targeted revoke for this grant id")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*profile == "") == (*grant == "") {
		return fail(stderr, "revoke: exactly one of --profile or --grant is required")
	}
	client, err := adminClient(*configPath)
	if err != nil {
		return fail(stderr, "revoke: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var resp adminapi.RevocationResult
	body := map[string]string{"profile": *profile, "grant_id": *grant}
	if err := client.do(ctx, "POST", "/v1/revoke", body, &resp); err != nil {
		return fail(stderr, "revoke: %v", err)
	}
	if *asJSON {
		return jsonOut(stdout, resp)
	}
	fmt.Fprintf(stdout, "revocation applied: mechanism=%s profile=%s grant=%s\n  %s\n",
		resp.Mechanism, resp.Profile, resp.GrantID, resp.Detail)
	fmt.Fprintln(stdout, "note: STS tokens cannot be invalidated; this is the deny-by-issue-time pattern (section 8.5)")
	return 0
}

// adminClient builds a socket client from the config's admin socket.
func adminClient(configPath string) (*socketClient, error) {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return nil, err
	}
	if cfg.Server.AdminSocket == "" {
		return nil, fmt.Errorf("server.admin_socket is not configured")
	}
	return newSocketClient(cfg.Server.AdminSocket, 60*time.Second), nil
}
