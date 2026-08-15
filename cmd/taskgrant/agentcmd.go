package main

// agentcmd.go implements `taskgrant agent token issue|rotate <agent>`
// (architecture section 4.3): mint a bearer token, print the plaintext
// exactly once, and print the config lines to paste. Only the SHA-256
// hash ever reaches config; expiry is mandatory.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/identity"
)

// defaultTokenTTL is the default bearer token lifetime (section 4.3).
const defaultTokenTTL = 24 * time.Hour

func cmdAgent(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "token" {
		fmt.Fprintln(stderr, "usage: taskgrant agent token <issue|rotate> <agent> [flags]")
		return 2
	}
	args = args[1:]
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: taskgrant agent token <issue|rotate> <agent> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "issue", "rotate":
		return cmdAgentToken(sub, rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "taskgrant agent token: unknown subcommand %q\n", sub)
		return 2
	}
}

func cmdAgentToken(mode string, args []string, stdout, stderr io.Writer) int {
	// The agent id may come before or after the flags.
	agentID := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		agentID = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("agent token "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	ttl := fs.Duration("expires", defaultTokenTTL, "token lifetime, for the token_expires line")
	asJSON := fs.Bool("json", false, "JSON output (still prints the plaintext; treat the output as a secret)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	switch {
	case agentID == "" && len(rest) == 1:
		agentID = rest[0]
	case agentID != "" && len(rest) == 0:
	default:
		return fail(stderr, "agent token %s: exactly one agent id is required", mode)
	}
	if err := identity.ValidateAgentID(agentID); err != nil {
		return fail(stderr, "agent token %s: %v", mode, err)
	}
	if *ttl <= 0 {
		return fail(stderr, "agent token %s: --expires must be positive; non-expiring tokens are not supported", mode)
	}

	// Cross-check against config. Rotation requires the agent to exist;
	// issue only warns, since the agent block may not be written yet.
	if cfg, err := config.LoadFile(*configPath); err == nil {
		agent, exists := cfg.Agents[agentID]
		switch {
		case mode == "rotate" && !exists:
			return fail(stderr, "agent token rotate: agent %q is not in %s", agentID, *configPath)
		case mode == "issue" && exists && agent.TokenSHA256 != "":
			fmt.Fprintf(stderr, "warning: agent %q already has a token (fingerprint %s); this issues a new one\n",
				agentID, identity.Fingerprint(agent.TokenSHA256))
		}
	} else if mode == "rotate" {
		return fail(stderr, "agent token rotate: %v", err)
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stderr, "warning: config %s did not load (%v); issuing anyway\n", *configPath, err)
	}

	tok, err := identity.GenerateToken()
	if err != nil {
		return fail(stderr, "agent token %s: %v", mode, err)
	}
	expires := time.Now().UTC().Add(*ttl).Truncate(time.Second)

	if *asJSON {
		return jsonOut(stdout, map[string]any{
			"agent":         agentID,
			"token":         tok.Plaintext,
			"token_sha256":  tok.SHA256Hex,
			"token_expires": expires.Format(time.RFC3339),
			"fingerprint":   tok.Fingerprint,
		})
	}

	fmt.Fprintf(stdout, "Bearer token for agent %q (shown once, never stored):\n\n", agentID)
	fmt.Fprintf(stdout, "  %s\n\n", tok.Plaintext)
	fmt.Fprintf(stdout, "Paste into the agents block of %s:\n\n", *configPath)
	fmt.Fprintf(stdout, "  %s:\n", agentID)
	fmt.Fprintf(stdout, "    token_sha256: \"%s\"\n", tok.SHA256Hex)
	fmt.Fprintf(stdout, "    token_expires: %s\n\n", expires.Format(time.RFC3339))
	fmt.Fprintf(stdout, "Decision log fingerprint: %s\n", tok.Fingerprint)
	fmt.Fprintf(stdout, "Reload or restart the broker for the new hash to take effect.\n")
	if mode == "rotate" {
		fmt.Fprintf(stdout, "The old token keeps working until the config change lands; replace it promptly.\n")
	}
	return 0
}
