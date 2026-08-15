// Command taskgrant is the single static binary of the taskgrant
// broker (architecture section 14): the serve loop, the credential
// helper, the approval and audit CLI, replay, revocation, preflight,
// provisioning, dataset tooling, agent token management, and the
// config template generators.
//
// The command tree is built on the standard library flag package: the
// module's dependency set is fixed by the foundation step and carries
// no CLI framework, so the cobra-shaped surface of section 14 is
// implemented with flag.FlagSet subcommands.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"

	"github.com/0hardik1/taskgrant/internal/stsmint"
)

// version is stamped by the build; "dev" otherwise.
var version = "dev"

// command is one CLI subcommand.
type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

// commands is the top-level command table, section 14 order.
var commands []command

func init() {
	commands = []command{
		{"serve", "run the broker (MCP transport, admin socket, sweeps)", cmdServe},
		{"creds", "request a grant over the admin socket and emit credential_process JSON", cmdCreds},
		{"approvals", "list or show pending approvals", cmdApprovals},
		{"approve", "approve a pending grant by id", cmdApprove},
		{"deny", "deny a pending grant by id", cmdDeny},
		{"audit", "query the decision log: list, show, search, trail, scope, verify, export", cmdAudit},
		{"replay", "recompile a grant from its logged inputs and diff the bytes", cmdReplay},
		{"revoke", "write a best-effort deny: --profile or --grant", cmdRevoke},
		{"preflight", "verify role wiring with a real minimal AssumeRole per profile", cmdPreflight},
		{"provision", "create or update the managed session policies for managed_policy capabilities", cmdProvision},
		{"dataset", "update or inspect the pinned IAM dataset artifact", cmdDataset},
		{"agent", "agent token issue|rotate", cmdAgent},
		{"config", "validate | trust-policy | broker-policy", cmdConfig},
		{"version", "print the taskgrant version", cmdVersion},
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	name := args[0]
	for _, c := range commands {
		if c.name == name {
			return c.run(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "taskgrant: unknown command %q\n\n", name)
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "taskgrant: per-task AWS credentials for AI agents")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage: taskgrant <command> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	names := make([]string, 0, len(commands))
	byName := map[string]string{}
	for _, c := range commands {
		names = append(names, c.name)
		byName[c.name] = c.summary
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-11s %s\n", n, byName[n])
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Global: --config <path> (default $TASKGRANT_CONFIG or /etc/taskgrant/config.yaml)")
}

func cmdVersion(_ []string, stdout, _ io.Writer) int {
	fmt.Fprintln(stdout, "taskgrant "+version)
	return 0
}

// defaultConfigPath resolves the config file path from the environment
// with the documented default.
func defaultConfigPath() string {
	if p := os.Getenv("TASKGRANT_CONFIG"); p != "" {
		return p
	}
	return "/etc/taskgrant/config.yaml"
}

// newLogger builds the process slog logger with the stsmint scrubber
// installed on the root handler (section 8.7): attributes whose keys
// match (?i)secret|token|authorization never reach a log line.
func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: stsmint.ScrubAttr,
	}))
}

// fail prints an error and returns exit code 1.
func fail(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "taskgrant: "+format+"\n", args...)
	return 1
}
