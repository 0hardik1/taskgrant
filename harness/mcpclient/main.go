// Command mcp-call is the scenario fleet's MCP client: one tool call
// per process against the taskgrant broker's streamable HTTP endpoint.
//
// It mirrors internal/mcpserver's transport exactly (the same
// github.com/modelcontextprotocol/go-sdk version, streamable HTTP at
// /mcp, Authorization: Bearer on every request), so a scenario agent
// exercises the real protocol path rather than a hand-rolled one.
//
// Usage:
//
//	mcp-call --url http://127.0.0.1:8770/mcp --token-file PATH \
//	         --tool request_grant --args '{"task":"..."}'
//	mcp-call --url ... --token-file PATH --list-tools
//
// Exit codes:
//
//	0  the server returned a tool result, INCLUDING denials, clarifications,
//	   and tool errors: those are normal results, not failures
//	1  usage or argument error (bad flags, unreadable token file, bad JSON)
//	2  transport, auth, or MCP session failure (broker unreachable, 401)
//	3  the tool call itself failed at the protocol level (JSON-RPC error)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	exitOK        = 0
	exitUsage     = 1
	exitTransport = 2
	exitCall      = 3
)

// bearerTransport injects one Authorization header on every request,
// the same shape internal/mcpserver's own HTTP tests use.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if b.token != "" {
		clone.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(clone)
}

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("mcp-call", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	url := fs.String("url", "http://127.0.0.1:8770/mcp", "broker MCP endpoint")
	tokenFile := fs.String("token-file", "", "file holding the bearer token plaintext")
	token := fs.String("token", "", "bearer token plaintext (use --token-file normally)")
	tool := fs.String("tool", "", "tool name: request_grant, get_grant, explain_grant, list_capabilities, release_grant")
	args := fs.String("args", "{}", "tool arguments as a JSON object")
	argsFile := fs.String("args-file", "", "read tool arguments from a JSON file instead of --args")
	listTools := fs.Bool("list-tools", false, "list the server's tools and exit")
	raw := fs.Bool("raw", false, "print only the structured content, not the result envelope")
	timeout := fs.Duration("timeout", 120*time.Second, "overall deadline for connect plus call")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return exitUsage
	}
	if *tool == "" && !*listTools {
		fmt.Fprintln(os.Stderr, "mcp-call: --tool or --list-tools is required")
		fs.Usage()
		return exitUsage
	}

	bearer := *token
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return failf(exitUsage, "read token file: %v", err)
		}
		bearer = strings.TrimSpace(string(data))
	}

	rawArgs := *args
	if *argsFile != "" {
		data, err := os.ReadFile(*argsFile)
		if err != nil {
			return failf(exitUsage, "read args file: %v", err)
		}
		rawArgs = string(data)
	}
	if strings.TrimSpace(rawArgs) == "" {
		rawArgs = "{}"
	}
	var toolArgs map[string]any
	if err := json.Unmarshal([]byte(rawArgs), &toolArgs); err != nil {
		return failf(exitUsage, "--args must be a JSON object: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "taskgrant-harness-mcp-call", Version: "1"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint: *url,
		HTTPClient: &http.Client{
			Transport: &bearerTransport{token: bearer, base: http.DefaultTransport},
			Timeout:   *timeout,
		},
	}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return failf(exitTransport, "connect %s: %v", *url, err)
	}
	defer session.Close()

	if *listTools {
		res, err := session.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			return failf(exitCall, "list tools: %v", err)
		}
		type toolOut struct {
			Name        string `json:"name"`
			Description string `json:"description,omitempty"`
			InputSchema any    `json:"input_schema,omitempty"`
		}
		out := struct {
			Tools []toolOut `json:"tools"`
		}{Tools: make([]toolOut, 0, len(res.Tools))}
		for _, t := range res.Tools {
			out.Tools = append(out.Tools, toolOut{
				Name:        t.Name,
				Description: t.Description,
				InputSchema: t.InputSchema,
			})
		}
		return emit(out)
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: *tool, Arguments: toolArgs})
	if err != nil {
		// A JSON-RPC level failure: the tool did not return a result.
		// Denials and tool errors do not land here; they are results.
		var code int
		if errors.Is(err, context.DeadlineExceeded) {
			code = exitTransport
		} else {
			code = exitCall
		}
		return failf(code, "call %s: %v", *tool, err)
	}

	if *raw {
		if res.StructuredContent == nil {
			return emit(map[string]any{})
		}
		return emit(res.StructuredContent)
	}
	envelope := struct {
		Tool              string        `json:"tool"`
		IsError           bool          `json:"is_error"`
		StructuredContent any           `json:"structured_content"`
		Content           []mcp.Content `json:"content,omitempty"`
	}{
		Tool:              *tool,
		IsError:           res.IsError,
		StructuredContent: res.StructuredContent,
		Content:           res.Content,
	}
	return emit(envelope)
}

// emit writes v as indented JSON on stdout.
func emit(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return failf(exitCall, "encode result: %v", err)
	}
	return exitOK
}

// failf prints a machine-readable error object on stdout, a human line
// on stderr, and returns the exit code.
func failf(code int, format string, a ...any) int {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, "mcp-call: "+msg)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"error": msg, "exit_code": code})
	return code
}
