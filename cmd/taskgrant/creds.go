package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/adminapi"
	"github.com/0hardik1/taskgrant/internal/config"
)

// capabilityFlags collects repeatable --capability values of the form
// "id" or "id:key=value,key=value".
type capabilityFlags []adminapi.CredsCapability

func (c *capabilityFlags) String() string { return fmt.Sprintf("%d capabilities", len(*c)) }

func (c *capabilityFlags) Set(v string) error {
	id, rest, _ := strings.Cut(v, ":")
	if id == "" {
		return fmt.Errorf("capability id is empty")
	}
	capability := adminapi.CredsCapability{ID: id}
	if rest != "" {
		capability.Params = map[string]string{}
		for _, pair := range strings.Split(rest, ",") {
			k, val, ok := strings.Cut(pair, "=")
			if !ok || k == "" {
				return fmt.Errorf("capability param %q is not key=value", pair)
			}
			capability.Params[k] = val
		}
	}
	*c = append(*c, capability)
	return nil
}

// cmdCreds performs a grant request over the admin socket and emits
// credential_process JSON (section 4.3). This keeps secrets out of the
// agent's context window: the recommended sidecar delivery mode.
func cmdCreds(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("creds", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	agent := fs.String("agent", "", "agent id (default: server.default_agent)")
	profile := fs.String("profile", "", "profile to mint under")
	task := fs.String("task", "", "the declared task (required)")
	reason := fs.String("reason", "", "why the task needs credentials")
	duration := fs.Int("duration", 0, "requested duration seconds")
	wait := fs.Int("wait", 30, "seconds to block for a human approval")
	idemKey := fs.String("idempotency-key", "", "repeat-safe key")
	var caps capabilityFlags
	fs.Var(&caps, "capability", "capability hint: id or id:key=value,key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *task == "" {
		return fail(stderr, "creds: --task is required")
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return fail(stderr, "creds: %v", err)
	}
	if cfg.Server.AdminSocket == "" {
		return fail(stderr, "creds: server.admin_socket is not configured")
	}

	client := newSocketClient(cfg.Server.AdminSocket, time.Duration(*wait+60)*time.Second)
	req := adminapi.CredsRequest{
		Agent:           *agent,
		Profile:         *profile,
		Task:            *task,
		Reason:          *reason,
		Capabilities:    caps,
		DurationSeconds: *duration,
		IdempotencyKey:  *idemKey,
		WaitSeconds:     *wait,
	}
	var resp adminapi.CredsResponse
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*wait+90)*time.Second)
	defer cancel()
	if err := client.do(ctx, "POST", "/v1/creds", req, &resp); err != nil {
		return fail(stderr, "creds: %v", err)
	}

	if resp.Status != "active" {
		detail := resp.Detail
		if resp.DenialCode != "" {
			detail = resp.DenialCode + ": " + detail
		}
		return fail(stderr, "creds: grant %s is %s: %s", resp.GrantID, resp.Status, detail)
	}

	// credential_process JSON, exactly the AWS shape, stdout only.
	out := struct {
		Version         int    `json:"Version"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
		Expiration      string `json:"Expiration"`
	}{
		Version:         1,
		AccessKeyID:     resp.AccessKeyID,
		SecretAccessKey: resp.SecretAccessKey,
		SessionToken:    resp.SessionToken,
		Expiration:      resp.Expiration,
	}
	enc := json.NewEncoder(stdout)
	if err := enc.Encode(out); err != nil {
		return fail(stderr, "creds: %v", err)
	}
	return 0
}
