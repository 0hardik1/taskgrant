# taskgrant

Per-task AWS credentials for AI agents.

taskgrant is a self-hosted broker that mints short-lived, least-privilege AWS credentials for
each declared agent task. An agent describes its task over MCP. taskgrant turns that declaration
into a scoped IAM session policy, calls `sts:AssumeRole` with that policy plus session tags and a
broker-authored SourceIdentity, returns the temporary credentials, and records the decision
(including the agent's stated justification) in a tamper-evident log.

It replaces "one broad standing role that only grows" with "one narrow session per declared
task".

## Why

1. **Least privilege per task.** Each grant carries a session policy synthesized for that task,
   never the role's full permissions.
2. **Justification on record.** Every grant stores the agent's task and reason verbatim, next to
   the exact policy minted for it.
3. **Attribution end to end.** Every session carries a SourceIdentity and session tags, so
   CloudTrail activity joins back to one decision record.
4. **No standing credentials for agents.** Agents hold nothing long-lived. The default session
   lifetime is 900 seconds.

This is a direct implementation of the pattern AWS recommends for MCP agents: assume a role with
a session policy restricted to what the specific invocation needs, tag the session for
attribution, and design permissions for acceptable scope of impact.

## How intent becomes a policy

The hard part is turning ambiguous agent intent into a correct, minimal policy. taskgrant does
not let a model write policies.

- An admin-authored **capability catalog** (YAML in git) defines everything that can be granted.
  Each entry pins its actions, ARN templates, condition keys, and parameter grammars.
- A **rules matcher** maps a request onto catalog entries. It needs no model and is the default
  path.
- An optional **LLM classifier** only selects among existing capability IDs and extracts
  parameter values. It is a closed-world selection. Its output still faces every grammar and
  allowlist check.
- A **guardrail evaluator** independently re-checks the concrete policy before any STS call. It
  reads IAM semantics, not strings: it expands actions against a pinned dataset, enforces access
  levels and a shipped escalation denylist, requires region and account conditions, and rejects
  `NotAction`, `Principal`, and non-Allow effects.

Agents never name raw IAM actions. Task text never reaches the policy bytes. Widening what is
grantable takes a reviewed catalog change, not a runtime call.

## Quickstart

```bash
go build ./cmd/taskgrant

# 1. Fetch and pin the IAM action dataset (needs network, once per update).
taskgrant dataset update

# 2. Point config.yaml at your catalog, dataset, roles, and agents.
taskgrant config validate

# 3. Generate the two IAM policies an admin must apply.
taskgrant config trust-policy    # for each target role
taskgrant config broker-policy   # for the broker principal

# 4. Verify the wiring with a real, discarded AssumeRole per profile.
taskgrant preflight

# 5. Run it.
taskgrant serve
```

`examples/catalog/` holds a starter catalog: S3 read and write by prefix, DynamoDB query, SQS
consume and produce, CloudWatch Logs read, and Lambda invoke.

## Deployment shapes

| | Sidecar (stdio) | Shared service (HTTP) |
|---|---|---|
| Agent auth | Process boundary, one fixed identity | Per-agent bearer tokens (OIDC seam for v2) |
| Agents | Exactly one | Many |
| Approvals | Blocking wait at the same terminal | Return and poll, plus the admin API |
| Delivery | `taskgrant creds` (credential_process) | MCP tool result |

Same binary, one flag apart, identical lifecycle, log schema, and guardrails.

## MCP tools

`request_grant`, `get_grant`, `explain_grant`, `list_capabilities`, `release_grant`.

Approve, deny, audit, revoke, and config are admin surfaces only. They are never reachable over
MCP. Cross-agent lookups return `NOT_FOUND`, never `FORBIDDEN`, so existence is not confirmed.

## Audit

```bash
taskgrant audit list   --agent invoice-bot --since 2026-08-01
taskgrant audit show   <grant_id>      # the full record chain
taskgrant audit trail  <grant_id>      # CloudTrail join keys and a ready query
taskgrant audit scope  <agent>         # union of live grants, for creep review
taskgrant audit verify                 # hash chain plus external anchor
taskgrant replay       <grant_id>      # recompile from logged inputs, diff the bytes
```

The log is append-only SQLite with a SHA-256 hash chain. Because a host compromise could rewrite
the whole file, the broker also writes signed checkpoints to a destination it can write but not
delete (S3 Object Lock or CloudWatch Logs), which makes a rewrite detectable.

## Honest limits

Read these before you deploy. They are properties of AWS, not bugs.

1. **taskgrant narrows a role. It does not scope a broad account.** Session permissions are the
   intersection of the role's identity policy and the session policy. A session policy never
   grants. Give each profile a narrow, dedicated role, ideally with a permissions boundary.
2. **Resource policies can bypass the session policy.** A resource-based policy naming the
   assumed-role session ARN grants access the session policy does not limit. Condition those
   policies on `aws:SourceIdentity`.
3. **There is no true revocation.** STS tokens cannot be invalidated. The short TTL is the
   primary control. `taskgrant revoke` writes a best-effort deny by token issue time.
4. **Intent is a claim.** The logged justification is what the agent said, not what taskgrant
   verified. The value is correlation and accountability, not proof of purpose.
5. **v1 is a single replica on SQLite.** If the broker is down, agents cannot get or renew
   credentials and live sessions expire within one TTL. That is fail-closed by design.

## Testing

```bash
go test ./...
```

`harness/` holds an adversarial harness: 100 scenarios in 14 families, each run by its own agent
session against a live broker and a real LocalStack backend. Every mint is a real
`sts:AssumeRole`. See `harness/REPORT.md` for the writeup and the defects it found.

## Documentation

`ARCHITECTURE.md` is the full v1 design: the trust model, the security invariants, the
synthesizer, the guardrails, the size budget, the STS plumbing, the log format, and the abuse
cases with their mitigations.

## License

MIT. See `LICENSE`.
