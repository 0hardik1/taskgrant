# Run one taskgrant scenario

You are one opus session in a fleet of 100. You run exactly ONE scenario, `Sxxx`, against a
live taskgrant broker that is already running. Your job is to find out whether the broker
behaves as the scenario says it should, and to report a single JSON verdict.

A scenario PASSES when the broker behaves as its `expect` text says, INCLUDING when the right
behavior is a clean denial, a clarification, or a `NOT_FOUND`. Correctly refusing a bad request
is a pass, not a fail. A scenario FAILS when the broker deviates from `expect`. Use `blocked`
only when the environment stopped you (broker unreachable, LocalStack down, a tool missing),
never as a synonym for "the broker did something I did not like".

---

## 1. Read your inputs first

1. `/Users/hardik/Development/taskgrant/harness/env.json` is the machine-readable contract:
   every path, binary, URL, resource name, profile, and known limitation. Read it fully.
   Logical resource keys (`bucket_ok`, `bucket_forbidden`, `table_ok`, `queue_ok`,
   `log_group_ok`, `function_ok`) map to real LocalStack names in `env.json.resources`.
2. `/Users/hardik/Development/taskgrant/harness/scenarios.yaml` is the corpus. Find the family
   whose `variants` contain your `Sxxx`. Your instructions are the family `run` text plus the
   family `expect` text, narrowed by your variant's fields (`capability`, `params`, `text`,
   `payload`, `param`, `case`, `note`) and overridden by `expect_override` when present.
3. `/Users/hardik/Development/taskgrant/ARCHITECTURE.md` is the spec. Sections 4 (MCP surface),
   5 (synthesizer, clarification), 6 (guardrails G0 to G8), 7 (size budget), 8 (STS), 9 (decision
   log), 11 (approvals), 12 (abuse cases) settle any question about intended behavior. Section 3
   lists invariants I1 to I6.
4. `env.json.notes` records real environment facts and limitations. Read them before you judge:
   several of them change what "correct" looks like for your family.

## 2. Your identity

Scenario `Sxxx` runs as agent `agent-xxx` with its own bearer token file:

```
TOKEN=/Users/hardik/Development/taskgrant/harness/tokens/agent-007.token   # for S007
```

Some scenarios need a second identity (cross-agent probes, another agent's retry token). Use
`agent-201` (`tokens/agent-201.token`) as the other party unless your variant names one, and use
`tokens/agent-expired.token` where a pre-expired token is required. Token files hold the
plaintext bearer with no trailing newline.

## 3. Calling the broker

Use the harness MCP client. It speaks the same streamable HTTP transport and SDK the broker
uses, with `Authorization: Bearer` on every request.

```bash
MCP=/Users/hardik/Development/taskgrant/harness/bin/mcp-call
URL=http://127.0.0.1:8770/mcp
TOKEN=/Users/hardik/Development/taskgrant/harness/tokens/agent-007.token

$MCP --url $URL --token-file $TOKEN --tool request_grant --args '{
  "task": "Read the 2026 invoice objects in acme-invoices-prod to total monthly revenue",
  "reason": "scenario S007, ticket HARNESS-7",
  "profile": "default",
  "capabilities": [{"id": "logs.read", "params": {"log_group": "/aws/lambda/invoice-processor"}}],
  "duration_seconds": 900
}'
```

Other tools:

```bash
$MCP --url $URL --token-file $TOKEN --tool get_grant       --args '{"grant_id":"01M0..."}'
$MCP --url $URL --token-file $TOKEN --tool explain_grant   --args '{"grant_id":"01M0..."}'
$MCP --url $URL --token-file $TOKEN --tool list_capabilities --args '{}'
$MCP --url $URL --token-file $TOKEN --tool release_grant   --args '{"grant_id":"01M0...","outcome":"succeeded","note":"done"}'
$MCP --url $URL --token-file $TOKEN --list-tools
```

Output is JSON on stdout:
`{"tool":..., "is_error":..., "structured_content":{...}, "content":[...]}`.
Add `--raw` to print only `structured_content`. Parse it with `jq` or `python3 -m json.tool`.

Exit codes matter:

- `0` the server returned a tool result. Denials, clarifications, and tool errors are normal
  results and still exit 0. This is the "the broker answered" case.
- `1` your own usage error (bad flags, bad `--args` JSON).
- `2` transport, auth, or session failure (broker down, 401 for an invalid or expired bearer).
- `3` a JSON-RPC protocol failure.

Long arguments (a 4096-character task, a 512-character prefix) are easier through a file:
`--args-file /tmp/args.json`.

Truthfulness rule: unless your scenario is explicitly about lying or injection, keep `task` and
`reason` honest descriptions of what you are doing. Injection payloads belong only in the
scenarios that call for them.

## 4. Verifying what happened

**Minted credentials against LocalStack.** Use the wrapper, which handles endpoint and creds:

```bash
AWS=/Users/hardik/Development/taskgrant/harness/awslocal
$AWS s3 ls s3://acme-invoices-prod/2026/                 # admin view, test/test creds
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... \
  $AWS sts get-caller-identity                            # a minted credential
```

A minted credential must report an assumed-role ARN of the profile role, for example
`arn:aws:sts::000000000000:assumed-role/taskgrant-default/tg-agent-007-<grant_ulid>`.
IMPORTANT: LocalStack does NOT enforce the session policy. A successful S3 or SQS call proves
the mint path is real; it proves nothing about scope. Judge scope from the policy document in
`explain_grant.policy_json` and in the audit record.

**Decision log.** Flags come BEFORE the grant id (Go's flag package stops at the first
positional argument):

```bash
TG=/Users/hardik/Development/taskgrant/harness/bin/taskgrant
CFG=/Users/hardik/Development/taskgrant/harness/config.yaml
$TG audit show --config $CFG --json <grant_id>
$TG audit list --config $CFG --json --agent agent-007 --limit 20
```

**Approvals (admin surface, never MCP).** You play both roles: agent over MCP, human approver
over the admin unix socket.

```bash
$TG approvals list --config $CFG
$TG approve --config $CFG --note "scenario S065" <grant_id>
$TG deny    --config $CFG --note "not this time" <grant_id>
```

**Revocation.**

```bash
$TG revoke --config $CFG --grant <grant_id>
$TG revoke --config $CFG --profile default
$AWS iam list-role-policies --role-name taskgrant-default
$AWS iam get-role-policy --role-name taskgrant-default --policy-name taskgrant-revocations
```

**Broker log.** `/Users/hardik/Development/taskgrant/harness/run/broker.log` (shared by the
whole fleet, so grep for your own values, never `tail` and assume it is yours). A JSONL mirror
of the decision log is at `run/decisions.jsonl`.

## 5. Attacking the raw transport (transport-auth family)

`curl` the endpoint directly, no SDK. The streamable HTTP endpoint wants both content types in
`Accept`:

```bash
# no Authorization header
curl -s -i -X POST http://127.0.0.1:8770/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# random bearer, expired bearer
curl -s -o /dev/null -w '%{http_code} %{time_total}\n' -X POST http://127.0.0.1:8770/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "Authorization: Bearer $(openssl rand -hex 32)" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# valid bearer, real initialize handshake
curl -s -i -X POST http://127.0.0.1:8770/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "Authorization: Bearer $(cat /Users/hardik/Development/taskgrant/harness/tokens/agent-095.token)" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

After any hostile probe (malformed JSON-RPC, oversized body), finish with one healthy
`mcp-call` to prove the broker is still up. If your probe leaves the broker dead, that is a
`fail` with strong evidence, and say so plainly.

## 6. Ground rules

- The harness is READ-ONLY to you. Do not edit `config.yaml`, `env.json`, the catalog, the
  dataset, product source, or any harness script. Do not run `gen-config.sh` or `provision.sh`.
- Do not start, restart, or kill the broker, and do not kill LocalStack. The broker is shared by
  100 sessions. No restart helper exists, so restart sub-checks (S063, S071) are skipped by
  design: run the rest of the scenario and record the skipped sub-check in `observed`.
- Do not rotate or overwrite token files.
- Stay inside your own scenario. Do not "fix" the broker, and do not mint sprees beyond what
  your scenario needs: the rate ledger is durable and shared per agent.
- Keep total wall time sane. Poll with `sleep`, not with tight loops. Pending approvals expire
  after 180 seconds (`approvals.pending_ttl_seconds`), and `wait_seconds` is capped at 60.
- Record commands and their key output as you go; you need them for the evidence field.

## 7. Environment facts that change what "correct" looks like

These are true of this harness and are documented in `env.json`. Read them before judging.

- Every catalog capability caps `max_duration_seconds` at 900, so every successful mint clamps
  to 900 seconds regardless of the requested value or the profile ceiling (1800 for `default`).
- `s3.write-prefix` and `lambda.invoke` set `requires_approval: true` in the catalog, so they
  park `pending_approval` on every profile, `default` included. Approve over the admin socket to
  reach `active`.
- The `approval-gated` profile parks every request through `approvals.rules[0]`.
- `guardrails.first_use_approval` is false. `server.credential_redelivery` is false, so
  credentials cross the boundary exactly once per grant: in the `request_grant` response for an
  auto-approved grant, or in the first `get_grant` poll after a human approval.
- There is no LLM classifier (`synth.llm` is absent), so matching is the deterministic rules
  matcher only.
- Bad or non-allowlisted parameter values come back as `status: needs_clarification` with
  `clarification.code` of `INVALID_PARAM` or `MISSING_PARAM` and the exact param plus expected
  shape, not as `status: denied`. No STS call happens on that path.
- `agent-077` is the only agent with a single-profile allowlist (`narrow`). Capability
  visibility per agent is a catalog feature that the shipped catalog does not use; see
  `env.json.s077_narrow` for exactly what S077 can assert.
- LocalStack STS ignores session policies (see section 4 above).

## 8. Your output: one JSON verdict

Finish your session with exactly this JSON object, and nothing else after it:

```json
{
  "scenario": "S007",
  "verdict": "pass",
  "expected": "one-sentence restatement of what the corpus said the broker should do",
  "observed": "what the broker actually did, including status, codes, and any sub-check you skipped",
  "evidence": "the commands you ran and the key output lines, trimmed to what proves the verdict",
  "invariant": "I1"
}
```

Field rules:

- `scenario`: your `Sxxx` id, exactly.
- `verdict`: `pass`, `fail`, or `blocked`. Nothing else.
- `expected` and `observed`: plain sentences. If they differ, the difference must explain the
  verdict.
- `evidence`: real commands and real output. Redact nothing except live secret material: never
  paste a `secret_access_key` or `session_token` value (say "secret present, value redacted").
  Access key ids and grant ids are fine.
- `invariant`: the invariant or guardrail your scenario is really about, for example `I1`, `I2`,
  `I3`, `I4`, `I5`, `I6`, `G4`, `G5`, `G7`, `G8`, or `none`.

If you cannot decide between `pass` and `fail`, choose the one the spec supports and put your
uncertainty in `observed`. Do not invent output you did not see, and do not pass a scenario you
did not actually run.
