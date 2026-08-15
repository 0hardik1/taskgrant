# taskgrant test harness report

100 adversarial scenarios, one opus session each, run against a live broker and a real
LocalStack AWS backend. The harness exercises the security invariants and guardrails of
ARCHITECTURE.md end to end: it declares tasks over MCP, mints real short-lived STS
credentials through LocalStack, and inspects the decision log.

## Result

| | Scenarios | Pass | Fail | Blocked |
|---|---|---|---|---|
| First run | 100 | 95 | 5 | 0 |
| After fixes (re-verified) | 100 | 100 | 0 | 0 |

The harness found 5 genuine deviations. All 5 were root-caused, fixed with regression tests
that fail on the pre-fix code, and re-verified live against the rebuilt broker. The five
failures clustered in one subsystem (the clarification retry-token) plus two isolated gaps.

## How it runs

- **LocalStack** (community 3.8.1) provides sts, iam, s3, sqs, dynamodb, logs, and lambda.
  The broker points at it through `aws.endpoint_url`. Every mint is a real `sts:AssumeRole`
  that returns usable session credentials; the harness exercises them with the AWS CLI.
- **The broker** runs in HTTP mode with 102 per-agent bearer tokens and four profiles
  (`default`, `approval-gated`, `short-cap`, `narrow`). It is the same single static binary
  the product ships.
- **The fleet**: 100 opus sessions, 14 concurrent, each owning one scenario `Sxxx`. A session
  calls the five MCP tools through a purpose-built `mcp-call` client, verifies with the
  `taskgrant audit` CLI and the AWS CLI, attacks the raw HTTP transport with curl, and writes
  full evidence to `results/Sxxx.json`.

A scenario passes when the broker behaves as the spec requires, which includes correctly
denying a hostile or malformed request. "Blocked" is reserved for environment faults; there
were none.

## Coverage by family

| Family | Scenarios | What it proves |
|---|---|---|
| happy-structured | S001-S010 | structured-hint mints are least-privilege, enumerated, region-pinned (I2, G5) |
| keyword-match | S011-S018 | free text never silently mints; it clarifies or denies to structured hints |
| prompt-injection | S019-S028 | task text cannot influence policy bytes (I1); byte-identical to a bland control |
| hostile-params | S029-S040 | grammars reject `*`, `?`, whitespace, traversal, homoglyphs, control bytes (I1, G4) |
| idempotency | S041-S045 | one key, one mint under retry storms |
| clarification | S046-S052 | 2-round bound, signed single-use agent-bound retry tokens (5.6) |
| budget-size | S053-S058 | reduction ladder, per-capability byte attribution, no wildcard coalescing (7.3, I2) |
| rate-creep | S059-S064 | durable token bucket and distinct-capability caps (G8, I5) |
| approvals | S065-S072 | durable pending queue, mint at approval not request, approver as a role (11) |
| isolation | S073-S078 | cross-agent lookups return NOT_FOUND, never FORBIDDEN (4.1) |
| credentials | S079-S084 | secrets delivered once, never in logs or the decision record (I4) |
| duration | S085-S089 | effective duration is the min of the cap chain, floor 900 (G7) |
| release-revoke | S090-S094 | release records, deny keyed only on the broker ULID, never caller_ref (I3, 8.5) |
| transport-auth | S095-S100 | bearer rejection leaks nothing; records carry token fingerprint and remote addr (4.3, 12.4) |

## Findings

### F1 (critical, security): retry-token accepted across agents

- **Scenario:** S051. Agent-051 received a `needs_clarification` retry-token. Agent-201
  presented that exact token, supplied the missing parameter, and the broker **minted live STS
  credentials under agent-051's grant ULID, attributed to agent-201**.
- **Why it matters:** a cross-agent credential-isolation breach. Section 4.1 requires
  cross-agent access to return `NOT_FOUND`; the retry path bypassed that.
- **Root cause:** the signed token payload was `{GrantID, IntentHash, Round}` with no agent
  binding, and the broker attached retries to a grant by ULID without checking ownership.
- **Fix:** the broker now resolves the retry grant's owner from live and durable state and
  returns `NOT_FOUND` when the grant is missing or owned by another agent, before any mint. As
  defense in depth the token payload gained an `AgentID` that verification must match.
- **Re-verified:** agent-201 presenting agent-051's token now returns `NOT_FOUND` with no mint.

### F2 (high): retry-token replayable after the grant resolved

- **Scenario:** S050. A round-1 token was resolved to an active grant (mint #1), then the same
  token was replayed and produced a **second mint under the same grant ULID**.
- **Root cause:** the retry path honored the token alone and never checked the grant's current
  state.
- **Fix:** a retry is accepted only when the grant is currently in `needs_clarification` with an
  open round matching the token; a resolved or terminal grant rejects the retry with no mint.
- **Re-verified:** first resolve mints once; the replay now returns `denied` with no second mint.

### F3 (high): retry-token still minted after CLARIFICATION_EXHAUSTED

- **Scenario:** S048. Two invalid rounds correctly returned `CLARIFICATION_EXHAUSTED`, but
  replaying the round-2 token with a now-valid parameter **minted an active grant** on the
  exhausted ULID.
- **Root cause:** shared with F2. Exhaustion closed the negotiation for the invalid-answer path
  only; a later valid answer bypassed the closed state.
- **Fix:** shared with F2. An exhausted or otherwise terminal grant is not in an open
  clarification round, so the retry is rejected.
- **Re-verified:** the post-exhaustion retry now returns `denied` with no mint.

### F4 (medium, strictness): value-supplied wildcard silently normalized

- **Scenario:** S030. Parameter `prefix = "2026/*"` (an agent-supplied `*`, not the
  template-controlled trailing wildcard) was silently stripped to `2026/` and minted.
- **Why it matters:** the emitted policy stayed correctly scoped, so this was a strictness gap
  rather than a broadening, but section 5.2 requires grammars to reject `*`. Tolerating a
  value-supplied wildcard weakens the guarantee that parameter values are exactly
  grammar-validated (I1).
- **Root cause:** the validator stripped a trailing `*` when `allow_trailing_wildcard` was set,
  then accepted the remainder.
- **Fix:** a value containing `*` or `?` is always rejected with `INVALID_PARAM` that names the
  parameter and its expected shape. `allow_trailing_wildcard` now means only that the template
  appends the wildcard, never that the value may carry one. The template still renders
  `.../2026/*` from a clean `2026/`, so the golden compilation output is byte-identical (I6).
- **Re-verified:** `2026/*` now returns `needs_clarification` with `clarification.code =
  INVALID_PARAM` and no mint; `2026/` still mints identically.

### F5 (low, observability): remote_addr absent from decision records

- **Scenario:** S099. The `grant_decision` record carried a valid 8-hex `token_fingerprint` but
  no `remote_addr`, which section 9.1 requires and section 12.4 relies on for reconstructing a
  token-theft window.
- **Root cause:** the field existed on the record but was never populated on the HTTP path.
- **Fix:** the peer address is captured at the HTTP boundary and threaded through to the record;
  an agent field cannot populate it. stdio and creds transports leave it empty, which is correct.
- **Re-verified:** an HTTP-originated grant now records `remote_addr` (for example
  `127.0.0.1:56278`) alongside the fingerprint and `transport = http`.

## What passed on the first run, worth calling out

- **Prompt injection (S019-S028):** every injection attempt, including a full IAM policy pasted
  into the task text and multilingual "ignore previous instructions" payloads, produced a
  byte-identical policy to a bland control. Task text never reached the policy (I1).
- **Credential secrecy (S079-S084):** secrets were delivered exactly once, never redelivered by
  `get_grant`, and never appeared in the broker log, the decision record, or `explain_grant`.
  The record stores the access key id only (I4).
- **Isolation (S073-S078):** every cross-agent probe returned `NOT_FOUND` with wording identical
  to a never-issued ULID, so existence is not confirmed (4.1).
- **Guardrails (throughout):** every mint recorded all of G0 through G8 passing, actions were
  always enumerated with no wildcard, and `aws:RequestedRegion` was present on every statement.

## Reproducing

```
cd harness
docker compose up -d                 # LocalStack 3.8.1 community
./provision.sh                       # buckets, tables, queues, log groups, roles, lambda
./gen-config.sh                      # config.yaml + 102 tokens (idempotent)
# start the broker (exact command in env.json: broker_start_cmd)
# then run one scenario or the whole fleet; per-scenario evidence lands in results/Sxxx.json
```

Artifacts: `scenarios.yaml` (the corpus), `env.json` (the machine contract), `run-scenario.md`
(the session manual), `results/` (100 evidence files), `results/_summary.json` (the aggregate).

Note on the artifacts: `results/` and `results/_summary.json` record the **first** run, so the
summary shows 95 pass and 5 fail. That is deliberate: those files are the evidence that found
F1 through F5. The re-verification after the fixes is reported in the table above and is covered
by the regression tests in the Go suite, each of which fails on the pre-fix code.
