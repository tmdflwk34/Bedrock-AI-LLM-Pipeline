# Bedrock Access Control Gateway — Requirements (v2: Async Long-Running)

> Last updated: 2026-04-02
> v1 (sync inline): DEPLOYED AND VERIFIED. Converse API, KRW cost-based monthly quota.
> v2 (async long-running): Adds Step Functions + Fargate for >15min Bedrock calls.
> Quota model: KRW cost-based monthly (unchanged from v1).

---

## Req 1: Mediated Bedrock Access (v2 Updated)

All Bedrock inference requests from FSx interactive users must be authorized through the gateway control plane. Direct Bedrock API calls are not permitted under the managed access model.

**v2 clarification**: The gateway control plane (API Gateway + Lambda) is the sole external-facing entry point for all Bedrock requests. Actual Bedrock invocation may be performed by authorized internal execution principals (Lambda exec role for short path, Fargate task role for long path). User roles never call Bedrock directly.

### Acceptance Criteria
- [x] Gateway control plane is the sole external entry point for managed users
- [x] FSx user AWS profiles route Bedrock calls through the gateway API endpoint
- [x] Direct `bedrock-runtime:InvokeModel` is not granted to user roles — **LIVE VERIFIED (2026-03-19)**
- [x] IAM deny policy on each `BedrockUser-*` role: explicit deny for all 4 Bedrock actions — **LIVE VERIFIED**
- [ ] User roles cannot directly invoke ECS RunTask, StepFunctions StartExecution, or Fargate tasks
- [ ] Only gateway Lambda exec role and Step Functions execution role can trigger Fargate tasks
- [ ] Fargate task role has Bedrock invoke permission but is not assumable by users
- [ ] Bypass verification includes: direct Bedrock, direct Fargate, direct Step Functions paths all denied for user roles

---

## Req 2: Identity Resolution and Principal Normalization

(Unchanged from v1. All acceptance criteria remain.)

The gateway must resolve the calling principal from the SigV4-signed request context and normalize it to an exact-match enforcement key: `<account_id>#<role_name>`.

### Acceptance Criteria
- [x] Principal identity extracted from API Gateway `requestContext.identity`
- [x] Normalization produces `<account_id>#<role_name>` — **LIVE VERIFIED**
- [ ] Unknown or unparseable identities are denied (fail-closed)
- [ ] Raw identity fields preserved in audit records

---

## Req 3: Model Access Control (Allowlist)

(Unchanged from v1.)

Each principal has an explicit list of allowed Bedrock models. Requests for non-allowed models are denied. Empty or missing allowlist = deny-all (fail-closed).

---

## Req 4: KRW Cost-Based Monthly Quota Enforcement (v2 Updated)

Each principal has a monthly KRW cost budget. The gateway estimates per-request cost from model-specific pricing and enforces the budget in near-real-time via DynamoDB.

### Core Parameters (unchanged)
- Default per-user monthly budget: KRW 500,000
- Hard ceiling per user: KRW 2,000,000
- Global monthly budget context: KRW 10,000,000 (alerting-only v1)

### v2 Additions for Async Path
- [ ] Pre-check at job submission: verify remaining budget >= estimated cost before accepting job
- [ ] Reserved cost: at job acceptance, atomically reserve estimated cost against quota
- [ ] Post-completion settlement: replace reserved cost with actual cost based on real token usage
- [ ] If actual > reserved: overshoot is logged and accepted (Bedrock already completed)
- [ ] If actual < reserved: difference is released back to available budget
- [ ] If job fails before Bedrock call: full reservation is released
- [ ] Reserved cost is visible in portal as "reserved" (distinct from "settled")
- [ ] MonthlyUsage tracks both reserved and settled amounts

### Model Pricing Reference (v2 Updated)
- [ ] ModelPricing table includes `pricing_version` and `effective_date` fields
- [ ] Pricing version is captured at job submission and stored with usage/ledger records
- [ ] Missing pricing for a model = deny request (fail-closed, unchanged)
- [ ] Admin can update pricing; new version takes effect for new requests only

---

## Req 5: Approval Ladder for Quota Increases

(Unchanged from v1. KRW 500,000 increments, hard cap 2,000,000.)

Approval requests work identically for both sync and async paths. The `/approval/request` endpoint remains on the gateway Lambda control plane.

---

## Req 6: Immutable Request Audit Ledger (v2 Updated)

Every gateway request and job lifecycle event is recorded in an immutable, append-only ledger.

### v2 Event Types
- [ ] `REQUEST_ACCEPTED` — job accepted, budget reserved. `source_path` field indicates routing decision (`gateway-inline` or `gateway-async`). This replaces a separate ROUTING_DECIDED event.
- [ ] `TASK_STARTED` — Fargate task launched
- [ ] `BEDROCK_INVOKED` — Bedrock Converse call initiated
- [ ] `TASK_COMPLETED` — job succeeded, actual cost settled
- [ ] `TASK_FAILED` — job failed, reservation released
- [ ] `TASK_TIMED_OUT` — job exceeded Step Functions timeout
- [ ] `RETRY_ATTEMPT` — Bedrock throttling retry within Fargate
- [ ] `QUOTA_DENIED` — pre-check quota denial
- [ ] `POLICY_DENIED` — model/principal policy denial

### Acceptance Criteria
- [ ] Each event is a separate append-only record with `request_id` + `event_type` + `timestamp`
- [ ] Ledger entries are never updated or deleted (Lambda IAM enforces PutItem only)
- [ ] Short path (sync) continues to write single `ALLOW`/`DENY` records as before
- [ ] Long path (async) writes multiple lifecycle events per job

---

## Req 7: Idempotency (v2 Updated)

### Sync Path (unchanged)
- Duplicate `request_id` returns cached response, not re-invocation

### Async Path (new)
- [ ] Duplicate `request_id` on job submission returns existing job reference (jobId + status)
- [ ] If job is still running: return `{jobId, status: RUNNING}`
- [ ] If job is completed: return `{jobId, status: SUCCEEDED, resultPointer}`
- [ ] Idempotency scope: per `request_id`, TTL 24 hours
- [ ] Collision behavior: second submission with same request_id never creates a new job

---

## Req 8: Session Metadata

(Unchanged from v1. TTL 30 days.)

---

## Req 9: Deny-by-Default (Fail-Closed)

(Unchanged from v1. All deny conditions remain.)

Additional deny conditions for async path:
- [ ] Step Functions execution fails to start → deny + release reservation
- [ ] Fargate task fails to launch → deny + release reservation + ledger event

---

## Req 10: Bedrock Invocation (v2 Updated)

### Short Path (v1, maintained)
- Gateway Lambda invokes Bedrock via Converse API (non-streaming)
- For requests completing within API Gateway timeout (currently 29s, pending increase to 900s)

### Long Path (v2, new)
- [ ] Fargate task invokes Bedrock via Converse API (non-streaming, same as v1)
- [ ] Fargate task role has `bedrock:InvokeModel` permission (not user role)
- [ ] Model ID, pricing key, and invocation target use the same `model_id` value in v2
- [ ] ConverseStream support deferred to v3

---

## Req 11: Admin Portal

(Unchanged from v1, with async job visibility additions.)

Additional for v2:
- [ ] Admin can view async job list with status (ACCEPTED/RUNNING/SUCCEEDED/FAILED)
- [ ] Admin can view reserved vs settled cost per job
- [ ] Admin can view job duration and retry count

---

## Req 12: User UI

(Unchanged from v1.)

Additional for v2:
- [ ] User can view their async job status
- [ ] User can see reserved cost while job is running

---

## Req 13: Observability (v2 Updated)

### Acceptance Criteria
- [ ] API Gateway access + execution logging → CloudWatch (unchanged)
- [ ] Lambda structured JSON logs with: request_id, job_id, principal_id, model_id, decision, cost_krw
- [ ] Fargate task structured JSON logs with: request_id, job_id, principal_id, model_id, input_tokens, output_tokens, cost_krw, retry_count, status, latency_ms
- [ ] Step Functions execution logs enabled
- [ ] CloudWatch metric: quota exhaustion events
- [ ] CloudWatch metric: task failure count
- [ ] CloudWatch metric: Bedrock throttling/retry count
- [ ] CloudWatch metric: concurrent running tasks
- [ ] Payload logging: config-driven mode (default: token counts + cost only; full payload mode available for debug)

---

## Req 14: Deployment (IaC)

(Extended from v1.)

- [ ] Terraform-managed: API Gateway, Lambda, DynamoDB, Step Functions, ECS task definition, IAM roles
- [ ] ECS cluster and Fargate task definition in `infra/bedrock-gateway/`
- [ ] Step Functions state machine in `infra/bedrock-gateway/`
- [ ] Lambda versioning + alias (`live`) for rollback (unchanged)
- [ ] Fargate image: ECR repository in same account

---

## Req 15: Non-Disruptive Integration (v2 Updated)

- [ ] Gateway remains a separate serverless control plane
- [ ] Existing Flask/Docker/nginx stack unchanged
- [ ] Fargate runs in existing VPC private subnets (no new VPC)
- [ ] No public ingress to Fargate tasks
- [ ] Existing sync `/converse` path maintained for short-running calls
- [ ] Async path is additive — does not replace sync path

---

## Req 16: Fargate Isolation and No-Bypass (NEW)

- [ ] Fargate tasks run in private subnets only
- [ ] `assignPublicIp: DISABLED`
- [ ] No ALB/NLB/service discovery exposure
- [ ] No ECS Exec enabled
- [ ] Inbound: none (no security group ingress rules)
- [ ] Outbound: Bedrock, DynamoDB, S3, CloudWatch Logs, STS via VPC endpoints or NAT
- [ ] User roles denied: `ecs:RunTask`, `ecs:ExecuteCommand`, `states:StartExecution`
- [ ] Only Lambda exec role and Step Functions role can `ecs:RunTask`

---

## Req 17: Concurrency Control (NEW)

- [ ] Maximum concurrent Fargate tasks is operator-configurable (default: 5)
- [ ] DynamoDB-based semaphore for slot acquisition
- [ ] Job submission denied with 429 if all slots occupied
- [ ] Slot released on task completion, failure, or timeout
- [ ] Orphan slot cleanup via TTL

---

## Req 18: Retry Policy (NEW)

- [ ] Bedrock 429 (ThrottlingException) and 500/503: exponential backoff with full jitter
- [ ] Max retries: 3 (configurable)
- [ ] Non-retryable: ValidationException, AccessDeniedException, ModelNotReadyException
- [ ] SDK-level retry disabled to prevent retry multiplication
- [ ] Step Functions retry is separate from Fargate-internal retry (no double retry)
- [ ] Each retry attempt logged as `RETRY_ATTEMPT` ledger event

---

## Req 19: Secure Payload Storage (NEW)

- [ ] Large input payloads (>256KB) stored in S3, referenced by pointer in job record
- [ ] Large output/results stored in S3, referenced by pointer
- [ ] S3 bucket: private, SSE-S3 encryption, lifecycle policy for cleanup
- [ ] Fargate reads input from S3, writes result to S3
- [ ] Result TTL: 7 days (configurable)
- [ ] S3 bucket accessible only by Lambda exec role and Fargate task role

---

## Req 20: Operator Controls (NEW)

- [ ] Max concurrent tasks (DynamoDB config, default: 5)
- [ ] Payload logging mode: `minimal` (default) | `full` (debug)
- [ ] Quota enforcement toggle (existing, unchanged)
- [ ] Job timeout: operator-configurable per Step Functions (default: 1 hour)
- [ ] All operator controls stored in DynamoDB `__gateway_config__` item

---

## Glossary (v2 additions)

| Term | Definition |
|------|------------|
| `job_id` | Unique identifier for an async job (UUID, prefixed `job-`) |
| `reserved_cost_krw` | Pessimistic cost estimate reserved at job submission |
| `settled_cost_krw` | Actual cost computed from real token usage after completion |
| `source_path` | `gateway-inline` (sync) or `gateway-async` (Fargate) |
| `pricing_version` | Snapshot identifier for pricing used at submission time |
