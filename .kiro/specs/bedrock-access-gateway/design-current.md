> Source of truth: current code / IaC / live infra (2026-04-11)
> Archive baseline: .kiro/specs/bedrock-access-gateway/archive-recovered/

# Bedrock Access Control Gateway — Current Design

## 1. Infrastructure Overview

```
API Gateway REST Regional (<GATEWAY_API_ID>)
  ├── Stage: v1, AWS_IAM auth, {proxy+} + root → Lambda proxy integration
  ├── Throttle: 50 req/s rate, 100 burst
  └── Access logs → CloudWatch

Lambda: bedrock-gw-dev-gateway
  ├── Python 3.12, 256 MB, 900s timeout, alias "live"
  └── Routes: /converse, /converse-jobs, /approval/request, /quota/status, /longrun/*

SQS: bedrock-gw-dev-job-queue
  ├── Standard queue, visibility 120s, retention 1 day, long-poll 5s
  ├── Redrive: maxReceiveCount=10 → bedrock-gw-dev-job-dlq (14 day retention)
  └── Dispatcher Lambda event source: batch=5, window=2s

Dispatcher Lambda: bedrock-gw-dev-dispatcher
  ├── Python 3.12, 128 MB, 60s timeout
  └── SQS → check global active → start SFN or re-enqueue

Step Functions Standard: bedrock-gw-dev-job-orchestrator
  ├── UpdateJobQueued → RunFargateTask.sync → UpdateJobSucceeded/Failed
  ├── Timeout: 3600s, error logging
  └── Catch States.ALL → UpdateJobFailed

ECS Cluster: bedrock-gw-dev-cluster (Container Insights enabled)
  └── Task: bedrock-gw-dev-worker, Fargate, 256 CPU / 512 MB
      ├── Image: ECR bedrock-gw-dev-worker:latest
      ├── Private subnets, no public IP
      └── awslogs driver → /aws/ecs/bedrock-gw-dev-worker

S3: bedrock-gw-dev-payload-{account_id}
  ├── AES256 SSE, public access blocked
  ├── Lifecycle: 7-day expiration
  └── Stores: payloads/{jobId}.json, results/{jobId}.json
```

## 2. DynamoDB Tables (15 tables)

All tables: PAY_PER_REQUEST, naming `bedrock-gw-dev-us-west-2-{name}`

| Table | PK | SK | TTL | Purpose |
|-------|----|----|-----|---------|
| principal-policy | principal_id | — | — | Per-user policy + gateway config |
| daily-usage | principal_id_date | model_id | ✓ | Legacy token tracking (deprecated) |
| monthly-usage | principal_id_month | model_id | ✓ 35d | KRW cost tracking + reservations |
| model-pricing | model_id | — | — | Admin-managed KRW rates |
| temporary-quota-boost | principal_id | boost_id | ✓ EOM | Approval-granted quota increases |
| approval-request | request_id | — | — | Approval requests (GSI: principal-status) |
| request-ledger | request_id | — | — | Immutable audit log (PutItem only) |
| session-metadata | request_id | — | ✓ 30d | Raw identity preservation |
| idempotency-record | request_id | — | ✓ 24h | Duplicate request detection |
| approval-pending-lock | principal_id | — | ✓ 7d | Race-safe one-pending-per-user |
| longrun-request | request_id | — | ✓ 1h | Tier 3 authorize/settle tracking |
| job-state | job_id | — | ✓ 7d | Async job lifecycle (GSI: principal-created) |
| concurrency-semaphore | slot_id | — | ✓ 2h | Legacy slot-based admission |
| team-config | team_id | — | — | Team governance structure |
| governance-audit | audit_id | — | ✓ 1y | Admin action audit trail |

## 3. Request Flow — v1 Sync

```
Client → API GW (AWS_IAM) → Lambda
  1. Extract principal from requestContext.identity.userArn
  2. Normalize: {account}#BedrockUser-{user}
  3. Check idempotency (IdempotencyRecord)
  4. Lookup PrincipalPolicy → deny if absent
  5. Check model_id in allowed_models → deny if not
  6. Lookup ModelPricing → deny if missing (fail-closed)
  7. Check monthly KRW quota (MonthlyUsage aggregate)
     - If exceeded: return 429 with band info + auto-create approval request
  8. Invoke bedrock_runtime.converse(modelId, messages, system, inferenceConfig, toolConfig)
  9. Estimate cost from response.usage (inputTokens, outputTokens)
  10. Atomic ADD to MonthlyUsage
  11. Check warning thresholds (30%/10% band remaining) → SES email
  12. Complete IdempotencyRecord with cached response
  13. Write RequestLedger (fail-closed: ledger failure → deny)
  14. Write SessionMetadata (non-fatal)
  → 200 {decision, output, usage, estimated_cost_krw, remaining_quota}
```

Long-running risk detection (`_should_route_async`): requests hitting `/converse` are auto-routed to async when ANY condition is true:
- Model in LONGRUN_MODELS (Opus variants) → always async
- `maxTokens >= 16384` → async (large output risk, any model)
- Input messages+system JSON > 200KB → async (large context)
This eliminates the 29-second API Gateway timeout risk for all models including Sonnet, DeepSeek, Nova.

## 4. Request Flow — v3 Async

```
Client → POST /converse-jobs → Lambda
  1. Validate, policy, model access, pricing, quota (same as sync)
  2. Reserve budget: min(2× estimated cost, 100K KRW, remaining budget)
  3. Create JobState (ACCEPTED), store payload (S3 if >256KB, else inline)
  4. Check per-user active limit (50) → 429 if exceeded
  5. Enqueue to SQS job queue
  → 202 {job_id, status: ACCEPTED, reserved_cost_krw}

SQS → Dispatcher Lambda (batch=5)
  1. Count RUNNING jobs globally (DynamoDB scan)
  2. For each message:
     - If slots available: start SFN execution, update JobState → QUEUED
     - If capacity full: re-enqueue with 30s delay (message consumed, not failed)
  3. Return empty batchItemFailures (all messages handled)

SFN → Fargate Worker
  1. SFN: UpdateJobQueued (DynamoDB) → RunFargateTask.sync
  2. Worker: update JobState → RUNNING
  3. Read payload from S3 or inline
  4. bedrock.converse() with retry (3 attempts, exponential backoff)
  5. Fail-closed: missing usage or pricing → raise (no zero accounting)
  6. Settlement: delete reservation, ADD actual cost to MonthlyUsage
  7. Write result to S3 (results/{jobId}.json)
  8. Update JobState → SUCCEEDED, write ledger
  9. Release semaphore slot
  On failure: release reservation, update FAILED, write ledger, release semaphore
```

## 5. Concurrency Limits

| Limit | Value | Enforcement |
|-------|-------|-------------|
| Global active (RUNNING) | 20 | Dispatcher: scan JobState, re-enqueue if full |
| Per-user active (ACCEPTED+QUEUED+RUNNING) | 50 | Lambda: query GSI principal-created-index |
| Per-user queue | 100 | Lambda: env var PER_USER_QUEUE_LIMIT |
| Global queue | 500 | Lambda: env var GLOBAL_QUEUE_LIMIT |

## 6. IAM Architecture

Gateway-managed roles (`BedrockUser-{user}`):
- `BedrockAccess`: Allow bedrock:InvokeModel, InvokeModelWithResponseStream on Claude/Amazon models
- `DenyDirectBedrockInference`: Deny bedrock:InvokeModel, InvokeModelWithResponseStream, Converse, ConverseStream, InvokeAgent, InvokeInlineAgent, InvokeFlow on *
- `DenyDirectECSAndSFN`: Deny ecs:RunTask, ExecuteCommand, StartTask, states:StartExecution, StartSyncExecution on *
- `AllowDevGatewayConverse`: Allow execute-api:Invoke on POST/converse
- `AllowDevGatewayConverseJobs`: Allow execute-api:Invoke on POST/converse-jobs, GET/converse-jobs/*, POST/converse-jobs/*
- `AllowDevGatewayApprovalRequest`: Allow execute-api:Invoke on POST/approval/request
- `AllowDevGatewayQuotaStatus`: Allow execute-api:Invoke on GET/quota/status
- `S3DataAccess`: Allow s3:GetObject/PutObject/DeleteObject/ListBucket on *

Exception users: `DenyDirectBedrockInference` + `DenyDirectECSAndSFN` removed, `BedrockAccess` upgraded with `bedrock:InvokeTool` + `bedrock:InvokeAgent`.

## 7. Admin Portal Integration

backend-admin Flask routes (JWT auth, port 5000):
- Policy CRUD, approval management, usage monitoring, pricing CRUD
- Team governance with auto-provisioning (IAM role + principal-policy on user add)
- Exception user monitoring via CloudWatch Logs Insights (`/aws/bedrock/modelinvocations`)
- Direct-access toggle: `PUT /api/gateway/users/<pid>/direct-access`
- Email-based approval: GET → confirmation HTML → form POST (token auth, no JWT)

Frontend: React SPA `BedrockGateway.jsx` — `formatKRW` with `toFixed(4)` for sub-1 KRW values.

## 8. Observability

- API Gateway access logs: `/aws/apigateway/bedrock-gw-dev-api/access` (90d)
- Lambda logs: `/aws/lambda/bedrock-gw-dev-gateway` (90d)
- Dispatcher logs: `/aws/lambda/bedrock-gw-dev-dispatcher` (90d)
- Worker logs: `/aws/ecs/bedrock-gw-dev-worker` (90d)
- SFN logs: `/aws/states/bedrock-gw-dev-job-orchestrator` (90d, ERROR level)
- Structured JSON logging throughout (timestamp, level, message, context fields)
- `alarm=True` flag on critical failures (ledger write, usage update)
