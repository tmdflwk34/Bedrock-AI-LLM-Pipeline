> Source of truth: current code / IaC / live infra (2026-04-11)
> Archive baseline: .kiro/specs/bedrock-access-gateway/archive-recovered/

# Bedrock Access Control Gateway — Current Requirements

## R1. Identity & Principal Model

- R1.1 All requests authenticated via API Gateway AWS_IAM authorization
- R1.2 Principal extracted from `requestContext.identity.userArn` (assumed-role ARN)
- R1.3 Normalization: `<account_id>#<role_name>` (Candidate F), e.g. `<ACCOUNT_ID>#BedrockUser-admin`
- R1.4 Fail-closed: empty principal → deny. Non-`BedrockUser-*` → deny. `BedrockUser-Shared` → deny
- R1.5 22 `BedrockUser-*` IAM roles provisioned. All gateway-managed except `intern` (missing deny policies) and `user05` (excluded/direct-access exception)

## R2. Policy & Access Control

- R2.1 PrincipalPolicy table: per-principal `allowed_models`, `monthly_cost_limit_krw` (default 500K), `max_monthly_cost_limit_krw` (hard cap 2M KRW)
- R2.2 Model access: request model_id must be in principal's `allowed_models` list. Empty list → deny all
- R2.3 No policy record → deny (fail-closed)
- R2.4 Gateway config stored as reserved `__gateway_config__` item in PrincipalPolicy table

## R3. KRW Cost-Based Monthly Quota

- R3.1 Monthly boundary: KST (UTC+9), format `YYYY-MM`
- R3.2 Cost formula: `(input_tokens × input_price_per_1k / 1000) + (output_tokens × output_price_per_1k / 1000)`
- R3.3 Accounting source: `response.usage` from Bedrock Converse API only (inputTokens, outputTokens)
- R3.4 Fail-closed: missing usage or missing pricing → deny (do not write zero accounting)
- R3.5 MonthlyUsage: atomic ADD per model per month. TTL ~35 days
- R3.6 ModelPricing: admin-managed fixed KRW rates, cold-start cached in Lambda, one reload on cache miss
- R3.7 Operator toggle: `quota_enforcement_enabled` flag. When false, quota check returns allowed=true but still logs usage
- R3.8 Cache tokens (cacheReadInputTokens, cacheWriteInputTokens) tracked but NOT included in cost calculation. Warning logged if nonzero

## R4. Approval Ladder (Quota Increase)

- R4.1 Fixed increment: 500K KRW per approval. Hard cap: 2M KRW
- R4.2 TemporaryQuotaBoost: TTL = end of current month (KST). Auto-expires
- R4.3 Race-safe: ApprovalPendingLock table (conditional PutItem, attribute_not_exists). One pending per principal
- R4.4 Auto-approval: system auto-creates approval request on quota exhaustion during inference
- R4.5 SES email notification to admin group (team-routed if team config exists)
- R4.6 Email action: GET → confirmation page → form POST → execute. Token-based auth (no JWT). HEAD returns 200 (SafeLinks safe)
- R4.7 Warning emails at 30% and 10% remaining within current band slice (500K bands). Dedup via policy attributes

## R5. Idempotency

- R5.1 IdempotencyRecord table: request_id PK, status IN_PROGRESS/COMPLETED, TTL 24h
- R5.2 Conditional PutItem (attribute_not_exists) for atomicity
- R5.3 COMPLETED → return cached response. IN_PROGRESS → 409

## R6. Audit & Immutability

- R6.1 RequestLedger: append-only (PutItem). IAM explicitly denies UpdateItem/DeleteItem
- R6.2 Ledger entries for both ALLOW and DENY decisions
- R6.3 SessionMetadata: raw identity fields preserved, TTL 30 days
- R6.4 Ledger write failure → deny response + alarm (fail-closed on audit)

## R7. v1 Sync Path (POST /converse)

- R7.1 Pipeline: principal → idempotency → policy → model access → pricing → quota → Bedrock Converse → usage update → ledger → session metadata
- R7.2 Returns 200 with Bedrock response, usage, estimated_cost_krw, remaining_quota
- R7.3 Long-running models (Opus variants) auto-routed to async path (hidden from caller)
- R7.4 Deny-by-default catch-all: unhandled exception → deny

## R8. v3 Async Path (POST /converse-jobs)

- R8.1 Submit: validates, reserves budget (2× pessimistic), creates JobState (ACCEPTED), enqueues to SQS → returns 202
- R8.2 SQS queue: `bedrock-gw-dev-job-queue`, visibility 120s, retention 1 day, maxReceiveCount 10 → DLQ
- R8.3 Dispatcher Lambda: batch_size=5, batching_window=2s, ReportBatchItemFailures
- R8.4 Dispatcher checks global active count (RUNNING only) vs GLOBAL_ACTIVE_LIMIT (20)
- R8.5 Capacity full → re-enqueue with 30s delay (not batch failure, avoids DLQ for valid jobs)
- R8.6 Step Functions Standard: UpdateJobQueued → RunFargateTask.sync → UpdateJobSucceeded/Failed. Timeout 3600s
- R8.7 Fargate worker: 256 CPU / 512 MB, client.converse() with retry (3 retries, exponential backoff, 30min read timeout)
- R8.8 Worker settlement: delete reservation, add actual cost, write result to S3, update JobState, write ledger
- R8.9 Semaphore release on both success and failure paths
- R8.10 Per-user active limit: 50 (ACCEPTED+QUEUED+RUNNING). Per-user queue limit: 100. Global queue limit: 500
- R8.11 Job status: GET /converse-jobs/{jobId}. Cancel: POST /converse-jobs/{jobId}/cancel (stops SFN, releases reservation+semaphore)
- R8.12 Stale reservation cleanup: on submit, scan and delete expired `__reserved__` entries

## R9. IAM Bypass Prevention

- R9.1 `DenyDirectBedrockInference` policy on all gateway-managed BedrockUser-* roles
- R9.2 `DenyDirectECSAndSFN` policy prevents users from directly running ECS tasks or Step Functions
- R9.3 Exception users: `direct_access_exception=true` in PrincipalPolicy, DenyDirect removed from IAM role
- R9.4 Portal toggle: `set_direct_access` endpoint switches between gateway-managed and direct-access

## R10. Admin Portal (backend-admin)

- R10.1 Policy CRUD: `/api/gateway/policies` (list/get/create/update/delete)
- R10.2 Approval management: `/api/gateway/approvals` (list/get/approve/reject)
- R10.3 Usage monitoring: `/api/gateway/users` (overview), `/users/<pid>/usage` (per-model), `/users/<pid>/daily` (KST daily breakdown)
- R10.4 Model pricing CRUD: `/api/gateway/model-pricing`
- R10.5 Team governance: `/api/gateway/teams` CRUD with auto-provisioning (IAM role + principal-policy on user add)
- R10.6 Exception user monitoring: `/api/gateway/exception-usage` via CloudWatch Logs Insights
- R10.7 Gateway config: `/api/gateway/config` (GET/PUT quota_enforcement_enabled)
- R10.8 Governance audit log: `/api/gateway/audit-log`
- R10.9 All admin endpoints require JWT auth (`@admin_required`, role=admin)

## R11. Shell Hook Integration

- R11.1 `GET /quota/status`: read-only quota state for shell hook / thin clients. Zero DynamoDB writes
- R11.2 Returns: usage, effective limit, band, pending state, threshold alerts (30%/10%), prompt decision

## R12. Longrun Authorize/Settle (Tier 3)

- R12.1 `POST /longrun/authorize`: pre-authorize with budget reservation (pessimistic 2×, max 100K KRW)
- R12.2 `POST /longrun/settle`: settle actual cost, delete reservation, write ledger
- R12.3 LongrunRequest table: states authorized → settled | failed. TTL 1 hour
