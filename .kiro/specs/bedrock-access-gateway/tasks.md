> Source of truth: current code / IaC / live infra (2026-04-11)
> Archive baseline: .kiro/specs/bedrock-access-gateway/archive-recovered/

# Bedrock Access Control Gateway — Current Task Status

## Legend
- [x] Done — deployed and verified in live infra
- [-] Partial — code exists but incomplete or has known issues
- [ ] Not started / remaining work

---

## 1. Infrastructure (Terraform)

- [x] 1.1 API Gateway REST Regional with AWS_IAM auth, {proxy+} routing, stage v1
- [x] 1.2 Gateway Lambda (Python 3.12, 256MB, 900s timeout, alias "live")
- [x] 1.3 DynamoDB 15 tables (PAY_PER_REQUEST, TTL configured where applicable)
- [x] 1.4 SQS job queue + DLQ (maxReceiveCount=10, 14d DLQ retention)
- [x] 1.5 Dispatcher Lambda (128MB, 60s, SQS event source batch=5)
- [x] 1.6 Step Functions Standard state machine (job orchestrator, 3600s timeout)
- [x] 1.7 ECS cluster + Fargate task definition (256 CPU / 512 MB, Container Insights)
- [x] 1.8 S3 payload bucket (AES256, 7-day lifecycle, public access blocked)
- [x] 1.9 CloudWatch log groups (5 groups, 90-day retention)
- [x] 1.10 IAM roles: lambda-exec, dispatcher-exec, fargate-exec, fargate-task, sfn-exec, apigw-cw
- [x] 1.11 Lambda IAM: Bedrock invoke, DynamoDB (ledger PutItem-only + Deny mutation), SES, SFN, S3, SQS

## 2. v1 Sync Path (/converse)

- [x] 2.1 Principal extraction + normalization (Candidate F: account#role)
- [x] 2.2 PrincipalPolicy lookup (fail-closed)
- [x] 2.3 Model access check (allowed_models list)
- [x] 2.4 ModelPricing cold-start cache + one-reload fallback
- [x] 2.5 KRW cost-based monthly quota check (KST boundary)
- [x] 2.6 Bedrock Converse invocation (non-streaming)
- [x] 2.7 Cost estimation from response.usage (fail-closed on missing usage/pricing)
- [x] 2.8 MonthlyUsage atomic ADD (cost_krw + tokens)
- [x] 2.9 IdempotencyRecord (conditional PutItem, 24h TTL)
- [x] 2.10 RequestLedger immutable write (fail-closed: ledger failure → deny)
- [x] 2.11 SessionMetadata write (30d TTL, non-fatal)
- [x] 2.12 Deny-by-default catch-all + deny ledger in finally block
- [x] 2.13 Quota exhaustion → auto-create approval request + 429 with band info
- [x] 2.14 Hidden async routing: Opus models on /converse → handle_converse_job_submit → 202

## 3. v3 Async Path (/converse-jobs)

- [x] 3.1 Job submit: validate, reserve budget (2× pessimistic, max 100K), create JobState, enqueue SQS
- [x] 3.2 Per-user active limit check (50, query GSI principal-created-index)
- [x] 3.3 Dispatcher: global active count scan, start SFN or re-enqueue with 30s delay
- [x] 3.4 Step Functions: QUEUED → RunFargateTask.sync → SUCCEEDED/FAILED
- [x] 3.5 Fargate worker: converse() with retry (3 attempts, exponential backoff, 30min read timeout)
- [x] 3.6 Worker settlement: delete reservation, ADD actual cost, write S3 result, update JobState
- [x] 3.7 Semaphore release on success and failure
- [x] 3.8 Job status query (GET /converse-jobs/{jobId})
- [x] 3.9 Job cancel (POST /converse-jobs/{jobId}/cancel — stop SFN, release reservation+semaphore)
- [x] 3.10 Stale reservation cleanup on submit
- [x] 3.11 Burst test verified: 200 requests (100 short + 100 long) → 100/100 SUCCEEDED, DLQ=0

## 4. Approval Ladder

- [x] 4.1 POST /approval/request with validation (reason, increment=500K, hard cap pre-check)
- [x] 4.2 ApprovalPendingLock (conditional PutItem, 7d TTL safety net)
- [x] 4.3 SES email notification (team-routed via team_config lookup)
- [x] 4.4 Email action flow: HEAD safe, GET → confirmation page, POST → execute (token auth)
- [x] 4.5 Auto-approval on quota exhaustion (non-portal flow)
- [x] 4.6 Warning emails at 30%/10% band remaining (dedup via policy attributes)

## 5. Admin Portal (backend-admin)

- [x] 5.1 Policy CRUD routes (gateway_policy.py)
- [x] 5.2 Approval list/approve/reject routes (gateway_approval.py)
- [x] 5.3 Usage monitoring: user overview, per-model breakdown, daily KST breakdown (gateway_usage.py)
- [x] 5.4 Model pricing CRUD routes (gateway_pricing.py)
- [x] 5.5 Team governance CRUD with auto-provisioning (gateway_teams.py)
- [x] 5.6 Direct-access toggle (set_direct_access endpoint — IAM + DynamoDB)
- [x] 5.7 Exception user monitoring via CloudWatch Logs Insights (30s cache)
- [x] 5.8 Gateway config GET/PUT (quota_enforcement_enabled)
- [x] 5.9 Governance audit log
- [x] 5.10 Frontend BedrockGateway.jsx (formatKRW with toFixed(4) for sub-1 KRW)

## 6. IAM & Bypass Prevention

- [x] 6.1 22 BedrockUser-* roles provisioned
- [x] 6.2 DenyDirectBedrockInference on gateway-managed roles
- [x] 6.3 DenyDirectECSAndSFN on gateway-managed roles
- [x] 6.4 Gateway invoke policies (converse, converse-jobs, approval/request, quota/status)
- [-] 6.5 intern role: missing DenyDirect policies (known gap)
- [-] 6.6 user05 role: excluded from gateway management (direct-access exception)

## 7. Shell Hook & Quota Status

- [x] 7.1 GET /quota/status endpoint (read-only, zero writes)
- [x] 7.2 Threshold detection (30%/10%), prompt decision, suppress reasons

## 8. Longrun Authorize/Settle (Tier 3)

- [x] 8.1 POST /longrun/authorize (pre-auth, budget reservation, LongrunRequest record)
- [x] 8.2 POST /longrun/settle (actual cost settlement, reservation cleanup, ledger write)

---

## Known Gaps & Remaining Work

- [x] G1. intern role: apply DenyDirectBedrockInference + DenyDirectECSAndSFN
- [ ] G2. RequestLedger has no GSI on principal_id — admin queries use full table scan (acceptable at MVP scale, not at growth)
- [ ] G3. Cache token cost not included in accounting — warning logged but no cost impact. Risk: undercount if cache usage becomes significant
- [ ] G4. No CloudWatch Alarms defined in Terraform for `alarm=True` log entries (ledger failure, usage update failure)
- [ ] G5. DailyUsage table still exists (deprecated by MonthlyUsage) — cleanup deferred
- [ ] G6. Discovery mode endpoint still in code (DISCOVERY_MODE=false) — dead code cleanup deferred
- [ ] G7. No CI/CD pipeline — Terraform apply and Lambda deploy are manual
- [ ] G8. Concurrency semaphore (slot-based) is legacy — dispatcher uses scan-based global count. Semaphore still used by worker for release but functionally redundant with dispatcher logic
- [ ] G9. No automated integration tests — burst test was manual one-time verification
- [ ] G10. SFN logging level is ERROR only — no trace-level visibility for normal job flow
