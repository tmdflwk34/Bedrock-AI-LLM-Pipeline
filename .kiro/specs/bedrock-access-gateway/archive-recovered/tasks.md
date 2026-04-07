# Bedrock Access Control Gateway — Implementation Tasks (v2: Async Long-Running)

> Last updated: 2026-04-02
> v1 Phases 0-4A: COMPLETE AND DEPLOYED.
> v2 Phases 8-16: Async Fargate path for long-running Bedrock calls.
> Approval gate: Per `devops-operating-model.md`.

---

## v1 Status Summary (Phases 0-7)

Phases 0-4A are complete and deployed. See previous task entries for details.
- Phase 0: Decisions resolved
- Phase 1: Data model migration (DynamoDB tables)
- Phase 2: Lambda quota logic rewrite (KRW monthly)
- Phase 3: Approval ladder rewrite
- Phase 4: Admin API + data layer
- Phase 4A: Data/IAM remediation
- Phase 5-7: Frontend, validation, documentation (partial)

**v1 current state**: Lambda timeout 900s, API Gateway timeout 29s (Service Quotas increase pending to 900s). Short path covers up to 15 minutes once API GW quota approved.

---

## Phase 8: Design and Document Alignment

### Task 8.1: Update Spec Documents for Async Architecture
- [x] Update requirements.md: Req 1 (mediated access via control plane, not sole Lambda invocation), Req 4 (reserved/settled cost), Req 6 (event-based ledger), Req 7 (async idempotency), Req 10 (Fargate invocation), new Reqs 16-20
- [x] Update design.md: async architecture, Step Functions + Fargate flow, data model, concurrency, security, retry, logging
- [x] Update tasks.md: Phase 8-16 for async implementation
- [x] Resolve contradiction: "Lambda is sole Bedrock invocation path" → "control plane is sole entry point, internal execution principals invoke Bedrock"

---

## Phase 9: Data Model Migration (Async Tables)

### Task 9.1: Add JobState DynamoDB Table
- [ ] Table: `bedrock-gw-${env}-${region}-job-state`
- [ ] PK: `job_id` (S)
- [ ] GSI: `principal-status-index` (PK: principal_id, SK: created_at)
- [ ] TTL on `ttl` attribute
- [ ] Fields: request_id, principal_id, model_id, region, status, pricing_version, reserved_cost_krw, settled_cost_krw, input_tokens, output_tokens, input_payload_ref, result_ref, sfn_execution_arn, ecs_task_arn, retry_count, error_message, source_path, created_at, updated_at, completed_at
- [ ] Terraform: `infra/bedrock-gateway/dynamodb.tf`

Requirements: Req 6, Req 7, Req 16

### Task 9.2: Add ConcurrencySemaphore DynamoDB Table
- [ ] Table: `bedrock-gw-${env}-${region}-concurrency-semaphore`
- [ ] PK: `slot_id` (S) — "slot-0" through "slot-4" (5 slots default)
- [ ] TTL on `ttl` attribute (orphan cleanup, 2 hours)
- [ ] Fields: job_id, acquired_at
- [ ] Seed initial empty slots
- [ ] Terraform: `infra/bedrock-gateway/dynamodb.tf`

Requirements: Req 17

### Task 9.3: Add S3 Payload Bucket
- [ ] Bucket: `bedrock-gw-${env}-payload-${account_id}`
- [ ] Private, SSE-S3 encryption
- [ ] Lifecycle: delete objects after 7 days
- [ ] Bucket policy: Lambda exec role + Fargate task role only
- [ ] Terraform: `infra/bedrock-gateway/s3.tf` (new file)

Requirements: Req 19

### Task 9.4: Extend RequestLedger Schema
- [ ] Add `event_type`, `job_id`, `source_path`, `pricing_version`, `reserved_cost_krw` fields
- [ ] DynamoDB is schemaless — no table change needed, just code changes
- [ ] Backward compatible: existing v1 records unaffected

Requirements: Req 6

### Task 9.5: Add ModelPricing Version Fields
- [ ] Add `pricing_version` and `effective_date` to existing ModelPricing records
- [ ] Backfill existing 115 records with initial version
- [ ] Code: capture pricing_version at job submission

Requirements: Req 4

---

## Phase 10: Lambda Control Plane Changes

### Task 10.1: Add POST /converse-jobs Endpoint
- [ ] Route in `lambda_handler`: `POST /converse-jobs`
- [ ] Handler: `handle_converse_job_submit()`
- [ ] Flow: identity → policy → allowlist → pricing → quota pre-check → idempotency → reserve budget → create job record → store payload → start Step Functions → return 202 + jobId
- [ ] Idempotency: duplicate request_id returns existing job reference
- [ ] Feature flag: `async_jobs_enabled` in gateway config

Requirements: Req 1, Req 4, Req 7, Req 9

### Task 10.2: Add GET /converse-jobs/{jobId} Endpoint
- [ ] Route in `lambda_handler`: `GET /converse-jobs/{jobId}`
- [ ] Handler: `handle_converse_job_status()`
- [ ] Validate principal owns the job
- [ ] Return: jobId, status, model_id, reserved/settled cost, tokens, result pointer, timestamps

Requirements: Req 12

### Task 10.3: Add GET /converse-jobs/{jobId}/result Endpoint
- [ ] Route in `lambda_handler`: `GET /converse-jobs/{jobId}/result`
- [ ] If result in S3: generate presigned URL (5min TTL)
- [ ] If result inline (small): return directly
- [ ] Validate principal owns the job and status=SUCCEEDED

Requirements: Req 19

### Task 10.4: Lambda IAM Updates
- [ ] Add `states:StartExecution` permission for Step Functions state machine ARN
- [ ] Add `s3:PutObject` permission for payload bucket (input storage)
- [ ] Add DynamoDB permissions for job-state and concurrency-semaphore tables
- [ ] Terraform: `infra/bedrock-gateway/iam.tf`

Requirements: Req 14

---

## Phase 11: Step Functions Workflow

### Task 11.1: Create Step Functions Standard State Machine
- [ ] State machine: `bedrock-gw-${env}-job-orchestrator`
- [ ] Input: `{job_id, request_id, principal_id, model_id, region, pricing_version, payload_ref}`
- [ ] States:
  1. AcquireSlot: Lambda function to acquire semaphore slot
  2. RunFargateTask: ECS RunTask with override env vars
  3. WaitForCompletion: wait for task to finish
  4. ReleaseSlot: Lambda function to release semaphore slot
  5. UpdateJobState: update DynamoDB job record
- [ ] Catch: on any failure → ReleaseSlot → UpdateJobFailed
- [ ] Timeout: 1 hour (configurable)
- [ ] Terraform: `infra/bedrock-gateway/stepfunctions.tf` (new file)

Requirements: Req 10, Req 17

### Task 11.2: Step Functions IAM Role
- [ ] `sts:AssumeRole` by states.amazonaws.com
- [ ] `ecs:RunTask` on Fargate task definition
- [ ] `iam:PassRole` for Fargate task role and execution role
- [ ] `dynamodb:GetItem, PutItem, UpdateItem` on job-state and semaphore tables
- [ ] `logs:*` for execution logging
- [ ] Terraform: `infra/bedrock-gateway/iam.tf`

Requirements: Req 14, Req 16

### Task 11.3: Semaphore Acquire/Release Lambda Functions
- [ ] Small Lambda functions (or inline in Step Functions):
  - `acquire_slot`: conditional PutItem on semaphore table
  - `release_slot`: UpdateItem to clear slot
- [ ] Or implement as Step Functions SDK integrations (DynamoDB direct)

Requirements: Req 17

---

## Phase 12: Fargate Task Implementation

### Task 12.1: Create Fargate Task Definition
- [ ] Family: `bedrock-gw-${env}-worker`
- [ ] CPU: 256, Memory: 512 (minimal — Bedrock call is I/O bound)
- [ ] Image: ECR repository `bedrock-gw-worker`
- [ ] Environment overrides: JOB_ID, REQUEST_ID, PRINCIPAL_ID, MODEL_ID, REGION, PRICING_VERSION, PAYLOAD_REF, RESULT_BUCKET
- [ ] Log driver: awslogs → `/aws/ecs/bedrock-gw-${env}-worker`
- [ ] Terraform: `infra/bedrock-gateway/ecs.tf` (new file)

Requirements: Req 10, Req 14

### Task 12.2: Create ECS Cluster
- [ ] Cluster: `bedrock-gw-${env}`
- [ ] Fargate capacity provider
- [ ] No EC2 instances
- [ ] Terraform: `infra/bedrock-gateway/ecs.tf`

Requirements: Req 14

### Task 12.3: Implement Fargate Worker Container
- [ ] Single Python script: `worker/main.py`
- [ ] Flow:
  1. Read env vars (JOB_ID, MODEL_ID, etc.)
  2. Update job state → RUNNING
  3. Ledger: TASK_STARTED
  4. Read input payload from S3/DynamoDB
  5. Call Bedrock Converse (with retry/backoff)
  6. Ledger: BEDROCK_INVOKED
  7. Extract usage tokens
  8. Compute actual cost (read pricing from DynamoDB using pricing_version)
  9. Settlement: delete reservation, ADD actual cost to MonthlyUsage
  10. Write result to S3
  11. Update job state → SUCCEEDED
  12. Ledger: TASK_COMPLETED
- [ ] Error handling: catch all exceptions → update job state → FAILED → ledger TASK_FAILED → release reservation
- [ ] Structured JSON logging throughout

Requirements: Req 10, Req 4, Req 6, Req 13

### Task 12.4: Implement Retry Logic in Worker
- [ ] Retryable errors: ThrottlingException (429), InternalServerException (500), ServiceUnavailableException (503)
- [ ] Non-retryable: ValidationException, AccessDeniedException, ModelNotReadyException
- [ ] Strategy: exponential backoff with full jitter (base 1s, max 60s, max 3 retries)
- [ ] Disable boto3 SDK retry: `Config(retries={"max_attempts": 0})`
- [ ] Each retry: ledger RETRY_ATTEMPT event

Requirements: Req 18

### Task 12.5: Build and Push Docker Image
- [ ] Dockerfile: Python 3.12 slim + boto3
- [ ] ECR repository: `bedrock-gw-worker`
- [ ] Build script in `infra/bedrock-gateway/worker/`
- [ ] Image tag: git SHA or date-based

Requirements: Req 14

---

## Phase 13: Networking and IAM Hardening

### Task 13.1: Fargate Networking
- [ ] Use existing VPC private subnets
- [ ] Security group: outbound only (443 to Bedrock, DynamoDB, S3, CloudWatch)
- [ ] No inbound rules
- [ ] `assignPublicIp: DISABLED`
- [ ] VPC endpoints where feasible (DynamoDB gateway endpoint exists; Bedrock interface endpoint if cost-justified)

Requirements: Req 16

### Task 13.2: Fargate Task Role (Least Privilege)
- [ ] `bedrock:InvokeModel` on `*`
- [ ] `dynamodb:GetItem, PutItem, UpdateItem` on job-state, monthly-usage, request-ledger
- [ ] `dynamodb:GetItem` on model-pricing
- [ ] `s3:GetObject, PutObject` on payload bucket
- [ ] `logs:CreateLogStream, PutLogEvents`
- [ ] NOT assumable by user roles

Requirements: Req 16

### Task 13.3: User Role Deny Policies
- [ ] Existing `DenyDirectBedrockInference` maintained (all 4 Bedrock actions)
- [ ] Add deny for: `ecs:RunTask`, `ecs:ExecuteCommand`, `states:StartExecution`
- [ ] Apply to all managed BedrockUser-* roles
- [ ] Verify: user cannot directly trigger Fargate or Step Functions

Requirements: Req 1, Req 16

---

## Phase 14: Client and Portal Updates

### Task 14.1: Update bedrock_gw.py
- [ ] Add `converse_async(model_id, text, **kwargs)` function
- [ ] Add `poll_job(job_id)` function
- [ ] Add `get_result(job_id)` function
- [ ] `_GatewayClient` gets `converse_async()` method
- [ ] Existing `converse()` and `get_client().converse()` unchanged

Requirements: Req 12

### Task 14.2: Update Portal for Async Jobs
- [ ] Job list view in BedrockGateway.jsx
- [ ] Job status badges: ACCEPTED, RUNNING, SUCCEEDED, FAILED
- [ ] Reserved vs settled cost display
- [ ] Job duration display
- [ ] Retry count display

Requirements: Req 11

---

## Phase 15: Testing and Validation

### Task 15.1: Unit Tests
- [ ] Semaphore acquire/release logic
- [ ] Cost reservation/settlement math
- [ ] Retry classifier (retryable vs non-retryable errors)
- [ ] Job state transition validation
- [ ] Idempotency behavior (async path)

### Task 15.2: Integration Tests
- [ ] Job submit → ACCEPTED → RUNNING → SUCCEEDED
- [ ] Duplicate request_id → same job reference
- [ ] Policy deny → 403
- [ ] Pricing missing → deny
- [ ] Quota exhausted → 429
- [ ] Concurrent job submissions → semaphore limits enforced
- [ ] Post-completion cost settlement accuracy

### Task 15.3: Long-Running Validation
- [ ] Submit job with synthetic 35+ second Bedrock call
- [ ] Verify API Gateway returns 202 immediately (not 504)
- [ ] Verify job completes in background
- [ ] Verify cost/tokens/ledger recorded correctly
- [ ] This proves "29-second problem is structurally solved"

### Task 15.4: No-Bypass Validation
- [ ] Managed user: direct Bedrock call → AccessDeniedException
- [ ] Managed user: direct ECS RunTask → AccessDeniedException
- [ ] Managed user: direct StepFunctions StartExecution → AccessDeniedException
- [ ] Gateway path: job submit → ACCEPTED (success)
- [ ] Fargate: no public IP, no inbound route

### Task 15.5: Pricing Validation
- [ ] Compare all 115 ModelPricing entries against AWS official pricing
- [ ] Document source URLs, retrieval date, FX rate assumption
- [ ] Verify pricing_version field populated

### Task 15.6: Logging Validation
- [ ] CloudWatch logs contain: request_id, job_id, principal_id, model_id, tokens, cost, status
- [ ] Minimal mode: no payload content in logs
- [ ] Full mode: truncated payload in logs

---

## Phase 16: Quota Assessment and Documentation

### Task 16.1: Service Quotas Assessment
- [ ] API Gateway: Maximum integration timeout (PENDING: 29s → 900s, request ID 9975ab80...)
- [ ] Bedrock: InvokeModel requests per minute per model (check current vs needed)
- [ ] Bedrock: InvokeModel tokens per minute per model (check current vs needed)
- [ ] Fargate: On-Demand vCPU resource count (check current limit)
- [ ] Step Functions: StartExecution throttle rate
- [ ] Document exact quota names + recommended values + rationale

### Task 16.2: Runbook Update
- [ ] Async job troubleshooting procedures
- [ ] Semaphore stuck slot recovery
- [ ] Fargate task failure investigation
- [ ] Cost reconciliation procedure

### Task 16.3: Rollback Documentation
- [ ] Feature flag: `async_jobs_enabled: false` disables async path
- [ ] Sync path always available
- [ ] New DynamoDB tables can be left in place (no data dependency)
- [ ] Step Functions/Fargate resources can be destroyed independently

---

## Task Dependencies

```
Phase 8 (Docs) ──────────────────────────────────┐
                                                   ▼
Phase 9 (Data Model) ───────────────────────────→ Phase 10 (Lambda)
                                                   ▼
Phase 11 (Step Functions) ──→ Phase 12 (Fargate) → Phase 13 (IAM/Network)
                                                   ▼
Phase 14 (Client/Portal) ──────────────────────→ Phase 15 (Testing)
                                                   ▼
                                                 Phase 16 (Quotas/Docs)
```

Short path improvements (Lambda 900s timeout, API GW quota increase) are independent and already in progress.
