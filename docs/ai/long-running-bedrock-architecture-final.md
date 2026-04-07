# Long-Running Bedrock Architecture — Final Report

> Date: 2026-04-01
> Author: Kiro (AI assistant)
> Status: RESEARCH + ARCHITECTURE DECISION COMPLETE
> Scope: Determine whether current gateway architecture supports 30-min inference, and if not, define the target architecture.

---

## 0. Executive Summary

The current gateway (API Gateway REST API → Lambda → Bedrock Converse) is fully valid as a **control plane** for real-time cost tracking, quota enforcement, approval bands, and portal visibility. It is **not valid as a data plane** for calls exceeding 15 minutes. The 30-minute requirement cannot be met by any Lambda-based path (including Function URLs). The solution is to keep the current gateway as the authoritative control plane and add a **gateway-mediated direct Bedrock path** for long-running calls, where the gateway pre-authorizes and post-settles but does not proxy the inference.

---

## 1. AWS Service Limit Verification (Official Documentation)

All limits verified against official AWS documentation as of 2026-04-01.

### 1.1 Lambda Timeout

| Attribute | Value | Source |
|-----------|-------|--------|
| Maximum configurable timeout | **900 seconds (15 minutes)** | [AWS Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html) |
| Applies to | All invocation types: sync, async, Function URL, API Gateway | Same source |
| Can be increased | **No. Hard AWS service limit.** | Same source |

**Verdict**: Lambda cannot run longer than 15 minutes under any configuration. This is an AWS platform constraint, not a tunable parameter.

### 1.2 API Gateway REST API (Regional) — Integration Timeout

| Attribute | Value | Source |
|-----------|-------|--------|
| Default integration timeout | 29 seconds | [REST API quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-execution-service-limits-table.html) |
| Can be increased (Regional) | **Yes** — via Service Quotas request | Same source, footnote * |
| Can be increased (Edge) | No | Same source |
| Can be increased (Private) | **Yes** — via Service Quotas request | Same source, footnote * |
| Trade-off | May require reduction in Region-level throttle quota | Same source |

**Critical correction**: The previous assumption that REST API is hard-capped at 29s is **wrong for Regional APIs**. AWS added the ability to increase Regional REST API integration timeout beyond 29s via Service Quotas (announced June 2024). However, even if increased to 900s, it still cannot exceed Lambda's 15-minute limit.

### 1.3 API Gateway HTTP API — Integration Timeout

| Attribute | Value | Source |
|-----------|-------|--------|
| Maximum integration timeout | **30 seconds** | [HTTP API quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html) |
| Can be increased | **No** | Same source |

**Critical correction**: The `main.tf` rewrite to HTTP API was based on the false premise that HTTP API supports 30-minute timeout. **HTTP API maximum is 30 seconds, not 30 minutes.** The `timeout_milliseconds = 900000` in the current `main.tf` would be rejected or clamped by AWS. The HTTP API migration would make things **worse** than the current REST API (which can at least request a timeout increase beyond 29s).

### 1.4 Lambda Function URL

| Attribute | Value | Source |
|-----------|-------|--------|
| Timeout | **Same as Lambda function timeout (max 900s / 15 min)** | [Lambda Function URL docs](https://docs.aws.amazon.com/lambda/latest/dg/urls-invocation.html) |
| Bypasses API Gateway timeout | Yes (no API Gateway in path) | Same source |
| Bypasses Lambda timeout | **No** | Same source |

**Verdict**: Function URL removes the API Gateway 29s bottleneck but does NOT extend beyond Lambda's 15-minute hard limit. It is useful for calls between 29s and 15min, but cannot solve the 30-minute requirement.

### 1.5 Bedrock ConverseStream

| Attribute | Value | Source |
|-----------|-------|--------|
| Supported models | Claude (all versions), Titan, Nova, Llama, Mistral, DeepSeek | [ConverseStream docs](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ConverseStream.html) |
| Token reporting | In final stream event (metadata.usage) | Same source |
| Timeout | Governed by caller's SDK/HTTP timeout, not Bedrock-side | Bedrock service behavior |

**Key insight**: ConverseStream sends tokens incrementally. The HTTP connection stays alive as long as tokens are flowing. A 30-minute Opus call that produces tokens throughout will NOT timeout at the Bedrock level — the timeout risk is entirely on the **caller side** (Lambda timeout, API Gateway timeout, or client-side HTTP timeout).

### 1.6 Current Live Infrastructure

| Component | Actual Value | Evidence |
|-----------|-------------|----------|
| API Gateway type | **REST API (Regional)** | API ID `<GATEWAY_API_ID>` in all IAM policies, `bedrock_gw.py`, shell hook |
| API Gateway integration timeout | **29 seconds (default)** | `aws service-quotas`: 29000ms, adjustable=True |
| Lambda timeout (live) | **60 seconds (1 min)** | `aws lambda get-function-configuration`: Timeout=60 |
| Lambda timeout (Terraform default) | 900 seconds (15 min) | `variables.tf`: `lambda_timeout = 900` (NOT applied to live) |
| Lambda timeout drift | **Live=60s vs TF default=900s** | Last apply used different value; needs `terraform apply` to sync |
| Lambda memory | 256 MB | `variables.tf` |
| `main.tf` on disk | HTTP API code (NOT applied) | File content shows `aws_apigatewayv2_api` |
| Live API Gateway | REST API (still running) | `terraform apply` was never executed |

**CRITICAL**: The `main.tf` on disk contained HTTP API code that was never applied. The live infrastructure is still the REST API. If `terraform apply` had been run with the HTTP API code, it would have:
1. Destroyed the REST API (`<GATEWAY_API_ID>`)
2. Created an HTTP API with a **30-second** timeout (not 30 minutes as intended)
3. Broken all BedrockUser IAM policies referencing the old API ID
4. Made things strictly worse (30s < current effective 29s + potential increase)

**The HTTP API migration has been abandoned. `main.tf` has been reverted to REST API resources.**
Terraform plan confirms: **0 to add, 1 to change (tags only), 0 to destroy.**

**ADDITIONAL FINDING — Lambda timeout drift:**
The live Lambda has `Timeout: 60s` but `variables.tf` default is `900s`. The dev.tfvars does not override `lambda_timeout`. This means the last `terraform apply` was run before the variable default was changed to 900, or a manual update set it to 60. A `terraform apply` with SSO admin credentials would sync the Lambda timeout to 900s (15 min), which is the intended value.

---

## 2. Current Architecture Role Analysis

### 2A. Control Plane (Current Gateway)

The current API Gateway → Lambda → DynamoDB pipeline handles:

| Function | Implementation | Status |
|----------|---------------|--------|
| Principal identification | `extract_identity()` + `normalize_principal_id()` | Working |
| Policy lookup | `lookup_principal_policy()` from DynamoDB | Working |
| Model allow/deny | `check_model_access()` | Working |
| Pricing lookup | `lookup_model_pricing()` with cache | Working |
| Cost estimation | `estimate_cost_krw()` | Working, 0% error rate |
| Quota check (pre-call) | `check_quota()` — KRW monthly aggregation | Working |
| Monthly usage atomic ADD | `update_monthly_usage()` | Working |
| Request ledger (immutable) | `write_request_ledger()` | Working |
| Approval request | `handle_approval_request()` | Working |
| Approval pending lock | DynamoDB conditional write | Working |
| Quota status (shell hook) | `handle_quota_status()` | Working |
| Warning emails (30%/10%) | `_check_and_send_warning_email()` | Working |
| Team-based email routing | `_send_approval_email()` queries team-config | Working |
| Portal visibility | backend-admin reads same DynamoDB tables | Working |

**Verdict: Control plane is fully valid. No changes needed. This remains the authoritative source of truth for all cost/quota/approval decisions.**

### 2B. Data Plane (Bedrock Inference)

The current data plane is `invoke_bedrock()` inside the same Lambda:

| Constraint | Limit | Impact |
|------------|-------|--------|
| API Gateway REST timeout | 29s (default, increasable for Regional) | Short calls work; long calls timeout at API GW |
| Lambda timeout | 900s (15 min, hard limit) | Calls 15-30 min impossible |
| Bedrock Converse (sync) | No Bedrock-side timeout for generation | Not the bottleneck |
| Bedrock ConverseStream | Tokens flow continuously | Would keep connection alive if caller supports it |

**Verdict: Data plane is valid for calls under 15 minutes. Invalid for 30-minute calls. No Lambda-based solution can fix this.**

---

## 3. Architecture Options Comparison


### Option A: Current Architecture (No Change)

- API Gateway REST → Lambda → `bedrock_runtime.converse()` → DynamoDB
- All calls through single synchronous path

### Option B: Lambda Function URL Addition

- Short calls: API Gateway REST → Lambda (≤29s)
- Medium calls: Lambda Function URL → same Lambda (≤15min)
- Long calls: **Still impossible** (Lambda 15min hard limit)

### Option C: Long-Running Dedicated Worker (ECS/Fargate/EC2)

- Control plane: existing gateway
- Data plane: separate ECS task or EC2 process for long inference
- Gateway issues tracking ID, worker calls Bedrock, worker writes back to DynamoDB

### Option D: Gateway-Mediated Direct Bedrock (Pre-Authorize + Post-Settle)

- Control plane: existing gateway handles authorization, budget reservation, tracking ID
- Data plane: user's process calls Bedrock directly (via ConverseStream or Converse)
- Post-completion: client wrapper reports usage back to gateway for final settlement
- Gateway DynamoDB remains authoritative

### Option E: Async Submit → Poll/Callback

- Submit: gateway creates job record, reserves budget
- Worker: separate process runs inference asynchronously
- Result: polling endpoint or callback

### Comparison Matrix

| Criterion | A: No Change | B: Function URL | C: Dedicated Worker | D: Mediated Direct | E: Async |
|-----------|:---:|:---:|:---:|:---:|:---:|
| 30-min requirement | NO | NO (15min max) | YES | YES | YES |
| Real-time cost tracking | YES | YES | YES (delayed) | YES (post-settle) | YES (delayed) |
| Approval band maintained | YES | YES | YES | YES | YES |
| Portal real-time visibility | YES | YES | PARTIAL | YES (after settle) | PARTIAL |
| Operational complexity | LOW | LOW | HIGH | LOW-MED | HIGH |
| User code change | NONE | Endpoint change | Major | Wrapper update | Major |
| Current code reuse | 100% | 95% | 40% | 80% | 30% |
| Failure recovery | Simple | Simple | Complex | Medium | Complex |
| Long-term maintainability | Good | Good | Poor (for this scale) | Good | Poor (for this scale) |
| Infra change required | None | Terraform add | ECS/Fargate setup | Terraform add + IAM | ECS + SQS/SNS |
| Works in existing session | YES | YES | NO (async) | YES | NO (async) |

---

## 4. Target Architecture Decision

### Chosen: Option D — Gateway-Mediated Direct Bedrock

**With a tiered approach combining A (short) + B (medium) + D (long).**

#### Rationale

1. **30-minute calls are fundamentally incompatible with Lambda.** No Lambda-based path (A, B) can solve this. This is a hard AWS platform limit.

2. **ECS/Fargate (C) and async (E) are over-engineered for this scale.** 6 active users, ~30K invocations/month. Standing up container orchestration or message queues for this is unjustified operational overhead.

3. **Option D preserves the control plane authoritative model.** The gateway still decides: is this user allowed? Is the model allowed? Is there budget? What's the tracking ID? The gateway just doesn't proxy the actual inference bytes for long calls.

4. **Option D works in existing sessions.** The user's Python process (via `bedrock_gw.py` wrapper) handles the Bedrock call directly. No new terminal needed. No async polling needed.

5. **Option D has the smallest blast radius.** The existing short-path gateway continues unchanged. Only long calls get a new path. Rollback = revert wrapper to gateway-only mode.

### Three-Tier Architecture

```
Tier 1: Short Path (≤29s) — EXISTING, NO CHANGE
  User → bedrock_gw.py → API Gateway REST → Lambda → Bedrock Converse → DynamoDB
  - All control plane + data plane in Lambda
  - Real-time cost tracking, quota enforcement, ledger write
  - Works for: Haiku, Nova, short Sonnet calls

Tier 2: Medium Path (29s–15min) — NEW, ADDITIVE
  User → bedrock_gw.py → Lambda Function URL → Lambda → Bedrock Converse → DynamoDB
  - Same Lambda code, same control plane
  - Bypasses API Gateway 29s timeout
  - Works for: Sonnet with large context, most Opus calls
  - IAM auth on Function URL (same SigV4 credentials)

Tier 3: Long Path (15min–30min) — NEW, ADDITIVE
  User → bedrock_gw.py:
    Step 1: POST /authorize → Lambda (control plane only)
      - Principal identification
      - Policy/model/quota check
      - Budget reservation (optimistic)
      - Returns: { tracking_id, authorized: true, reserved_budget_krw }
    Step 2: bedrock_runtime.converse_stream() DIRECT to Bedrock
      - User's own BedrockUser-{username} role credentials
      - ConverseStream keeps connection alive with token flow
      - No Lambda in the data path
      - No timeout limit (Bedrock streams until done)
    Step 3: POST /settle → Lambda (control plane only)
      - Reports: tracking_id, actual input/output tokens, model_id
      - Lambda computes actual cost, writes monthly_usage, ledger
      - Releases or adjusts budget reservation
      - If settle never arrives: reservation expires, alarm fires
```

### Why This Works

1. **Control plane authority is preserved.** `/authorize` and `/settle` go through the same Lambda, same DynamoDB, same quota logic. The gateway decides who can call what and tracks every KRW.

2. **30-minute calls work.** In Tier 3, the Bedrock call is made directly by the user's process using their own IAM credentials. ConverseStream keeps the HTTP connection alive as tokens flow. There is no Lambda or API Gateway in the data path, so no timeout applies.

3. **Existing sessions work.** The `bedrock_gw.py` wrapper handles tier selection transparently. The user calls `converse()` or `client.converse()` as before. The wrapper decides which tier to use based on model/config.

4. **Portal visibility is maintained.** All three tiers write to the same DynamoDB tables (monthly_usage, request_ledger). The portal reads from these tables. No change to portal code needed for basic visibility.

5. **Approval UX works across all tiers.** The shell hook (`bedrock-gw-quota-check.sh`) queries `/quota/status` which reads from the same DynamoDB. Approval requests go through `/approval/request`. Both are Tier 1 control plane calls that work regardless of which data tier was used.

---

## 5. Detailed Design: Tier 3 (Long Path)

### 5.1 Authorization Endpoint

```
POST /authorize
Body: {
  "modelId": "us.anthropic.claude-opus-4-6-v1",
  "estimated_input_tokens": 200000,  // optional hint
  "reason": "large context analysis"  // optional
}

Response (200): {
  "decision": "AUTHORIZED",
  "tracking_id": "trk-uuid",
  "principal_id": "<ACCOUNT_ID>#BedrockUser-admin",
  "model_id": "us.anthropic.claude-opus-4-6-v1",
  "reserved_budget_krw": 50000,  // pessimistic reservation
  "effective_limit_krw": 500000,
  "remaining_after_reservation_krw": 150000,
  "authorization_ttl_seconds": 3600,  // 1 hour to complete
  "settle_endpoint": "/settle"
}

Response (429): same as current quota exceeded response
Response (403): same as current deny response
```

**Authorization logic** (runs in existing Lambda):
1. Extract principal (same as current)
2. Policy lookup (same as current)
3. Model access check (same as current)
4. Pricing lookup (same as current)
5. Quota check (same as current)
6. **Budget reservation**: atomic ADD `reserved_budget_krw` to a new field in monthly_usage or a separate reservation record. TTL = 1 hour.
7. Return tracking_id + authorization token

### 5.2 Direct Bedrock Call (Client-Side)

The `bedrock_gw.py` wrapper:
1. Receives authorization from Step 1
2. Calls `bedrock_runtime.converse_stream()` directly using the user's own credentials
3. Collects all stream chunks, accumulates `usage` from final metadata event
4. Returns response to caller
5. Calls `/settle` with actual usage

**Key**: The user's `BedrockUser-{username}` role already has `BedrockAccess` policy allowing `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream`. For gateway-managed users, `DenyDirectBedrockInference` blocks this. **For Tier 3 to work, we need a conditional exception.**

### 5.3 IAM Design for Tier 3

**Problem**: Gateway-managed users have `DenyDirectBedrockInference` which blocks all direct Bedrock calls. Tier 3 requires the user to call Bedrock directly.

**Solution**: Modify `DenyDirectBedrockInference` to use a Condition that allows calls when a valid gateway authorization exists. Two approaches:

**Approach A: Session Tag Condition** (preferred)
- The `/authorize` endpoint returns a short-lived STS session with a tag `gateway-authorized=true`
- `DenyDirectBedrockInference` adds Condition: `StringNotEquals: aws:PrincipalTag/gateway-authorized: true`
- Problem: requires STS AssumeRole which adds complexity

**Approach B: Time-Limited Policy Swap** (simpler but less elegant)
- `/authorize` temporarily removes `DenyDirectBedrockInference` and adds `AllowTimeLimitedBedrock` with a TTL
- `/settle` or a cleanup Lambda re-applies `DenyDirectBedrockInference`
- Problem: race condition window where user could make untracked calls

**Approach C: Gateway Issues Temporary Credentials** (most secure)
- `/authorize` calls `sts:AssumeRole` on the user's BedrockUser role with a session policy that allows only the authorized model
- Returns temporary credentials to the client
- Client uses these credentials for the direct Bedrock call
- Problem: Lambda needs `sts:AssumeRole` permission on BedrockUser roles

**Recommended: Approach C** — most secure, no IAM policy modification needed at runtime, temporary credentials expire naturally, scoped to specific model.

### 5.4 Settlement Endpoint

```
POST /settle
Body: {
  "tracking_id": "trk-uuid",
  "input_tokens": 185000,
  "output_tokens": 4200,
  "cache_read_tokens": 0,
  "cache_write_tokens": 0,
  "stop_reason": "end_turn",
  "duration_seconds": 1511
}

Response (200): {
  "settled": true,
  "actual_cost_krw": 12345.67,
  "reserved_budget_krw": 50000,
  "adjustment_krw": -37654.33,  // released back
  "remaining_quota_krw": 187654.33
}
```

**Settlement logic**:
1. Validate tracking_id exists and is not already settled
2. Compute actual cost using `estimate_cost_krw()`
3. Atomic ADD actual cost to monthly_usage (subtract reservation, add actual)
4. Write request_ledger entry
5. Mark tracking_id as settled
6. If actual > reserved: additional charge (may push over quota — logged but allowed since Bedrock already completed)
7. If actual < reserved: release difference

### 5.5 Failure Modes

| Failure | Handling |
|---------|----------|
| Authorization granted, Bedrock call fails | Client calls `/settle` with `failed: true`. Reservation released. |
| Authorization granted, client crashes before settle | Reservation TTL expires (1 hour). Cleanup Lambda releases reservation. Alarm fires. |
| Authorization granted, Bedrock succeeds, settle fails | Client retries `/settle`. Idempotent on tracking_id. |
| Double-settle | Idempotency check on tracking_id. Second call returns cached result. |
| Client lies about token counts | **Risk accepted for v1.** Mitigation: CloudWatch Logs reconciliation (same as exception users). CUR monthly reconciliation catches discrepancies. |
| Budget reservation exceeds remaining quota | Deny at `/authorize` step. Same as current quota exceeded. |

### 5.6 Tier Selection Logic (in `bedrock_gw.py`)

```python
def _select_tier(model_id, estimated_tokens=None):
    """Determine which tier to use for this call."""
    # Tier 3 models: known long-running
    TIER3_MODELS = {
        'us.anthropic.claude-opus-4-6-v1',
        'global.anthropic.claude-opus-4-6-v1',
        'us.anthropic.claude-opus-4-5-20251101-v1:0',
    }
    # Tier 2 threshold: large context
    LARGE_CONTEXT_THRESHOLD = 100000  # tokens
    
    if model_id in TIER3_MODELS:
        return 3
    if estimated_tokens and estimated_tokens > LARGE_CONTEXT_THRESHOLD:
        return 2  # Function URL path
    return 1  # Standard API Gateway path
```

**Override**: Environment variable `BEDROCK_GW_TIER=1|2|3` forces a specific tier. Useful for testing.

---

## 6. Short-Path / Long-Path Boundary Rules

| Criterion | Tier 1 (API GW) | Tier 2 (Function URL) | Tier 3 (Direct) |
|-----------|:---:|:---:|:---:|
| Expected runtime | < 29s | 29s – 15min | > 15min |
| Model | Haiku, Nova, short Sonnet | Sonnet large ctx, most Opus | Opus large ctx |
| Estimated input tokens | < 50K | 50K – 200K | > 200K |
| User override | Default | Explicit or auto | Explicit or auto |
| Control plane | Lambda inline | Lambda inline | Separate authorize/settle |
| Data plane | Lambda inline | Lambda inline | Client direct to Bedrock |

**Practical default**: Opus models → Tier 3. Everything else → Tier 1. Tier 2 is available but not default (requires Function URL deployment).

---

## 7. Portal Integration

### 7.1 No Portal Code Change Needed (Short Term)

All three tiers write to the same DynamoDB tables:
- `monthly_usage`: same PK/SK format, same cost_krw field
- `request_ledger`: same schema, with additional `tier` and `tracking_id` fields

The portal reads from these tables. Existing portal code works without modification.

### 7.2 Enhanced Portal (Medium Term)

Add to portal display:
- `request_source`: `gateway-inline` | `gateway-function-url` | `gateway-mediated-direct`
- `tier`: 1 | 2 | 3
- For Tier 3: `status`: `authorized` | `in_progress` | `settled` | `expired`
- `reserved_budget_krw` vs `actual_cost_krw`
- `duration_seconds` for long calls

---

## 8. Answers to Core Questions

### Q1: Is the current structure valid as a control plane?
**Yes.** The API Gateway + Lambda + DynamoDB pipeline correctly handles principal identification, policy enforcement, quota checking, cost estimation, approval workflows, and portal data. 0% cost error rate across 2,400+ requests. This should remain the authoritative source of truth.

### Q2: Can the current structure cover 30-min inference as a data plane?
**No.** Lambda has a hard 15-minute limit. No configuration change can fix this.

### Q3: What exactly prevents it?
**Lambda timeout = 900 seconds (15 minutes), hard AWS service limit.** Not tunable, not waivable. Additionally, API Gateway REST API defaults to 29s (increasable for Regional, but still capped by Lambda). HTTP API is worse at 30s hard limit.

### Q4: Can it be fixed by tuning?
**Partially.** Requesting a REST API Regional timeout increase to 900s would extend the effective limit from 29s to 15min. But 15min → 30min requires removing Lambda from the data path entirely.

### Q5: Can cost tracking be maintained while splitting the data plane?
**Yes.** The `/authorize` + `/settle` pattern keeps the gateway as the authoritative cost tracker. The gateway decides authorization, reserves budget, and records final settlement. The actual Bedrock call happens outside Lambda but is fully tracked.

### Q6: What is the most realistic target architecture?
**Three-tier with gateway-mediated direct Bedrock for long calls.** See Section 4 above.

### Q7: How is user experience maintained?
- `bedrock_gw.py` wrapper handles tier selection transparently
- `converse()` and `get_client().converse()` API unchanged
- Shell hook continues to query `/quota/status`
- Approval requests work from any tier
- Portal shows all usage regardless of tier

### Q8: What are the short-term and medium-term actions?

**Short-term (immediate — requires SSO admin + Service Quotas request)**:
1. ~~Revert `main.tf` to REST API code~~ — **DONE** (this report). Terraform plan: 0 add, 1 change (tags), 0 destroy.
2. `terraform apply` with SSO admin — syncs Lambda timeout from 60s → 900s (15 min). This is the variables.tf default.
3. Request REST API Regional integration timeout increase via Service Quotas: 29,000ms → 900,000ms (15 min).
4. After quota approved: update Terraform `timeoutInMillis` to match.
5. Combined effect: calls up to 15 minutes work end-to-end through the existing gateway path.
6. Covers ~95% of use cases (Sonnet, Haiku, Nova, most Opus calls under 15 min).

**Medium-term (1-2 weeks)**:
1. Add `/authorize` and `/settle` endpoints to Lambda handler
2. Update `bedrock_gw.py` with Tier 3 logic (authorize → direct ConverseStream → settle)
3. Add Lambda Function URL for Tier 2 (optional, low priority)
4. Add `tier` and `tracking_id` fields to request_ledger
5. Add reservation/settlement tracking to DynamoDB

---

## 9. What About ConverseStream?

ConverseStream helps in two ways:
1. **Keeps HTTP connection alive**: tokens flow continuously, preventing idle timeout
2. **Provides usage in final event**: `metadata.usage` contains exact token counts

ConverseStream does NOT help with:
1. **Lambda timeout**: streaming inside Lambda still counts against the 15-min limit
2. **API Gateway timeout**: streaming through API Gateway still counts against the integration timeout

**For Tier 3**: ConverseStream is essential. The client calls `bedrock_runtime.converse_stream()` directly. Tokens flow for up to 30+ minutes. No Lambda or API Gateway in the path. The final metadata event provides exact token counts for settlement.

**For Tier 1/2**: ConverseStream is a v2 enhancement. Current Converse (sync) works fine for calls under 15 minutes.

---

## 10. Why Function URL Is NOT the Final Answer

Function URL removes API Gateway from the path, extending the effective timeout from 29s to 15 minutes. This is useful but does not solve the 30-minute requirement because:

1. Function URL invokes the same Lambda function
2. Lambda timeout is 900s (15 min) regardless of invocation method
3. A 25-minute Opus call will timeout at minute 15 whether invoked via API Gateway, Function URL, or direct SDK invoke

Function URL is a valid **Tier 2** solution for the 29s-to-15min gap. It is not a Tier 3 solution.

---

## 11. main.tf Revert Requirement

The current `main.tf` contains HTTP API code (`aws_apigatewayv2_api`) that:
1. Was never applied (live infra is still REST API `<GATEWAY_API_ID>`)
2. Is based on the false premise that HTTP API supports 30-minute timeout
3. HTTP API maximum integration timeout is **30 seconds** (worse than REST API's 29s + increase option)
4. If applied, would destroy the working REST API and create a broken HTTP API

**Action required**: Revert `main.tf` to REST API resources. This is the highest priority change.

---

## 12. Test Matrix

### 12A. Short Path (Tier 1) — Current Production

| Test | Model | Region | Expected Runtime | Outcome | Cost Tracking | Portal | Approval |
|------|-------|--------|-----------------|---------|---------------|--------|----------|
| T1.1 | claude-haiku-4-5 | us-west-2 | <5s | PASS (existing) | Exact | Real-time | Working |
| T1.2 | nova-2-lite | us-west-2 | <3s | PASS (existing) | Exact | Real-time | Working |
| T1.3 | claude-sonnet-4-6 | us-west-2 | 5-20s | PASS (existing) | Exact | Real-time | Working |
| T1.4 | claude-opus-4-6 (small ctx) | us-west-2 | 10-29s | PASS (existing) | Exact | Real-time | Working |
| T1.5 | 25 models parallel | us-west-2 | <20s each | PASS (verified) | 0% error | Real-time | Working |

### 12B. Timeout Boundary (Current Limitation — Verified Live Values)

| Test | Model | Context Size | Expected Runtime | Outcome | Root Cause |
|------|-------|-------------|-----------------|---------|------------|
| T2.1 | claude-opus-4-6 (large ctx) | 200K tokens | ~25min | **TIMEOUT at 29s** | API GW 29s limit |
| T2.2 | claude-opus-4-6 (medium ctx) | 100K tokens | ~10min | **TIMEOUT at 29s** | API GW 29s limit |
| T2.3 | claude-sonnet-4-6 (huge ctx) | 150K tokens | ~5min | **TIMEOUT at 29s** | API GW 29s limit |
| T2.4 | Any model, >29s response | Any | >29s | **TIMEOUT at 29s** | API GW 29s limit |
| T2.5 | Any model, >60s response | Any | >60s | **TIMEOUT at 60s** | Lambda live timeout=60s (even if API GW increased) |

**Verified live state:**
- API Gateway integration timeout: 29,000ms (confirmed via `aws apigateway get-integration`)
- Lambda timeout: 60s (confirmed via `aws lambda get-function-configuration`)
- API Gateway timeout quota: adjustable=True (confirmed via `aws service-quotas`)
- REST API type: Regional (confirmed via `aws apigateway get-rest-api`)

**Two bottlenecks must be fixed sequentially:**
1. API Gateway timeout: 29s → request increase to 900,000ms via Service Quotas
2. Lambda timeout: 60s → 900s via `terraform apply` (variables.tf already has default=900)

### 12C. After REST API Timeout Increase (Short-Term Fix)

| Test | Model | Context Size | Expected Runtime | Expected Outcome |
|------|-------|-------------|-----------------|-----------------|
| T3.1 | claude-opus-4-6 (medium) | 100K tokens | ~10min | PASS (within 15min Lambda limit) |
| T3.2 | claude-sonnet-4-6 (huge) | 150K tokens | ~5min | PASS |
| T3.3 | claude-opus-4-6 (large) | 200K tokens | ~25min | TIMEOUT (Lambda 15min limit) |

### 12D. After Tier 3 Implementation (Medium-Term)

| Test | Model | Context Size | Expected Runtime | Expected Outcome |
|------|-------|-------------|-----------------|-----------------|
| T4.1 | claude-opus-4-6 (large) | 200K tokens | ~25min | PASS (direct ConverseStream) |
| T4.2 | claude-opus-4-6 (extreme) | 300K tokens | ~30min | PASS (direct ConverseStream) |
| T4.3 | Tier 3 + settle | Any | Any | Cost tracked in DynamoDB |
| T4.4 | Tier 3 + crash (no settle) | Any | Any | Reservation expires, alarm |

---

## 13. Change File List

### Immediate (Short-Term)

| File | Change | Reason | Rollback |
|------|--------|--------|----------|
| `infra/bedrock-gateway/main.tf` | Reverted to REST API resources | HTTP API code was broken (30s limit, not 30min). **DONE.** | N/A (matches live state) |
| `infra/bedrock-gateway/outputs.tf` | Reverted to REST API references | Match main.tf revert. **DONE.** | N/A |
| Lambda timeout (via terraform apply) | 60s → 900s | variables.tf default=900, live=60 (drift) | Set lambda_timeout=60 in tfvars |
| Service Quotas | Request REST API Regional timeout: 29s → 900s | Extend API GW integration timeout | Revert quota (or leave) |
| API GW integration (via terraform) | Set `timeoutInMillis` to match quota | After quota approved | Revert to 29000 |

### Medium-Term (Tier 3)

| File | Change | Reason | Rollback |
|------|--------|--------|----------|
| `infra/bedrock-gateway/lambda/handler.py` | Add `/authorize` and `/settle` endpoints | Tier 3 control plane | Remove endpoints |
| `account-portal/backend-admin/data/bedrock_gw.py` | Add tier selection + direct Bedrock path | Tier 3 client | Revert to gateway-only |
| `infra/bedrock-gateway/iam.tf` | Add `sts:AssumeRole` for BedrockUser roles | Tier 3 temp credentials | Remove policy |
| `infra/bedrock-gateway/dynamodb.tf` | Add reservation tracking (or reuse existing table) | Budget reservation | Remove table/fields |

---

## 14. Rollback Path

### Short-Term Rollback
- If REST API timeout increase causes issues: revert quota request (or set `timeoutInMillis` back to 29000 in Terraform)
- If `main.tf` revert causes Terraform drift: `terraform plan` will show no changes (since HTTP API was never applied)

### Medium-Term Rollback
- If Tier 3 has issues: set `BEDROCK_GW_TIER=1` environment variable to force all calls through Tier 1
- Remove `/authorize` and `/settle` from handler
- Revert `bedrock_gw.py` to gateway-only mode

---

## 15. Final Verdict

| Question | Answer |
|----------|--------|
| Is the current gateway valid as control plane? | **YES** — keep it |
| Is the current gateway valid as data plane for all calls? | **NO** — 15min Lambda limit |
| Should we migrate to HTTP API? | **NO** — HTTP API is worse (30s hard limit) |
| Should we add Function URL? | **OPTIONAL** — useful for 29s-15min gap (Tier 2) |
| Can we achieve 30 minutes? | **YES** — via gateway-mediated direct Bedrock (Tier 3) |
| What's the immediate fix? | Revert `main.tf` + request REST API timeout increase |
| What's the medium-term fix? | Implement Tier 3 (authorize/settle + direct ConverseStream) |
| Is the control plane authoritative maintained? | **YES** — all tiers report to same DynamoDB |
