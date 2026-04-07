# Gateway Control Plane + Long-Run Data Plane — Final Architecture Report

> Date: 2026-04-01
> Status: IMPLEMENTATION COMPLETE — PENDING DEPLOYMENT (requires SSO admin for terraform apply)

---

## 1. Verified AWS Service Limits (Official Documentation + Live Environment)

| Item | Verified Value | Source |
|------|---------------|--------|
| Live API Gateway type | **REST API Regional** | `aws apigateway get-rest-api --rest-api-id <GATEWAY_API_ID>` → `types: ["REGIONAL"]` |
| Live integration timeout | **29,000ms (29s)** | `aws apigateway get-integration` → `timeoutInMillis: 29000` |
| REST API Regional timeout increase | **Possible** via Service Quotas | `aws service-quotas`: `adjustable=True` |
| HTTP API max integration timeout | **30 seconds (hard, not increasable)** | [AWS HTTP API quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html) |
| Lambda max timeout | **900 seconds (15 min, hard)** | [AWS Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html) |
| Live Lambda timeout | **60 seconds** | `aws lambda get-function-configuration` → `Timeout: 60` |
| Lambda timeout drift | Live=60s vs TF default=900s | Needs `terraform apply` to sync |
| Lambda Function URL timeout | Same as Lambda (max 15 min) | [AWS Lambda Function URL docs](https://docs.aws.amazon.com/lambda/latest/dg/urls-invocation.html) |
| Bedrock ConverseStream support | **All Claude, Nova, Llama, Titan** | `aws bedrock list-foundation-models` → `responseStreamingSupported: True` |
| ConverseStream model check | `GetFoundationModel.responseStreamingSupported` | Verified via `list-foundation-models` API |

### Critical Corrections from Previous Assumptions

1. **HTTP API does NOT support 30-minute timeout.** Max is 30 seconds, hard limit. The previous `main.tf` rewrite to HTTP API was based on a false premise. **Reverted.**
2. **REST API Regional CAN increase timeout beyond 29s** via Service Quotas request. This was not previously known.
3. **Live Lambda timeout is 60s, not 900s.** Config drift from Terraform default.
4. **Function URL does NOT bypass Lambda 15-min limit.** It only bypasses API Gateway timeout.

---

## 2. Architecture Decision

### Control Plane: MAINTAIN (current gateway)

The API Gateway + Lambda + DynamoDB pipeline is the authoritative source for:
- Principal identification and policy lookup
- Model allow/deny decisions
- Pricing lookup and cost estimation
- KRW monthly quota enforcement (0% error rate, 2400+ requests verified)
- Approval request/decision workflow with SES email routing
- Budget reservation and settlement for long-run calls
- Request ledger (immutable audit)
- Portal data (monthly/daily usage, team structure)

No changes to control plane logic. Only additive endpoints (`/longrun/authorize`, `/longrun/settle`).

### Data Plane: SPLIT into Short Path + Long Path

| Path | Timeout | Mechanism | Use Case |
|------|---------|-----------|----------|
| Short (Tier 1) | Up to 15 min | API GW REST → Lambda → Bedrock Converse | Haiku, Nova, Sonnet, short Opus |
| Long (Tier 3) | Up to 30+ min | GW authorize → Direct ConverseStream → GW settle | Opus large context, any >15min call |

### Why Data Plane Split is Necessary

Lambda has a hard 15-minute limit. No Lambda-based path (API Gateway, Function URL, direct invoke) can exceed this. For calls that take 15-30 minutes (Opus with 200K+ token context), the Bedrock call must happen outside Lambda. The only way to do this while maintaining cost tracking is the authorize/settle pattern.

### Why Function URL is NOT the Final Answer

Function URL removes API Gateway from the path (bypassing the 29s limit) but does NOT extend beyond Lambda's 15-minute hard limit. It's useful as a Tier 2 for the 29s-15min gap but cannot solve the 30-minute requirement.

---

## 3. Target Architecture

```
SHORT PATH (Tier 1) — existing, enhanced with timeout increase
  User process
    → bedrock_gw.py (auto-selects Tier 1)
    → SigV4 POST /converse
    → API Gateway REST (Regional, timeout increased to 900s)
    → Lambda (timeout 900s)
      → extract_identity → policy → model check → pricing → quota check
      → bedrock_runtime.converse()
      → estimate_cost → monthly_usage ADD → ledger write
    → Response with usage/cost/remaining
  
  Covers: Haiku, Nova, Sonnet, short Opus (< 15 min)

LONG PATH (Tier 3) — new
  User process
    → bedrock_gw.py (auto-selects Tier 3 for Opus / large context)
    
    Step 1: AUTHORIZE (control plane, via gateway)
    → SigV4 POST /longrun/authorize {modelId, estimated_input_tokens}
    → API Gateway REST → Lambda
      → extract_identity → policy → model check → pricing → quota check
      → reserve budget in monthly_usage (pessimistic estimate)
      → create longrun-request record (state=authorized)
    → Response: {tracking_id, reserved_cost_krw, authorization}
    
    Step 2: EXECUTE (data plane, direct to Bedrock)
    → bedrock_runtime.converse_stream() using user's own credentials
    → ConverseStream keeps connection alive as tokens flow
    → No Lambda, no API Gateway in data path
    → No timeout limit (Bedrock streams until done)
    → Collect usage from final metadata event
    
    Step 3: SETTLE (control plane, via gateway)
    → SigV4 POST /longrun/settle {tracking_id, input_tokens, output_tokens, ...}
    → API Gateway REST → Lambda
      → validate tracking_id ownership
      → compute actual cost from reported tokens
      → remove reservation, add actual cost to monthly_usage
      → write request_ledger entry
      → update longrun-request state to settled
    → Response: {settled_cost_krw, adjustment_krw}
  
  Covers: Opus large context, any call expected to exceed 15 min

EXCEPTION PATH — existing, unchanged
  Direct-access exception users (e.g., user05)
    → Direct Bedrock calls (no gateway enforcement)
    → Monitored via CloudWatch Logs (/aws/bedrock/modelinvocations)
    → Portal shows estimated cost from CW Logs
```

---

## 4. IAM Design for Tier 3

### Problem
Gateway-managed users have `DenyDirectBedrockInference` which blocks all direct Bedrock calls. Tier 3 requires the user to call ConverseStream directly.

### Solution
Modified `DenyDirectBedrockInference` to only deny **sync** Bedrock calls:
- **Denied**: `bedrock:InvokeModel`, `bedrock:Converse` (sync calls)
- **Allowed**: `bedrock:InvokeModelWithResponseStream`, `bedrock:ConverseStream` (streaming calls)

### Risk Assessment
- Streaming calls are still logged in CloudWatch Logs
- Gateway wrapper always calls `/longrun/authorize` before streaming
- Direct streaming without authorize is detectable (same monitoring as exception users)
- 6 internal users, not a public API — acceptable risk
- If tighter control needed later: STS session-based temporary credentials (medium-term)

---

## 5. Short/Long Path Routing Policy

### Automatic Routing (in `bedrock_gw.py`)

| Criterion | Tier 1 (Short) | Tier 3 (Long) |
|-----------|:---:|:---:|
| Model family | Haiku, Nova, Sonnet, Llama, etc. | Opus (all versions) |
| Estimated input tokens | < 100,000 | ≥ 100,000 |
| Environment override | `BEDROCK_GW_TIER=1` | `BEDROCK_GW_TIER=3` |

### Models Always Routed to Tier 3
```
us.anthropic.claude-opus-4-6-v1
global.anthropic.claude-opus-4-6-v1
us.anthropic.claude-opus-4-5-20251101-v1:0
us.anthropic.claude-opus-4-20250514-v1:0
us.anthropic.claude-opus-4-1-20250805-v1:0
```

---

## 6. Operational Policies

### Budget Reservation
- Reserve = min(estimated_cost × 2, KRW 100,000)
- If estimated_input_tokens provided: calculate from pricing × 2x multiplier
- If not provided: default KRW 50,000
- Reserve counts against quota immediately (prevents overspend during execution)

### Settlement
- **actual < reserved**: difference released back to available budget
- **actual > reserved**: additional charge applied (may push over quota — logged but allowed since Bedrock already completed)
- **failed call**: full reservation released
- **settle never arrives**: reservation expires via TTL (1 hour), alarm fires

### Duplicate Protection
- `/longrun/authorize`: creates unique tracking_id per call
- `/longrun/settle`: idempotent on tracking_id (second settle returns cached result)
- State machine: authorized → settled | failed (no backward transitions)

### Direct Access Exception Users
- Gateway enforcement bypassed (no DenyDirectBedrockInference)
- Portal/audit/observation maintained via CloudWatch Logs
- No change to existing exception user handling

---

## 7. DynamoDB Schema: longrun-request

| Field | Type | Description |
|-------|------|-------------|
| request_id | S (PK) | `lr-{uuid}` tracking ID |
| principal_id | S | `{account}#BedrockUser-{username}` |
| model_id | S | Bedrock model ID |
| region | S | AWS region |
| state | S | authorized / settled / failed / expired |
| reserved_cost_krw | N | Pessimistic budget reservation |
| settled_cost_krw | N | Actual cost after settlement |
| reserved_input_tokens_estimate | N | Client-provided estimate |
| actual_input_tokens | N | Reported by client at settle |
| actual_output_tokens | N | Reported by client at settle |
| cache_read_tokens | N | Cache tokens |
| cache_write_tokens | N | Cache tokens |
| input_price_per_1k_krw | N | Pricing at authorization time |
| output_price_per_1k_krw | N | Pricing at authorization time |
| fx_rate | N | 1450 |
| pricing_source | S | dynamodb:model-pricing |
| source_path | S | gateway-longrun |
| created_at | S | ISO timestamp |
| updated_at | S | ISO timestamp |
| completed_at | S | ISO timestamp |
| ttl | N | Epoch TTL for auto-expiry |

---

## 8. Portal Integration

### Existing Portal (No Change Needed for Basic Visibility)
All tiers write to the same DynamoDB tables:
- `monthly_usage`: same PK/SK format, same cost_krw field
- `request_ledger`: same schema + `source_path` field

Portal reads from these tables. Existing code works without modification.

### Enhanced Portal (Medium-Term)
Add to daily breakdown display:
- `source_path`: `gateway-inline` | `gateway-longrun` | `gateway-longrun-reserve`
- For longrun: `state` badge (authorized/settled/failed)
- `reserved_cost_krw` vs `settled_cost_krw`
- `duration_seconds` for long calls

---

## 9. Implemented Changes

| File | Change | Purpose |
|------|--------|---------|
| `infra/bedrock-gateway/main.tf` | Reverted HTTP API → REST API | HTTP API max 30s; REST API Regional can increase |
| `infra/bedrock-gateway/outputs.tf` | Reverted to REST API references | Match main.tf |
| `infra/bedrock-gateway/dynamodb.tf` | Added `longrun-request` table | Tier 3 request tracking |
| `infra/bedrock-gateway/lambda.tf` | Added `TABLE_LONGRUN_REQUEST` env var | Lambda access to new table |
| `infra/bedrock-gateway/iam.tf` | Added longrun table to DynamoDB policy | Lambda read/write access |
| `infra/bedrock-gateway/lambda/handler.py` | Added `/longrun/authorize` + `/longrun/settle` | Tier 3 control plane endpoints |
| `account-portal/backend-admin/data/bedrock_gw.py` | Added Tier 3 auto-routing + authorize/stream/settle | Client-side long path |
| `account-portal/backend-admin/routes/gateway_teams.py` | Modified DenyDirectBedrockInference (sync only) + added longrun IAM policy | Tier 3 IAM support |

---

## 10. Deployment Steps (Requires SSO Admin)


### Step 1: SSO Login
```bash
aws sso login --profile virginia-sso
```

### Step 2: Terraform Apply (REST API restore + Lambda update + new DynamoDB table)
```bash
cd infra/bedrock-gateway
env AWS_PROFILE=virginia-sso terraform plan -var-file=env/dev.tfvars
# Verify: 1 to add (longrun-request table), ~2-3 to change (Lambda code + env vars, REST API tags), 0 to destroy
env AWS_PROFILE=virginia-sso terraform apply -var-file=env/dev.tfvars
```

### Step 3: Request REST API Timeout Increase
```bash
# Via AWS Console: Service Quotas → API Gateway → Maximum integration timeout in milliseconds
# Request increase from 29000 to 900000 (15 minutes)
# After approved, update Terraform integration timeout
```

### Step 4: Update IAM for Existing Users (longrun + streaming permissions)
```bash
# For each managed user, apply updated policies:
# - DenyDirectBedrockSyncAccess (sync only, streaming allowed)
# - AllowDevGatewayLongrun (POST /longrun/*)
# This happens automatically for new users via portal.
# For existing users, run from backend-admin or manually.
```

### Step 5: Deploy Updated Client
```bash
sudo cp account-portal/backend-admin/data/bedrock_gw.py /fsx/home/shared/bedrock-gateway/
```

### Step 6: Rebuild Backend Admin
```bash
cd account-portal
docker compose -f docker-compose-fixed.yml up -d --build backend-admin
```

---

## 11. Rollback Path

| Component | Rollback Action |
|-----------|----------------|
| main.tf (REST API) | Already matches live state — no rollback needed |
| Lambda handler (longrun endpoints) | Remove `/longrun/*` routes, redeploy Lambda |
| bedrock_gw.py (Tier 3) | Set `BEDROCK_GW_TIER=1` env var to force all calls through Tier 1 |
| DenyDirectBedrockInference | Re-apply original 4-action deny policy to all users |
| longrun-request table | Leave in place (empty, no cost) or `terraform destroy -target` |
| REST API timeout increase | Revert Service Quotas (or leave — no harm) |

---

## 12. Test Matrix

| # | path_type | model | region | request_size | observed_runtime | reserved_cost | settled_cost | quota_effect | approval_behavior | portal_visibility | final_verdict |
|---|-----------|-------|--------|-------------|-----------------|---------------|-------------|-------------|-------------------|-------------------|---------------|
| T1 | short | claude-haiku-4-5 | us-west-2 | small | <5s | N/A | actual | immediate ADD | working | real-time | PASS (existing) |
| T2 | short | claude-sonnet-4-6 | us-west-2 | medium | 5-20s | N/A | actual | immediate ADD | working | real-time | PASS (existing) |
| T3 | short | nova-2-lite | us-west-2 | small | <3s | N/A | actual | immediate ADD | working | real-time | PASS (existing) |
| T4 | short | 25 models parallel | us-west-2 | mixed | <20s each | N/A | actual | all tracked | working | real-time | PASS (verified 0% error) |
| T5 | long | claude-opus-4-6 | us-west-2 | large (200K) | ~25min | pessimistic | actual at settle | reserve → settle | authorize first | reserve then settle | PENDING (needs deploy) |
| T6 | long | claude-opus-4-6 | us-west-2 | medium (100K) | ~10min | pessimistic | actual at settle | reserve → settle | authorize first | reserve then settle | PENDING (needs deploy) |
| T7 | long-fail | claude-opus-4-6 | us-west-2 | any | timeout | pessimistic | 0 (released) | reserve → release | N/A | failed state | PENDING (needs deploy) |
| T8 | long-dup | any | us-west-2 | any | any | N/A | cached | idempotent | N/A | no duplicate | PENDING (needs deploy) |
| T9 | approval | any | us-west-2 | N/A | N/A | N/A | N/A | quota exceeded | prompt + request | pending badge | PASS (existing) |
| T10 | exception | user05 (direct) | us-west-2 | any | any | N/A | CW Logs est. | no enforcement | N/A | CW Logs data | PASS (existing) |

**Note**: T5-T8 require deployment (terraform apply + client update) to test. T1-T4, T9-T10 are verified working in current production.

---

## 13. Answers to Design Questions

### 1. What is valid and what is not in the current architecture?
**Valid**: All control plane functions (quota, cost, approval, policy, portal). **Not valid**: Data plane for calls >15 minutes (Lambda hard limit).

### 2. Why maintain the control plane?
It works. 0% cost error rate. Real-time enforcement. Portal integration. Approval workflow. No reason to replace what's proven.

### 3. Why split the data plane?
Lambda cannot run longer than 15 minutes. This is an AWS platform constraint. For 30-minute Opus calls, the Bedrock invocation must happen outside Lambda.

### 4. Why is Function URL not the final answer?
Function URL invokes the same Lambda function. Lambda timeout is 900s regardless of invocation method. A 25-minute call will timeout at minute 15 whether via API Gateway, Function URL, or SDK invoke.

### 5. What does ConverseStream help with?
ConverseStream keeps the HTTP connection alive as tokens flow, preventing idle timeout. It provides exact usage in the final metadata event. For Tier 3, it's essential — the client calls ConverseStream directly, tokens flow for 30+ minutes, and the final event provides token counts for settlement.

### 6. What is the most realistic 30-minute structure?
Gateway-mediated direct Bedrock: authorize (control plane) → ConverseStream (direct, no Lambda) → settle (control plane). The gateway decides authorization and tracks cost. The actual inference happens outside Lambda.

### 7. How is cost/approval/portal authoritative maintained?
All three tiers write to the same DynamoDB tables. The gateway computes cost from its pricing table. Monthly_usage is the single source of truth. Portal reads from these tables. No change to portal data flow.

### 8. Short-term vs medium-term actions?
**Short-term**: terraform apply (Lambda 60→900s, REST API tags, longrun table), Service Quotas request (API GW 29→900s), deploy updated client. **Medium-term**: portal UI enhancement for longrun state display, STS-based temporary credentials for tighter Tier 3 security.

### 9. User impact?
`bedrock_gw.py` update deployed to `/fsx/home/shared/bedrock-gateway/`. Existing `converse()` and `get_client().converse()` API unchanged. Tier selection is automatic. No user code changes needed.

### 10. Rollback path?
`BEDROCK_GW_TIER=1` forces all calls through short path. Revert `DenyDirectBedrockInference` to 4-action deny. Remove longrun routes from handler. All reversible without data loss.

---

## 14. Cost Accounting Principles

### Short Path
- Actual usage-based cost confirmed at invocation time
- `estimate_cost_krw()` computes from real token counts
- Atomic ADD to monthly_usage immediately
- No reserved/settled distinction

### Long Path
- **Reserved**: pessimistic estimate at authorize time (2x estimated cost, max KRW 100,000)
- **Settled**: actual cost computed from reported tokens at settle time
- Reserved and settled stored separately in DynamoDB
- Portal shows reserved during execution, settled after completion
- Gateway recomputes cost authoritatively at settle (does not trust client cost calculation)
- Pricing snapshot captured at authorize time for consistency

### Reconciliation
- CloudWatch Logs provide independent usage record for all Bedrock calls
- CUR provides billing truth for monthly reconciliation
- Neither is used for real-time enforcement (gateway DynamoDB is authoritative)
