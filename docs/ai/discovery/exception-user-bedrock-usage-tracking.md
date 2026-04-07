# Exception User Bedrock Usage Tracking — Data Source Discovery

**Date:** 2026-03-17  
**Status:** Research Complete  
**Scope:** Identify existing data sources for tracking direct Bedrock usage by exception users (specifically user05)

---

## Executive Summary

**Finding:** user05 is hardcoded as a direct-use exception user in the gateway admin API (`gateway_usage.py`), with a documented note that usage is "tracked via `/aws/bedrock/modelinvocations` only." However, **no existing CloudWatch Logs integration exists in the codebase** to surface this data. The infrastructure is ready to consume it, but the data pipeline is not implemented.

**Current State:**
- ✅ Exception user hardcoded with clear intent
- ✅ CloudWatch Log Groups created (Lambda, API Gateway)
- ✅ Backend-cost service has Athena integration for CUR data
- ❌ No CloudWatch Logs client usage in any backend service
- ❌ No route/endpoint to query `/aws/bedrock/modelinvocations` logs
- ❌ No data pipeline to aggregate user05's direct Bedrock usage

**Data Sources Available (but not yet integrated):**
1. **AWS CloudWatch Logs** — `/aws/bedrock/modelinvocations` (Bedrock service logs)
2. **AWS Cost Explorer / CUR** — Bedrock costs in billing data (already integrated via Athena)
3. **DynamoDB** — Gateway-managed usage (not applicable to user05; she bypasses gateway)

---

## Current Architecture

### Backend Services

#### backend-admin (port 5000)
- **Routes:** 18 Flask blueprints registered
- **Relevant routes:**
  - `gateway_usage.py` — Read-only admin APIs for usage/policy monitoring
  - `gateway_approval.py` — Approval request handling
- **Exception user handling:** Hardcoded in `gateway_usage.py` lines 51–59

#### backend-cost (port 5001)
- **Routes:** 2 Flask blueprints
  - `cost_monitoring.py` — Daily/monthly cost aggregation via Athena (1416 lines, complex)
  - `finops_routes.py` — FinOps dashboard and daily cost queries
- **Data source:** Athena queries against CUR database (`cur_database.acme_hourly_cur`)
- **No CloudWatch Logs integration**

### Bedrock Gateway Infrastructure (Terraform)

**CloudWatch Logs already configured:**
- `/aws/apigateway/{prefix}-api/access` — API Gateway access logs (90-day retention)
- `/aws/lambda/{prefix}-gateway` — Lambda function logs (90-day retention)

**Lambda environment variables:** All DynamoDB table names, SES emails, but **no CloudWatch Logs configuration** for reading Bedrock logs.

---

## Exception User Configuration

### Current Hardcoding (gateway_usage.py, lines 51–59)

```python
EXCEPTION_USERS = {
    '<ACCOUNT_ID>#BedrockUser-user05': {
        'principal_id': '<ACCOUNT_ID>#BedrockUser-user05',
        'status': 'direct-use exception',
        'gateway_managed': False,
        'note': 'Usage tracked via /aws/bedrock/modelinvocations only',
    },
}
```

**Implications:**
- user05 is **not** gateway-managed (no DynamoDB usage records)
- user05's usage is expected to be in AWS Bedrock CloudWatch Logs
- The admin portal lists her as an exception user but provides no usage data
- No approval workflow applies to her (she has direct AWS access)

### Usage in gateway_usage.py

**Line 156–157:** Exception users are excluded from managed user list
```python
if _is_exception_user(pid):
    continue
```

**Line 195–196:** Exception users are returned separately with no usage data
```python
exception_users = list(EXCEPTION_USERS.values())
return jsonify({
    'month': month,
    'managed_users': managed_users,
    'exception_users': exception_users,
}), 200
```

---

## Data Sources Analysis

### 1. CloudWatch Logs — `/aws/bedrock/modelinvocations`

**Status:** ✅ Available in AWS, ❌ Not integrated in codebase

**What it contains:**
- Model invocation events from Bedrock API calls
- Includes: principal identity, model ID, input/output tokens, timestamp, cost
- Retention: AWS-managed (typically 30 days default, configurable)

**How to access:**
```python
import boto3
logs_client = boto3.client('logs', region_name='us-west-2')
response = logs_client.filter_log_events(
    logGroupName='/aws/bedrock/modelinvocations',
    startTime=start_epoch_ms,
    endTime=end_epoch_ms,
    filterPattern='BedrockUser-user05'  # or other principal filter
)
```

**Limitations:**
- Real-time data (not aggregated)
- Requires parsing log events
- No built-in cost calculation (must derive from token counts + pricing)
- Query performance degrades with large time ranges

### 2. AWS Cost Explorer / CUR

**Status:** ✅ Integrated via Athena in backend-cost

**Current usage:**
- `cost_monitoring.py` queries `cur_database.acme_hourly_cur` (Athena table)
- Aggregates EC2 instance costs by project/user
- No Bedrock-specific queries currently

**Bedrock in CUR:**
- Product code: `AmazonBedrock`
- Line item type: `Usage`, `DiscountedUsage`, `SavingsPlanCoveredUsage`
- Dimensions: model ID, principal identity (if available), region
- Cost: `line_item_unblended_cost` or `reservation_effective_cost`

**Advantages:**
- Already integrated (Athena client exists)
- Aggregated daily/monthly
- Includes RI/Savings Plan discounts
- Reliable for billing reconciliation

**Limitations:**
- 24–48 hour delay (CUR is not real-time)
- Principal identity may not be captured in CUR (depends on Bedrock logging config)
- Requires Athena table schema to include Bedrock product code

### 3. DynamoDB — Gateway-Managed Usage

**Status:** ✅ Configured, ❌ Not applicable to user05

**Tables:**
- `bedrock-gw-{env}-{region}-monthly-usage` — Per-model monthly aggregates
- `bedrock-gw-{env}-{region}-daily-usage` — Per-model daily aggregates (deprecated in Phase 2)

**Why not applicable:**
- user05 bypasses the gateway entirely
- No Lambda invocation → no DynamoDB writes
- These tables only track gateway-mediated requests

---

## Existing Data Pipeline Patterns

### Pattern 1: Athena-based Cost Aggregation (backend-cost)

**Used for:** EC2 instance costs, project allocation

**Flow:**
1. CUR data lands in S3 (`acme-or-cur-stg`)
2. Athena queries CUR tables (partitioned by year/month)
3. Results cached in Python (1-hour TTL)
4. Returned via Flask API

**Code location:** `account-portal/backend-cost/routes/cost_monitoring.py` (lines 254–700+)

**Reusable pattern:** Yes. Could add Bedrock-specific Athena queries.

### Pattern 2: CloudWatch Logs Querying (Not yet implemented)

**Potential approach:**
1. Use CloudWatch Logs Insights (SQL-like queries)
2. Or use `filter_log_events()` API with pagination
3. Parse JSON events
4. Aggregate by principal/model/date
5. Cache results

**Code location:** None currently. Would need new utility module.

---

## Gaps and Risks

### Gap 1: No CloudWatch Logs Integration
- **Impact:** Cannot surface user05's direct Bedrock usage in admin portal
- **Severity:** Medium (workaround: query AWS console manually)
- **Effort to close:** Low–Medium (1–2 days for basic integration)

### Gap 2: No Principal Identity in CUR (Assumption)
- **Impact:** CUR may not distinguish user05's usage from other principals
- **Severity:** High (if true, CUR is unusable for per-principal tracking)
- **Effort to verify:** Low (check CUR schema in Athena)
- **Mitigation:** Use CloudWatch Logs as primary source, CUR for reconciliation

### Gap 3: Hardcoded Exception User List
- **Impact:** Adding new exception users requires code change + redeploy
- **Severity:** Low (rare operation)
- **Effort to improve:** Low (move to DynamoDB config table)

### Gap 4: No Approval Workflow for Exception Users
- **Impact:** user05 has unlimited access (by design, but no audit trail)
- **Severity:** Medium (acceptable for MVP, but should be documented)
- **Effort to add:** Medium (would require separate approval flow)

---

## Recommendations

### Immediate (Phase 4 Scope)

**Option A: Use CUR + Athena (Preferred)**
- **Rationale:** Leverages existing Athena integration, minimal new code
- **Effort:** Low (1–2 days)
- **Risk:** Depends on CUR including principal identity; must verify schema first
- **Implementation:**
  1. Verify CUR schema includes Bedrock product code and principal identity
  2. Add Athena query for Bedrock costs filtered by principal
  3. Add new route: `GET /api/gateway/exception-users/<principal_id>/usage`
  4. Cache results (1-hour TTL, same as EC2 costs)

**Option B: Use CloudWatch Logs Insights (Alternative)**
- **Rationale:** Real-time data, direct from Bedrock service
- **Effort:** Medium (2–3 days)
- **Risk:** Query performance, parsing complexity
- **Implementation:**
  1. Add CloudWatch Logs client to backend-admin
  2. Create utility function for Logs Insights queries
  3. Parse JSON events, aggregate by model/date
  4. Add new route with same interface as Option A

**Recommendation:** Start with **Option A** (CUR). If CUR lacks principal identity, fall back to **Option B** (CloudWatch Logs).

### Pre-Implementation Validation

**Must verify before proceeding:**
1. Does CUR include Bedrock product code? (Check Athena schema)
2. Does CUR include principal identity for Bedrock? (Check sample rows)
3. What is the CUR data delay? (Typically 24–48 hours)
4. Is `/aws/bedrock/modelinvocations` log group accessible? (Check IAM permissions)

### Future (Phase 5+)

- Move exception user list to DynamoDB config table
- Add approval workflow for exception user quota increases
- Implement real-time usage dashboard (CloudWatch Logs Insights)
- Add cost anomaly detection for exception users

---

## Evidence from Codebase

### gateway_usage.py (Lines 51–59)
```python
EXCEPTION_USERS = {
    '<ACCOUNT_ID>#BedrockUser-user05': {
        'principal_id': '<ACCOUNT_ID>#BedrockUser-user05',
        'status': 'direct-use exception',
        'gateway_managed': False,
        'note': 'Usage tracked via /aws/bedrock/modelinvocations only',
    },
}
```

### gateway_usage.py (Lines 156–157)
```python
for policy in policy_resp.get('Items', []):
    pid = policy.get('principal_id', '')
    if _is_exception_user(pid):
        continue
```

### logs.tf (CloudWatch Log Groups)
```hcl
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.prefix}-gateway"
  retention_in_days = 90
}
```

### cost_monitoring.py (Athena Integration)
```python
athena_client = boto3.client('athena', region_name='us-west-2')
r_cur = athena_client.start_query_execution(
    QueryString=query_cur,
    QueryExecutionContext={'Database': 'cur_database'},
    ResultConfiguration={'OutputLocation': 's3://acme-or-cur-stg/athena-results/'}
)
```

---

## Assumptions

1. **user05 has direct AWS IAM access** (BedrockUser-user05 role) and does not use the gateway
2. **Bedrock API calls are logged to `/aws/bedrock/modelinvocations`** (AWS default behavior)
3. **CUR data is available in Athena** (already confirmed by existing queries)
4. **Principal identity is captured somewhere** (CUR, CloudWatch Logs, or both)
5. **48-hour data delay is acceptable** for exception user usage reporting (same as EC2 costs)

---

## Next Steps

1. **Verify CUR schema** — Check if Bedrock product code and principal identity are present
2. **Test CloudWatch Logs access** — Confirm IAM permissions and log group availability
3. **Write implementation plan** — Choose Option A or B based on verification results
4. **Implement and validate** — Add new route, test with user05's actual usage
5. **Document in runbook** — Add exception user usage tracking to operator docs

