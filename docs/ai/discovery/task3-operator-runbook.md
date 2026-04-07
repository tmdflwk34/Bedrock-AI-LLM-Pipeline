# Task 3: Operator Handoff Runbook — Principal Discovery

> Date: 2026-03-17
> Author: kiro-agent (static analysis) → human operator (live execution)
> Status: READY FOR OPERATOR EXECUTION
>
> This document is the complete, self-contained package for a human operator
> to execute Task 3 live captures. The agent cannot execute these steps
> (no AWS credentials, no FSx access, no laptop environment).

---

## 0. What This Runbook Achieves

Task 3 validates whether the provisional normalization rule (Candidate F: `<account>#<role-name>`)
produces correct, stable, distinct principal_ids for per-user assume-role sessions across
laptop and FSx environments.

**Outcome**: evidence to confirm, reject, or flag Candidate F before any runtime code changes.

**What was already completed (Phase E — code review)**:
- `handler.py` `normalize_principal_id()` implements Candidate F (`<account>#<role-name>`) — live-verified
- `lookup_principal_policy()` uses DynamoDB GetItem (exact-match by design) — confirmed
- No derived username in any enforcement path — confirmed
- RequestLedger immutability (IAM explicit Deny on UpdateItem/DeleteItem) — confirmed
- No wildcard/prefix/suffix/contains matching anywhere in handler.py — confirmed
- Full evidence: `docs/ai/discovery/phase-e-code-review.json`

---

## 1. Prerequisites

### 1.1 Accounts and Roles

| Item | Value |
|---|---|
| AWS Account | `<ACCOUNT_ID>` |
| Region | `us-west-2` |
| User A role | `arn:aws:iam::<ACCOUNT_ID>:role/BedrockUser-user16` |
| User B role | `arn:aws:iam::<ACCOUNT_ID>:role/BedrockUser-user04` |
| Fail-closed role | `arn:aws:iam::<ACCOUNT_ID>:role/BedrockUser-Shared` |

Substitutions allowed: if user16 or user04 are unavailable, use any two distinct
`BedrockUser-<username>` roles. Record which roles were actually used.

### 1.2 Tools Required

- `aws` CLI v2 (with `sts` and `apigateway` support)
- `terraform` CLI (for discovery deployment)
- SigV4-capable HTTP client: `awscurl`, `curl --aws-sigv4` (7.75+), or a boto3 script
- Access to both environments:
  - **Laptop**: ability to `aws sts assume-role` into per-user roles
  - **FSx**: SSH/interactive access to FSx host where `[default]` profile is configured

### 1.3 Terraform Source

Discovery deployment uses the existing code in `infra/bedrock-gateway/`.
No code changes required — `DISCOVERY_MODE=true` is passed via `-var`.

---

## 2. Phase A: Discovery Environment Setup

### Step A1: Create Terraform discovery workspace

```bash
cd infra/bedrock-gateway
terraform workspace new discovery || terraform workspace select discovery
```

### Step A2: Plan discovery deployment

```bash
terraform plan \
  -var environment=discovery \
  -var discovery_mode=true
```

Review the plan. It should create:
- API Gateway (discovery stage)
- Lambda function (with `DISCOVERY_MODE=true`)
- DynamoDB tables (discovery-prefixed, no business data written)
- IAM roles

**No prod resources should appear in the plan.** If they do, STOP — you are not in the discovery workspace.

### Step A3: Apply discovery deployment

```bash
terraform apply \
  -var environment=discovery \
  -var discovery_mode=true
```

Record the API Gateway endpoint URL from Terraform output:
```
DISCOVERY_URL="https://<api-id>.execute-api.us-west-2.amazonaws.com/discovery"
```

### Step A4: Grant execute-api:Invoke to per-user roles

Add a temporary IAM policy to each role that will be tested.
This grants invoke permission ONLY on the discovery API Gateway.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DiscoveryInvoke",
    "Effect": "Allow",
    "Action": "execute-api:Invoke",
    "Resource": "arn:aws:execute-api:us-west-2:<ACCOUNT_ID>:<api-id>/discovery/POST/*"
  }]
}
```

Attach to:
- `BedrockUser-user16` (User A)
- `BedrockUser-user04` (User B)
- `BedrockUser-Shared` (fail-closed test)

**Record the policy ARN or inline policy name — you will remove it in teardown.**

---

## 3. Phase B: User A Captures (C1 laptop + C2 FSx)

### Capture C1: User A — Laptop

#### Step B1: Assume role on laptop

```bash
# Option 1: explicit assume-role
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/BedrockUser-user16 \
  --role-session-name laptop-discovery \
  --query 'Credentials' --output json > /tmp/creds-user16.json

export AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId /tmp/creds-user16.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey /tmp/creds-user16.json)
export AWS_SESSION_TOKEN=$(jq -r .SessionToken /tmp/creds-user16.json)

# Option 2: if you have a named profile for BedrockUser-user16
export AWS_PROFILE=bedrock-user-user16
```

#### Step B2: Credential validation

```bash
aws sts get-caller-identity
```

**Record the full JSON output.** Expected shape:
```json
{
  "Account": "<ACCOUNT_ID>",
  "UserId": "AROA...:laptop-discovery",
  "Arn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-user16/laptop-discovery"
}
```

Copy this output into `docs/ai/discovery/c1-evidence.json` → `sts_get_caller_identity`.

#### Step B3: SigV4 discovery request

```bash
# Using awscurl:
awscurl --service execute-api --region us-west-2 \
  -X POST \
  -d '{"modelId":"discovery-test"}' \
  "${DISCOVERY_URL}/converse"

# OR using curl --aws-sigv4 (curl 7.75+):
curl --aws-sigv4 "aws:amz:us-west-2:execute-api" \
  --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
  -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"modelId":"discovery-test"}' \
  "${DISCOVERY_URL}/converse"
```

**Record the full JSON response.** Expected shape:
```json
{
  "discovery": true,
  "raw_identity": {
    "userArn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-user16/laptop-discovery",
    "caller": "AROA...:laptop-discovery",
    "accountId": "<ACCOUNT_ID>",
    "accessKey": "ASIA...",
    "sourceIp": "...",
    "userAgent": "..."
  },
  "derived_principal_id": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-user16/laptop-discovery"
}
```

Copy into `c1-evidence.json` → `api_gateway_request_context_identity` and `discovery_lambda_response`.

#### Step B4: Extract fields for C1

From the `userArn` in the response, extract:
- `role_name`: the second `/`-delimited segment (e.g. `BedrockUser-user16`)
- `session_name`: the third `/`-delimited segment (e.g. `laptop-discovery`)
- `account_id`: the fifth `:`-delimited segment (e.g. `<ACCOUNT_ID>`)

Compute Candidate F: `{account_id}#{role_name}` → e.g. `<ACCOUNT_ID>#BedrockUser-user16`

Fill these into `c1-evidence.json` → `extracted_fields` and `candidate_f_result`.

---

### Capture C2: User A — FSx

#### Step B5: SSH to FSx host, verify existing profile

```bash
# On FSx host, as user user16:
cat ~/.aws/config
# Expected:
# [default]
# role_arn = arn:aws:iam::<ACCOUNT_ID>:role/BedrockUser-user16
# credential_source = Ec2InstanceMetadata
```

**Do NOT modify this file.** Read only.

#### Step B6: Credential validation on FSx

```bash
aws sts get-caller-identity
```

**Record the full JSON output.** Expected:
```json
{
  "Account": "<ACCOUNT_ID>",
  "UserId": "AROA...:<session-name>",
  "Arn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-user16/<session-name>"
}
```

Note: `<session-name>` will likely be an EC2 instance ID (e.g. `i-0abc123def456`) or
a boto3-generated value — NOT `laptop-discovery`. This is expected and correct.

Copy into `c2-evidence.json` → `sts_get_caller_identity`.

#### Step B7: SigV4 discovery request on FSx

```bash
# awscurl uses [default] profile automatically:
awscurl --service execute-api --region us-west-2 \
  -X POST \
  -d '{"modelId":"discovery-test"}' \
  "${DISCOVERY_URL}/converse"
```

**Record the full JSON response.** Copy into `c2-evidence.json`.

#### Step B8: Extract fields for C2 and compare with C1

Extract `role_name`, `session_name`, `account_id` from C2 response.
Compute Candidate F for C2.

**Critical comparison (C1 vs C2):**

| Field | C1 (laptop) | C2 (FSx) | Must Match? |
|---|---|---|---|
| `role_name` | `BedrockUser-user16` | `BedrockUser-user16` | YES — same role |
| `session_name` | `laptop-discovery` | `<instance-id>` | NO — expected to differ |
| `account_id` | `<ACCOUNT_ID>` | `<ACCOUNT_ID>` | YES |
| Candidate F | `<ACCOUNT_ID>#BedrockUser-user16` | `<ACCOUNT_ID>#BedrockUser-user16` | YES — must be identical |

If Candidate F values match → cross-environment consistency CONFIRMED for User A.
If they don't match → STOP. Document the discrepancy. Do not proceed to Phase F.

---

## 4. Phase C: User B Captures (C3, optional C4)

### Capture C3: User B — Laptop or FSx

Repeat Steps B1-B4 (or B5-B8) for User B (`BedrockUser-user04`).
Choose whichever environment is more convenient.

Fill `docs/ai/discovery/c3-evidence.json`.

**Critical comparison (C1/C2 vs C3):**

| Check | Expected |
|---|---|
| C3 `role_name` | `BedrockUser-user04` (different from C1/C2 `BedrockUser-user16`) |
| C3 Candidate F | `<ACCOUNT_ID>#BedrockUser-user04` (different from C1/C2) |
| C1 Candidate F ≠ C3 Candidate F | YES — cross-role isolation confirmed |

If C1 Candidate F == C3 Candidate F → CRITICAL FAILURE. Family-level collision detected.
Document and STOP.

### Capture C4 (OPTIONAL): User B — opposite environment

If C3 was laptop, do C4 on FSx (or vice versa).
This validates User B cross-environment consistency (same as C1/C2 did for User A).
Fill `docs/ai/discovery/c4-evidence.json`.

Skip if time-constrained — C3 alone is sufficient for cross-role isolation.

---

## 5. Phase D: Fail-Closed Verification (C5)

### Capture C5: BedrockUser-Shared

```bash
# Assume BedrockUser-Shared:
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/BedrockUser-Shared \
  --role-session-name shared-discovery \
  --query 'Credentials' --output json > /tmp/creds-shared.json

export AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId /tmp/creds-shared.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey /tmp/creds-shared.json)
export AWS_SESSION_TOKEN=$(jq -r .SessionToken /tmp/creds-shared.json)
```

```bash
aws sts get-caller-identity
```

```bash
awscurl --service execute-api --region us-west-2 \
  -X POST \
  -d '{"modelId":"discovery-test"}' \
  "${DISCOVERY_URL}/converse"
```

Fill `docs/ai/discovery/c5-evidence.json`.

**Important note on C5 interpretation:**

~~The current `normalize_principal_id()` is a PLACEHOLDER — it returns the raw `userArn`.~~
**UPDATE**: Discovery Lambda 재배포 완료. `normalize_principal_id()`는 Candidate F 로직을 사용 중.
C5 캡처 시 `BedrockUser-Shared` role로 호출하면:
- `derived_principal_id` = `""` (empty string) — fail-closed 동작
- `raw_identity.userArn` = full ARN (audit용)

~~This is NOT the fail-closed behavior. The fail-closed behavior is what the POST-DISCOVERY
implementation will do:~~
Candidate F 로직:
- Extract `role_name` = `BedrockUser-Shared`
- Check: `role_name == "BedrockUser-Shared"` → return `""` → deny-by-default

**What to record for C5:**
1. The actual `userArn` pattern (confirms ARN structure matches assumed-role pattern)
2. The `role_name` extracted from the ARN (should be `BedrockUser-Shared`)
3. `derived_principal_id` = `""` (expected — Candidate F fail-closed behavior)
4. ~~Note that placeholder returns raw userArn (expected)~~
5. ~~Note that post-implementation Candidate F will return `""` for this role (by design)~~

If `BedrockUser-Shared` is unavailable, use any non-`BedrockUser-<username>` role
(e.g. a service role, or a role without the `BedrockUser-` prefix) and document it.

---

## 5.5 Phase F-redeploy: Redeploy Discovery Lambda with Candidate F Normalization — COMPLETE

> Added: 2026-03-17. Updated: 2026-03-17 — 재배포 완료, live smoke test 통과.
> `normalize_principal_id()` Candidate F 구현 완료 후 discovery Lambda 재배포.
> ~~현재 배포된 Lambda는 placeholder (raw userArn 반환).~~ 재배포 완료 — Candidate F 로직 반영.

### Why Redeploy?

~~현재 discovery Lambda (`<DISCOVERY_API_ID>`)는 placeholder `normalize_principal_id()`를 사용 중:~~
~~- `derived_principal_id` = full userArn (session name 포함)~~
~~- C1 evidence에서 확인: `"derived_principal_id": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/BedrockUser-admin/botocore-session-1773732261"`~~

**재배포 완료 (2026-03-17):**
- `derived_principal_id` = `<ACCOUNT_ID>#BedrockUser-admin` (Candidate F) — live 확인
- `raw_identity.userArn` = full ARN (변경 없음 — audit용)
- Smoke test session: `botocore-session-1773807868`

### What Changes

Terraform `archive_file`이 `lambda/` 디렉토리를 zip으로 패키징. `handler.py` 변경으로 zip hash가 달라지므로 `terraform apply`가 Lambda 코드 업데이트를 감지.

변경 대상:
- Lambda function code (새 zip)
- Lambda published version (새 버전 번호)
- Lambda alias `live` (새 버전으로 포인트)

변경 없음:
- DynamoDB 테이블
- API Gateway
- IAM roles/policies

참고: `test_normalize_principal_id.py`가 zip에 포함됨. Lambda는 `handler.lambda_handler`만 호출하므로 런타임 영향 없음.

### Step F-R1: Redeploy

```bash
cd infra/bedrock-gateway
terraform workspace select discovery
terraform plan -var environment=discovery -var discovery_mode=true
```

**Plan 검토**: Lambda function code + version + alias만 변경되어야 함. DynamoDB/API Gateway/IAM 변경이 있으면 STOP.

```bash
terraform apply -var environment=discovery -var discovery_mode=true
```

### Step F-R2: Smoke Test (FSx, admin)

```bash
# Credential validation
aws sts get-caller-identity

# SigV4 discovery request
awscurl --service execute-api --region us-west-2 \
  -X POST \
  -d '{"modelId":"discovery-test"}' \
  "https://<DISCOVERY_API_ID>.execute-api.us-west-2.amazonaws.com/v1/discovery"
```

### Step F-R3: Success Criteria — ALL PASSED (2026-03-17)

| Field | Expected Value | Pass? |
|---|---|---|
| `derived_principal_id` | `<ACCOUNT_ID>#BedrockUser-admin` | ✅ |
| `raw_identity.userArn` | `arn:aws:sts::...assumed-role/BedrockUser-admin/botocore-session-1773807868` | ✅ |
| `discovery` | `true` | ✅ |

**ALL THREE passed.** CloudWatch logs에서도 normalized `derived_principal_id` 확인됨.

### Step F-R4: CloudWatch Verification (Optional)

Lambda log group에서 `discovery_capture` 로그 엔트리 확인:
- `derived_principal_id` = `<ACCOUNT_ID>#BedrockUser-admin`
- `userArn` = full ARN (raw)

### Failure Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `derived_principal_id` = full ARN | Lambda code not updated | `terraform apply` 재실행, zip hash 확인 |
| `derived_principal_id` = `""` (empty) | Fail-closed triggered | ARN 패턴 확인 — `BedrockUser-admin`이 아닌 role로 호출했는지 확인 |
| 403 | IAM permission | `execute-api:Invoke` 권한 확인 |
| 500 | Lambda crash | CloudWatch Logs 확인 |

---

## 6. Phase E: Already Complete (Code Review)

No operator action needed. See `docs/ai/discovery/phase-e-code-review.json`.

Summary of confirmed invariants:
- E1: `normalize_principal_id()` — Candidate F implemented, live-verified, no wildcard logic
- E2: `lookup_principal_policy()` — DynamoDB GetItem exact-match
- E3: No derived username in enforcement paths
- E4: RequestLedger immutability (IAM Deny)
- E5: PrincipalPolicy PK exact-match by design
- E6: No wildcard/prefix/suffix/contains matching in handler.py

---

## 7. Phase F: Teardown (IMMEDIATELY after captures)

### Step F1: Destroy discovery deployment

```bash
cd infra/bedrock-gateway
terraform workspace select discovery
terraform destroy \
  -var environment=discovery \
  -var discovery_mode=true
```

Confirm all resources destroyed.

### Step F2: Delete discovery workspace

```bash
terraform workspace select default
terraform workspace delete discovery
```

### Step F3: Remove temporary IAM policies

Remove the `DiscoveryInvoke` policy from:
- `BedrockUser-user16`
- `BedrockUser-user04`
- `BedrockUser-Shared`

### Step F4: Clean up temporary credential files

```bash
rm -f /tmp/creds-user16.json /tmp/creds-shared.json
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

---

## 8. Result Matrix Template

After all captures, fill this matrix:

| # | Environment | User | Role | Candidate F Result | Session Name | Cross-Check |
|---|---|---|---|---|---|---|
| C1 | laptop | user16 | BedrockUser-user16 | `___________` | `___________` | — |
| C2 | FSx | user16 | BedrockUser-user16 | `___________` | `___________` | C1==C2? ☐ |
| C3 | _______ | user04 | BedrockUser-user04 | `___________` | `___________` | C1≠C3? ☐ |
| C4 | _______ | user04 | BedrockUser-user04 | `___________` | `___________` | C3==C4? ☐ (optional) |
| C5 | _______ | admin | BedrockUser-Shared | `___________` | `___________` | fail-closed? ☐ |

---

## 9. Pass/Fail Criteria

All of the following must be TRUE for Candidate F to be CONFIRMED:

| # | Criterion | How to Check | Pass? |
|---|---|---|---|
| P1 | C1 and C2 Candidate F values are identical | Compare `candidate_f_result` in c1 vs c2 evidence | ☐ |
| P2 | C1 `role_name` == C2 `role_name` | Both should be `BedrockUser-user16` | ☐ |
| P3 | C1 `session_name` ≠ C2 `session_name` | Laptop vs FSx session names differ (expected) | ☐ |
| P4 | C1 Candidate F ≠ C3 Candidate F | Different users → different principal_ids | ☐ |
| P5 | C3 `role_name` ≠ C1 `role_name` | Different role names | ☐ |
| P6 | C5 `role_name` == `BedrockUser-Shared` | ARN structure matches expected pattern | ☐ |
| P7 | C5 would fail closed under Candidate F | `BedrockUser-Shared` → empty string → deny | ☐ |
| P8 | All `userArn` values match `arn:aws:sts::<acct>:assumed-role/<role>/<session>` pattern | Structural validation | ☐ |
| P9 | No capture required `session_name` for correct Candidate F | Session name excluded from key | ☐ |

---

## 10. How to Interpret Results

### Branch 1: ALL PASS (P1-P9 all TRUE)

**Candidate F is CONFIRMED.**

Next steps:
1. Return evidence files to the agent (or commit to repo)
2. Agent will update `normalize_principal_id()` in `handler.py:84-96` with Candidate F logic
3. Agent will update governance docs: design.md (PROVISIONAL → CONFIRMED), requirements.md, risk_register.md, todo.md, validation_plan.md, runbook.md
4. Deployment block is lifted
5. Proceed to Task 10 (checkpoint)

### Branch 2: PARTIAL FAILURE (some criteria fail)

**Candidate F is PARTIALLY UNRESOLVED.**

Document exactly which criteria failed and what was observed.
Do NOT force a conclusion. The agent will:
1. Analyze the failure
2. Determine if an alternative normalization rule is needed
3. Propose a revised discovery plan if necessary

Common partial failure scenarios:
- P3 fails (session names are the same): unusual but Candidate F still works (session name is excluded)
- P8 fails (ARN structure unexpected): Candidate F parsing logic needs revision — BLOCKER
- P1 fails (cross-env Candidate F mismatch): critical — role name extraction is broken — BLOCKER

### Branch 3: CRITICAL FAILURE

**Candidate F is REJECTED.**

If any of these occur:
- P4 fails: two different users produce the same principal_id → family-level collision → BLOCKER
- P8 fails with non-assumed-role ARN pattern → fundamental assumption wrong → BLOCKER

Document everything. Do not proceed with implementation. Return to planning.

---

## 11. Files Changed by This Runbook

### Files the operator will modify (evidence only):

| File | Action |
|---|---|
| `docs/ai/discovery/c1-evidence.json` | Fill `<FILL>` fields with real capture data |
| `docs/ai/discovery/c2-evidence.json` | Fill `<FILL>` fields with real capture data |
| `docs/ai/discovery/c3-evidence.json` | Fill `<FILL>` fields with real capture data |
| `docs/ai/discovery/c4-evidence.json` | (Optional) Fill `<FILL>` fields |
| `docs/ai/discovery/c5-evidence.json` | Fill `<FILL>` fields with real capture data |

### Files the operator must NOT modify:

| File | Reason |
|---|---|
| `infra/bedrock-gateway/lambda/handler.py` | Runtime code — no changes until evidence reviewed |
| `infra/bedrock-gateway/*.tf` | Terraform — no changes (discovery uses separate workspace) |
| `account-portal/**` | Existing services — no changes |
| `ansible/**` | Existing automation — no changes |

### Temporary AWS resources created and destroyed:

| Resource | Created in Step | Destroyed in Step |
|---|---|---|
| Terraform `discovery` workspace | A1 | F2 |
| API Gateway (discovery stage) | A3 | F1 |
| Lambda (DISCOVERY_MODE=true) | A3 | F1 |
| DynamoDB tables (discovery-prefixed) | A3 | F1 |
| IAM roles (discovery) | A3 | F1 |
| `DiscoveryInvoke` policy on per-user roles | A4 | F3 |

---

## 12. Static Code Review Observations (Reference)

These observations from Phase E are provided for context. No operator action needed.

| Location | Observation |
|---|---|
| `handler.py:84-96` `normalize_principal_id()` | Candidate F IMPLEMENTED — returns `<account>#<role-name>`. Fail-closed on non-BedrockUser/Shared roles. Live-verified: `<ACCOUNT_ID>#BedrockUser-admin`. |
| `handler.py:196-208` `lookup_principal_policy()` | Uses `table.get_item(Key={"principal_id": principal_id})`. DynamoDB GetItem = exact-match by design. No scan, no query, no filter. |
| `handler.py` — all enforcement paths | No derived username extraction. Raw `principal_id` flows through policy, quota, ledger, session metadata. |
| `dynamodb.tf` `principal_policy` table | PK = `principal_id` (String). No range key, no GSI. Exact-match only. |
| `iam.tf` `RequestLedgerDenyMutation` | Explicit Deny on UpdateItem/DeleteItem for RequestLedger. Append-only enforced at IAM level. |
| `handler.py` — entire file | No `startswith`, `endswith`, `in`, `regex`, `re.match`, `fnmatch`, `glob`, `begins_with`, `contains`, `BETWEEN`, `FilterExpression` in any enforcement path. |

---

## 13. Validation Questions Mapping

| Question | Captures Needed | Criterion |
|---|---|---|
| Q1: 동일 사용자가 laptop/FSx에서 동일 principal_id? | C1 + C2 | P1, P2 |
| Q2: 서로 다른 per-user role → 서로 다른 principal_id? | C1 vs C3 | P4, P5 |
| Q3: BedrockUser-Shared가 fail-closed? | C5 | P6, P7 |
| Q4: session_name이 enforcement에 불필요? | C1, C2 (session differs, key same) | P3, P9 |
| Q5: userArn 패턴이 assumed-role 형태? | All captures | P8 |
| Q6: Candidate F 수정 필요 여부? | All criteria | All pass → no revision needed |

---

## 14. Troubleshooting

### Discovery Lambda returns 403

- Check: per-user role has `execute-api:Invoke` on the discovery API Gateway ARN
- Check: SigV4 signing uses the correct region (`us-west-2`) and service (`execute-api`)
- Check: temporary credentials are not expired

### Discovery Lambda returns 500

- Check CloudWatch Logs for the discovery Lambda
- Likely cause: Lambda environment variables not set correctly

### `terraform workspace new discovery` fails

- Check: you have write access to the Terraform state backend (S3 bucket)
- Check: workspace name doesn't already exist (`terraform workspace list`)

### awscurl not available

Use `curl --aws-sigv4` (requires curl 7.75+) or write a short boto3 script:

```python
import boto3, json
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

session = boto3.Session()
credentials = session.get_credentials().get_frozen_credentials()
url = "https://<api-id>.execute-api.us-west-2.amazonaws.com/discovery/converse"
data = json.dumps({"modelId": "discovery-test"})

request = AWSRequest(method="POST", url=url, data=data,
                     headers={"Content-Type": "application/json"})
SigV4Auth(credentials, "execute-api", "us-west-2").add_auth(request)

import urllib.request
req = urllib.request.Request(url, data=data.encode(),
                             headers=dict(request.headers), method="POST")
resp = urllib.request.urlopen(req)
print(json.loads(resp.read()))
```

---

## 15. No-Change Confirmation

This runbook is a governance/planning artifact only.
No runtime code, Terraform files, IAM policies, or infrastructure were modified to produce it.

Created: `docs/ai/discovery/task3-operator-runbook.md` (this file)
Modified: none
