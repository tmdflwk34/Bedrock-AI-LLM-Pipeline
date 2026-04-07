# user05 Gateway 편입 체크리스트 — 감사 보고서

> Date: 2026-04-03
> Status: Research artifact — read-only analysis, no implementation changes.
> Scope: Code-level + IaC-level audit of user05 gateway-managed onboarding readiness.
> Method: Static analysis of repo code, Terraform, and planning docs. No live DynamoDB/IAM queries executed.

---

## 배경

`docs/ai/phase4-corrected-user-classification.md` (2026-03-24)에서 user05는 **locked exception user**로 분류됨:

> "user05 is NOT seeded into principal_policy — ever, unless operator explicitly reverses this decision."

본 보고서는 운영자가 이 결정을 번복하여 user05를 gateway-managed로 편입하려 할 때, 코드/인프라 수준에서 무엇이 준비되어 있고 무엇이 미비한지를 점검한다.

---

## 1. Direct Access 예외 제거 여부

### 현재 상태

- **EXCEPTION_USERS 하드코딩 dict는 없다.** Exception user 판별은 DynamoDB `principal_policy` 테이블의 `direct_access_exception` boolean 속성으로 수행됨.
  - 코드 위치: `gateway_usage.py` → `_is_exception_user()` (line ~155), `_get_exception_users_from_db()` (line ~165)
- user05가 현재 `principal_policy`에 `direct_access_exception=true`로 등록되어 있는지는 **live DynamoDB 조회 필요** (코드만으로는 확인 불가).

### DenyDirectBedrockInference 정책

- **Terraform `iam.tf`에 `DenyDirectBedrockInference` IAM policy는 정의되어 있지 않다.**
- 현재 모델: BedrockUser-* IAM role에 직접 `bedrock:InvokeModel` 권한이 없으면 자연적으로 차단됨. 그러나 이것은 **명시적 Deny가 아닌 implicit deny**이므로, 다른 경로(inline policy, permission boundary 누락 등)로 우회 가능.
- ECS RunTask / ECS ExecuteCommand / Step Functions StartExecution에 대한 사용자 수준 차단 정책도 Terraform에 없음.

### 판정: ⚠️ 확인 필요

| 항목 | 상태 |
|------|------|
| `direct_access_exception` DynamoDB 속성 | Live 조회 필요 |
| `DenyDirectBedrockInference` IAM policy | **미구현** — implicit deny만 존재 |
| ECS/SFN direct 차단 | **미구현** |

### 편입 시 필요 조치

1. DynamoDB에서 user05의 `direct_access_exception` 속성을 `false`로 변경 (또는 삭제)
2. user05의 BedrockUser-user05 IAM role에 explicit `Deny bedrock:InvokeModel` 추가 (gateway Lambda만 허용)
3. 또는 permission boundary로 direct Bedrock 차단

---

## 2. Gateway Invoke 권한

### 현재 상태

- Gateway API는 `AWS_IAM` auth 사용 (API Gateway Regional REST API).
- 사용자는 `BedrockUser-{username}` role로 assume-role 후 SigV4 서명으로 API Gateway 호출.
- **API Gateway resource policy 또는 IAM policy에서 `execute-api:Invoke`를 BedrockUser-user05에 명시적으로 허용하는 코드는 Terraform에 없다.**
- 현재 구조: API Gateway에 IAM auth가 걸려 있고, BedrockUser-* role이 `execute-api:Invoke` 권한을 가지고 있으면 호출 가능. 이 권한은 role 자체의 IAM policy에 의존.

### 판정: ⚠️ 확인 필요

| 항목 | 상태 |
|------|------|
| `execute-api:Invoke` on BedrockUser-user05 | Live IAM 조회 필요 |
| `/converse` path 호출 가능 여부 | IAM 권한 확인 후 판단 |
| `/quota/status`, `/approval/request` 호출 가능 여부 | 동일 |

### 편입 시 필요 조치

- BedrockUser-user05 role에 gateway API invoke 권한이 없으면 추가 필요:
  ```json
  {
    "Effect": "Allow",
    "Action": "execute-api:Invoke",
    "Resource": "arn:aws:execute-api:us-west-2:<ACCOUNT_ID>:<GATEWAY_API_ID>/v1/*"
  }
  ```

---

## 3. Principal Normalization

### 현재 상태

- Lambda handler `normalize_principal_id()` (handler.py line ~120):
  - `arn:aws:sts::<acct>:assumed-role/<role-name>/<session-name>` → `<acct>#<role-name>`
  - user05가 `BedrockUser-user05` role로 assume하면 → `<ACCOUNT_ID>#BedrockUser-user05`
  - Fail-closed 조건: `BedrockUser-Shared` 차단, `BedrockUser-` prefix 필수

### 코드 검증

```python
# handler.py normalize_principal_id()
role_name = parts[1]  # e.g. "BedrockUser-user05"
if not role_name.startswith("BedrockUser-"):
    return ""  # fail closed
if role_name == "BedrockUser-Shared":
    return ""  # fail closed
account_id = user_arn.split(":")[4]
return f"{account_id}#{role_name}"
```

- `BedrockUser-user05`는 prefix 조건 충족, Shared 아님 → **정상 정규화됨**.
- 결과: `<ACCOUNT_ID>#BedrockUser-user05`

### 일관성 검증

| 시스템 | principal_id 형식 | 일치 여부 |
|--------|-------------------|-----------|
| Lambda handler | `<ACCOUNT_ID>#BedrockUser-user05` | ✅ |
| PrincipalPolicy PK | `principal_id` (same format) | ✅ |
| MonthlyUsage PK | `{principal_id}#{YYYY-MM}` | ✅ |
| RequestLedger | `principal_id` field | ✅ |
| Portal gateway_usage.py | same format | ✅ |
| Shell hook (bedrock_gw.py) | SigV4 → API GW → Lambda extraction | ✅ |

### 판정: ✅ 충족

---

## 4. PrincipalPolicy 등록 상태

### 현재 상태

- `docs/ai/phase4-corrected-user-classification.md` §3에서 user05는 **"NOT seeded into principal_policy"**로 명시.
- 편입하려면 새로 등록해야 함.

### 등록 방법

`POST /api/gateway/policies` (gateway_policy.py):
```json
{
  "principal_id": "<ACCOUNT_ID>#BedrockUser-user05",
  "monthly_cost_limit_krw": 500000,
  "max_monthly_cost_limit_krw": 2000000,
  "allowed_models": ["<모델 목록>"]
}
```

또는 직접 DynamoDB PutItem.

### 필수 속성 확인

| 속성 | 필요 여부 | 기본값 |
|------|-----------|--------|
| `monthly_cost_limit_krw` | 필수 | 500,000 |
| `max_monthly_cost_limit_krw` | 필수 | 2,000,000 |
| `allowed_models` | 필수 | [] (빈 리스트 = 전체 차단) |
| `notification_email` | 권장 | — |
| `direct_access_exception` | false 또는 미설정 | false |

### 판정: ❌ 미충족 — 등록 필요

---

## 5. allowed_models 정합성

### 현재 상태

- user05가 실제로 사용하는 모델 목록은 **CloudWatch Logs 조회 또는 운영자 확인 필요**.
- `gateway_usage.py`의 `USER_EMAIL_MAP`에 user05가 포함되어 있음 → 시스템에서 인지하는 사용자.
- `/mars` 경로 사용 여부: `bedrock_gw.py` Python 클라이언트가 `/fsx/home/shared/bedrock-gateway`에 배포되어 있고, PYTHONPATH에 추가됨 (bedrock-gw-quota-check.sh). `/mars` (project_10) 사용자가 이 클라이언트를 통해 호출하면 gateway path를 탐.

### 코드 검증

- `check_model_access()` (handler.py): `allowed_models` 리스트에 정확히 일치하는 `model_id`만 허용. 빈 리스트 = 전체 차단.
- 모델 ID는 정규화 없이 strict match: `us.anthropic.claude-sonnet-4-6` ≠ `anthropic.claude-sonnet-4-6`

### 판정: ⚠️ 확인 필요

| 항목 | 상태 |
|------|------|
| user05 실제 사용 모델 목록 | CW Logs 조회 또는 운영자 확인 필요 |
| `/mars` 경로 모델 요구사항 | 운영자 확인 필요 |
| allowed_models에 inference profile variant 포함 여부 | 모델 목록 확정 후 검증 |

---

## 6. ModelPricing Coverage

### 현재 상태

- ModelPricing 테이블의 현재 항목 수는 live 조회 필요.
- `docs/ai/phase4-corrected-user-classification.md` §6에서 11개 모델 pricing seed 계획 언급.
- Lambda handler `lookup_model_pricing()`: **fail-closed** — pricing 없으면 요청 거부.

### 코드 검증

```python
# handler.py
pricing = lookup_model_pricing(model_id)
if not pricing:
    denial_reason = f"no pricing defined for model {model_id}"
    return deny_response(denial_reason)
```

### 판정: ⚠️ 확인 필요

| 항목 | 상태 |
|------|------|
| user05 사용 모델의 pricing entry 존재 여부 | Live DynamoDB 조회 필요 |
| Fail-closed 동작 | ✅ 코드 확인됨 |

---

## 7. Quota/Accounting 경로

### 현재 상태

코드 분석 결과, gateway-managed 사용자의 전체 accounting 경로:

1. **MonthlyUsage**: `update_monthly_usage()` — PK: `{principal_id}#{YYYY-MM}`, SK: `model_id`, atomic ADD
2. **RequestLedger**: `write_request_ledger()` — immutable PutItem, 모든 ALLOW/DENY 기록
3. **JobState** (async path): `handle_converse_job_submit()` → job_state 테이블
4. **Portal**: `gateway_usage.py` → `_get_monthly_usage()` → MonthlyUsage 조회

### Reserved/In-Progress vs Completed/Settled

- **Short path** (`/converse`): 동기 처리. Bedrock 호출 후 즉시 `update_monthly_usage()` + `write_request_ledger()`. Reserved 개념 없음.
- **Long path** (`/converse-jobs`): 
  - Submit 시: `__reserved__{job_id}` 항목으로 MonthlyUsage에 예약 비용 기록
  - 완료 시: worker가 settle → reserved 삭제 + actual 기록
  - 취소 시: reserved 삭제
  - Stale cleanup: `_cleanup_stale_reservations()` — TTL 만료된 reservation 정리

### 판정: ✅ 충족 (코드 수준)

user05가 principal_policy에 등록되면 동일한 accounting 경로를 탐. 별도 코드 변경 불필요.

---

## 8. Hidden Async Long-Running 경로

### 현재 상태

Lambda handler `lambda_handler()` (line ~2270):

```python
# Server-side hidden async routing
if model_id in LONGRUN_MODELS:
    return handle_converse_job_submit(principal_id, identity_fields, body, request_id)
```

`LONGRUN_MODELS` (handler.py line ~1710):
```python
LONGRUN_MODELS = {
    "us.anthropic.claude-opus-4-6-v1",
    "global.anthropic.claude-opus-4-6-v1",
    "us.anthropic.claude-opus-4-5-20251101-v1:0",
    "us.anthropic.claude-opus-4-20250514-v1:0",
    "us.anthropic.claude-opus-4-1-20250805-v1:0",
    "anthropic.claude-opus-4-6-v1",
}
```

- 사용자가 `/converse`로 Opus 모델 호출 → 서버가 자동으로 `/converse-jobs` (async/Fargate) 경로로 라우팅.
- API Gateway 29초 제한 회피: 202 Accepted 즉시 반환 → Step Functions → Fargate worker 실행.
- `bedrock_gw.py` Python 클라이언트가 이를 투명하게 처리: `_select_tier()` → Tier 3 → poll loop.

### 판정: ✅ 충족 (코드 수준)

user05가 gateway-managed로 전환되면 동일한 hidden async 라우팅이 자동 적용됨. 단, `allowed_models`에 Opus 모델이 포함되어야 함.

---

## 9. /mars 실제 사용 경로와의 연동

### 현재 상태

- `bedrock_gw.py` 클라이언트는 `/fsx/home/shared/bedrock-gateway`에 배포.
- `bedrock-gw-quota-check.sh`가 `PYTHONPATH`에 이 경로를 추가:
  ```bash
  export PYTHONPATH="/fsx/home/shared/bedrock-gateway${PYTHONPATH:+:$PYTHONPATH}"
  ```
- `/mars` (project_10) 애플리케이션이 `from bedrock_gw import converse`를 사용하면 gateway path를 탐.
- **그러나**: `/mars`가 `bedrock_gw` 클라이언트를 사용하는지, 아니면 직접 `boto3.client('bedrock-runtime').converse()`를 호출하는지는 **코드 확인 필요**.

### 판정: ⚠️ 확인 필요

| 항목 | 상태 |
|------|------|
| `/mars` 코드가 `bedrock_gw` 클라이언트 사용 여부 | 코드 확인 필요 |
| Direct Bedrock 우회 가능성 | IAM explicit deny 미구현 → 우회 가능 |

---

## 10. Portal 가시성

### 현재 상태

Portal (BedrockGateway.jsx) + backend-admin API 분석:

| 정보 | API 경로 | gateway-managed 지원 | exception 지원 |
|------|----------|---------------------|----------------|
| Current usage | `GET /api/gateway/users` | ✅ `managed_users[].current_month_cost_krw` | ❌ (별도 endpoint) |
| Remaining budget | `GET /api/gateway/users/<pid>/policy` | ✅ `effective_limit_krw - usage` | ❌ |
| Allowed models | `GET /api/gateway/users/<pid>/policy` | ✅ `allowed_models` | ❌ |
| Request history | `GET /api/gateway/users/<pid>/history` | ✅ (ledger scan) | ❌ |
| Daily breakdown | `GET /api/gateway/users/<pid>/daily` | ✅ (ledger KST grouping) | ❌ |

- user05가 gateway-managed로 전환되면 위 모든 endpoint에서 자동으로 노출됨.
- Exception user 전용 endpoint (`/api/gateway/exception-usage`)에서는 제외됨 (`direct_access_exception=false`이므로).

### 판정: ✅ 충족 (코드 수준)

principal_policy 등록 + 실제 gateway 사용 시작 후 portal에서 admin과 동일한 가시성 확보.

---

## 11. 최종 판정

### **user05 편입 보류**

아래 항목이 미충족:

| # | 미충족 항목 | 필요 조치 | 차단 수준 |
|---|------------|-----------|-----------|
| 1 | **PrincipalPolicy 미등록** | DynamoDB에 user05 policy 생성 (monthly_cost_limit_krw, max_monthly_cost_limit_krw, allowed_models, notification_email) | 필수 |
| 2 | **DenyDirectBedrockInference 미구현** | BedrockUser-user05 IAM role에 explicit deny 추가. 없으면 gateway 우회 가능. | 필수 (bypass prevention) |
| 3 | **allowed_models 미확정 + ModelPricing coverage 미검증** | user05 실제 사용 모델 확인 → allowed_models 설정 → pricing entry 존재 확인 | 필수 |

### 추가 확인 필요 (live 조회)

| # | 항목 | 확인 방법 |
|---|------|-----------|
| A | `direct_access_exception` DynamoDB 현재 값 | `aws dynamodb get-item --table bedrock-gw-dev-us-west-2-principal-policy --key '{"principal_id":{"S":"<ACCOUNT_ID>#BedrockUser-user05"}}'` |
| B | BedrockUser-user05 IAM role의 `execute-api:Invoke` 권한 | `aws iam get-role-policy` / `list-attached-role-policies` |
| C | `/mars` 코드의 Bedrock 호출 경로 | `/home/app/mars/project_10` 소스 코드 확인 |
| D | ModelPricing 테이블 현재 항목 | `aws dynamodb scan --table bedrock-gw-dev-us-west-2-model-pricing` |

---

## 편입 실행 순서 (승인 후)

```
Step 1: Live 확인 (A, B, C, D)
Step 2: BedrockUser-user05에 DenyDirectBedrockInference 추가
Step 3: BedrockUser-user05에 execute-api:Invoke 권한 확인/추가
Step 4: allowed_models 확정 + ModelPricing coverage 확인
Step 5: PrincipalPolicy 등록 (POST /api/gateway/policies)
Step 6: direct_access_exception 속성 제거 (있는 경우)
Step 7: notification_email seed (POST /api/gateway/seed-emails 또는 직접 UpdateItem)
Step 8: 검증 — shell hook quota check + /converse 테스트 호출
Step 9: Portal에서 user05 가시성 확인
```

---

## 코드 변경 필요 여부

| 영역 | 변경 필요 | 설명 |
|------|-----------|------|
| Lambda handler | ❌ | 코드 변경 없음. principal_policy 등록만으로 동작 |
| gateway_usage.py | ❌ | exception user 판별이 DB 기반이므로 코드 변경 불필요 |
| gateway_policy.py | ❌ | 기존 CRUD API로 등록 가능 |
| Terraform iam.tf | ⚠️ | DenyDirectBedrockInference policy 추가 필요 (선택적이나 강력 권장) |
| BedrockUser-user05 IAM | ⚠️ | execute-api:Invoke 권한 + direct deny 추가 |
| bedrock_gw.py | ❌ | 클라이언트 변경 불필요 |
| Frontend | ❌ | 자동 노출 |

---

## 위험 요소

| 위험 | 영향 | 완화 |
|------|------|------|
| DenyDirectBedrockInference 없이 편입 시 user05가 gateway 우회하여 직접 Bedrock 호출 가능 | 비용 통제 무력화, 감사 누락 | IAM explicit deny 선행 적용 |
| allowed_models 누락 시 필요한 모델 사용 불가 | 업무 중단 | CW Logs에서 실제 사용 모델 확인 후 설정 |
| ModelPricing 미등록 모델 호출 시 fail-closed | 요청 거부 | pricing seed 선행 |
| `/mars` 코드가 직접 boto3 호출 시 gateway 경로 미적용 | 비용 추적 누락 | 코드 확인 + 필요 시 bedrock_gw 클라이언트로 전환 |
