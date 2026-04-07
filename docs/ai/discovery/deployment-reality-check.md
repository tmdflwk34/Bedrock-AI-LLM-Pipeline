# Deployment Reality Check: Bedrock Access Gateway

> Date: 2026-03-17
> Updated: 2026-03-17 — Discovery gateway NOW DEPLOYED.
> Purpose: Task 3 실행 전 배포 현실 점검. IaC 정의 vs 실제 배포 상태 비교.
> Trigger: `cost-dashboard-api` (zkamnr5ig7)가 유일한 us-west-2 API Gateway로 확인됨 — Bedrock gateway API Gateway는 미배포. (**UPDATE**: discovery gateway `<DISCOVERY_API_ID>` 이후 배포됨)

---

## 1. 핵심 결론

**~~Bedrock Access Gateway 인프라는 전혀 배포되지 않았다.~~**

**UPDATE (2026-03-17): Discovery gateway가 배포되었다.**

- Discovery API Gateway: `<DISCOVERY_API_ID>`, stage `v1`
- Invoke URL: `https://<DISCOVERY_API_ID>.execute-api.us-west-2.amazonaws.com/v1/discovery`
- `DISCOVERY_MODE=true` — Lambda returns raw requestContext only
- 단일 사용자 캡처 완료 (admin, FSx 환경)
- Discovery Lambda 재배포 완료 — `normalize_principal_id()` Candidate F 반영. `derived_principal_id` = `<ACCOUNT_ID>#BedrockUser-admin` live 확인.
- `dynamodb.tf` TTL 구문 오류는 수정됨 (배포 성공으로 확인)
- `cost-dashboard-api` (zkamnr5ig7)는 별도 프로젝트 — Bedrock gateway와 무관
- Prod 배포는 여전히 차단 — discovery-only 배포만 활성

---

## 2. IaC 정의 vs 배포 상태 인벤토리

### 2.1 API Gateway

| 항목 | IaC 정의 (main.tf) | 배포 상태 |
|---|---|---|
| REST API 이름 | `bedrock-gw-${env}-api` (e.g. `bedrock-gw-discovery-api`) | **미배포** |
| 타입 | Regional REST API | — |
| 인증 | AWS_IAM (SigV4) | — |
| 라우팅 | `{proxy+}` ANY + root ANY → Lambda proxy integration | — |
| Stage 이름 | `var.api_gateway_stage_name` (default: `v1`, discovery 시 `v1`) | — |
| Invoke URL 형식 | `https://<api-id>.execute-api.us-west-2.amazonaws.com/v1` | — |
| Throttle | rate=50 rps, burst=100 (default) | — |
| Access logging | CloudWatch `/aws/apigateway/${prefix}-api/access` | — |

**확인된 사실**: us-west-2에 존재하는 유일한 API Gateway는 `zkamnr5ig7 cost-dashboard-api`. 이것은 `backend-cost` 서비스용이며 Bedrock gateway와 무관.

### 2.2 Lambda

| 항목 | IaC 정의 (lambda.tf) | 배포 상태 |
|---|---|---|
| Function 이름 | `bedrock-gw-${env}-gateway` (e.g. `bedrock-gw-discovery-gateway`) | **Discovery 배포 완료** — Candidate F normalization 반영. `derived_principal_id` = `<ACCOUNT_ID>#BedrockUser-admin` live 확인. |
| Runtime | Python 3.12 | — |
| Handler | `handler.lambda_handler` | — |
| Memory | 256 MB (default) | — |
| Timeout | 60s (default) | — |
| Alias | `live` → latest version | — |
| 소스 | `infra/bedrock-gateway/lambda/handler.py` → zip | — |
| Env vars | 8 DynamoDB table names + SES emails + `DISCOVERY_MODE` + `ENVIRONMENT` | — |

### 2.3 DynamoDB (8 tables)

| 테이블 | IaC 이름 패턴 | 배포 상태 |
|---|---|---|
| PrincipalPolicy | `bedrock-gw-${env}-${region}-principal-policy` | **미배포** |
| DailyUsage | `bedrock-gw-${env}-${region}-daily-usage` | **미배포** |
| TemporaryQuotaBoost | `bedrock-gw-${env}-${region}-temporary-quota-boost` | **미배포** |
| ApprovalRequest | `bedrock-gw-${env}-${region}-approval-request` | **미배포** |
| RequestLedger | `bedrock-gw-${env}-${region}-request-ledger` | **미배포** |
| SessionMetadata | `bedrock-gw-${env}-${region}-session-metadata` | **미배포** |
| IdempotencyRecord | `bedrock-gw-${env}-${region}-idempotency-record` | **미배포** |
| ApprovalPendingLock | `bedrock-gw-${env}-${region}-approval-pending-lock` | **미배포** |

모든 테이블: PAY_PER_REQUEST billing, TTL 설정 포함 (해당 테이블).

### 2.4 IAM

| 항목 | IaC 정의 (iam.tf) | 배포 상태 |
|---|---|---|
| Lambda execution role | `bedrock-gw-${env}-lambda-exec` | **미배포** |
| Bedrock policy | `bedrock:Converse` Allow | — |
| DynamoDB policy | 7 tables RW + RequestLedger PutItem only + Deny mutation | — |
| SES policy | `ses:SendEmail`, `ses:SendRawEmail` | — |
| API GW CW role | Optional (`manage_api_gateway_account_cloudwatch_role=false` default) | — |

### 2.5 CloudWatch Log Groups

| 항목 | IaC 정의 (logs.tf) | 배포 상태 |
|---|---|---|
| API GW access log | `/aws/apigateway/${prefix}-api/access` | **미배포** |
| Lambda log | `/aws/lambda/${prefix}-gateway` | **미배포** |

### 2.6 Terraform State

| 항목 | 상태 |
|---|---|
| S3 backend | `backend.tf`에 주석 처리됨 — 미설정 |
| Local state | `.terraform/`, `terraform.tfstate` 존재 여부 미확인 (repo에 없음, `.gitignore` 대상) |
| `terraform init` 실행 여부 | 불확실 — S3 backend 미설정이므로 local state만 가능 |

`backend.tf` 내용:
```hcl
# S3 backend — uncomment and configure before first apply.
# terraform {
#   backend "s3" {
#     bucket         = "REPLACE-terraform-state-bucket"
#     key            = "bedrock-gateway/terraform.tfstate"
#     region         = "us-west-2"
#     dynamodb_table = "REPLACE-terraform-lock-table"
#     encrypt        = true
#   }
# }
```

**S3 backend이 설정되지 않았으므로 `terraform apply`가 실행된 적이 없거나, local state로만 실행되었을 가능성이 있다. 그러나 us-west-2에 Bedrock gateway API Gateway가 없으므로 apply는 실행되지 않은 것으로 판단.**

---

## 3. `dev.tfvars` 분석

```hcl
environment          = "dev"
aws_region           = "us-west-2"
ses_sender_email     = "REPLACE-bedrock-gw@example.com"
ses_admin_group_email = "REPLACE-admin-group@example.com"
discovery_mode       = true
manage_api_gateway_account_cloudwatch_role = false
api_gateway_data_trace_enabled = true
api_gateway_execution_logging_level = "INFO"
```

- SES 이메일이 `REPLACE-` placeholder — 실제 값 미설정
- `discovery_mode = true` — dev.tfvars가 discovery용으로 준비됨
- prod.tfvars는 존재하지 않음

---

## 4. Task 3 실행 차단 요인

| # | 차단 요인 | 심각도 | 해결 방법 | 상태 |
|---|---|---|---|---|
| B1 | API Gateway 미배포 — discovery endpoint 없음 | **BLOCKER** | `terraform apply` (discovery workspace) | ✅ RESOLVED — `<DISCOVERY_API_ID>` 배포됨 |
| B2 | Lambda 미배포 — discovery handler 없음 | **BLOCKER** | B1과 동시 해결 | ✅ RESOLVED |
| B3 | DynamoDB 미배포 — Lambda env vars 참조 실패 | **BLOCKER** | B1과 동시 해결 | ✅ RESOLVED |
| B4 | IAM role 미배포 — Lambda 실행 불가 | **BLOCKER** | B1과 동시 해결 | ✅ RESOLVED |
| B5 | S3 backend 미설정 — state 관리 불안정 | **WARNING** | Local state로 discovery 가능하나, S3 backend 설정 권장 | Open (discovery는 local state로 진행) |
| B6 | SES sender email placeholder | **NON-BLOCKING** | Discovery mode에서 SES 미사용 | N/A (discovery) |
| B7 | Per-user role에 `execute-api:Invoke` 미부여 | **BLOCKER** | Discovery API Gateway ARN 확정 후 IAM policy 추가 | ✅ RESOLVED — admin 캡처 성공으로 확인 |
| B8 | `dynamodb.tf` `approval_pending_lock` TTL 구문 불완전 + tags 누락 | **BLOCKER** | TTL block 완성 + tags block 추가 | ✅ PARTIALLY RESOLVED — TTL 수정됨 (배포 성공). tags 블록은 여전히 누락이나 non-blocking. |

---

## 5. `dynamodb.tf` 구문 오류

`approval_pending_lock` 테이블 (파일 마지막 리소스)에 두 가지 문제:

**문제 1**: TTL 블록 불완전 (line ~207):
```hcl
  ttl {
    attribute_name   # ← "= \"ttl\"" 누락
  }                  # ← enabled = true 누락
```

**문제 2**: `tags` 블록 누락 — 다른 모든 테이블에는 `tags { Service, Env }` 블록이 있으나 이 테이블에는 없음.

이 상태로는 `terraform plan`이 실패한다. Discovery 배포 전 수정 필요.

**수정 필요 내용**:
```hcl
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }

```

이 수정은 IaC 파일 변경이므로 **명시적 승인 필요** (devops-operating-model.md 준수).

---

## 6. Discovery 배포를 위한 최소 조치 목록

Task 3 live capture를 위해 필요한 최소 조치 (순서대로):

### 사전 조건 (IaC 수정 — 승인 필요)

1. **`dynamodb.tf` TTL 구문 수정** — `approval_pending_lock` 테이블의 `ttl` block 완성
2. **`backend.tf` 결정** — S3 backend 설정 또는 local state 사용 결정
3. **`dev.tfvars` 또는 discovery용 tfvars** — SES placeholder는 discovery에서 non-blocking이므로 그대로 가능

### 배포 (operator 실행)

4. `terraform init` (infra/bedrock-gateway/)
5. `terraform workspace new discovery`
6. `terraform plan -var environment=discovery -var discovery_mode=true`
7. Plan 검토 — 생성될 리소스 확인
8. `terraform apply -var environment=discovery -var discovery_mode=true`
9. Output에서 `api_gateway_invoke_url` 기록

### IAM 설정 (operator 실행)

10. Per-user role (`BedrockUser-user16`, `BedrockUser-user04`, `BedrockUser-Shared`)에 discovery API Gateway `execute-api:Invoke` 권한 추가

### 캡처 실행

11. Phases B-D (task3-operator-runbook.md 참조)

### 정리

12. `terraform destroy` + workspace 삭제 + IAM policy 제거

---

## 7. 명시적 제외

- `cost-dashboard-api` (zkamnr5ig7): 별도 프로젝트. Bedrock gateway와 무관. Task 3 대상 아님.
- 기존 backend-admin, backend-cost, nginx, docker-compose: 변경 없음.
- prod 배포: Task 3 완료 전까지 차단 유지.

---

## 8. No-Change Confirmation

이 문서는 governance/planning artifact only.
런타임 코드, Terraform 파일, IAM 정책, 인프라에 대한 변경 없음.

생성: `docs/ai/discovery/deployment-reality-check.md` (이 파일)
수정: 없음
