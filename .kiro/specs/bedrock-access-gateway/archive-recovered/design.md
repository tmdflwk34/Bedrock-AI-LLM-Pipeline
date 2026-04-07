# Design Document: Bedrock Access Control Gateway

## Overview

서버리스 Bedrock 접근 통제 게이트웨이. Regional REST API (AWS_IAM auth) + Lambda + DynamoDB. v1은 Converse API(non-streaming)만 지원. ConverseStream, InvokeModel, InvokeModelWithResponseStream은 v2로 명시적 연기. Converse API를 지원하지 않는 모델은 v1에서 사용 불가. 사용자 identity는 SigV4 서명에서 AWS가 검증하며, Gateway Lambda만 Bedrock 호출 권한을 가짐.

이전 Flask/Docker/Nginx/JWT 기반 설계는 폐기됨.

> **v1 명시적 연기**: ConverseStream, InvokeModel/InvokeModelWithResponseStream, WAF. v2에서 검토.
> **IaC**: Terraform (`infra/bedrock-gateway/`). SAM/CDK는 사용하지 않음. Ansible은 기존 컨테이너/호스트 운영에만 사용.

## Locked Architecture Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Regional REST API (v1) | 랩탑 + FSx 모두 Private API 네트워크 도달성을 가정할 수 없음. Private API는 VPC-only 환경용 future variant |
| 2 | Non-streaming only (v1) | API Gateway REST API는 Lambda proxy에서 streaming 미지원. ConverseStream, InvokeModel, InvokeModelWithResponseStream은 v2로 명시적 연기 |
| 3 | Principal: userArn 우선, raw fields 보존 | requestContext.identity.caller가 항상 canonical이 아닐 수 있음. discovery 검증 필수 |
| 4 | Bedrock 차단: SCP 목표, IAM deny 임시 | SCP 즉시 적용 불가 시 human role에 IAM deny 적용 |
| 5 | backend-admin: admin portal only | inference 프록시 금지. inference는 API Gateway AWS_IAM auth 경유 필수 |
| 6 | SES: 외부화, verified sender 1개/env | admin group alias로 수신자 설정 |
| 7 | DynamoDB: `bedrock-gw-${env}-${region}-${table}` | 환경/리전 인식 네이밍 |

## Architecture

```
사용자 (랩탑/FSx)
  │  IAM Identity Center SSO → AssumeRole → temporary credentials
  │
  ▼  SigV4-signed HTTPS request
Regional REST API Gateway (AWS_IAM auth)
  │  SigV4 검증 (AWS가 수행, 실패 시 403)
  │  access logging + execution logging → CloudWatch
  ▼
Gateway Lambda
  │  request context에서 identity fields 추출:
  │    userArn, caller, accountId, accessKey (모두 추출)
  │  Principal 정규화: userArn 우선 사용
  │  raw fields → SessionMetadata에 감사용 보존
  │
  ├── Idempotency: X-Request-Id로 RequestLedger 중복 확인
  ├── PrincipalPolicy 조회 (DynamoDB) → 없으면 deny
  ├── Model allowlist 확인 → 불허 시 deny
  ├── DailyUsage 조회 + TemporaryQuotaBoost 확인 → 쿼터 초과 시 deny
  │
  ├── Bedrock Converse API 호출 (v1, non-streaming)
  │     └── Gateway Lambda execution role만 허용
  │
  ├── DailyUsage 원자적 업데이트 (DynamoDB ADD)
  ├── RequestLedger PutItem (immutable)
  └── SessionMetadata PutItem

Admin Portal (account-portal frontend)
  │  기존 JWT 인증으로 admin UI 접근
  ▼
backend-admin (기존 Flask, port 5000)
  │  DynamoDB 직접 조회/수정:
  │    PrincipalPolicy CRUD
  │    ApprovalRequest 승인/거부
  │    TemporaryQuotaBoost 생성
  │    DailyUsage/RequestLedger 조회
  │  SES 알림 발송
  └── inference 프록시로 사용하지 않음
```

## Trust Boundaries

1. **SigV4 boundary (AWS managed)**: API Gateway가 요청 서명을 검증. Lambda에 도달하는 모든 요청은 AWS가 인증한 identity를 가짐.
2. **Lambda execution role boundary**: Gateway Lambda만 Bedrock 호출 가능.
3. **DynamoDB IAM boundary**: Lambda role에 최소 권한. RequestLedger는 PutItem만.
4. **Admin portal boundary**: backend-admin의 기존 인증으로 admin 역할 확인. inference 경로와 완전 분리.
5. **Inference path**: 사용자 → API Gateway (SigV4) → Lambda. backend-admin을 경유하지 않음.

## Principal Extraction and Normalization

### 추출 (모든 요청)
```
event.requestContext.identity:
  userArn    → 정규화 대상 (우선)
  caller     → fallback + 감사 필드
  accountId  → 감사 필드
  accessKey  → 감사 필드 (마스킹 저장)
```

### 정규화 규칙 (discovery 검증 후 확정)
예상 패턴:
- userArn: `arn:aws:sts::ACCOUNT:assumed-role/AWSReservedSSO_PermSet_HASH/username`
- 정규화: `arn:aws:iam::ACCOUNT:role/AWSReservedSSO_PermSet_HASH` (session name 제거)

**주의**: 이 패턴은 가정임. Task 3 discovery에서 실제 requestContext를 캡처하여 검증 필수.

### Discovery Gate 요건 (Task 3 완료 조건)
principal_id 정규화 규칙은 다음 두 환경 모두에서 실제 requestContext.identity를 캡처한 후에만 확정할 수 있다:
1. **랩탑 환경**: IAM Identity Center SSO 세션으로 SigV4 서명한 요청 1건 이상
2. **FSx 인터랙티브 환경**: IAM Identity Center SSO 세션으로 SigV4 서명한 요청 1건 이상

두 환경의 userArn, caller, accountId, accessKey 필드를 비교하여 정규화 규칙이 동일 사용자를 동일 principal_id로 매핑하는지 검증해야 한다. 한 환경만 캡처한 상태에서 정규화 규칙을 확정하는 것은 허용하지 않는다.

### 감사 보존
raw identity fields (userArn, caller, accountId, accessKey 마스킹)는 SessionMetadata에 그대로 저장. 정규화된 principal_id와 별도.

## Data Model (DynamoDB)

테이블 네이밍: `bedrock-gw-${env}-${region}-${table}`

### PrincipalPolicy
| Key | Type | Description |
|-----|------|-------------|
| principal_id (PK) | String | 정규화된 identity (discovery 후 확정) |
| display_name | String | 사용자 표시명 |
| allowed_models | List[String] | 허용된 Bedrock 모델 ID 목록 |
| daily_input_token_limit | Number | 일일 최대 인풋 토큰 수 |
| daily_output_token_limit | Number | 일일 최대 아웃풋 토큰 수 |
| is_admin | Boolean | 관리자 여부 |
| updated_at | String | ISO8601 |

### DailyUsage
| Key | Type | Description |
|-----|------|-------------|
| principal_id#date (PK) | String | 정규화 identity + UTC 날짜 |
| model_id (SK) | String | 모델 ID |
| input_tokens | Number | 당일 해당 모델 누적 인풋 토큰 |
| output_tokens | Number | 당일 해당 모델 누적 아웃풋 토큰 |
| request_count | Number | 당일 해당 모델 호출 횟수 (참고용) |
| ttl | Number | Unix timestamp (25시간 후 자동 삭제) |

> **쿼터 시행 방식**: PrincipalPolicy의 daily_input_token_limit / daily_output_token_limit은 Principal 글로벌 한도이다 (모델별 한도가 아님). 쿼터 비교 시 Gateway Lambda는 해당 principal_id#date의 모든 model_id SK에 대해 Query를 수행하고 input_tokens / output_tokens를 합산하여 글로벌 한도와 비교한다. DailyUsage 레코드 자체는 모델별로 기록하여 모델별 사용량 분석을 지원한다.

### TemporaryQuotaBoost
| Key | Type | Description |
|-----|------|-------------|
| principal_id (PK) | String | 정규화 identity |
| boost_id (SK) | String | UUID |
| boost_input_tokens | Number | 추가 인풋 토큰 |
| boost_output_tokens | Number | 추가 아웃풋 토큰 |
| expires_at | Number | Unix timestamp |
| approved_by | String | 승인 관리자 |
| ttl | Number | expires_at과 동일 |

### ApprovalRequest
| Key | Type | Description |
|-----|------|-------------|
| request_id (PK) | String | UUID |
| principal_id (GSI PK) | String | 요청자 정규화 identity |
| status (GSI SK) | String | pending / approved / denied |
| boost_input_tokens | Number | 요청 인풋 토큰 |
| boost_output_tokens | Number | 요청 아웃풋 토큰 |
| reason | String | 요청 사유 |
| reviewed_by | String | 승인/거부 관리자 |
| created_at | String | ISO8601 |

### RequestLedger
| Key | Type | Description |
|-----|------|-------------|
| request_id (PK) | String | UUID (idempotency key) |
| timestamp (SK) | String | ISO8601 |
| principal_id | String | 정규화 identity |
| model_id | String | 요청 모델 |
| decision | String | allow / deny |
| denial_reason | String | 거부 사유 (nullable) |
| input_tokens | Number | 이 요청의 인풋 토큰 |
| output_tokens | Number | 이 요청의 아웃풋 토큰 |
| duration_ms | Number | 처리 시간 |

### SessionMetadata
| Key | Type | Description |
|-----|------|-------------|
| request_id (PK) | String | UUID |
| raw_user_arn | String | 원본 userArn |
| raw_caller | String | 원본 caller |
| account_id | String | AWS account ID |
| access_key_masked | String | 마스킹된 access key (앞 4자리만) |
| source_ip | String | 요청 소스 IP |
| user_agent | String | 클라이언트 User-Agent |
| timestamp | String | ISO8601 |
| ttl | Number | 40일 후 자동 삭제 |

## Request Flow

### Inference Path (사용자 → Bedrock)
```
1. 사용자: IAM Identity Center SSO 인증 → temporary credentials 획득
2. 사용자: SigV4-signed HTTPS POST → API Gateway endpoint
3. API Gateway: SigV4 검증 (실패 → 403, Lambda 미도달)
4. API Gateway: access log + execution log → CloudWatch
5. Gateway Lambda:
   a. requestContext.identity에서 userArn, caller, accountId, accessKey 추출
   b. userArn → principal_id 정규화
   c. raw fields → SessionMetadata PutItem
   d. X-Request-Id로 RequestLedger 중복 확인 (hit → 이전 결과 반환)
   e. PrincipalPolicy 조회 (없음 → deny)
   f. model_id allowlist 확인 (불허 → deny)
   g. DailyUsage Query (principal_id#date의 모든 model_id SK) + TemporaryQuotaBoost 확인
   h. 전체 모델 합산 인풋/아웃풋 토큰을 글로벌 쿼터와 비교 (초과 → deny + 부스트 안내)
   i. Bedrock Converse API 호출
   j. 응답에서 usage.inputTokens, usage.outputTokens 추출
   k. DailyUsage 원자적 업데이트 (ADD)
   l. RequestLedger PutItem (immutable)
   m. 응답 반환 (사용 토큰 + 잔여 쿼터 포함)
6. 실패 시: 모든 단계에서 deny-by-default, CloudWatch 로깅
```

### Admin Path (관리자 → DynamoDB)
```
1. 관리자: account-portal 프론트엔드 로그인 (기존 JWT 인증)
2. 프론트엔드: backend-admin API 호출
3. backend-admin:
   - PrincipalPolicy CRUD
   - ApprovalRequest 승인/거부
   - TemporaryQuotaBoost 생성
   - DailyUsage/RequestLedger 조회
4. backend-admin → DynamoDB 직접 접근 (boto3)
5. 승인/거부 시 → SES 알림 발송
```

### Approval Path (사용자 → 관리자 → 부스트)
```
1. 사용자: 쿼터 초과 deny 응답 수신 (부스트 요청 안내 포함)
2. 사용자: POST /approval/request → Gateway Lambda
3. Gateway Lambda: ApprovalRequest PutItem (pending, principal당 1개 제한)
4. Gateway Lambda: SES → admin 그룹 알림
5. 관리자: Admin UI에서 ApprovalRequest 확인
6. 관리자: 승인 → backend-admin → TemporaryQuotaBoost 생성
   또는 거부 → backend-admin → status "denied" + SES 알림
7. 사용자: 다음 요청부터 부스트 쿼터 적용 (만료 시 자동 복귀)
```

## Quota Race Condition Analysis

### 문제
동시 요청 시 DailyUsage 조회 → Bedrock 호출 → 업데이트 사이에 race condition 발생 가능.

### v1 전략: post-call ADD, 최대 1회 초과 허용
```
요청 A: DailyUsage 조회 (900/1000) → 통과 → Bedrock 호출 (150 토큰)
요청 B: DailyUsage 조회 (900/1000) → 통과 → Bedrock 호출 (200 토큰)
결과: 1250/1000 (250 초과)
```

- DynamoDB ADD는 원자적이므로 카운터 자체는 정확
- 쿼터 확인은 Bedrock 호출 전에 수행하므로, 동시 요청 시 최대 1회 호출분 초과 가능
- v1에서 이 수준의 초과는 허용 (비용 영향 미미)
- 후속 요청은 업데이트된 카운터로 정확히 차단됨

### 대안 (v2 고려)
- DynamoDB ConditionExpression으로 pre-check + atomic increment 결합
- 단, Bedrock 호출 전에 토큰 수를 알 수 없으므로 예상치 기반 예약 필요
- 복잡도 대비 v1에서는 불필요

## Idempotency Strategy

### 메커니즘
- 클라이언트가 `X-Request-Id` 헤더로 UUID 전송
- 헤더 없으면 Lambda가 UUID 자동 생성
- RequestLedger에서 request_id로 GetItem
  - hit: 이전 결과 반환 (Bedrock 재호출 없음, 토큰 중복 카운팅 없음)
  - miss: 정상 처리 진행

### 제약
- RequestLedger PutItem은 Bedrock 호출 완료 후 수행
- Bedrock 호출 성공 → RequestLedger PutItem 실패 시: 응답은 반환하되 알람 트리거
- 이 경우 동일 request_id로 재시도하면 Bedrock 재호출 발생 (edge case, v1 허용)

### TTL
- RequestLedger에 TTL 없음 (감사 목적 영구 보존)
- SessionMetadata는 30일 TTL

## Approval Abuse Prevention

### Principal당 pending 1개 제한
ApprovalRequest 테이블은 request_id(PK) + principal_id(GSI PK) + status(GSI SK) 구조이다.
pending 1개 제한은 단순 PutItem ConditionExpression으로는 구현할 수 없다 (PK가 request_id이므로).

구현 방식:
```python
# Step 1: GSI로 해당 principal의 pending 요청 존재 여부 확인
response = table.query(
    IndexName="principal-status-index",
    KeyConditionExpression="principal_id = :pid AND #status = :pending",
    ExpressionAttributeNames={"#status": "status"},
    ExpressionAttributeValues={":pid": principal_id, ":pending": "pending"}
)
if response["Count"] > 0:
    return deny("이미 pending 상태의 ApprovalRequest가 존재합니다")

# Step 2: PutItem (race condition 가능하나 v1에서 허용 — 최악의 경우 pending 2개)
table.put_item(Item={...})
```
- GSI 조회 → PutItem 사이에 race condition이 존재하나, v1에서 pending 2개가 생기는 것은 허용 가능한 수준
- v2에서 DynamoDB Transactions 또는 별도 lock 테이블로 강화 가능

### Replay 방지
- ApprovalRequest의 request_id는 UUID (추측 불가)
- 승인/거부는 backend-admin의 admin 인증 경계 내에서만 수행
- 승인 시 TemporaryQuotaBoost에 expires_at 필수 (무기한 부스트 불가)
- TemporaryQuotaBoost TTL = expires_at (자동 만료)

### 남용 시나리오 대응
- 반복 요청: pending 1개 제한으로 차단
- 과도한 부스트 요청: admin이 거부하면 됨 (v1에서 자동 제한 불필요)
- 승인된 부스트 악용: expires_at으로 시한 제한, 부스트 토큰량은 admin이 결정

## Failure Modes

| Failure | Impact | Response | Recovery |
|---------|--------|----------|----------|
| DynamoDB PrincipalPolicy 조회 실패 | 정책 확인 불가 | deny | 자동 복구 (DynamoDB 일시적 오류) |
| DynamoDB DailyUsage 조회 실패 | 쿼터 확인 불가 | deny | 자동 복구 |
| Bedrock API 오류 | 모델 호출 실패 | 에러 반환 + 로깅 | Bedrock 서비스 복구 대기 |
| DailyUsage ADD 실패 (Bedrock 성공 후) | 카운터 누락 | 응답 반환 + CloudWatch 알람 | 운영자 수동 보정 |
| RequestLedger PutItem 실패 | 감사 로그 누락 | deny + CloudWatch 알람 | 운영자 확인 |
| SES 발송 실패 | 알림 미전달 | ApprovalRequest는 저장, 알림만 실패 | 운영자 수동 확인 |
| Lambda cold start | 지연 증가 | 정상 처리 (지연만) | Provisioned Concurrency (v2) |
| API Gateway throttling | 429 응답 | 클라이언트 재시도 | 스테이지 throttle 설정 조정 |

## Rollback Strategy

### Terraform 기반 롤백
- API Gateway + Lambda + DynamoDB가 Terraform state로 관리됨
- `terraform plan` / `terraform apply`로 이전 상태 복구 가능
- Lambda alias(`live`)로 즉시 이전 버전 전환 가능
- DynamoDB 테이블은 Terraform에서 `prevent_destroy` lifecycle로 보호

### DynamoDB 데이터
- PrincipalPolicy: 롤백 시 데이터 유지 (스키마 호환성 필수)
- DailyUsage: TTL로 자동 정리, 롤백 영향 없음
- RequestLedger: immutable, 롤백 영향 없음
- TemporaryQuotaBoost: TTL로 자동 만료

### 비상 차단
- API Gateway 스테이지 배포를 이전 버전으로 전환
- 또는 Lambda alias를 이전 버전으로 전환
- 최악의 경우: API Gateway 스테이지 삭제 (모든 요청 차단)

## Non-Disruptive Integration

### 원칙
Bedrock gateway는 기존 운영 스택과 분리된 서버리스 제어 평면으로 도입한다. 기존 인프라의 변경을 최소화하고, 불가피한 변경은 additive only로 제한한다.

### 기존 컴포넌트 영향 분석

| Component | Impact | Details |
|-----------|--------|---------|
| backend-cost | 없음 | 변경 불필요. 별도 승인 없는 한 수정 금지. |
| backend-admin | 최소 (additive) | admin-plane Blueprint 추가 (정책 CRUD, 승인, 사용량/감사 조회). inference 프록시 금지. IAM role에 DynamoDB + SES 권한 추가 필요 (별도 승인). |
| frontend | 최소 (additive) | 관리자/사용자 페이지 추가. 기존 페이지 수정 없음. |
| nginx | 없음 | Bedrock gateway는 별도 API Gateway 엔드포인트 사용. nginx 설정 변경 불필요. |
| docker-compose | 없음~최소 | 구조 변경 없음. frontend/backend-admin 이미지 재빌드만 발생 (UI/admin 통합 시). |
| VPC/SG/EC2 | 없음 | 서버리스 아키텍처이므로 기존 네트워크 인프라 변경 불필요. |
| FSx 사용자 환경 | 별도 승인 게이트 | per-user ~/.aws/config, SSO bootstrap, shell init 설정은 gateway 구현 승인과 독립적으로 승인 필요. |

### FSx Per-User Credential Setup (별도 승인 게이트)

**후보 모델: IAM Identity Center Permission-Set-Based Named Profiles**

별도 per-user IAM role 생성 대신, IAM Identity Center permission set 기반 named profile을 사용한다. 이유:
- IAM Identity Center가 이미 per-user session을 관리하므로 별도 IAM role 불필요
- permission set 하나로 모든 gateway 사용자에게 `execute-api:Invoke` 권한 부여
- 사용자별 차등 접근(모델 allowlist, 쿼터)은 gateway Lambda의 PrincipalPolicy에서 처리

**API Gateway에 나타나는 identity:**
```
userArn: arn:aws:sts::<ACCOUNT>:assumed-role/AWSReservedSSO_<PermSetName>_<HASH>/<username>
caller:  <RoleId>:<username>
```
- session name = IAM Identity Center SSO username (사용자 변경 불가)
- 동일 사용자가 동일 permission set으로 랩탑/FSx에서 로그인 → 동일 role ARN + 동일 session name → 동일 principal_id

**Named profile이 [default]보다 선호되는 이유:**
- 명시적 의도: `--profile bedrock-gw`로 gateway 호출임을 명시
- 다중 계정/역할 공존: 기존 워크플로우의 default profile을 덮어쓰지 않음
- 최소 권한: gateway용 permission set은 `execute-api:Invoke`만 필요
- 감사 명확성: shell history에서 profile 추적 가능

**예상 ~/.aws/config 구조:**
```ini
[sso-session bedrock-gw-sso]
sso_start_url = https://<org>.awsapps.com/start
sso_region = <identity-center-region>
sso_registration_scopes = sso:account:access

[profile bedrock-gw]
sso_session = bedrock-gw-sso
sso_account_id = <ACCOUNT_ID>
sso_role_name = <BedrockGatewayUser_PermissionSetName>
region = <bedrock-region>
output = json
```

**공유 FSx 안전성 전제 조건:**
- 홈 디렉토리 권한: `700` (rwx------) 필수
- `.aws/` 디렉토리 권한: `700` 필수
- `.aws/sso/cache/` 내 토큰 파일: `600` 필수
- 각 사용자 홈 디렉토리 소유자 = 해당 사용자 UID
- 권한 미충족 시 SSO access token 노출 → 다른 사용자로 API 호출 가능

**잔여 리스크:**
- root/sudo 사용자의 타 사용자 credential 접근 (shared host 본질적 한계)
- 홈 디렉토리 권한 drift (정기 감사로 완화)
- SSO token 유효 기간 내 탈취 (session duration 최소화로 완화)

**승인 게이트 후 필요한 설정 단계:**
1. (IAM Identity Center 관리자) Gateway 사용자용 permission set 생성 + 사용자/그룹 할당
2. (FSx — 별도 승인) per-user `~/.aws/config`에 named profile + sso-session 추가
3. (FSx — 별도 승인) 홈 디렉토리/`.aws/` 권한 700 강제
4. (사용자) `aws sso login --profile bedrock-gw` 실행 (브라우저 인증)
5. (검증) `aws sts get-caller-identity --profile bedrock-gw`로 assumed-role ARN 확인

이 설정은 설계/계획 단계에서 기술할 수 있으나, 실행은 명시적 승인 후에만 허용된다. Gateway 구현이 승인되더라도 FSx credential 설정은 별도로 차단 상태를 유지한다.

## Operational Ownership

| Component | Owner | Responsibility |
|-----------|-------|---------------|
| API Gateway + Lambda | DevOps/Platform | 배포, 모니터링, 스케일링, 롤백 |
| DynamoDB 테이블 | DevOps/Platform | 용량 관리, 백업, TTL 확인 |
| PrincipalPolicy 관리 | Platform Admin | 사용자 정책 CRUD (Admin UI) |
| ApprovalRequest 처리 | Platform Admin | 승인/거부 (Admin UI) |
| SES 설정 | DevOps/Platform | verified sender, admin alias 관리 |
| IAM deny / SCP | Security/DevOps | Bedrock 직접 차단 정책 관리 |
| 클라이언트 가이드 | Platform | SigV4 호출 방법 문서화 |
| CloudWatch 알람 대응 | DevOps/Platform | 알람 트리거 시 수동 보정 |

## Frontend Integration

### Admin Pages (account-portal frontend)
- `BedrockPolicyAdmin`: PrincipalPolicy CRUD (사용자별 모델 허용, 토큰 쿼터 설정)
- `BedrockApprovalAdmin`: ApprovalRequest 목록, 승인/거부, TemporaryQuotaBoost 생성
- `BedrockUsageDashboard`: 전체/사용자별 DailyUsage 조회
- `BedrockLedger`: RequestLedger 감사 로그 조회

### User Page (account-portal frontend)
- `BedrockMyUsage`: 본인 사용량, 잔여 쿼터, 허용 모델, 부스트 요청

### API 경로 (backend-admin)
```
GET    /api/gateway/policies              → 전체 PrincipalPolicy 목록
POST   /api/gateway/policies              → PrincipalPolicy 생성
PUT    /api/gateway/policies/:principal_id → PrincipalPolicy 수정
DELETE /api/gateway/policies/:principal_id → PrincipalPolicy 삭제
GET    /api/gateway/approvals             → ApprovalRequest 목록
PUT    /api/gateway/approvals/:request_id → 승인/거부
GET    /api/gateway/usage                 → DailyUsage 조회
GET    /api/gateway/usage/:principal_id   → 사용자별 DailyUsage
GET    /api/gateway/ledger                → RequestLedger 조회
```

## IAM Roles Summary

### Gateway Lambda Execution Role
```
Allow:
  - bedrock:Converse (지정 모델) — v1 유일 Bedrock API. InvokeModel/ConverseStream은 v2에서 추가
  - dynamodb:GetItem, PutItem, UpdateItem, Query (gateway 테이블 6개)
  - logs:CreateLogGroup, CreateLogStream, PutLogEvents
  - ses:SendEmail (verified sender)
Deny:
  - dynamodb:DeleteItem on RequestLedger (불변성 보장)
```

### backend-admin Container Role (확장)
```
기존 권한 + 추가:
  - dynamodb:GetItem, PutItem, UpdateItem, DeleteItem, Query, Scan (gateway 테이블)
  - ses:SendEmail (verified sender)
```

### Human Roles (Bedrock 차단)
```
임시 (IAM deny):
  Deny: bedrock:Converse, bedrock:ConverseStream,
        bedrock:InvokeModel, bedrock:InvokeModelWithResponseStream
  Condition: 해당 permission set / role에 적용

목표 (SCP):
  Deny: bedrock:* (Gateway Lambda role ARN 제외)
  Condition: StringNotEquals aws:PrincipalArn = Gateway Lambda role ARN
```

## Direct Bedrock Access Control

### 임시 전략 (IAM Deny)
- human access role / permission set에 Bedrock API deny policy 부착
- 대상 actions: `bedrock:Converse`, `bedrock:ConverseStream`, `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`
- Gateway Lambda execution role은 제외 (별도 role이므로 영향 없음)
- 적용 범위: 계정 수준

### 목표 전략 (SCP)
- Organization SCP로 Bedrock API deny
- Condition: `StringNotEquals aws:PrincipalArn` = Gateway Lambda execution role ARN
- 적용 범위: 조직 수준 (모든 계정)
- SCP 적용 가능 시점에 IAM deny에서 전환

### 전환 계획
1. v1 배포 시: IAM deny 적용
2. SCP 적용 승인 획득 후: SCP 배포 + IAM deny 제거
3. 검증: Bedrock 직접 호출 차단 확인 (human role로 테스트)

## Observability v1 Audit Path

### 3-layer 감사 경로
```
Layer 1: API Gateway Logs
  - access log: 요청 메타데이터 (IP, method, path, status, latency)
  - execution log: 통합 요청/응답 상세

Layer 2: Lambda Structured Logs (CloudWatch)
  - JSON 형식: request_id, principal_id, model_id, decision, tokens, duration
  - deny 사유 포함
  - 쿼터 초과 시 CloudWatch 메트릭 emit

Layer 3: Bedrock Invocation Logs
  - Bedrock 서비스 자체 로깅 (모델 호출 상세)
  - CloudWatch Logs 또는 S3로 전달
```

### CloudTrail과의 관계
- CloudTrail은 API Gateway/Lambda/DynamoDB API 호출을 자동 기록
- 그러나 v1 감사 경로는 CloudTrail에 의존하지 않음
- 위 3-layer가 primary audit path
- CloudTrail은 보조/보안 감사용

### v1 CloudWatch 알람
- RequestLedger PutItem 실패 → 알람
- DailyUsage ADD 실패 (Bedrock 성공 후) → 알람
- Lambda 에러율 > 임계값 → 알람
- 쿼터 초과 빈도 메트릭 (참고용, 알람 선택적)
