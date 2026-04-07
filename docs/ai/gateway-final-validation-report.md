# Bedrock Gateway — 최종 검증 보고서

> Date: 2026-04-07
> Status: 구현 + 배포 + live 검증 완료

---

## 결과 상태: `/converse` 기본 진입점 통일 완료 / `/converse-jobs` 하위호환 유지 완료 / 포털 UI 전환 완료

---

## 1. Executive Summary

Lambda handler에 `_should_route_async()` 추가하여 모델 종류 무관하게 장시간 위험 요청을 자동 async 전환. Client wrapper에 202 자동 poll/fetch 추가. `DenyDirectBedrockInference`에 InvokeAgent/InvokeInlineAgent/InvokeFlow 추가하여 bypass 차단 (InvokeTool만 허용). `AllowDevGatewayConverseJobs`에 `POST/converse-jobs` (root path) 추가하여 explicit async submit 403 해결. 포털 버튼 backend에 전체 정책 세트 적용 + fail-closed 로직 추가.

## 2. 변경 파일

| 파일 | 변경 |
|------|------|
| `infra/bedrock-gateway/lambda/handler.py` | `_should_route_async()` 추가, `LONGRUN_MODELS` 체크를 일반화, 임계값: maxTokens>=16384, input>200KB |
| `account-portal/backend-admin/data/bedrock_gw.py` | `_poll_and_fetch()` 공통 함수 추출, `_short_path_converse()` 202 처리 추가, `_GatewayClient.converse()` 202 처리 추가 |
| `account-portal/backend-admin/routes/gateway_teams.py` | `_DENY_DIRECT_POLICY` InvokeAgent/InvokeInlineAgent/InvokeFlow 추가, `_BEDROCK_ACCESS_POLICY` InvokeAgent 제거 InvokeTool 유지, `AllowDevGatewayConverseJobs` POST/converse-jobs root 추가, `set_direct_access()` 전체 정책 세트 적용 + fail-closed |

## 3. 배포 증거

| Component | Action | Result |
|-----------|--------|--------|
| Lambda bedrock-gw-dev-gateway | Code update + publish version 1 + alias live | Deployed |
| backend-admin container | Docker rebuild + restart | Up (healthy) |
| IAM BedrockUser-user05 | DenyDirectBedrockInference + BedrockAccess + AllowDevGatewayConverseJobs updated | Applied |
| IAM BedrockUser-admin | Same policies updated | Applied |
| Trust policy cleanup | Root removed from BedrockUser-user05 | Cleaned |

## 4. Effective Permission Matrix (user05 = admin, managed state)

| Action | Result | Source |
|--------|--------|--------|
| bedrock:InvokeModel | explicitDeny | DenyDirectBedrockInference |
| bedrock:InvokeModelWithResponseStream | explicitDeny | DenyDirectBedrockInference |
| bedrock:Converse | explicitDeny | DenyDirectBedrockInference |
| bedrock:ConverseStream | explicitDeny | DenyDirectBedrockInference |
| bedrock:InvokeAgent | explicitDeny | DenyDirectBedrockInference |
| bedrock:InvokeInlineAgent | explicitDeny | DenyDirectBedrockInference |
| bedrock:InvokeFlow | explicitDeny | DenyDirectBedrockInference |
| bedrock:InvokeTool | allowed | BedrockAccess |
| bedrock:Retrieve | implicitDeny | no allow policy |
| bedrock:RetrieveAndGenerate | implicitDeny | no allow policy |
| bedrock:ListFoundationModels | allowed | BedrockAccess (read-only) |
| ecs:RunTask | explicitDeny | DenyDirectECSAndSFN |
| ecs:ExecuteCommand | explicitDeny | DenyDirectECSAndSFN |
| states:StartExecution | explicitDeny | DenyDirectECSAndSFN |
| execute-api POST /converse | allowed | AllowDevGatewayConverse |
| execute-api POST /converse-jobs | allowed | AllowDevGatewayConverseJobs |
| execute-api GET /converse-jobs/* | allowed | AllowDevGatewayConverseJobs |
| execute-api POST /converse-jobs/*/cancel | allowed | AllowDevGatewayConverseJobs |

## 5. Long-run Detection Coverage

| Condition | Trigger | Async? |
|-----------|---------|--------|
| model in LONGRUN_MODELS (Opus variants) | always | yes |
| maxTokens >= 16384 | any model | yes |
| input messages+system JSON > 200KB | any model | yes |
| Sonnet small request (maxTokens < 16384, input < 200KB) | — | no (sync 200) |
| DeepSeek/Nova with maxTokens >= 16384 | maxTokens threshold | yes |
| pptx_gen ~120s Sonnet | maxTokens typically large | yes |

## 6. Live Validation Proof (BedrockUser-user05, actual Bedrock)

| Case | Endpoint | Status | Result | Cost KRW | Tokens |
|------|----------|--------|--------|----------|--------|
| A: Short Sonnet | POST /converse | 200 | PASS | 0.3654 | 14/14 |
| B: Opus hidden async | POST /converse → 202 | poll SUCCEEDED | PASS | 0.34075 | 17/6 |
| B2: Sonnet maxTokens=16384 | POST /converse → 202 | poll SUCCEEDED | PASS | 0.82215 | 14/35 |
| C: Explicit /converse-jobs | POST /converse-jobs → 202 | poll SUCCEEDED | PASS | 0.34365 | — |
| D: Cancel | POST /converse-jobs → cancel | 200 CANCELED | PASS | — | — |

## 7. Aggregate Accounting (this session's 4 completed jobs)

| Source | Total Cost KRW | Jobs |
|--------|---------------|------|
| Test A (sync) | 0.3654 | 1 |
| Test B (Opus async) | 0.34075 | 1 |
| Test B2 (Sonnet async) | 0.82215 | 1 |
| Test C (explicit async) | 0.34365 | 1 |
| Test D (canceled) | 0 | 1 |
| Total | 1.87195 | 5 |

## 8. User Contract Validation

| Question | Answer |
|----------|--------|
| User-facing endpoint changed? | no |
| User must call /converse-jobs directly? | no |
| Existing /converse-jobs clients still work? | yes (Test C) |
| Direct boto3 still required for normal use? | no |
| 29s API GW timeout exposed to user? | no |
| Wrapper handles 202 internally? | yes |

## 9. Backward Compatibility

| Path | Status |
|------|--------|
| POST /converse-jobs submit | PASS (Test C) |
| GET /converse-jobs/{jobId} poll | PASS (Tests B, B2, C) |
| POST /converse-jobs/{jobId}/cancel | PASS (Test D) |
| Hidden async + explicit async coexistence | PASS |
| Semantics preserved | yes |

## 10. user05 Final State

| Item | Value |
|------|-------|
| gateway_managed | true |
| direct_access_exception | false |
| DenyDirectBedrockInference | present (7 actions denied) |
| DenyDirectECSAndSFN | present |
| InvokeTool | allowed |
| execute-api bundle | complete (converse + converse-jobs + poll + cancel) |
| Trust policy | cleaned (root removed) |
| Policy parity with admin | yes (SESAccess excluded from comparison per instructions) |
