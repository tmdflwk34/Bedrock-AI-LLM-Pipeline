# Bedrock Gateway v2 Spec

## Date: 2026-03-31

## 배경

v1은 Converse API(non-streaming)만 지원. 실제 사용자(user05)가 InvokeTool(websearch/grounding)을 사용 중이며, 향후 ConverseStream, InvokeAgent도 필요. 모든 Bedrock 호출이 gateway를 통해 quota enforcement + cost tracking 되어야 함.

## v2 추가 지원 범위

| API | IAM Action | 토큰 수집 | v2 판정 |
|-----|-----------|----------|---------|
| Converse | bedrock:InvokeModel | 정확 (usage 필드) | v1 유지 |
| ConverseStream | bedrock:InvokeModelWithResponseStream | 정확 (마지막 chunk metadata.usage) | v2 추가 |
| InvokeTool | bedrock:InvokeTool | 불가 (토큰 기반 아님, tool별 과금) | scope 밖 |
| InvokeAgent | bedrock:InvokeAgent | 불가 (multi-turn, 토큰 집계 불명확) | scope 밖 |
| InvokeModel (raw) | bedrock:InvokeModel | 불안정 (모델별 응답 구조 상이) | scope 밖 |

v2 = Converse + ConverseStream만. 실시간 토큰 기반 정확한 비용 제어가 가능한 API만 gateway scope에 포함.

InvokeTool/InvokeAgent/InvokeModel(raw)을 쓰는 사용자는 direct-access 예외로 관리하고 CloudWatch Logs로 사후 모니터링.

## 구현 계획

### 1. Lambda handler 확장

현재 handler.py의 라우팅:
- `POST /converse` → Converse API
- `POST /approval/request` → 승인 요청
- `GET /quota/status` → 한도 조회

v2 추가 라우트:
- `POST /converse-stream` → ConverseStream (Lambda response streaming 또는 chunked)
- `POST /invoke-tool` → InvokeTool (websearch/grounding)
- `POST /invoke-agent` → InvokeAgent
- `POST /invoke-model` → InvokeModel (raw, non-Converse)

### 2. 비용 산정 방식

| API | 과금 단위 | 비용 추적 방법 |
|-----|----------|---------------|
| Converse | input/output tokens | 현행 유지 (estimate_cost_krw) |
| ConverseStream | input/output tokens | 스트림 완료 후 usage 집계 |
| InvokeTool | 요청당 + 결과 토큰 | tool별 pricing 필요 |
| InvokeAgent | session 기반 | agent 호출 비용 별도 정의 |
| InvokeModel | input/output tokens | Converse와 동일 |

### 3. ConverseStream 구현 방안

옵션 A: Lambda response streaming (Lambda URL + RESPONSE_STREAM)
- API Gateway REST API는 streaming 미지원
- Lambda Function URL을 별도로 노출하고 IAM auth 적용
- 장점: 진짜 스트리밍
- 단점: API Gateway 밖의 별도 endpoint

옵션 B: Lambda에서 전체 스트림을 버퍼링 후 일괄 반환
- 기존 API Gateway REST API 구조 유지
- 장점: 인프라 변경 최소
- 단점: 스트리밍 아님 (latency 증가)

옵션 C: API Gateway HTTP API + Lambda streaming
- REST API → HTTP API 전환
- HTTP API는 Lambda response streaming 지원
- 장점: 진짜 스트리밍 + API Gateway 유지
- 단점: REST API에서 HTTP API로 마이그레이션 필요

권장: 옵션 C (HTTP API 전환) 또는 옵션 A (Function URL 병행)

### 4. InvokeTool 구현

```
POST /invoke-tool
{
  "toolName": "amazon.nova_grounding",
  "input": { ... }
}
```

Lambda가 `bedrock-runtime.invoke_tool()` 호출 → 결과 반환.
비용: Nova Grounding은 요청당 과금 ($0.01/request 등) — pricing table에 tool별 항목 추가.

### 5. Lambda IAM 변경

```hcl
Action = [
  "bedrock:InvokeModel",
  "bedrock:InvokeModelWithResponseStream",
  "bedrock:InvokeTool",      # 추가
  "bedrock:InvokeAgent",     # 추가
]
Resource = ["*"]
```

### 6. API Gateway 라우트 추가

기존 proxy resource (`{proxy+}`)가 모든 경로를 Lambda로 전달하므로 API Gateway 변경 불필요. Lambda handler에서 path 기반 라우팅만 추가하면 됨.

### 7. Terraform 변경

- Lambda IAM policy에 InvokeTool, InvokeAgent 추가
- (옵션 C 선택 시) HTTP API 리소스 추가
- pricing table에 tool 과금 항목 추가

## 우선순위

1. InvokeTool — user05가 지금 필요 (websearch)
2. ConverseStream — 대부분의 사용자가 원할 기능
3. InvokeAgent — 향후 agent 기반 워크플로우
4. InvokeModel (raw) — 특수 케이스

## 일정 제안

- Phase 1: InvokeTool 지원 (1-2일)
- Phase 2: ConverseStream 지원 (3-5일, 인프라 결정 포함)
- Phase 3: InvokeAgent 지원 (2-3일)

## 리스크

- ConverseStream은 API Gateway REST API에서 직접 지원 불가 → 인프라 결정 필요
- InvokeTool 비용 산정은 토큰 기반이 아니므로 pricing model 확장 필요
- InvokeAgent는 multi-turn session이므로 quota 산정 방식 재정의 필요
