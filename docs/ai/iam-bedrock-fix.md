# IAM Bedrock Permission Fix — Operator Runbook

> Created: 2026-03-19. **APPLIED (2026-03-19).**
> `terraform apply` complete. IAM policy verified. State clean (no drift).
> Scope: `infra/bedrock-gateway/iam.tf` — `aws_iam_role_policy.bedrock` only
> Blast radius: 1 IAM inline policy on Lambda execution role. No other resources affected.

## Problem

Smoke test (2026-03-18) reached Bedrock but failed:
```
AccessDeniedException: User: arn:aws:sts::<ACCOUNT_ID>:assumed-role/bedrock-gw-dev-lambda-exec/bedrock-gw-dev-gateway
is not authorized to perform: bedrock:InvokeModel on resource: arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-3-haiku-20240307-v1:0
```

## Root Cause

`iam.tf` granted `bedrock:Converse` — this is NOT a valid IAM action.
AWS maps the Converse API to `bedrock:InvokeModel` at the IAM level.
Similarly, ConverseStream maps to `bedrock:InvokeModelWithResponseStream`.

Source: [AWS Bedrock Converse API Reference](https://docs.aws.amazon.com/goto/WebAPI/bedrock-runtime-2023-09-30/Converse) — "This operation requires permission for the bedrock:InvokeModel action."

## Fix Applied (IaC)

`infra/bedrock-gateway/iam.tf` — `aws_iam_role_policy.bedrock`:

Before:
```hcl
Action = ["bedrock:Converse"]
Sid    = "BedrockConverseOnly"
```

After:
```hcl
Action = [
  "bedrock:InvokeModel",
  "bedrock:InvokeModelWithResponseStream",
]
Sid = "BedrockInference"
```

- `bedrock:InvokeModel` — fixes current failure (Converse API)
- `bedrock:InvokeModelWithResponseStream` — v2 streaming readiness (ConverseStream)
- `bedrock:Converse` removed — not a valid IAM action, was a no-op

## Operator Commands

### Step 1: Review plan
```bash
cd infra/bedrock-gateway
terraform workspace select dev
terraform plan -var-file=env/dev.tfvars
```

Expected plan output:
```
~ aws_iam_role_policy.bedrock (update in-place)
    ~ policy: ... "bedrock:Converse" → "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream" ...
```

Red flags — STOP if plan shows ANY of:
- Any `destroy` action
- Any change to `aws_lambda_function.gateway`
- Any change to `aws_api_gateway_*` resources
- Any change to DynamoDB tables
- More than 1 resource changed

### Step 2: Apply
```bash
terraform apply -var-file=env/dev.tfvars
```

### Step 3: Verify IAM policy updated
```bash
aws iam get-role-policy \
  --role-name bedrock-gw-dev-lambda-exec \
  --policy-name bedrock-gw-dev-bedrock \
  --region us-west-2 \
  | python3 -c "
import sys, json
doc = json.load(sys.stdin)['PolicyDocument']
actions = doc['Statement'][0]['Action']
print('Actions:', actions)
assert 'bedrock:InvokeModel' in actions, 'MISSING bedrock:InvokeModel'
assert 'bedrock:InvokeModelWithResponseStream' in actions, 'MISSING bedrock:InvokeModelWithResponseStream'
assert 'bedrock:Converse' not in actions, 'STALE bedrock:Converse still present'
print('PASS: IAM policy correct')
"
```

### Step 4: Re-run smoke test
```bash
# From FSx or laptop with BedrockUser-admin credentials:
python3 docs/ai/phase2-smoke-test.py
```

Expected: Bedrock Converse response (no more AccessDeniedException).

### Step 5: Confirm terraform state clean
```bash
terraform plan -var-file=env/dev.tfvars
# Expected: "No changes. Your infrastructure matches the configuration."
```

## Rollback

```bash
cd infra/bedrock-gateway
git checkout iam.tf
terraform apply -var-file=env/dev.tfvars
```

This reverts to `bedrock:Converse` only — smoke test will fail again, but no other impact.

## Post-Fix

After successful smoke test, proceed with C5-C9 verification per `docs/ai/phase2-post-deploy-verification.md`.
