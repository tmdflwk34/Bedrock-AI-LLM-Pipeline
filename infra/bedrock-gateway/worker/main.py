"""
Bedrock Gateway — Fargate Worker (v2 async long-running path).

Reads job parameters from environment variables, calls Bedrock Converse,
handles retry/backoff, writes usage/cost/result to DynamoDB/S3.

Environment variables (set by Step Functions RunTask override):
  JOB_ID, REQUEST_ID, PRINCIPAL_ID, MODEL_ID, REGION, PRICING_VERSION, PAYLOAD_REF
  TABLE_JOB_STATE, TABLE_MONTHLY_USAGE, TABLE_MODEL_PRICING, TABLE_REQUEST_LEDGER
  PAYLOAD_BUCKET, TABLE_CONCURRENCY_SEMAPHORE
"""
import json, os, sys, time, uuid, logging
from datetime import datetime, timezone, timedelta
from decimal import Decimal

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# KST timezone
KST = timezone(timedelta(hours=9))

# Disable SDK retry — we handle retries ourselves
BEDROCK_CONFIG = Config(
    retries={"max_attempts": 0},
    read_timeout=1800,  # 30 min read timeout
    connect_timeout=10,
)

# Retry config
MAX_RETRIES = 3
BASE_DELAY = 1.0
MAX_DELAY = 60.0
RETRYABLE_ERRORS = {'ThrottlingException', 'InternalServerException',
                    'ServiceUnavailableException', 'ServiceException'}

MAX_CONCURRENT_JOBS = 5


def log_structured(level, message, **kwargs):
    entry = {"level": level, "message": message, "timestamp": datetime.now(timezone.utc).isoformat()}
    entry.update(kwargs)
    print(json.dumps(entry, default=str))


def current_month_kst():
    return datetime.now(KST).strftime('%Y-%m')


def is_retryable(error):
    error_code = getattr(error, 'response', {}).get('Error', {}).get('Code', '')
    return error_code in RETRYABLE_ERRORS


def backoff_delay(attempt):
    import random
    delay = min(BASE_DELAY * (2 ** attempt), MAX_DELAY)
    return random.uniform(0, delay)


def _release_semaphore_slot(dynamodb, table_name, job_id):
    """Release the semaphore slot held by this job."""
    if not table_name:
        return
    sem_table = dynamodb.Table(table_name)
    for i in range(MAX_CONCURRENT_JOBS):
        slot_id = f"slot-{i}"
        try:
            sem_table.update_item(
                Key={"slot_id": slot_id},
                UpdateExpression="SET job_id = :empty",
                ConditionExpression="job_id = :jid",
                ExpressionAttributeValues={":empty": "", ":jid": job_id},
            )
            log_structured("info", "semaphore_released", slot_id=slot_id, job_id=job_id)
            return
        except Exception:
            continue
    log_structured("warning", "semaphore_release_no_slot_found", job_id=job_id)


def main():
    # Read environment
    job_id = os.environ.get('JOB_ID', '')
    request_id = os.environ.get('REQUEST_ID', '')
    principal_id = os.environ.get('PRINCIPAL_ID', '')
    model_id = os.environ.get('MODEL_ID', '')
    region = os.environ.get('REGION', 'us-west-2')
    pricing_version = os.environ.get('PRICING_VERSION', '')
    payload_ref = os.environ.get('PAYLOAD_REF', '')

    table_job_state = os.environ.get('TABLE_JOB_STATE', '')
    table_monthly_usage = os.environ.get('TABLE_MONTHLY_USAGE', '')
    table_model_pricing = os.environ.get('TABLE_MODEL_PRICING', '')
    table_request_ledger = os.environ.get('TABLE_REQUEST_LEDGER', '')
    payload_bucket = os.environ.get('PAYLOAD_BUCKET', '')
    table_concurrency_semaphore = os.environ.get('TABLE_CONCURRENCY_SEMAPHORE', '')

    if not all([job_id, principal_id, model_id]):
        log_structured("error", "missing_required_env", job_id=job_id, principal_id=principal_id, model_id=model_id)
        sys.exit(1)

    dynamodb = boto3.resource('dynamodb', region_name=region)
    bedrock = boto3.client('bedrock-runtime', region_name=region, config=BEDROCK_CONFIG)
    s3 = boto3.client('s3', region_name=region)

    job_table = dynamodb.Table(table_job_state)
    usage_table = dynamodb.Table(table_monthly_usage)
    pricing_table = dynamodb.Table(table_model_pricing)
    ledger_table = dynamodb.Table(table_request_ledger)

    start_time = time.time()
    retry_count = 0

    log_structured("info", "worker_started", job_id=job_id, model_id=model_id, principal_id=principal_id)

    try:
        # Update job state → RUNNING
        job_table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :status, updated_at = :ts",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "RUNNING", ":ts": datetime.now(timezone.utc).isoformat()},
        )

        # Ledger: TASK_STARTED
        ledger_table.put_item(Item={
            "request_id": f"{request_id}#TASK_STARTED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_id": principal_id, "model_id": model_id,
            "event_type": "TASK_STARTED", "job_id": job_id,
            "decision": "ALLOW", "source_path": "gateway-async",
        })

        # Read input payload
        if payload_ref.startswith("s3://"):
            s3_key = payload_ref.replace(f"s3://{payload_bucket}/", "")
            resp = s3.get_object(Bucket=payload_bucket, Key=s3_key)
            converse_params = json.loads(resp['Body'].read().decode())
        else:
            # Inline payload stored in job record
            job_resp = job_table.get_item(Key={"job_id": job_id})
            converse_params = json.loads(job_resp.get('Item', {}).get('inline_payload', '{}'))

        # Ensure modelId is set
        converse_params['modelId'] = model_id

        # Call Bedrock with retry
        bedrock_response = None
        last_error = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                log_structured("info", "bedrock_invoke_attempt", job_id=job_id, attempt=attempt, model_id=model_id)

                # Ledger: BEDROCK_INVOKED
                ledger_table.put_item(Item={
                    "request_id": f"{request_id}#BEDROCK_INVOKED#{attempt}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "principal_id": principal_id, "model_id": model_id,
                    "event_type": "BEDROCK_INVOKED" if attempt == 0 else "RETRY_ATTEMPT",
                    "job_id": job_id, "decision": "ALLOW",
                    "source_path": "gateway-async", "retry_count": attempt,
                })

                bedrock_response = bedrock.converse(**{k: v for k, v in converse_params.items()
                                                       if k in ('modelId', 'messages', 'system', 'inferenceConfig', 'toolConfig')})
                break  # Success

            except ClientError as e:
                last_error = e
                if is_retryable(e) and attempt < MAX_RETRIES:
                    delay = backoff_delay(attempt)
                    log_structured("warning", "bedrock_retryable_error",
                                   job_id=job_id, attempt=attempt, error=str(e), delay=delay)
                    retry_count = attempt + 1
                    time.sleep(delay)
                else:
                    raise

        if bedrock_response is None:
            raise last_error or Exception("bedrock invocation failed with no response")

        # Extract usage — fail-closed: if usage is missing, do not write zero accounting
        usage = bedrock_response.get('usage')
        if not usage or 'inputTokens' not in usage or 'outputTokens' not in usage:
            raise ValueError(f"Bedrock response missing usage field for job {job_id}. "
                             "Cannot write settled accounting without actual token counts.")
        input_tokens = usage['inputTokens']
        output_tokens = usage['outputTokens']
        stop_reason = bedrock_response.get('stopReason', '')

        # Lookup pricing — fail-closed: if pricing is missing, do not write zero cost
        pricing_resp = pricing_table.get_item(Key={"model_id": model_id})
        pricing = pricing_resp.get('Item')
        if not pricing or 'input_price_per_1k' not in pricing or 'output_price_per_1k' not in pricing:
            raise ValueError(f"No pricing found for model {model_id}. "
                             "Cannot write settled accounting without pricing data.")
        input_price = Decimal(str(pricing['input_price_per_1k']))
        output_price = Decimal(str(pricing['output_price_per_1k']))
        actual_cost = (Decimal(input_tokens) * input_price / 1000) + (Decimal(output_tokens) * output_price / 1000)

        # Settlement: remove reservation, add actual cost
        month = current_month_kst()
        pk = f"{principal_id}#{month}"

        # Delete reservation
        try:
            usage_table.delete_item(Key={"principal_id_month": pk, "model_id": f"__reserved__{job_id}"})
        except Exception as e:
            log_structured("error", "reservation_delete_failed", job_id=job_id, error=str(e))

        # Add actual usage
        ttl_val = int(time.time()) + 35 * 24 * 3600
        usage_table.update_item(
            Key={"principal_id_month": pk, "model_id": model_id},
            UpdateExpression="ADD cost_krw :c, input_tokens :i, output_tokens :o SET #t = :ttl",
            ExpressionAttributeNames={"#t": "ttl"},
            ExpressionAttributeValues={
                ":c": actual_cost, ":i": input_tokens, ":o": output_tokens, ":ttl": ttl_val,
            },
        )

        # Write result to S3
        result_data = {
            "output": bedrock_response.get('output', {}),
            "usage": {"inputTokens": input_tokens, "outputTokens": output_tokens},
            "stopReason": stop_reason,
        }
        result_key = f"results/{job_id}.json"
        s3.put_object(Bucket=payload_bucket, Key=result_key, Body=json.dumps(result_data, default=str),
                      ContentType='application/json')

        duration_s = int(time.time() - start_time)

        # Update job state → SUCCEEDED
        job_table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :status, settled_cost_krw = :cost, "
                             "input_tokens = :inp, output_tokens = :out, "
                             "result_ref = :ref, retry_count = :rc, "
                             "completed_at = :ts, updated_at = :ts, "
                             "stop_reason = :sr",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "SUCCEEDED", ":cost": actual_cost,
                ":inp": input_tokens, ":out": output_tokens,
                ":ref": f"s3://{payload_bucket}/{result_key}",
                ":rc": retry_count,
                ":ts": datetime.now(timezone.utc).isoformat(),
                ":sr": stop_reason,
            },
        )

        # Ledger: TASK_COMPLETED
        ledger_table.put_item(Item={
            "request_id": f"{request_id}#TASK_COMPLETED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_id": principal_id, "model_id": model_id,
            "event_type": "TASK_COMPLETED", "job_id": job_id,
            "decision": "ALLOW", "source_path": "gateway-async",
            "input_tokens": input_tokens, "output_tokens": output_tokens,
            "estimated_cost_krw": actual_cost, "duration_ms": duration_s * 1000,
            "retry_count": retry_count, "pricing_version": pricing_version,
        })

        log_structured("info", "worker_completed", job_id=job_id, model_id=model_id,
                       input_tokens=input_tokens, output_tokens=output_tokens,
                       cost_krw=float(actual_cost), duration_s=duration_s, retry_count=retry_count)

        # Release semaphore slot on success
        _release_semaphore_slot(dynamodb, table_concurrency_semaphore, job_id)

    except Exception as e:
        duration_s = int(time.time() - start_time)
        error_msg = str(e)
        log_structured("error", "worker_failed", job_id=job_id, error=error_msg, duration_s=duration_s)

        # Release reservation
        try:
            month = current_month_kst()
            pk = f"{principal_id}#{month}"
            usage_table.delete_item(Key={"principal_id_month": pk, "model_id": f"__reserved__{job_id}"})
        except Exception:
            pass

        # Update job state → FAILED
        try:
            job_table.update_item(
                Key={"job_id": job_id},
                UpdateExpression="SET #s = :status, error_message = :err, "
                                 "completed_at = :ts, updated_at = :ts, retry_count = :rc",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":status": "FAILED", ":err": error_msg[:500],
                    ":ts": datetime.now(timezone.utc).isoformat(),
                    ":rc": retry_count,
                },
            )
        except Exception:
            pass

        # Ledger: TASK_FAILED
        try:
            ledger_table.put_item(Item={
                "request_id": f"{request_id}#TASK_FAILED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "principal_id": principal_id, "model_id": model_id,
                "event_type": "TASK_FAILED", "job_id": job_id,
                "decision": "DENY", "denial_reason": error_msg[:200],
                "source_path": "gateway-async", "duration_ms": duration_s * 1000,
            })
        except Exception:
            pass

        # Release semaphore slot on failure
        _release_semaphore_slot(dynamodb, table_concurrency_semaphore, job_id)

        sys.exit(1)


if __name__ == "__main__":
    main()
