"""Synthetic long-running worker for testing. Sleeps for SYNTHETIC_SLEEP_SECONDS then writes mock result."""
import json, os, sys, time, logging
from datetime import datetime, timezone, timedelta
from decimal import Decimal
import boto3

logging.basicConfig(level=logging.INFO, format='%(message)s')
KST = timezone(timedelta(hours=9))

def log_structured(level, message, **kwargs):
    entry = {"level": level, "message": message, "timestamp": datetime.now(timezone.utc).isoformat()}
    entry.update(kwargs)
    print(json.dumps(entry, default=str))

def current_month_kst():
    return datetime.now(KST).strftime('%Y-%m')

def main():
    job_id = os.environ.get('JOB_ID', '')
    request_id = os.environ.get('REQUEST_ID', '')
    principal_id = os.environ.get('PRINCIPAL_ID', '')
    model_id = os.environ.get('MODEL_ID', '')
    region = os.environ.get('REGION', 'us-west-2')
    pricing_version = os.environ.get('PRICING_VERSION', '')
    sleep_seconds = int(os.environ.get('SYNTHETIC_SLEEP_SECONDS', '60'))

    table_job_state = os.environ.get('TABLE_JOB_STATE', '')
    table_monthly_usage = os.environ.get('TABLE_MONTHLY_USAGE', '')
    table_request_ledger = os.environ.get('TABLE_REQUEST_LEDGER', '')
    payload_bucket = os.environ.get('PAYLOAD_BUCKET', '')

    dynamodb = boto3.resource('dynamodb', region_name=region)
    s3 = boto3.client('s3', region_name=region)
    job_table = dynamodb.Table(table_job_state)
    usage_table = dynamodb.Table(table_monthly_usage)
    ledger_table = dynamodb.Table(table_request_ledger)

    start_time = time.time()
    log_structured("info", "synthetic_worker_started", job_id=job_id, sleep_seconds=sleep_seconds)

    try:
        job_table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :status, updated_at = :ts",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "RUNNING", ":ts": datetime.now(timezone.utc).isoformat()},
        )
        ledger_table.put_item(Item={
            "request_id": f"{request_id}#TASK_STARTED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_id": principal_id, "model_id": model_id,
            "event_type": "TASK_STARTED", "job_id": job_id,
            "decision": "ALLOW", "source_path": "gateway-async-synthetic",
        })

        # Simulate long-running work
        log_structured("info", "synthetic_sleeping", job_id=job_id, seconds=sleep_seconds)
        time.sleep(sleep_seconds)

        # Mock Bedrock result
        mock_input_tokens = 50000
        mock_output_tokens = 2000
        mock_cost = Decimal("145.0")  # Simulated cost

        # Settlement
        month = current_month_kst()
        pk = f"{principal_id}#{month}"
        try:
            usage_table.delete_item(Key={"principal_id_month": pk, "model_id": f"__reserved__{job_id}"})
        except Exception:
            pass
        ttl_val = int(time.time()) + 35 * 24 * 3600
        usage_table.update_item(
            Key={"principal_id_month": pk, "model_id": model_id},
            UpdateExpression="ADD cost_krw :c, input_tokens :i, output_tokens :o SET #t = :ttl",
            ExpressionAttributeNames={"#t": "ttl"},
            ExpressionAttributeValues={":c": mock_cost, ":i": mock_input_tokens, ":o": mock_output_tokens, ":ttl": ttl_val},
        )

        result_key = f"results/{job_id}.json"
        s3.put_object(Bucket=payload_bucket, Key=result_key,
                      Body=json.dumps({"output": {"message": {"role": "assistant", "content": [{"text": "synthetic result after sleep"}]}},
                                       "usage": {"inputTokens": mock_input_tokens, "outputTokens": mock_output_tokens}}, default=str),
                      ContentType='application/json')

        duration_s = int(time.time() - start_time)
        job_table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :status, settled_cost_krw = :cost, input_tokens = :inp, output_tokens = :out, "
                             "result_ref = :ref, completed_at = :ts, updated_at = :ts, stop_reason = :sr",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "SUCCEEDED", ":cost": mock_cost,
                ":inp": mock_input_tokens, ":out": mock_output_tokens,
                ":ref": f"s3://{payload_bucket}/{result_key}",
                ":ts": datetime.now(timezone.utc).isoformat(), ":sr": "synthetic_complete",
            },
        )
        ledger_table.put_item(Item={
            "request_id": f"{request_id}#TASK_COMPLETED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_id": principal_id, "model_id": model_id,
            "event_type": "TASK_COMPLETED", "job_id": job_id,
            "decision": "ALLOW", "source_path": "gateway-async-synthetic",
            "input_tokens": mock_input_tokens, "output_tokens": mock_output_tokens,
            "estimated_cost_krw": mock_cost, "duration_ms": duration_s * 1000,
        })
        log_structured("info", "synthetic_worker_completed", job_id=job_id, duration_s=duration_s,
                       input_tokens=mock_input_tokens, output_tokens=mock_output_tokens, cost_krw=float(mock_cost))
    except Exception as e:
        log_structured("error", "synthetic_worker_failed", job_id=job_id, error=str(e))
        try:
            month = current_month_kst()
            pk = f"{principal_id}#{month}"
            usage_table.delete_item(Key={"principal_id_month": pk, "model_id": f"__reserved__{job_id}"})
        except Exception:
            pass
        try:
            job_table.update_item(
                Key={"job_id": job_id},
                UpdateExpression="SET #s = :status, error_message = :err, completed_at = :ts, updated_at = :ts",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":status": "FAILED", ":err": str(e)[:500], ":ts": datetime.now(timezone.utc).isoformat()},
            )
        except Exception:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
