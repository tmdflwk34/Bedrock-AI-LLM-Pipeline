"""
Bedrock Gateway — Job Dispatcher (v3 queue/scheduler).

Triggered by SQS. For each message:
1. Check global active count (RUNNING only) against GLOBAL_ACTIVE_LIMIT
2. If runnable: start Step Functions execution, update JobState → QUEUED
3. If capacity full: re-enqueue with delay (not batch failure — avoids DLQ)
"""
import json
import os
import time
import logging
from datetime import datetime, timezone

import boto3

logging.basicConfig(level=logging.INFO, format='%(message)s')

GLOBAL_ACTIVE_LIMIT = int(os.environ.get('GLOBAL_ACTIVE_LIMIT', '20'))
TABLE_JOB_STATE = os.environ.get('TABLE_JOB_STATE', '')
SFN_STATE_MACHINE_ARN = os.environ.get('SFN_STATE_MACHINE_ARN', '')
SQS_QUEUE_URL = os.environ.get('SQS_QUEUE_URL', '')
AWS_REGION = os.environ.get('BEDROCK_REGION', os.environ.get('AWS_REGION', 'us-west-2'))

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sfn_client = boto3.client('stepfunctions', region_name=AWS_REGION)
sqs_client = boto3.client('sqs', region_name=AWS_REGION)


def _log(level, message, **kwargs):
    entry = {"level": level, "message": message,
             "timestamp": datetime.now(timezone.utc).isoformat()}
    entry.update(kwargs)
    print(json.dumps(entry, default=str))


def _count_running_global():
    """Count jobs in RUNNING state globally."""
    table = dynamodb.Table(TABLE_JOB_STATE)
    resp = table.scan(
        FilterExpression="#s = :s1",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s1": "RUNNING"},
        Select="COUNT",
    )
    return resp.get("Count", 0)


def handler(event, context):
    """Process SQS messages — each is a job to dispatch."""
    records = event.get("Records", [])

    # Check global capacity once per batch
    running_count = _count_running_global()
    slots_available = max(0, GLOBAL_ACTIVE_LIMIT - running_count)

    _log("info", "dispatcher_batch", records=len(records),
         running=running_count, slots=slots_available)

    dispatched = 0
    for record in records:
        message_id = record.get("messageId", "")
        try:
            body = json.loads(record.get("body", "{}"))
            job_id = body.get("job_id", "")
            principal_id = body.get("principal_id", "")

            if not job_id or not principal_id:
                _log("error", "invalid_message", message_id=message_id)
                continue  # Drop invalid — don't retry

            if dispatched >= slots_available:
                # Capacity full — re-enqueue with 30s delay, NOT batch failure
                try:
                    sqs_client.send_message(
                        QueueUrl=SQS_QUEUE_URL,
                        MessageBody=record.get("body", "{}"),
                        DelaySeconds=30,
                    )
                    _log("info", "requeued_capacity_full", job_id=job_id,
                         running=running_count, dispatched=dispatched)
                except Exception as e:
                    _log("error", "requeue_failed", job_id=job_id, error=str(e))
                continue  # Message consumed successfully (re-enqueued)

            # Start Step Functions execution
            try:
                sfn_resp = sfn_client.start_execution(
                    stateMachineArn=SFN_STATE_MACHINE_ARN,
                    name=job_id,
                    input=json.dumps(body),
                )
                sfn_arn = sfn_resp.get("executionArn", "")
            except sfn_client.exceptions.ExecutionAlreadyExists:
                _log("warning", "sfn_already_exists", job_id=job_id)
                dispatched += 1
                continue
            except Exception as e:
                _log("error", "sfn_start_failed", job_id=job_id, error=str(e))
                # Re-enqueue on SFN failure too
                try:
                    sqs_client.send_message(
                        QueueUrl=SQS_QUEUE_URL,
                        MessageBody=record.get("body", "{}"),
                        DelaySeconds=10,
                    )
                except Exception:
                    pass
                continue

            # Update JobState → QUEUED + SFN ARN
            table = dynamodb.Table(TABLE_JOB_STATE)
            try:
                table.update_item(
                    Key={"job_id": job_id},
                    UpdateExpression="SET #s = :status, sfn_execution_arn = :arn, updated_at = :ts",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={
                        ":status": "QUEUED",
                        ":arn": sfn_arn,
                        ":ts": datetime.now(timezone.utc).isoformat(),
                    },
                )
            except Exception as e:
                _log("error", "job_state_update_failed", job_id=job_id, error=str(e))

            dispatched += 1
            _log("info", "job_dispatched", job_id=job_id,
                 principal_id=principal_id, sfn_arn=sfn_arn[:60],
                 dispatched=dispatched, slots=slots_available)

        except Exception as e:
            _log("error", "dispatch_error", message_id=message_id, error=str(e))

    _log("info", "dispatcher_done", dispatched=dispatched, requeued=len(records)-dispatched)
    # Return empty batch failures — all messages consumed (dispatched or re-enqueued)
    return {"batchItemFailures": []}
