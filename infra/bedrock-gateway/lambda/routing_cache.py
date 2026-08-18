"""Async-routing rules cache for `lambda/handler.py`.

Loads the per-model async-routing rules from the
`bedrock-gw-<env>-<region>-model-routing` DynamoDB table at handler
cold-start so a newly-synced model id can flip from sync to async
without redeploying the Lambda.

The hard-coded `ALWAYS_ASYNC_MODELS` and `SLOW_MODEL_PATTERNS` literals in
`handler.py` are retained as the bounded fallback (Req 4.5–4.6). On any
DynamoDB read failure the loader emits the
`BedrockAutoSync/HandlerRoutingFallback` CloudWatch metric and returns
the fallback baseline for THIS request only — the cache is NOT poisoned
with the baseline, so the next request retries the routing-table load.

Extracted into its own module so `tests/auto_sync_models/` can exercise
the cache without importing `handler.py` (which pulls in the whole
gateway dependency tree).
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

METRIC_NAMESPACE = "BedrockAutoSync"
FALLBACK_METRIC_NAME = "HandlerRoutingFallback"

# Module-level cache. `None` until the first successful Scan completes.
# A transient DynamoDB error during cold-start MUST NOT pin this to the
# fallback baseline for the lifetime of the warm container.
_async_rules_cache: Optional[dict] = None


def _emit_fallback_metric(cloudwatch_client) -> None:
    """Emit `BedrockAutoSync/HandlerRoutingFallback`. Best-effort."""
    if cloudwatch_client is None:
        return
    try:
        cloudwatch_client.put_metric_data(
            Namespace=METRIC_NAMESPACE,
            MetricData=[{"MetricName": FALLBACK_METRIC_NAME, "Value": 1}],
        )
    except (ClientError, BotoCoreError):
        # Never let metric emission fail the routing decision.
        logger.warning("HandlerRoutingFallback metric emission failed", exc_info=True)


def load_async_rules_from_routing_table(
    dynamodb_resource,
    table_name: str,
    cloudwatch_client=None,
) -> Optional[dict]:
    """Run a single `Scan` on the routing table and parse the rows.

    Returns
    -------
    dict
        ``{"always_async": set[str], "slow_pattern": set[str]}`` on
        success.
    None
        On `ClientError` / `BotoCoreError` (with the
        `BedrockAutoSync/HandlerRoutingFallback` metric emitted).
    """
    try:
        resp = dynamodb_resource.Table(table_name).scan(
            ProjectionExpression="rule_type,rule_value",
            ConsistentRead=False,
        )
    except (ClientError, BotoCoreError) as exc:
        logger.warning("model-routing 테이블 읽기 실패, fallback 사용: %s", exc)
        _emit_fallback_metric(cloudwatch_client)
        return None

    out: dict = {"always_async": set(), "slow_pattern": set()}
    for item in resp.get("Items", []) or []:
        rt = item.get("rule_type")
        rv = item.get("rule_value")
        if rt in out and isinstance(rv, str):
            out[rt].add(rv)
    return out


def ensure_async_rules(
    dynamodb_resource,
    table_name: str,
    fallback_always_async: Iterable[str],
    fallback_slow_pattern: Iterable[str],
    cloudwatch_client=None,
) -> dict:
    """Return the cached rules dict, loading on cold-start.

    On loader success the result is cached for the warm-container
    lifetime. On loader failure the fallback baseline pair is returned
    WITHOUT caching (so the next request retries the load).
    """
    global _async_rules_cache
    if _async_rules_cache is not None:
        return _async_rules_cache

    loaded = load_async_rules_from_routing_table(
        dynamodb_resource,
        table_name,
        cloudwatch_client=cloudwatch_client,
    )
    if loaded is None:
        return {
            "always_async": set(fallback_always_async),
            "slow_pattern": set(fallback_slow_pattern),
        }
    _async_rules_cache = loaded
    return _async_rules_cache


def _reset_cache_for_tests() -> None:
    """Test-only helper to clear the module-level cache between examples."""
    global _async_rules_cache
    _async_rules_cache = None
