"""Lambda entry point for the daily Bedrock model auto-sync (Task 13.3).

Wraps :func:`scripts.auto_sync_models.sync.run` with the env-var → RunArgs
glue. Triggered by EventBridge at 09:00 KST and on-demand via
``aws lambda invoke``. The function returns immediately on lock contention
so a second concurrent trigger never doubles up writes.

Required environment variables:

* ``ENVIRONMENT``                 default ``dev``
* ``AWS_REGION``                  default ``us-west-2``
* ``PRICELIST_SNAPSHOT_BUCKET``   required, S3 bucket for pricelist replay
* ``EXPLICIT_PRICING_PATH``       optional, default
                                  ``/var/task/scripts/add_missing_models/explicit_pricing.json``

The handler returns a dict with ``statusCode`` (200 / 500) and ``exit_code``
matching the values defined in :mod:`scripts.auto_sync_models.sync` so the
EventBridge target / step-functions caller can inspect outcomes.
"""

from __future__ import annotations

import os

from scripts.auto_sync_models import sync as auto_sync
from scripts.auto_sync_models._common import RunArgs, SES_RECIPIENT


def lambda_handler(event, context):  # noqa: D401 — AWS Lambda entry shape
    # NOTIFICATION_TOGGLE controls operator emails. Default to enabled for
    # the daily schedule; set "0"/"false" to silence (e.g. during incident
    # cooldowns) without redeploying.
    notify_raw = os.environ.get("NOTIFICATION_TOGGLE", "1").strip().lower()
    notification_toggle = notify_raw not in ("0", "false", "no", "off", "")

    args = RunArgs(
        env=os.environ.get("ENVIRONMENT", "dev"),
        region=os.environ.get("AWS_REGION", "us-west-2"),
        snapshot_bucket=os.environ["PRICELIST_SNAPSHOT_BUCKET"],
        notification_toggle=notification_toggle,
        notification_email=SES_RECIPIENT,
        explicit_pricing_path=os.environ.get(
            "EXPLICIT_PRICING_PATH",
            "/var/task/scripts/add_missing_models/explicit_pricing.json",
        ),
        curated_catalog_path=os.environ.get(
            "CURATED_CATALOG_PATH",
            "/var/task/scripts/auto_sync_models/curated_catalog.json",
        ),
    )
    exit_code = auto_sync.run(args)
    return {
        "statusCode": 200 if exit_code == auto_sync.EXIT_OK else 500,
        "exit_code": exit_code,
    }


__all__ = ["lambda_handler"]
