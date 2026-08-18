"""
Bedrock Gateway — Fargate Worker (v2 async long-running path).

Reads job parameters from environment variables, calls Bedrock Converse,
handles retry/backoff, writes usage/cost/result to DynamoDB/S3.

Environment variables (set by Step Functions RunTask override):
  JOB_ID, REQUEST_ID, PRINCIPAL_ID, MODEL_ID, REGION, PRICING_VERSION, PAYLOAD_REF
  TABLE_JOB_STATE, TABLE_MONTHLY_USAGE, TABLE_MODEL_PRICING, TABLE_REQUEST_LEDGER
  PAYLOAD_BUCKET, TABLE_CONCURRENCY_SEMAPHORE
"""
import json, os, signal, sys, time, uuid, logging
from collections.abc import Mapping
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import NamedTuple, Optional

import boto3
from botocore.config import Config
# ReadTimeoutError / ConnectTimeoutError are imported here because the retry
# loop has to *name* them: neither is a ClientError subclass (both descend from
# BotoCoreError and, via requests' Timeout, from OSError), which is exactly why
# a read timeout used to leave the loop unretried — D14. See
# `classify_bedrock_error`.
from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# KST timezone
KST = timezone(timedelta(hours=9))

# Disable SDK retry — we handle retries ourselves.
# This is the BASE config. The converse path derives each attempt's read timeout
# and builds a client from `BEDROCK_CONFIG.merge(...)` (task 4.2,
# `_bedrock_client_for_attempt`), so the 1800 below is only the inherited
# default there.
#
# **The image InvokeModel path still uses this config as-is, and task 7.1 left
# it that way on purpose** — see `_invoke_image_model` for the reasoning. So this
# 1800 is a live per-attempt ceiling for exactly one path, and the constant stays
# where it is rather than being renamed or removed.
BEDROCK_CONFIG = Config(
    retries={"max_attempts": 0},
    read_timeout=1800,  # 30 min read timeout
    connect_timeout=10,
)

# Retry config — aggressive backoff for Bedrock throttle recovery (50 concurrent jobs)
MAX_RETRIES = 10
BASE_DELAY = 15.0
MAX_DELAY = 180.0

# Per-error retry budget (surgical split).
# ThrottlingException KEEPS the full aggressive budget (MAX_RETRIES) because
# backoff genuinely recovers throttling under high concurrency.
# Server-side 5xx (InternalServerException / ServiceException /
# ServiceUnavailableException) are capped SHORT: LIVE-MEASURED they do NOT
# recover across the full budget — every observed creative-upscale 5xx failed
# all 11 attempts and tied up a Fargate slot ~30 min (duration_s ~1800) before
# failing. A short cap surfaces the failure in a few minutes with zero loss of
# success rate, while still giving a genuinely-transient blip a couple retries.
THROTTLE_ERRORS = {'ThrottlingException'}
SERVER_ERROR_CODES = {'InternalServerException', 'ServiceUnavailableException',
                      'ServiceException'}
SERVER_ERROR_MAX_RETRIES = 2  # 3 total attempts for 5xx (initial + 2 retries)

#: HTTP 408. The server said *this* request outran the model's own per-request
#: ceiling, so it is a duration verdict rather than a server fault
#: (design.md §"408 `ModelTimeoutException`을 별도로 노출하는 이유", R5.3).
DURATION_LIMIT_ERROR_CODES = {'ModelTimeoutException'}

#: Retryable ClientError codes — **derived**, not declared. It used to be a
#: fourth literal set listing the same four codes as the two sets above, which
#: is one classification source too many: a code added to SERVER_ERROR_CODES
#: alone would then be capped short by `classify_bedrock_error` while
#: `is_retryable` still called it terminal. The union cannot drift (task 4.3).
RETRYABLE_ERRORS = THROTTLE_ERRORS | SERVER_ERROR_CODES

#: `ReadTimeoutError`: retryable **once**, if the remaining budget affords it
#: (design.md "남은 예산이 허용할 때 1회"). An attempt that ran all the way to a
#: read timeout has already spent most of the budget, so the count is not what
#: bounds this — `next_attempt_timeout` is. With the 2100s total deadline in
#: force today a 1800s attempt leaves under the 300s minimum viable window, so
#: this cap is reached in arithmetic and never in practice. That is the design
#: (tasks.md 4.3), not an oversight: what the retryable verdict buys is an
#: accurate record, and R1.5 still governs whether a call actually happens.
READ_TIMEOUT_MAX_RETRIES = 1

#: `ConnectTimeoutError`: the connection was never established, so no generation
#: started and nothing was billed — retrying is free of the double-spend risk
#: that makes a read timeout delicate. Still a short cap ("짧은 상한"): a
#: connect timeout that repeats is an endpoint or network fault that backoff
#: does not fix, and the same short cap as 5xx keeps one policy instead of two.
CONNECT_TIMEOUT_MAX_RETRIES = SERVER_ERROR_MAX_RETRIES

MAX_CONCURRENT_JOBS = 50


# ---------------------------------------------------------------------------
# Time budget — ADDITIVE (arithmetic: task 4.1, wiring: task 4.2).
#
# The calculators below are pure and were added first, on their own, so the
# effect of the structure change stays separable from the effect of the value
# change. `main()` now calls them (task 4.2): the process fixes an absolute
# deadline on entry and each attempt's read timeout is min(ceiling, remaining).
#
# Task 7.1 made that ceiling per-model: `attempt_ceiling_seconds` resolves
# min(model Duration_Ceiling, injected cap) and the grant is
# min(that, remaining) <= 7200. **The effective value is still 1800** while the
# task definition injects PER_ATTEMPT_TIMEOUT_SECONDS = 1800 (task 5.5); task
# 7.2 raises the injected value, and that is the step with the behaviour change.
# Same discipline as before: the lookup lands first and the number moves second,
# so a regression can be attributed to one or the other.
#
# Why a derived per-attempt timeout instead of a static one (design.md C4-b,
# D5): a static value lets a late attempt claim more time than the process has
# left, so the attempt outlives the deadline and the outer layers (RunTask, the
# state machine) end up stopping a task that never wrote its termination
# record. The budget therefore bounds retries by *time*, not by a count.
#
# Both functions are pure — the clock arrives as the `now` argument and is
# never read from time.time() in here. That is what lets Property 14 inject a
# fake clock and charge every second for free.
# ---------------------------------------------------------------------------

#: Declared Duration_Ceiling per model family, in seconds (R1.1, design.md
#: §모델별 상한). Claude and the OpenAI/mantle families declare 7200; Nova is
#: 3600 because 60 minutes is the only server-side per-request ceiling AWS has
#: published (U2). Keys are family markers matched as model-id **substrings,
#: longest key first**, so "amazon.nova" wins over a bare "nova".
#:
#: **Read since task 7.1** by `model_duration_ceiling`. Before then the ceiling
#: was one number for every model; the table was declaration-only because
#: raising the ceiling ahead of the leak fixes (4.2, 5.1, 5.3, 5.4) is the
#: ordering design.md rejects — the leak window is proportional to this value.
#:
#: **Nova cannot exceed 3600 no matter what we configure.** AWS published a
#: per-request model timeout for exactly one family — Nova, 60 minutes — as the
#: condition behind 408 `ModelTimeoutException`. If we granted a Nova attempt
#: 7200s, Bedrock would cut it at 3600 and we would record a server verdict we
#: could have predicted. That is why the ceiling is per-model rather than one
#: value per Delivery_Path (design.md §모델별 상한, R1.1/R1.2). Nova does not
#: appear in this gateway's async traffic (0 of the audited 2,027 jobs), so the
#: entry stands on the published limit, not on our own measurement.
MODEL_DURATION_CEILING_SECONDS = {
    "amazon.nova": 3600,
    "nova": 3600,
    "anthropic": 7200,
    "openai": 7200,
}

#: Ceiling for a model id no marker above matches. **Kept at 1800 on purpose**,
#: and since task 7.1 this constant has exactly one job left: the unknown-model
#: fallback.
#:
#: Why 1800 rather than 7200 or 3600: it is the ceiling in force before this
#: task, so an id we have never measured can never be granted more time than
#: today's deployed value. R1.1 requires a declared ceiling to be *true*, and
#: the audit found ceilings that differ per family (the 128k output limit, the
#: large-output slowdown, Nova's published 60 minutes) — so 7200 for an
#: unmeasured id would be a declaration we cannot support. Unknown ids are not
#: hypothetical: the image models (`stability.*`,
#: `amazon.titan-image-generator-v2:0`) match no family marker, and any model
#: added to the gateway before this table lands here too.
DEFAULT_DURATION_CEILING_SECONDS = 1800

#: Smallest window in which starting a generation attempt is worth the spend.
#: Below it the attempt is granted time it cannot use, and the honest outcome
#: is to stop and record `duration_limit` (R1.5) instead of paying for a call
#: that dies on the same wall.
#:
#: Why 300s:
#:  * Establishing the call is already bounded elsewhere (connect_timeout=10
#:    plus SigV4 signing), so the floor is not about connection setup alone. A
#:    buffered Converse has no time-to-first-byte signal at all — the first
#:    byte arrives when the response completes (design.md §왜 read_timeout
#:    인상만으로 부족한가) — so "enough time to reach the first byte" can only
#:    mean "enough time for a short generation to finish".
#:  * At the audited large-output throughput for opus-5 (80–105 tok/s bulk,
#:    68.5 tok/s median for >=10k-token outputs) 300s buys roughly 20k–31k
#:    output tokens. So a granted attempt has room for real work, while an
#:    attempt below the floor could not finish even a small generation.
#:  * It is the value the retry arithmetic already assumes: with the total
#:    deadline of 2100 introduced in task 4.2, a 1800s attempt that dies leaves
#:    under 300s, so no retry follows (tasks.md 4.3 — "이것이 의도다"). It also
#:    matches the settlement/cleanup reserve design.md derives the 7500 total
#:    deadline from (7200 generation + 300).
#:
#: The default only. ``main()`` reads the MIN_VIABLE_ATTEMPT_SECONDS
#: environment variable (task 4.2) and passes it to ``next_attempt_timeout``,
#: so the task definition owns the effective value and this constant is the
#: fallback when nothing is injected.
MIN_VIABLE_ATTEMPT_SECONDS = 300


def remaining_budget(deadline_at, now, settlement_reserve):
    """Seconds of generation time left before the worker's process deadline.

    ``deadline_at`` and ``now`` are absolute epoch seconds (``time.time()``
    style); ``settlement_reserve`` is the tail the worker keeps for shutting
    down honestly — writing the termination record, settling usage, releasing
    the reservation and the semaphore slot (design.md C4-a counts 3 DynamoDB
    writes + 1 S3 write + 1 ledger write, which is also why ``stopTimeout``
    becomes 120).

    Pure by construction: the clock is an argument. Reading ``time.time()``
    inside would make the retry budget untestable, and clock injection is the
    premise of Property 14.

    **A negative result is clamped to 0.0.** The reasoning, since the choice is
    not obvious:

    * Nothing downstream distinguishes 0 from -59. Every gate is
      ``remaining >= MIN_VIABLE_ATTEMPT_SECONDS`` and both values fail it, so
      returning the signed overrun buys no decision.
    * No information is lost. A caller that needs to know *how far* past the
      deadline it is holds both ``now`` and ``deadline_at`` and subtracts them
      (``now - deadline_at``); this function is not the only place that fact
      lives, so clamping hides nothing from the termination record or metrics.
    * 0.0 is safe to feed to the timeout arithmetic. A negative would have to
      be special-cased at every call site or it eventually reaches a boto3
      ``read_timeout``, which does not reject it and turns into a nonsense
      socket timeout instead of a clear "no budget" decision.

    The clamp is the contract Property 14 is stated against
    (``tests/long_output/test_property_14_retry_budget.py``): the grant may not
    exceed ``max(0, deadline_at - now - reserve)``. An earlier form of that
    assertion, ``now + remaining + reserve <= deadline_at``, could not hold
    together with ``remaining >= 0`` once ``now`` was already past
    ``deadline_at - reserve`` — the interval the generator visits on purpose
    (2099s burned of a 2100s deadline with a 60s reserve). Task 4.2 rewrote it
    against the clamp rather than weakening either side.
    """
    return max(0.0, float(deadline_at) - float(now) - float(settlement_reserve))


def next_attempt_timeout(remaining, model_ceiling, min_viable=None):
    """Read timeout to grant the next generation attempt, or ``None``.

    ``None`` means **do not attempt**: terminate with ``termination_reason =
    duration_limit`` (R1.5) rather than start a call that cannot produce
    anything. This is how the retry budget stays bounded by time instead of by
    a count (design.md C4-b): a ``ReadTimeoutError`` is classified retryable
    (task 4.3), yet the re-call only happens when the budget still affords one.

    The grant is ``min(model_ceiling, remaining)`` floored to whole seconds, so
    it can never exceed either the model's declared Duration_Ceiling or the
    time the process actually has left. Flooring rather than rounding keeps the
    same direction: rounding up could hand out a second the budget does not
    contain.

    Boundary, fixed explicitly: ``remaining == MIN_VIABLE_ATTEMPT_SECONDS`` is
    **viable** and returns a timeout — the comparison is ``>=``, matching
    design.md C4-b ("``remaining`` >= 최소 실행 가능치일 때만"). The floor is
    applied to the derived value, not to ``remaining`` alone, so a model
    ceiling below the floor also yields ``None``: an attempt capped under the
    minimum viable window is no more useful than an exhausted budget.

    ``min_viable`` overrides the module floor (task 4.2). It exists because
    design.md C4 requires the budget knobs to arrive as task-definition
    environment variables rather than baked into the image, and ``main()`` is
    the only place allowed to read ``os.environ``. Passing the override as an
    argument keeps this function pure — omit it and the module constant is the
    single source, which is what 4.1's two-argument call sites still get.
    """
    floor = (MIN_VIABLE_ATTEMPT_SECONDS if min_viable is None
             else float(min_viable))
    budget = min(float(model_ceiling), float(remaining))
    # Sub-second grants are treated as no grant at all, whatever the floor
    # says: boto3 reads a ``read_timeout`` of 0 as a zero-second socket
    # timeout, not as "no budget", so handing one out would turn a clear
    # duration_limit decision into an unexplained transport failure.
    if budget < floor or budget < 1.0:
        return None
    return int(budget)


def model_duration_ceiling(model_id, table=None, default=None):
    """Declared Duration_Ceiling for ``model_id``, in seconds (R1.1, task 7.1).

    Pure: no environment, no clock, no I/O. ``table`` and ``default`` exist so a
    test can state the matching rule against a table of its own instead of
    against the deployed one; omit both and the module's declaration is the
    single source.

    **Matching rule.** The keys of :data:`MODEL_DURATION_CEILING_SECONDS` are
    family *markers*, not model ids, because the ids that reach here are
    inference-profile-prefixed and versioned (``us.anthropic.claude-opus-5``,
    ``openai.gpt-5.6-sol``, ``amazon.nova-canvas-v1:0``) and enumerating every
    one of them would make this table go stale the next time AWS ships a
    version. So a marker matches if it appears anywhere in the id, and **the
    longest matching marker wins**:

      * ``amazon.nova`` must beat ``nova`` — both are in the table today at the
        same value, so nothing observable depends on the order *yet*. That is
        precisely why the rule is fixed now: the day the two values diverge, a
        dict-order lookup would silently answer with whichever key came first.
      * Equal-length markers are broken alphabetically, so the answer is
        deterministic rather than dependent on insertion order.

    Comparison is case-folded on both sides. Bedrock ids are lowercase by
    convention, and a `MODEL_ID` that arrives capitalised should get its family's
    ceiling rather than silently fall through to the unknown default.

    An unmatched id gets :data:`DEFAULT_DURATION_CEILING_SECONDS` (1800) — see
    that constant for why the conservative direction is the honest one.
    """
    ceilings = MODEL_DURATION_CEILING_SECONDS if table is None else table
    fallback = int(DEFAULT_DURATION_CEILING_SECONDS if default is None
                   else default)
    text = str(model_id or "").lower()
    # Longest marker first, then alphabetical: "amazon.nova" > "nova", and two
    # markers of equal length always resolve the same way.
    for marker in sorted(ceilings, key=lambda k: (-len(str(k)), str(k))):
        if str(marker).lower() in text:
            return int(ceilings[marker])
    return fallback


def attempt_ceiling_seconds(model_id, env_cap=None, table=None, default=None):
    """Per-attempt ceiling this process will use: ``min(model ceiling, cap)``.

    Pure — ``main()`` reads ``PER_ATTEMPT_TIMEOUT_SECONDS`` and passes it in.
    Together with `next_attempt_timeout` this is the full rule task 7.1 asks
    for: the grant is ``min(model Duration_Ceiling, env cap, remaining budget)``
    and can never exceed 7200 because no entry in the table does.

    **The environment variable is a cap, not an override, and that is the
    staging mechanism.** Task 7.1 changes the *lookup*; task 7.2 changes the
    *value*. `ecs.tf` injects ``PER_ATTEMPT_TIMEOUT_SECONDS = 1800`` today
    (task 5.5), so with this function in place the effective ceiling stays
    ``min(7200, 1800)`` = **1800** for Claude and OpenAI and ``min(3600, 1800)``
    = 1800 for Nova — no behaviour change from this task alone. When 7.2 raises
    the injected value to 7200 the same expression becomes ``min(7200, 7200)`` =
    7200, while Nova stays at ``min(3600, 7200)`` = 3600.

    Treating the variable as an override instead would collapse the two steps
    into one: the structural change would land already carrying the value
    change, and the rollback the task definition provides
    (``PER_ATTEMPT_TIMEOUT_SECONDS`` back to 1800) would stop working for any
    model whose declared ceiling is higher than the injected number — a revision
    rollback would leave Claude at 7200. As a cap it also keeps the invariant
    the task definition is supposed to enforce: no revision can hand out *more*
    time than the model declares, only less.

    ``env_cap`` of ``None`` means "nothing injected" and the model ceiling
    stands. ``main()`` gets that for free by passing the model ceiling as
    `_env_seconds`' default, so an absent, unparseable or negative variable
    reduces this to the model ceiling without a second code path.
    """
    ceiling = model_duration_ceiling(model_id, table=table, default=default)
    if env_cap is None:
        return int(ceiling)
    return int(min(int(ceiling), int(env_cap)))


# ---------------------------------------------------------------------------
# Total process deadline — WIRED HERE (task 4.2).
#
# This is where the calculators above stop being declaration-only: ``main()``
# fixes an absolute deadline at process start, and every attempt's read timeout
# is derived from what is left of it.
#
# Two things this step deliberately does NOT change:
#
#  * **The per-attempt ceiling stays 1800.** With the default 2100 deadline and
#    the 300s settlement reserve, a fresh process grants its first attempt
#    exactly today's 1800 (2100 - 300), so nothing about a normal single-attempt
#    job moves. Task 7.1 replaced the single ceiling with
#    ``min(model Duration_Ceiling, injected cap, remaining) <= 7200`` — still
#    1800 in effect, because the injected cap is 1800 until task 7.2 raises it.
#    Structure first, value later — otherwise the effect of the value change and
#    the effect of the structure change arrive mixed together and neither can be
#    attributed.
#  * **The retry policy's meaning.** Throttling keeps ``MAX_RETRIES`` with the
#    long backoff, 5xx keeps its short cap, and exception classification is
#    untouched (``except ClientError`` only — D14 is task 4.3). The single
#    addition is a *time* gate.
#
# Why 2100 (design.md §Phase 1, tasks.md 4.2): backoff sums to at most 1305s,
# fast-failing attempts add little on top, and 300s is kept for settlement. The
# throttle retry budget therefore survives intact — a throttled response comes
# back immediately, so those attempts spend no generation time and all 11 still
# fit. What the deadline actually cuts is the pathological chain in which every
# attempt burns a whole read timeout (worst case today
# ``11 x 1800 + 1305 = 21,105s``, and 80,505s once the ceiling reaches 7200),
# and the full audit found no evidence that chain ever contributed to success:
# the 56-failure read-timeout cluster shows ``retry_count = 0`` throughout.
# ---------------------------------------------------------------------------

#: Wall-clock budget for the whole worker process, in seconds. Overridable via
#: ``WORKER_TOTAL_DEADLINE_SECONDS``; task 5.5 injects it from the task
#: definition and task 7.2 raises the injected value to 7500.
DEFAULT_WORKER_TOTAL_DEADLINE_SECONDS = 2100

#: Tail reserved for terminating honestly — the termination record, settlement,
#: the reservation delete, the result write and the semaphore release
#: (design.md C4-a counts 3 DynamoDB writes + 1 S3 write + 1 ledger write).
#: Overridable via ``SETTLEMENT_RESERVE_SECONDS``. 300 is the value design.md
#: derives 7500 from (7200 generation + 300) and it is what makes 2100 grant a
#: full 1800 to the first attempt. Zero is legal: it means "spend everything on
#: generation", which is only sane in tests.
DEFAULT_SETTLEMENT_RESERVE_SECONDS = 300


class WorkerDeadlineExceeded(Exception):
    """The process ran out of time before another attempt could start.

    Raised by the time gate, never by Bedrock. It exists as its own type so the
    outer handler can record ``termination_reason = duration_limit`` and
    ``TIMED_OUT`` (R1.5, R5.3, design.md §예외 -> 분류 -> 기록 매핑, row "워커 총
    데드라인 초과") without string-matching an error message.

    Task 4.4 folded this into `classify_termination`, which every termination
    path now reads. Two routes reach the same verdict and agree by construction:
    the ``deadline_exceeded`` flag (branch 3) and this type through
    `classify_bedrock_error` (branch 4). The failure path derives the flag from
    ``isinstance(e, WorkerDeadlineExceeded)`` precisely so the two cannot
    disagree.
    """


class WorkerSigterm(Exception):
    """SIGTERM arrived while a generation was still in flight (task 5.3, D4).

    **Constructed and classified, never raised.** That is unusual enough to
    justify, and the justification is measured rather than assumed.

    Raising from a signal handler is the tidier design on paper: the exception
    unwinds the in-flight call, and the outer handler's existing cleanup runs.
    It does not survive contact with botocore. Measured on
    ``python:3.12`` + botocore, with the main thread blocked in a real socket
    read against a server that accepts and never answers: the handler ran
    promptly (at +1.000s of a 1.0s timer — PEP 475 turns the ``EINTR`` into a
    handler call), the raise propagated into ``botocore/httpsession.py:send``,
    and *that* function's blanket ``except Exception`` re-raised it as
    ``HTTPClientError``. The type is gone by the time it reaches the outer
    handler, so `classify_bedrock_error` would answer `unknown` → FAILED with no
    Termination_Reason — precisely the mis-record this task exists to prevent.

    So the handler does the cleanup itself and this class is the *value* it hands
    the classifier, keeping one classification source (design.md §예외 → 분류 →
    기록 매핑, row `SIGTERM (취소)`) instead of a second mapping written inline in
    the handler.
    """


class MantleHTTPError(Exception):
    """mantle answered with an HTTP error status (task 7.4, D6).

    Raised by `_invoke_mantle_responses` in place of the bare
    ``Exception(f"mantle HTTP {code}: ...")`` it used to raise. **The bare
    exception was the bug**: by the time it reached the outer handler the status
    was inside a string, so `classify_bedrock_error` answered `unknown` → FAILED
    with no Termination_Reason and no `bedrock_error_code` — a mantle 5xx was
    recorded as "something went wrong" while design.md's table calls it
    `server_error`. The status has to survive as data for the single
    classification source to be able to read it.

    ``status`` is the HTTP status code; ``detail`` is the truncated response body
    the previous message carried, kept so nothing an operator could read before
    is lost.

    Defined here rather than in the mantle section below so every exception the
    classifier names lives in one place. It is deliberately **not** a subclass of
    ``urllib.error.HTTPError``: that type descends from ``URLError`` → ``OSError``
    and would therefore be swallowed by the transport branch, which is terminal.
    A 5xx is retryable, so the two must not share a type.
    """

    def __init__(self, status, detail=""):
        self.status = int(status)
        self.detail = str(detail or "")
        super().__init__(f"mantle HTTP {self.status}: {self.detail}")


class UsageMissingError(ValueError):
    """The response carried no readable token counts, so we refuse to settle.

    The fail-closed rule R6.3 asks for (task 4.5), given a type so it can be
    *recorded* rather than only raised: `classify_bedrock_error` answers
    ``usage_source = "missing"`` for it, which is the audit trail design.md's
    §"usage를 얻을 수 없는 경우" asks for. Before this it was a bare ``ValueError``
    and the record said only "something went wrong", which is the same shape a
    JSON decode failure or a bug in us produces.

    ``ValueError`` subclass on purpose, twice over: it is what the deployed code
    raised for this condition, so nothing that catches ``ValueError`` changes
    behaviour, and "the value you handed me is not a usage report" is exactly
    what the base type means.

    **Not the same act as a pending price.** A pending pricing row settles at a
    deliberate *zero* (R6.8) because we know the counts and do not yet know the
    rate; this exception exists because we do not know the counts, and inventing
    a zero there would state that a generation cost nothing. The two live one
    branch apart in `compute_settled_cost` and mean opposite things.
    """


# ---------------------------------------------------------------------------
# Exception classification — SINGLE SOURCE (task 4.3, D14, R8.1/R8.2/R5.4).
#
# One pure function answers every question the retry loop and the termination
# record used to answer by comparing code strings in two different places.
# design.md §"예외 → 분류 → 기록 매핑" is transcribed here row for row, and the
# retry loop below reads its verdict instead of re-deciding.
#
# What changes behaviourally, and only this:
#
#  * **`ReadTimeoutError` is retryable** (D14, R8.2). It is not a `ClientError`,
#    so the old `except ClientError` loop could not see it and every read
#    timeout failed with `retry_count = 0` — the signature of all 54 sampled
#    rows in the audited 56-failure cluster. Whether a re-call actually happens
#    is still decided by the budget (`next_attempt_timeout`), which with today's
#    2100s deadline means it usually does not. **That is intended.**
#  * **408 `ModelTimeoutException` is terminal**, `duration_limit`, `TIMED_OUT`.
#    Not retryable on purpose: the server told us this request exceeded *its*
#    time ceiling, so an identical request produces an identical outcome and the
#    only thing a retry reliably doubles is the bill. The code is recorded
#    verbatim so U2 — Bedrock's undocumented per-request ceiling — can be
#    measured from the failures once task 7.1 raises our own ceiling.
#  * **`ConnectTimeoutError` is retryable with a short cap**, `server_error`,
#    FAILED. Connection never established → nothing generated, nothing billed.
#
# What deliberately does NOT change: throttling keeps `MAX_RETRIES` with the
# long backoff, 5xx keeps `SERVER_ERROR_MAX_RETRIES`, and every other exception
# stays terminal.
#
# Task 7.4 folded the mantle Responses path into the same source. Two additions,
# both of them the removal of a second opinion rather than a new policy:
#
#  * **`MantleHTTPError` carries the status as data**, so a mantle 5xx is
#    classified `server_error` (retryable, `SERVER_ERROR_MAX_RETRIES`) and a
#    mantle 4xx is classified as a request error, exactly as the equivalent
#    `ClientError` rows are. Before, the status was formatted into a message
#    string and every mantle HTTP failure landed in `unknown`.
#  * **The mantle transport timeout keeps its terminal verdict and now carries
#    `usage_source = "unavailable"`.** The inner retry loop that used to retry it
#    up to 11 times is gone (see `_invoke_mantle_responses`), so this branch is
#    the only thing that decides, and R8.3 says do not re-call.
# ---------------------------------------------------------------------------

#: Bedrock throttled us. Backoff genuinely recovers this one.
ERROR_CLASS_THROTTLE = "throttle"
#: The server failed or was unreachable; the request was not processed.
ERROR_CLASS_SERVER = "server"
#: Time ran out — our deadline, the model's 408, or a read timeout.
ERROR_CLASS_DURATION = "duration"
#: Our socket gave up on a buffered call. Distinct from `duration` because the
#: server may have finished and billed while we stopped listening (U5), which is
#: why task 7.4 makes this class non-retryable and records `usage_source`.
ERROR_CLASS_TRANSPORT = "transport"
#: The request itself was rejected — validation, access, unknown model. Ours to
#: fix, not Bedrock's, and never worth a retry.
ERROR_CLASS_REQUEST = "request"
#: The orchestrator stopped us: SIGTERM from ECS `StopTask`, which the cancel
#: path triggers through `stop_execution` (task 5.3, D4). Not an error at all —
#: nothing failed, somebody asked us to stop — but it travels the same
#: classification road so the record shape has one source.
ERROR_CLASS_CANCELED = "canceled"
#: We hold a response but not the token counts, so settlement refuses to write
#: accounting (task 4.5, R6.3). Its own class for one reason only: it is what
#: makes the record carry `usage_source = "missing"`. Everything else about the
#: verdict is the `unknown` row it used to land in — terminal, FAILED, no
#: Termination_Reason (R5.1 has no value for "we could not read the usage") and
#: no `bedrock_error_code` (Bedrock reported nothing to put there).
ERROR_CLASS_USAGE_MISSING = "usage_missing"
#: Anything the table does not name: a bug in us or in the response shape.
ERROR_CLASS_UNKNOWN = "unknown"
#: **No exception at all** (task 4.4): the generation ended on Bedrock's own
#: `stopReason`, so there is nothing to classify as an error.
#: `classify_bedrock_error` never returns this — only `classify_termination`'s
#: `complete` and `max_tokens` branches carry it. It is deliberately absent from
#: :data:`_REASON_RECORDED_CLASSES`, which answers a question only *error*
#: verdicts ask; those two branches record their reason unconditionally and say
#: so in their own `records_reason` field.
ERROR_CLASS_NONE = "none"

#: Classes for which design.md's table fixes a Termination_Reason, and therefore
#: the only classes whose reason is written to the record.
#:
#: `request` and `unknown` are absent, and that absence is the whole of the
#: table's "`server_error`가 아니라 요청 오류로 분리". R5.1 closes
#: Termination_Reason to six values and none of them means "your request was
#: invalid"; growing the enum would break R5.1's exclusivity and Property 6,
#: and design.md refuses that trade explicitly elsewhere (§청크 유휴 타임아웃:
#: "열거를 늘리지 않는다 ... 구분이 필요한 정보는 `bedrock_error_code`가 담는다").
#: So a request error keeps today's record shape — FAILED, no
#: Termination_Reason — and gains `bedrock_error_code = "ValidationException"`
#: plus the original message. It is never labelled `server_error`, which is what
#: the table asked for. The reason slot these verdicts still carry exists only
#: so the function is total over R5.1's vocabulary (a caller that needs one of
#: six always gets one); `records_reason` is what decides whether it is written.
_REASON_RECORDED_CLASSES = frozenset({
    ERROR_CLASS_THROTTLE, ERROR_CLASS_SERVER, ERROR_CLASS_DURATION,
    ERROR_CLASS_TRANSPORT, ERROR_CLASS_CANCELED})

#: `usage_source` value for "we cannot know what was spent" (R6.4, design.md
#: §JobState 신규 필드 and §usage를 얻을 수 없는 경우, row "mantle 전송 타임아웃").
#:
#: design.md defines four values — `stream_metadata`, `gateway_counted`,
#: `missing`, `unavailable`. Task 7.4 added this one; task 4.5 added `missing`
#: below, once the fail-closed settlement extraction gave that condition a type
#: to be recognised by. The remaining two still belong to a path that does not
#: exist: both need the worker to consume a stream (task 13.7), and writing a
#: value for a path that cannot produce it would be inventing a record.
#:
#: What it buys: a buffered call that timed out on **our** side does not tell us
#: the server did not finish and bill (U5), so the settled cost of 0 may be
#: wrong. This field is what makes that gap auditable instead of invisible —
#: design.md's "그 지출이 원장에 보이지 않을 수 있음을 인정한다". Zero-settling
#: silently and zero-settling with a tag are different acts; only the second one
#: can be counted later.
USAGE_SOURCE_UNAVAILABLE = "unavailable"

#: Classes whose settlement value cannot be known, and therefore the only ones
#: that record :data:`USAGE_SOURCE_UNAVAILABLE` today.
#:
#: Only `transport`. A `duration` verdict from our own deadline gate never sent a
#: request that completed, and SIGTERM has `reclaimed_by` naming its cause;
#: design.md does list `unavailable` for both of those rows, but writing it there
#: is a record change neither task 7.4 nor any earlier task asked for, and this
#: task is the one whose exception can have been billed without us knowing.
_USAGE_SOURCE_UNAVAILABLE_CLASSES = frozenset({ERROR_CLASS_TRANSPORT})

#: `usage_source` value for "the response reported no token counts we could
#: read" (R6.4, task 4.5, design.md §usage를 얻을 수 없는 경우, row "usage 결손").
#:
#: The distinction from :data:`USAGE_SOURCE_UNAVAILABLE` is the whole point of
#: having two values. `unavailable` tags a settled **zero** that may be wrong
#: because our socket gave up on a call the server may have completed;
#: `missing` tags a job that was **not settled at all**, because R6.3 forbids
#: inventing a zero charge for a generation whose token counts we never saw.
#: One says "this number may be too low", the other says "there is no number".
USAGE_SOURCE_MISSING = "missing"

#: Classes that record :data:`USAGE_SOURCE_MISSING`. Only the class the
#: fail-closed settlement raise produces — see :class:`UsageMissingError`.
_USAGE_SOURCE_MISSING_CLASSES = frozenset({ERROR_CLASS_USAGE_MISSING})


class BedrockErrorClass(NamedTuple):
    """The verdict on one exception.

    The first five fields are positional contract: design.md declares
    ``classify_bedrock_error(exc) -> (retryable, retry_cap, termination_reason,
    error_code, http_status)`` and callers (including Property 14) unpack in
    that order. ``error_class`` and ``job_status`` are appended, not inserted.

    ``retry_cap`` is the number of *retries* allowed, so it is compared against
    the zero-based attempt index: ``attempt < retry_cap``. Terminal verdicts
    carry 0 rather than a negative sentinel — `retryable` is the flag that
    decides, and a cap of 0 reads the same as design.md's "상한 0" column.

    ``job_status`` is the JobState the table pairs with the reason, so the outer
    handler does not re-derive it from an exception type. ``TIMED_OUT`` appears
    exactly where the table puts it: our own deadline, 408, a read timeout, and
    a buffered transport timeout.
    """

    retryable: bool
    retry_cap: int
    termination_reason: str
    error_code: str
    http_status: Optional[int]
    error_class: str
    job_status: str

    @property
    def records_reason(self) -> bool:
        """Write ``termination_reason`` for this verdict? See
        :data:`_REASON_RECORDED_CLASSES` for why request/unknown say no."""
        return self.error_class in _REASON_RECORDED_CLASSES

    @property
    def records_error_code(self) -> bool:
        """Write ``bedrock_error_code``? Everything except `unknown`, whose
        "code" is a Python class name that `error_message` already carries —
        putting it in a field named after Bedrock would invent an attribution."""
        return bool(self.error_code) and self.error_class != ERROR_CLASS_UNKNOWN

    @property
    def usage_source(self) -> str:
        """`usage_source` for this verdict, or ``""`` to write nothing.

        ``"unavailable"`` for a transport give-up (task 7.4),
        ``"missing"`` for the fail-closed settlement raise (task 4.5), and
        nothing for every other verdict — see
        :data:`_USAGE_SOURCE_UNAVAILABLE_CLASSES` and
        :data:`_USAGE_SOURCE_MISSING_CLASSES`. Derived rather than passed in so
        the field cannot disagree with the class it is supposed to describe.
        """
        if self.error_class in _USAGE_SOURCE_UNAVAILABLE_CLASSES:
            return USAGE_SOURCE_UNAVAILABLE
        if self.error_class in _USAGE_SOURCE_MISSING_CLASSES:
            return USAGE_SOURCE_MISSING
        return ""


def classify_bedrock_error(exc):
    """Classify ``exc`` per design.md's exception → classification → record map.

    Pure: no clock, no environment, no I/O. The budget question ("can we afford
    another attempt?") is deliberately *not* here — that is
    ``remaining_budget`` / ``next_attempt_timeout``, and keeping the two apart
    is what lets a read timeout be "retryable" while almost never being retried.

    Order of the type checks is load-bearing. ``ReadTimeoutError`` and
    ``ConnectTimeoutError`` are both ``OSError`` subclasses (botocore routes
    them through requests' ``Timeout``), so the mantle-transport branch has to
    come last or it would swallow them and silently undo D14.
    """
    # Ours, not Bedrock's: the time gate raised it. Kept first because it is a
    # plain Exception and would otherwise fall through to the unknown branch,
    # losing the duration_limit/TIMED_OUT verdict task 4.2 established.
    if isinstance(exc, WorkerDeadlineExceeded):
        # No `bedrock_error_code`: no Bedrock call reported anything. The record
        # already carries `deadline_at` and the elapsed time (design.md's 기록
        # column for this row), so inventing a code would only add noise.
        return BedrockErrorClass(False, 0, "duration_limit", "", None,
                                 ERROR_CLASS_DURATION, "TIMED_OUT")

    # Also ours: the SIGTERM handler built it (task 5.3). Kept beside the
    # deadline branch for the same reason — a plain Exception would otherwise
    # fall through to `unknown` and lose the `canceled` / CANCELED verdict.
    #
    # Why the branch belongs *here* rather than inline in the handler: this
    # function is what design.md's mapping table is transcribed into, and the
    # SIGTERM row is one of its rows. A handler that decided
    # `("canceled", "CANCELED")` on its own would be the second classification
    # source that task 4.3 removed. No `bedrock_error_code`: Bedrock reported
    # nothing, `reclaimed_by = "sigterm"` is what names the cause.
    if isinstance(exc, WorkerSigterm):
        return BedrockErrorClass(False, 0, "canceled", "", None,
                                 ERROR_CLASS_CANCELED, "CANCELED")

    # Also ours: settlement refused to write accounting because the response
    # carried no readable token counts (task 4.5, R6.3). Kept beside the other
    # two self-raised types, and **before** the `ClientError` rows for the same
    # reason they are — it is a plain `ValueError` subclass and would otherwise
    # reach the unknown fallback, which is where this condition used to land and
    # why nothing ever recorded `usage_source = "missing"`.
    #
    # Everything except `usage_source` is that fallback's verdict, unchanged:
    # terminal, FAILED, no Termination_Reason (the class is absent from
    # `_REASON_RECORDED_CLASSES` — R5.1 has no value meaning "we could not read
    # the usage", and design.md refuses to grow the enum), and an empty
    # `error_code` so `records_error_code` stays False. A Python class name in a
    # field named after Bedrock would invent an attribution `error_message`
    # already carries.
    if isinstance(exc, UsageMissingError):
        return BedrockErrorClass(False, 0, "server_error", "", None,
                                 ERROR_CLASS_USAGE_MISSING, "FAILED")

    if isinstance(exc, ClientError):
        response = getattr(exc, 'response', None) or {}
        code = str((response.get('Error') or {}).get('Code', '') or '')
        http_status = (response.get('ResponseMetadata') or {}).get(
            'HTTPStatusCode')
        if not code:
            # A ClientError with no code is still a Bedrock-side rejection; name
            # it after the exception so the record is searchable rather than
            # blank.
            code = type(exc).__name__
        if code in THROTTLE_ERRORS:
            return BedrockErrorClass(True, MAX_RETRIES, "throttled", code,
                                     http_status, ERROR_CLASS_THROTTLE,
                                     "FAILED")
        if code in SERVER_ERROR_CODES:
            return BedrockErrorClass(True, SERVER_ERROR_MAX_RETRIES,
                                     "server_error", code, http_status,
                                     ERROR_CLASS_SERVER, "FAILED")
        if code in DURATION_LIMIT_ERROR_CODES:
            return BedrockErrorClass(False, 0, "duration_limit", code,
                                     http_status, ERROR_CLASS_DURATION,
                                     "TIMED_OUT")
        # Validation / access denied / not found / model not ready: the request
        # was refused. Terminal, FAILED, and NOT `server_error` — the reason is
        # not recorded at all for this class, see _REASON_RECORDED_CLASSES.
        return BedrockErrorClass(False, 0, "server_error", code, http_status,
                                 ERROR_CLASS_REQUEST, "FAILED")

    if isinstance(exc, ReadTimeoutError):
        # D14. `"ReadTimeout"` is the code design.md fixes so the 56-failure
        # cluster becomes searchable in the ledger (R5.4).
        return BedrockErrorClass(True, READ_TIMEOUT_MAX_RETRIES,
                                 "duration_limit", "ReadTimeout", None,
                                 ERROR_CLASS_DURATION, "TIMED_OUT")

    if isinstance(exc, ConnectTimeoutError):
        return BedrockErrorClass(True, CONNECT_TIMEOUT_MAX_RETRIES,
                                 "server_error", "ConnectTimeout", None,
                                 ERROR_CLASS_SERVER, "FAILED")

    if isinstance(exc, MantleHTTPError):
        # mantle answered with a status (task 7.4, D6). Same two verdicts the
        # `ClientError` rows above reach, for the same reasons — the only
        # difference is that mantle speaks HTTP to us instead of through botocore,
        # so the status is what we have to classify on.
        #
        # The code is `MantleHTTP<status>`: honest about what we actually know.
        # mantle's error bodies are not guaranteed to carry an AWS error code, so
        # naming one would be a guess, while the status is the fact the server
        # stated. It is recorded verbatim in both JobState and the ledger (R5.4),
        # which is what makes a mantle failure searchable at all — before this it
        # was a substring of `error_message`.
        if 500 <= exc.status < 600:
            # "요청이 처리되지 않았다는 서버의 명시적 신호이므로 기존대로 재시도한다".
            # The cap is the gateway's **one** 5xx policy rather than the inner
            # loop's separate `MAX_RETRIES`: two caps for the same condition is
            # the drift a single classification source exists to prevent, and the
            # measured reasoning behind the short cap (see SERVER_ERROR_MAX_RETRIES
            # — every observed 5xx failed all 11 attempts while holding a slot)
            # only gets stronger now that one attempt may last 7200s.
            return BedrockErrorClass(True, SERVER_ERROR_MAX_RETRIES,
                                     "server_error",
                                     f"MantleHTTP{exc.status}", exc.status,
                                     ERROR_CLASS_SERVER, "FAILED")
        # 4xx (and anything else non-5xx): terminal, exactly as the inner loop
        # already treated it ("5xx is transient; 4xx (incl. 401/403/400) is
        # terminal"). Classified `request`, so no Termination_Reason is written —
        # the request was refused, and R5.1 has no value for that.
        return BedrockErrorClass(False, 0, "server_error",
                                 f"MantleHTTP{exc.status}", exc.status,
                                 ERROR_CLASS_REQUEST, "FAILED")

    if isinstance(exc, (urllib.error.URLError, TimeoutError, OSError)):
        # mantle transport timeout (design.md row "mantle 전송 타임아웃"):
        # terminal, because our side giving up does not tell us the server did —
        # it may have completed and billed (U5), and R8.3 forbids the re-call.
        # Task 7.4 removed the inner loop that used to retry this up to 11 times,
        # so this verdict is now the only one that decides, and `usage_source`
        # records that the settled 0 may not be the truth.
        return BedrockErrorClass(False, 0, "duration_limit",
                                 "TransportTimeout", None,
                                 ERROR_CLASS_TRANSPORT, "TIMED_OUT")

    # Not in the table: a JSON decode failure, a bug, any `ValueError` that is
    # not the fail-closed usage raise above. Terminal, FAILED, no invented
    # Bedrock code. The reason slot holds `server_error` so the function is total
    # over R5.1, but `records_reason` is False for this class so nothing is
    # written — today's record shape, unchanged.
    return BedrockErrorClass(False, 0, "server_error", type(exc).__name__,
                             None, ERROR_CLASS_UNKNOWN, "FAILED")


# ---------------------------------------------------------------------------
# Termination classification — SINGLE SOURCE (task 4.4, R5.1/R5.2/R5.3).
#
# `classify_bedrock_error` answers "what does this exception mean?".
# `classify_termination` answers the question the *record* asks: "why did this
# generation end, and what does the job row say?" — for every path, including
# the ones where nothing went wrong. It is the second half of one source rather
# than a second source: the exception branch **delegates** to
# `classify_bedrock_error` and inspects no exception type of its own. Re-deriving
# reasons from types here is exactly the drift task 4.3 removed one layer down.
#
# What it adds beyond `classify_bedrock_error`, which is why it exists:
#
#  * **`complete` and `max_tokens`.** No exception can produce either, so until
#    now a job that ended normally carried no Termination_Reason at all — while
#    R5.1 asks for exactly one of six on *every* termination — and R5.2's
#    `max_tokens` -> truncated -> SUCCEEDED row had no code behind it.
#  * **`truncated`, with three states.** An empty `stop_reason` means *unknown*,
#    not "not truncated" (design.md C6: "`stop_reason: ""`은 "완료"가 아니라
#    미지"). See `_truncated_from_stop_reason`.
#
# PRECEDENCE — total, and the order is the contract rather than an accident of
# the if/elif sequence. Property 6 (task 4.6) states exclusivity and determinism
# over the whole cross product, so every pair has a fixed winner:
#
#   1. `stop_reason == "max_tokens"`  ->  max_tokens   / SUCCEEDED / truncated
#   2. `canceled`                     ->  canceled     / CANCELED
#   3. `deadline_exceeded`            ->  duration_limit / TIMED_OUT
#   4. `exc is not None`              ->  classify_bedrock_error(exc)
#   5. otherwise                      ->  complete     / SUCCEEDED
#
# Why that order, pair by pair:
#
#  * **max_tokens outranks everything.** R5.2 is unconditional ("WHEN Bedrock이
#    `stopReason = max_tokens`를 보고하면"), and Property 6 forbids `max_tokens`
#    ever being reported as `server_error` or `duration_limit`. It is also the
#    only verdict here issued by the party that did the generating: Bedrock said
#    it stopped because the output limit was reached, which means generation
#    finished and the output exists. Everything below it describes what *we* were
#    doing, not what the generation did.
#  * **canceled outranks deadline_exceeded.** A cancel is a stated act by
#    somebody outside this process; a deadline is our own budget arithmetic.
#    R9.1 requires a canceled generation to be recorded `canceled`, and letting
#    an ambient timer outrank it would make cancellation unauditable in exactly
#    the case where both are true. A signal does not carry its cause, and
#    `reclaimed_by = "sigterm"` is what keeps that residual ambiguity visible —
#    the reasoning is in the SIGTERM block below and is not repeated here.
#  * **deadline_exceeded outranks exc.** This is the precedence the deployed code
#    already has, kept rather than invented: the time gate raises
#    `WorkerDeadlineExceeded(...) from e`, so a throttle chain that runs out of
#    *time* is recorded `duration_limit` because the gate is what stopped it.
#    The flag is its own parameter (design.md fixes the signature this way)
#    because a caller can know the deadline elapsed without holding that
#    exception — the watchdog of task 11.1 is such a caller.
#  * **exc outranks the fallback.** An exception means the generation did not end
#    on Bedrock's terms, so `complete` would be a false statement.
#
# Reachability, stated because a total order over unreachable pairs reads like
# over-engineering otherwise: **in this worker no two of the four inputs are ever
# set together.** A response in hand moves the SIGTERM phase to `settling`, so
# `stop_reason` and `canceled` cannot both arrive; the time gate raises before an
# attempt starts, so it never holds a `stop_reason` either; and the failure path
# passes `""` on purpose (see its call site). The order is what makes the
# function *total* for callers that are not this worker — the watchdog, the SFN
# mapping, and Property 6's generator, which visits the full cross product
# including the combinations production cannot reach.
# ---------------------------------------------------------------------------

#: R5.1's closed vocabulary: exactly one of these is recorded per termination.
#:
#: Named here so the closure is visible in one place and `classify_termination`
#: can be read against it — every branch returns a literal from this set, which
#: is what makes the function total over R5.1. design.md refuses to grow it: a
#: condition needing a finer distinction goes in `bedrock_error_code`, not in a
#: seventh reason ("열거를 늘리지 않는다").
TERMINATION_REASONS = frozenset({
    "complete", "max_tokens", "duration_limit", "throttled", "server_error",
    "canceled"})

#: The `stopReason` Bedrock reports when the output-token limit ended generation
#: (R5.2). Compared case-folded so a reader never has to know whether the field
#: arrives as `max_tokens` or `MAX_TOKENS`: Converse sends the former, and an API
#: version sending the latter must not silently turn a truncated job into a
#: complete one — that is a false accounting statement, not a cosmetic slip.
STOP_REASON_MAX_TOKENS = "max_tokens"


def _truncated_from_stop_reason(stop_reason):
    """Truncated_Flag for ``stop_reason``: ``True``, ``False``, or ``None``.

    ``None`` means **unknown**, and the third state is the point (R3.3, R5.5,
    design.md C6). An absent or empty `stop_reason` is what a job row written
    before this feature carries, and what the mantle path can produce; answering
    ``False`` there would state "not truncated" on no evidence at all. design.md
    is explicit that blurring the two makes truncation visibility worthless ("이
    구분을 흐리면 잘림 가시성 자체가 무의미해진다").

    A non-empty value that is not `max_tokens` is ``False``: Bedrock reported a
    stop reason and it was not the output limit. That includes reasons we do not
    recognise — an unfamiliar marker is still a statement that the limit was not
    what stopped generation.

    One nuance worth naming rather than discovering later: the mantle Responses
    path stores its `status` in this field, so an `incomplete` status reads as
    ``False`` here. mantle's own truncation signal lives in
    `incomplete_details.reason`, and mapping it is not this task's — inventing a
    mapping for it here would be a guess dressed as a fact.
    """
    text = str(stop_reason or "").strip()
    if not text:
        return None
    return text.lower() == STOP_REASON_MAX_TOKENS


class TerminationVerdict(NamedTuple):
    """Why a generation ended, and what the job row says about it.

    The first three fields are positional contract: design.md declares
    ``classify_termination(stop_reason, exc, deadline_exceeded, canceled) ->
    (reason, job_status, truncated)`` and callers — Property 6 among them —
    unpack in that order. Everything after is appended, never inserted, the same
    discipline :class:`BedrockErrorClass` follows.

    ``reason`` is always one of :data:`TERMINATION_REASONS`; ``job_status`` is
    always one of Job_State's terminal values; ``truncated`` is ``True`` /
    ``False`` / ``None`` (unknown).

    ``records_reason`` is stored rather than derived from ``error_class`` because
    two different questions decide it. For a plain error verdict it is
    `BedrockErrorClass.records_reason` — a request error records no reason, since
    R5.1 has no value meaning "your request was invalid". For a *termination* the
    caller knows something the exception does not: the time gate's
    `duration_limit` is recorded even when the exception underneath it was a
    validation error, because the gate is what stopped the job.

    ``error`` is the delegated `BedrockErrorClass`, or ``None`` when there was no
    exception. Kept whole so the exception's facts (`error_code`, `http_status`,
    `usage_source`) reach the record without being copied field by field, and the
    aliases below let `finalize_termination` read one object whichever path built
    it.
    """

    reason: str
    job_status: str
    truncated: Optional[bool]
    records_reason: bool
    error_class: str
    error: Optional[BedrockErrorClass]

    @property
    def termination_reason(self) -> str:
        """Alias for :attr:`reason`.

        `finalize_termination` was written against `BedrockErrorClass` and writes
        the same record whichever verdict arrives; an alias is cheaper than two
        readers of two shapes, which is how the cleanup paths drifted apart
        before task 5.3 merged them.
        """
        return self.reason

    @property
    def error_code(self) -> str:
        """Bedrock's code from the delegated verdict, or ``""`` (R5.4)."""
        return "" if self.error is None else self.error.error_code

    @property
    def records_error_code(self) -> bool:
        """Write ``bedrock_error_code``? Only when an exception produced one."""
        return self.error is not None and self.error.records_error_code

    @property
    def http_status(self) -> Optional[int]:
        return None if self.error is None else self.error.http_status

    @property
    def usage_source(self) -> str:
        """`usage_source` from the delegated verdict, or ``""`` (task 7.4)."""
        return "" if self.error is None else self.error.usage_source


def classify_termination(stop_reason, exc=None, deadline_exceeded=False,
                         canceled=False):
    """Why this generation ended (R5.1). Precedence is in the block above.

    Pure: no clock, no environment, no I/O, and it cannot raise —
    `classify_bedrock_error` is total over exception types and ``str()`` is total
    over ``stop_reason``, including garbage.

    ``stop_reason`` is the `stopReason` Bedrock reported **for a response this
    process accepted as the job's outcome**, and ``""`` when there is none. The
    qualifier carries weight: a response whose settlement then failed is not a
    completed job, so the failure path passes ``""`` and lets the exception
    decide (see its call site). ``""`` means *unknown*, never `complete` — the
    reason falls back to `complete` only when nothing else stopped us, and
    ``truncated`` stays ``None`` so nothing claims the output was whole.

    ``exc`` may be any exception, including types the mapping table does not
    name. ``deadline_exceeded`` and ``canceled`` are the two conditions this
    process can know about without an exception to point at.
    """
    error = None if exc is None else classify_bedrock_error(exc)
    truncated = _truncated_from_stop_reason(stop_reason)

    # 1. Bedrock said the output limit stopped it (R5.2): generation finished,
    #    the output exists, and it is truncated. `None` and `False` both fall
    #    through — only a positive statement of truncation wins here.
    if truncated is True:
        return TerminationVerdict("max_tokens", "SUCCEEDED", True, True,
                                  ERROR_CLASS_NONE, error)

    # 2. Somebody stopped us (R9.1). The class is fixed here rather than taken
    #    from `error` so the canceled *record shape* — the `if_not_exists` guard,
    #    `reclaimed_by`, the TASK_CANCELED ledger row — is the same whether the
    #    caller passed the `WorkerSigterm` value or only the flag. For the one
    #    reachable case (the SIGTERM handler, which passes that value) this
    #    triple and `classify_bedrock_error`'s row are identical, so the branch
    #    is not a second opinion about cancellation.
    if canceled:
        return TerminationVerdict("canceled", "CANCELED", truncated, True,
                                  ERROR_CLASS_CANCELED, error)

    # 3. Our own budget ran out (R1.5, R5.3). `error_class` keeps describing the
    #    exception, if there was one — that is a fact about what the process was
    #    doing when the gate fired — while the *reason* names what stopped the
    #    job. `records_reason` is True regardless of the class underneath,
    #    because the gate's verdict is ours and it is one of R5.1's six.
    if deadline_exceeded:
        return TerminationVerdict(
            "duration_limit", "TIMED_OUT", truncated, True,
            ERROR_CLASS_NONE if error is None else error.error_class, error)

    # 4. Delegate to the single source (task 4.3). No exception type is inspected
    #    in this function; that is the whole of its discipline.
    if error is not None:
        return TerminationVerdict(error.termination_reason, error.job_status,
                                  truncated, error.records_reason,
                                  error.error_class, error)

    # 5. Nothing stopped us: generation ended on Bedrock's own terms. `complete`
    #    even when `stop_reason` is empty — R5.1 requires one of six and no other
    #    value fits a job that produced a settled response — while `truncated`
    #    stays `None`, which is how the record admits what it does not know
    #    (design.md C6).
    return TerminationVerdict("complete", "SUCCEEDED", truncated, True,
                              ERROR_CLASS_NONE, None)


# ---------------------------------------------------------------------------
# Settlement arithmetic — SINGLE SOURCE (task 4.5, R6.2/R6.3/R6.8).
#
# The formula that used to live inline in `main()`, between a DynamoDB
# `get_item` above it and three DynamoDB writes below it. Nothing about the
# arithmetic moves: this is an **extraction**, and the number every reachable
# input produces is the number the deployed formula produces, down to the
# Decimal exponent. Two things it deliberately does not do, because HC3 and the
# audit's settled figures both rest on them:
#
#  * It does not re-derive rounding, precision, or the order of operations. The
#    cached branch divides the summed KRW·tokens by 1000 **once at the end**
#    while the plain branch divides each term separately; those two are not the
#    same Decimal expression and both are transcribed as they were.
#  * It does not convert currencies. The pricing row's `*_price_per_1k` values
#    are already KRW per 1000 tokens (the sync writer resolves USD -> KRW before
#    the row is written; `exchange_rate_krw_per_usd` exists in the row for ledger
#    metadata and is read by nothing in this file). A conversion here would
#    double-apply the rate.
#
# What the extraction buys is what Property 1 (task 4.7) needs: the settlement
# claim R6.3 makes — "never more than the cost of the tokens actually reported"
# — becomes checkable over a generated cross product with **nothing mocked**. In
# the inline form the same claim required a DynamoDB fake, an S3 fake and a full
# `main()` run per example, which is why it was never checked at all.
#
# The three settlement shapes, and why each is a branch rather than a special
# case of the others:
#
#   1. **Pending price** (R6.8) — the row exists but the daily sync has not
#      resolved a rate yet. Cost 0, tagged `pricing_source_at_charge = "pending"`
#      so the backfill pass can find and recompute the row later. A *deliberate*
#      zero: we know the tokens, we do not yet know the price.
#   2. **Image model** — settles per returned image, not per token, and the
#      per-image KRW is stored in the row's `input_price_per_1k`.
#   3. **Tokens**, with the cached-input discount applied only when the row
#      carries a cached rate *and* the response reported cached tokens.
#
# And the shape that is **not** a settlement at all: missing usage raises
# (R6.3). See :class:`UsageMissingError` for why inventing a zero there would be
# a different, and much worse, act than the pending zero it sits next to.
# ---------------------------------------------------------------------------

#: `pricing_source_at_charge` value written beside a zero cost when the price was
#: Pending (bedrock-model-auto-sync Req 8.1-8.3). Named so the settlement writer
#: and the tests that assert the tag read the same literal.
PRICING_SOURCE_PENDING = "pending"


class UsageTokens(NamedTuple):
    """The three counts settlement reads, already validated.

    ``cached_tokens`` is 0 for every Converse job — only the mantle Responses
    path reports it — and it is never negative, so the cached branch can trust
    the ``> 0`` test it turns on.
    """

    input_tokens: int
    output_tokens: int
    cached_tokens: int


def _token_count(value):
    """``value`` as a non-negative integer count, or ``None`` if it is not one.

    Everything that reaches settlement is a JSON integer: Converse reports
    `usage.inputTokens` / `outputTokens` as ints and the mantle path already
    refuses anything else (`_invoke_mantle_responses`). So this is a validator,
    not a coercion layer — its job is to answer "is this a token count?" for the
    fail-closed rule, and every reachable input passes through it unchanged.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return None
    try:
        count = int(value)
    except (ValueError, OverflowError, ArithmeticError):
        return None  # NaN / Infinity
    if count != value or count < 0:
        # Fractional or negative token counts are not counts. Negative is the
        # one worth naming: a negative input count would make the cached branch
        # bill *more* than the tokens reported, which is the exact direction
        # R6.3 forbids, and no valid usage report can produce it.
        return None
    return count


def require_usage_tokens(usage, job_id=""):
    """Validated :class:`UsageTokens`, or raise :class:`UsageMissingError`.

    Pure: no clock, no environment, no I/O. ``job_id`` only names the job in the
    message, exactly as the inline check did.

    **Fail-closed is the whole function** (R6.3). It does not default to zero
    tokens and its caller must not: a settled zero is a statement that the
    generation cost nothing, and for a response we could not read that statement
    is false. The job fails instead, and `classify_bedrock_error` tags the record
    `usage_source = "missing"` so the gap is auditable rather than invisible.

    One source for the rule, called from both places that need it: `main()`'s
    settlement, which needs the counts for the usage/ledger/result writes, and
    `compute_settled_cost`, which must be independently fail-closed because
    Property 1 calls it with nothing around it.
    """
    for_job = f" for job {job_id}" if job_id else ""
    if not isinstance(usage, Mapping) or 'inputTokens' not in usage \
            or 'outputTokens' not in usage:
        raise UsageMissingError(
            f"Bedrock response missing usage field{for_job}. "
            "Cannot write settled accounting without actual token counts.")
    counts = {}
    for key in ('inputTokens', 'outputTokens'):
        counts[key] = _token_count(usage[key])
        if counts[key] is None:
            raise UsageMissingError(
                f"Bedrock response reported an unreadable {key} "
                f"({usage[key]!r}){for_job}. Cannot write settled accounting "
                "without actual token counts.")
    # Absent or null cached tokens mean "none reported", which is the Converse
    # case and not a missing usage report — `int(x or 0)`, as the inline formula
    # had it. A *present but unreadable* value is a broken report, so it fails
    # closed with the other two.
    raw_cached = usage.get('cachedInputTokens', 0) or 0
    cached_tokens = _token_count(raw_cached)
    if cached_tokens is None:
        raise UsageMissingError(
            f"Bedrock response reported an unreadable cachedInputTokens "
            f"({raw_cached!r}){for_job}. Cannot write settled accounting "
            "without actual token counts.")
    return UsageTokens(counts['inputTokens'], counts['outputTokens'],
                       cached_tokens)


def is_pending_pricing(pricing):
    """Is this pricing row Pending — i.e. settle at zero and tag it (R6.8)?

    Pure, and the same four-way test the inline code performed: either price
    absent, or either of the two status fields saying `pending`. All four have to
    stay because the sync writes them independently — a row can carry both prices
    and still be marked pending, and a Tier_1 row can be missing one price.

    Kept as its own predicate rather than folded into the cost so the *tag* is
    observable without re-deriving it: `compute_settled_cost` returns a Decimal
    (design.md fixes that signature), and the caller has to write
    `pricing_source_at_charge` and emit the `PendingPricingCostCharged` metric
    from the same answer. Deriving it twice is how two readers of one condition
    drift apart.
    """
    pricing = pricing or {}
    return (
        pricing.get('input_price_per_1k') is None
        or pricing.get('output_price_per_1k') is None
        or str(pricing.get('pricing_status', '')).lower() == PRICING_SOURCE_PENDING
        or str(pricing.get('pricing_source', '')).lower() == PRICING_SOURCE_PENDING
    )


def compute_settled_cost(usage, pricing, *, image_count=0):
    """Settled KRW for one generation. Pure — no DynamoDB, no S3, no clock.

    ``usage`` is the Converse-shaped usage mapping (`inputTokens`,
    `outputTokens`, optionally `cachedInputTokens`); ``pricing`` is the
    ModelPricing row. ``image_count`` is 0 for a token settlement and the number
    of returned images for an image model, whose per-image KRW lives in the row's
    `input_price_per_1k`.

    Order of the two guards is load-bearing and matches the deployed code: usage
    is validated **first**, so a Pending price cannot turn an unreadable usage
    report into a settled zero. The two zeros mean opposite things —
    :class:`UsageMissingError` says "there is no number", the pending branch says
    "the number is zero until the rate lands" — and one line separates them.

    Non-negative by construction (Property 1): the counts are validated
    non-negative and `image_count` is a count, so the result can only go negative
    if a pricing row carries a negative rate. That would be a pricing-table
    integrity failure, and inventing a clamp for it here would hide it from the
    one place that can fix it.
    """
    counts = require_usage_tokens(usage)

    # 1. Pending price: a deliberate zero, tagged by the caller (R6.8). Checked
    #    before the shape branches because it applies to all of them — an image
    #    model with an unresolved price settles at zero too.
    if is_pending_pricing(pricing):
        return Decimal(0)

    input_price = Decimal(str(pricing.get('input_price_per_1k')))

    # 2. Image models settle per image (e.g. Creative Upscale = 889.5 KRW each).
    #    `image_count = 0` means "not an image settlement", which is why the
    #    Converse path can pass the default. `_invoke_image_model` raises before
    #    settlement when Bedrock returns no images, so an image response with a
    #    zero count does not reach here; if it ever did, both this branch and the
    #    token branch below would answer zero.
    if image_count:
        return input_price * Decimal(image_count)

    output_price = Decimal(str(pricing.get('output_price_per_1k')))

    # 3. Cached-input discount (parity with the sync /openai/responses path):
    #    applied only when the pricing row carries a cached rate AND the response
    #    reported cached tokens. Converse jobs never set `cachedInputTokens`, so
    #    they keep the exact original expression in the fall-through.
    cached_price_raw = pricing.get('cached_input_price_per_1k')
    if cached_price_raw is not None and counts.cached_tokens > 0:
        cached_price = Decimal(str(cached_price_raw))
        std_in = counts.input_tokens - counts.cached_tokens
        if std_in < 0:
            # More cached than input reported. Clamped rather than rejected,
            # exactly as before: the cached tokens are still billed at the cached
            # rate, and no negative share is subtracted.
            std_in = 0
        return (
            (Decimal(std_in) * input_price)
            + (Decimal(counts.cached_tokens) * cached_price)
            + (Decimal(counts.output_tokens) * output_price)
        ) / Decimal(1000)
    return (
        (Decimal(counts.input_tokens) * input_price / 1000)
        + (Decimal(counts.output_tokens) * output_price / 1000)
    )


def _env_seconds(name, default):
    """Read a non-negative seconds value from the environment.

    Anything unparseable or negative falls back to ``default`` and says so in
    the log rather than failing the job: a typo in a task-definition
    environment variable must not be able to kill every generation, and a
    negative deadline would make the gate fire before the first attempt.
    """
    raw = os.environ.get(name, '')
    if raw == '':
        return int(default)
    try:
        value = int(float(raw))
    except (TypeError, ValueError):
        value = -1
    if value < 0:
        log_structured("warning", "invalid_budget_env", env_var=name,
                       value=raw, fallback=int(default))
        return int(default)
    return value


def _bedrock_client_for_attempt(region, read_timeout, cache):
    """A bedrock-runtime client whose ``read_timeout`` is ``read_timeout``.

    **Why a new client instead of mutating ``BEDROCK_CONFIG``**: botocore
    consumes ``read_timeout`` when the endpoint's connection pool is built, i.e.
    at client construction. Assigning to ``config.read_timeout`` afterwards
    changes the object and nothing else — the live client keeps the timeout it
    was born with — so a derived per-attempt timeout can only be applied by
    constructing a client for it. ``Config.merge`` is used so
    ``retries={"max_attempts": 0}`` and ``connect_timeout=10`` are inherited
    from ``BEDROCK_CONFIG`` and the module constant stays at 1800.

    **Cost**: one client per distinct granted timeout, at most
    ``MAX_RETRIES + 1`` per process, and the botocore service model is loaded
    once per process and cached by the session — so the extra cost is tens of
    milliseconds against attempts measured in minutes. ``cache`` keyed on the
    timeout keeps a chain of identical grants (the common case: every attempt
    gets the full 1800) down to a single construction.
    """
    client = cache.get(read_timeout)
    if client is None:
        client = boto3.client(
            'bedrock-runtime', region_name=region,
            config=BEDROCK_CONFIG.merge(Config(read_timeout=read_timeout)))
        cache[read_timeout] = client
    return client


# ---------------------------------------------------------------------------
# OpenAI Responses (bedrock-mantle) support — ADDITIVE. The converse path below
# is unchanged; for these models the worker calls the mantle Responses API over
# SigV4 instead of bedrock-runtime Converse, then normalizes the result to the
# Converse usage shape so all downstream settlement/ledger code is reused as-is.
# Mirrors lambda/handler.py _responses_* (same models, same per-model region).
# ---------------------------------------------------------------------------
import urllib.request
import urllib.error
import botocore.session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

_RESPONSES_ALLOWLIST = frozenset({
    "openai.gpt-5.5", "openai.gpt-5.5-2026-04-23",
    "openai.gpt-5.4", "openai.gpt-5.4-2026-03-05",
    # gpt-5.6 family (GA 2026-07-13). Sol is In-Region only in us-east-1 /
    # us-east-2; Terra and Luna add us-west-2. See _RESPONSES_REGION_OVERRIDE.
    "openai.gpt-5.6-sol", "openai.gpt-5.6-terra", "openai.gpt-5.6-luna",
    "openai.gpt-oss-120b", "openai.gpt-oss-20b",
    "openai.gpt-oss-safeguard-120b", "openai.gpt-oss-safeguard-20b",
})
# gpt-5.5 is published only in us-east-2; everything else defaults to us-west-2.
# gpt-5.4: us-west-2 engine availability is intermittent (mantle returns 400
# "Engine not found" under load); us-east-2 serves gpt-5.4 reliably. Route it
# cross-region to us-east-2 for parity with gpt-5.5. LIVE-CONFIRMED 2026-07.
# gpt-5.6 Sol is In-Region only in us-east-1 / us-east-2 (NOT us-west-2), so it
# is routed cross-region to us-east-2. Terra/Luna are also in us-west-2 and use
# the default region (not overridden).
_RESPONSES_REGION_OVERRIDE = {
    "openai.gpt-5.5": "us-east-2",
    "openai.gpt-5.5-2026-04-23": "us-east-2",
    "openai.gpt-5.4": "us-east-2",
    "openai.gpt-5.4-2026-03-05": "us-east-2",
    "openai.gpt-5.6-sol": "us-east-2",
}
_RESPONSES_PATH = "/openai/v1/responses"
_RESPONSES_SIGV4_SERVICE = "bedrock"

# `_RESPONSES_HTTP_TIMEOUT = 1800` used to live here and is **gone** (task 7.4).
#
# It was a second per-attempt ceiling: a static 1800 that no budget could see and
# no task-definition revision could move, so `openai.*` models were the one
# family the ceiling rise of tasks 7.1/7.2 could not reach. Since the whole point
# of raising the ceiling is that it be model-independent (design.md C8-c: "상한
# 인상은 모델 무관하다"), the value now arrives as `_invoke_mantle_responses`'
# `timeout` argument — `min(model Duration_Ceiling, injected cap, remaining
# budget)`, the same expression the converse path gets.
#
# Deleted rather than kept as a default. `attempt_ceiling_seconds` already answers
# 7200 for this family and `_env_seconds` already falls back to it when the task
# definition injects nothing, so a module-level 1800 would have no job left
# except to be picked up by mistake — and picking it up would silently restore
# the wall this task removes.


def _is_responses_model(model_id: str) -> bool:
    return model_id in _RESPONSES_ALLOWLIST


def _responses_region(model_id: str) -> str:
    return _RESPONSES_REGION_OVERRIDE.get(model_id, "us-west-2")


def _invoke_mantle_responses(model_id: str, params: dict, timeout) -> dict:
    """Call the bedrock-mantle OpenAI Responses API for ``model_id`` and return
    a Converse-shaped dict ``{"usage": {"inputTokens", "outputTokens"},
    "output": <responses payload>, "stopReason"}`` so the existing settlement
    path is reused unchanged. SigV4 with the Fargate task role (no API key).

    ``timeout`` is the seconds this **single** attempt may take, and ``main()``
    passes the same derived grant the converse path gets: ``min(model
    Duration_Ceiling, injected cap, remaining budget)``. That is the whole of
    task 7.4's first half — the static 1800 that used to be applied here was the
    reason `openai.*` models could not receive the raised ceiling. Required
    rather than defaulted: a default would be a second ceiling waiting to be
    used by accident, and there is exactly one caller.

    **The internal retry loop is gone, and that is the second half.** It ran up
    to ``MAX_RETRIES + 1`` attempts *inside* one attempt of the outer loop, which
    made three things wrong at once:

      * **Double retry.** Outer attempts x inner attempts is up to 121 mantle
        calls for one job. The audit's own reasoning about retry chains
        (`retry_count` never exceeding 10) could not even see the inner ones.
      * **The time gate could not see it either.** `main()` grants one attempt a
        timeout and then trusts it to come back; an inner loop could spend that
        grant repeatedly and walk straight past the worker's total deadline.
        With the grant now up to 7200s that is 22 hours of possible overrun —
        exactly D5, one level down.
      * **A transport timeout was retried up to 11 times, each attempt possibly
        billed in full.** Our socket giving up says nothing about whether the
        server finished and charged (U5), so R8.3 forbids the re-call. The
        classifier has said so since task 4.3; this loop was overruling it.

    So the outer loop is the only retry loop now: one call per invocation, the
    exception classified by `classify_bedrock_error`, and the re-call decision
    made by the budget. mantle 5xx is still retried (with backoff) because a 5xx
    is the server stating the request was not processed; a transport timeout and
    a 4xx are terminal.
    """
    region = _responses_region(model_id)
    host = f"bedrock-mantle.{region}.api.aws"
    url = f"https://{host}{_RESPONSES_PATH}"

    # Build the Responses request from the stored payload: keep input + tuning
    # fields, set `model`, force buffered, drop Converse-only keys.
    fwd = {k: v for k, v in (params or {}).items()
           if k not in ("modelId", "messages", "system", "inferenceConfig",
                        "toolConfig", "estimated_input_tokens")}
    fwd["model"] = model_id
    fwd.pop("stream", None)
    body = json.dumps(fwd).encode("utf-8")

    creds = botocore.session.Session().get_credentials()
    if creds is None:
        raise RuntimeError("no task-role credentials for mantle SigV4")

    headers = {"Content-Type": "application/json", "Host": host}
    req = AWSRequest(method="POST", url=url, data=body, headers=headers)
    SigV4Auth(creds, _RESPONSES_SIGV4_SERVICE, region).add_auth(req)
    r = urllib.request.Request(url, data=body, headers=dict(req.headers), method="POST")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        # Status as data, not as a formatted string: `MantleHTTPError` is what
        # lets the single classification source separate a retryable 5xx from a
        # terminal 4xx. `raise ... from e` keeps the original traceback.
        raise MantleHTTPError(e.code, detail) from e
    # `(URLError, TimeoutError, OSError)` is deliberately NOT caught: it
    # propagates to `main()`'s outer handler, where `classify_bedrock_error`
    # answers `transport` -> terminal, `duration_limit`, `TIMED_OUT`,
    # `bedrock_error_code = "TransportTimeout"`, `usage_source = "unavailable"`.
    # Catching it here is what used to retry a possibly-billed call.
    usage = payload.get("usage") or {}
    in_tok = usage.get("input_tokens")
    out_tok = usage.get("output_tokens")
    if not isinstance(in_tok, int) or not isinstance(out_tok, int):
        # Fail-closed: no zero accounting on a response we cannot read. Terminal
        # and FAILED with no invented Bedrock code, exactly as before — task 4.5
        # only gave the condition its own type, so this refusal and settlement's
        # record the same `usage_source = "missing"` instead of the mantle one
        # being indistinguishable from a bug in us.
        raise UsageMissingError(
            f"mantle response missing usage tokens for {model_id}")
    return {
        "usage": {"inputTokens": in_tok, "outputTokens": out_tok,
                  "cachedInputTokens": int((usage.get("input_tokens_details") or {}).get("cached_tokens", 0) or 0)},
        "output": payload,
        "stopReason": payload.get("status", ""),
    }


# ---------------------------------------------------------------------------
# Image InvokeModel support (async /invoke-jobs) — ADDITIVE. For Stability
# image-edit models whose sync latency (e.g. Creative Upscale ~58s, Conservative
# ~40s) exceeds the 29s API Gateway limit. The worker calls bedrock-runtime
# InvokeModel via the system-defined cross-region inference profile (bare ->
# us.<id>, since these models reject on-demand invocation) and settles per-image
# (per-image KRW is stored in the pricing row's input_price_per_1k). The
# converse / mantle-responses paths are untouched.
# ---------------------------------------------------------------------------
_IMAGE_PROFILE_REMAP = {
    "stability.stable-conservative-upscale-v1:0": "us.stability.stable-conservative-upscale-v1:0",
    "stability.stable-creative-upscale-v1:0":     "us.stability.stable-creative-upscale-v1:0",
    "stability.stable-fast-upscale-v1:0":         "us.stability.stable-fast-upscale-v1:0",
    "stability.stable-image-control-sketch-v1:0": "us.stability.stable-image-control-sketch-v1:0",
    "stability.stable-image-control-structure-v1:0": "us.stability.stable-image-control-structure-v1:0",
    "stability.stable-image-erase-object-v1:0":   "us.stability.stable-image-erase-object-v1:0",
    "stability.stable-image-inpaint-v1:0":        "us.stability.stable-image-inpaint-v1:0",
    "stability.stable-image-remove-background-v1:0": "us.stability.stable-image-remove-background-v1:0",
    "stability.stable-image-search-recolor-v1:0": "us.stability.stable-image-search-recolor-v1:0",
    "stability.stable-image-search-replace-v1:0": "us.stability.stable-image-search-replace-v1:0",
    "stability.stable-image-style-guide-v1:0":    "us.stability.stable-image-style-guide-v1:0",
    "stability.stable-outpaint-v1:0":             "us.stability.stable-outpaint-v1:0",
    "stability.stable-style-transfer-v1:0":       "us.stability.stable-style-transfer-v1:0",
}
# Image models settle per-image: bare ids + their us. profile ids + other
# image-gen models that may be routed async.
_IMAGE_MODELS = frozenset(set(_IMAGE_PROFILE_REMAP.keys()) | set(_IMAGE_PROFILE_REMAP.values()) | {
    "stability.sd3-5-large-v1:0", "stability.stable-image-core-v1:1",
    "stability.stable-image-ultra-v1:1", "amazon.titan-image-generator-v2:0",
    "amazon.nova-canvas-v1:0",
})


def _is_image_model(model_id: str) -> bool:
    return model_id in _IMAGE_MODELS


def _invoke_image_model(model_id: str, params: dict, region: str) -> dict:
    """Call bedrock-runtime InvokeModel for an image model and return a
    settlement-shaped dict. Uses the inference-profile remap for edit models.
    Cost is per-image (count of returned images).

    **Keeps ``BEDROCK_CONFIG`` (read_timeout 1800) rather than the derived
    per-attempt timeout — decided in task 7.1, deliberately out of scope.**

    * These calls are seconds, not hours: the measured latencies that pushed
      these models onto the async path in the first place are Creative Upscale
      ~58s and Conservative ~40s, both against a 29s API Gateway limit. 1800 is
      already ~30x the slowest observed call, so a longer ceiling buys nothing
      an image request can use.
    * There is nothing to declare for them. `MODEL_DURATION_CEILING_SECONDS`
      holds text-generation families; ``stability.*`` and
      ``amazon.titan-image-generator-v2:0`` match no marker and would resolve to
      the unknown default. R1.1 asks for a ceiling that is *true*, and 7200 for
      a 58-second call would be a declaration with no measurement behind it.
    * R1.4/HC2 are about a single **generation** running past an hour. An image
      InvokeModel has no output-token stream, no `stopReason = max_tokens`, and
      no throughput to extrapolate; it is not the request class this ceiling
      exists for.

    The time gate above still bounds this path in the way that matters: the loop
    refuses to *start* an image attempt once the remaining budget is under the
    minimum viable window, so an image job cannot outlive the worker's total
    deadline. What it does not do is hand the grant to this client. If a future
    image model ever runs long enough for that gap to matter, the fix is one
    argument — pass the granted timeout in and merge it the way
    `_bedrock_client_for_attempt` does — and a declared ceiling to go with it.
    """
    inner = params.get("body")
    if not isinstance(inner, dict):
        inner = {k: v for k, v in (params or {}).items()
                 if k not in ("modelId", "body", "estimated_images",
                              "estimated_input_tokens")}
    invoke_id = _IMAGE_PROFILE_REMAP.get(model_id, model_id)
    br = boto3.client("bedrock-runtime", region_name=region, config=BEDROCK_CONFIG)
    resp = br.invoke_model(modelId=invoke_id, body=json.dumps(inner),
                           contentType="application/json", accept="application/json")
    payload = json.loads(resp["body"].read().decode("utf-8"))
    images = payload.get("images") if isinstance(payload, dict) else None
    n = len(images) if isinstance(images, list) else 0
    if n <= 0:
        raise ValueError(f"image model {model_id} returned no images")
    return {
        "_is_image": True,
        "_image_count": n,
        "usage": {"inputTokens": 0, "outputTokens": 0},
        # Store result WITHOUT the base64 image bytes (too large for job state);
        # keep seeds/finish_reasons + count. Full images are the caller's payload.
        "output": {"seeds": payload.get("seeds"),
                   "finish_reasons": payload.get("finish_reasons"),
                   "image_count": n,
                   "images": images},
        "stopReason": "COMPLETE",
    }


def log_structured(level, message, **kwargs):
    entry = {"level": level, "message": message, "timestamp": datetime.now(timezone.utc).isoformat()}
    entry.update(kwargs)
    print(json.dumps(entry, default=str))


def current_month_kst():
    return datetime.now(KST).strftime('%Y-%m')


def is_retryable(error):
    """Delegates to `classify_bedrock_error` — no second opinion lives here.

    It used to compare `error.response['Error']['Code']` against the literal
    `RETRYABLE_ERRORS` set, which made it a second, independent classifier: it
    called a `ReadTimeoutError` terminal (no `.response` at all) while the fix
    for D14 calls it retryable. Two sources would have to be kept in step by
    hand, so this one now asks the single source. The visible consequence is
    that transport timeouts answer True here as well, which is the D14 fix
    itself; no caller in this module reads this function today.
    """
    return classify_bedrock_error(error).retryable


def backoff_delay(attempt):
    import random
    delay = min(BASE_DELAY * (2 ** attempt), MAX_DELAY)
    return random.uniform(delay * 0.8, delay)


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


# ---------------------------------------------------------------------------
# Termination cleanup — ONE path, two callers (task 5.3, D4, R9.1/R7.5/R5.1)
#
# The order below is the order `main()`'s outer handler already used: release the
# reservation, write the JobState record, append to the ledger, release the
# semaphore slot. It is now a function because the SIGTERM handler needs exactly
# the same four writes, and two independent cleanup paths mean one of them goes
# stale — the failure path gains a field, the signal path does not, and nobody
# notices until an audit asks why canceled jobs have no `termination_reason`.
#
# What differs between the two callers is derived from the verdict, not passed in
# as flags: the `canceled` class writes `reclaimed_by`, guards against
# overwriting somebody else's terminal record, and appends `TASK_CANCELED`
# instead of `TASK_FAILED`. Everything else — the order, the "swallow and carry
# on" discipline, the field names — is shared, so the failure path's behaviour is
# byte-for-byte what it was.
# ---------------------------------------------------------------------------

#: Exit status when SIGTERM stopped us: 128 + SIGTERM(15), the shell convention.
#:
#: **Non-zero on purpose, and the reason is not cosmetic.** With the Step
#: Functions `ecs:runTask.sync` integration, exit 0 is reported as task *success*
#: and the state machine advances to `UpdateJobSucceeded`, which sets
#: `status = SUCCEEDED` unconditionally (`stepfunctions.tf`) — a canceled
#: generation would be recorded as a completed one. A non-zero exit routes to the
#: `Catch` instead, where `UpdateJobFailed` writes FAILED while preserving
#: `error_message` (task 5.2). FAILED over our CANCELED is a loss of precision;
#: SUCCEEDED over it would be a false accounting statement.
#:
#: In the dominant case this never arises: a user cancel calls `stop_execution`
#: first, so the execution is already ABORTED and neither branch runs — the
#: record this worker wrote is the final one.
EXIT_CODE_SIGTERM = 143

#: JobState `reclaimed_by` value for this path (design.md §예외 → 분류 → 기록
#: 매핑, and §JobState 신규 필드 where `reclaimed_by` is the reclaimer-audit
#: field). Additive: no existing field changes name, type or meaning.
RECLAIMED_BY_SIGTERM = "sigterm"

#: Terminal JobState values the SIGTERM record must not overwrite.
#:
#: `CANCELED` is deliberately absent. The cancel Lambda writes it *after* calling
#: `stop_execution`, so at SIGTERM time the row is usually still `RUNNING` and
#: sometimes already `CANCELED`; in the second case this path must still be able
#: to add `termination_reason` and `reclaimed_by`, which R9.1 requires and the
#: Lambda does not write. The other three mean somebody else already reached a
#: verdict with more information than a signal carries.
_FOREIGN_TERMINAL_STATUSES = ("SUCCEEDED", "FAILED", "TIMED_OUT")


class TerminationContext:
    """Everything the four cleanup writes need, in one object.

    Built by ``main()`` once the tables exist and published to the SIGTERM
    handler through :data:`_SIGTERM_STATE`. Mutable — ``retry_count`` moves as
    the retry loop advances, and the handler has to record the count as of the
    moment the signal landed, not zero.
    """

    __slots__ = ("job_id", "request_id", "principal_id", "model_id",
                 "job_table", "usage_table", "ledger_table", "dynamodb",
                 "semaphore_table", "started_at", "retry_count")

    def __init__(self, *, job_id, request_id, principal_id, model_id,
                 job_table, usage_table, ledger_table, dynamodb,
                 semaphore_table, started_at):
        self.job_id = job_id
        self.request_id = request_id
        self.principal_id = principal_id
        self.model_id = model_id
        self.job_table = job_table
        self.usage_table = usage_table
        self.ledger_table = ledger_table
        self.dynamodb = dynamodb
        self.semaphore_table = semaphore_table
        self.started_at = started_at
        self.retry_count = 0


def finalize_termination(ctx, verdict, error_message, retry_count, duration_s):
    """Write the termination record and give back both held resources.

    Reservation → JobState → ledger → semaphore, in that order, each step
    independently guarded so a failure in one still lets the others run. That
    ordering is not arbitrary: the reservation is the resource whose leak this
    task exists to stop (R7.5), so it goes first and does not depend on the
    record write succeeding.

    ``verdict`` is a :class:`TerminationVerdict` since task 4.4 — both callers
    now build it with `classify_termination`. A `BedrockErrorClass` still works
    unchanged: the two shapes answer the same seven names this function reads
    (`error_class`, `job_status`, `termination_reason`, `records_reason`,
    `error_code`, `records_error_code`, `usage_source`), which is why the switch
    needed no change here. Nothing is re-derived from either object.

    Returns ``(termination_reason, bedrock_error_code, record_written)``. The
    SIGTERM handler logs it after the fact, which is how a completed cleanup is
    told apart from one the stop grace cut in half — the failure path logs its
    verdict before cleanup instead, and that line is left exactly as it was.
    """
    canceled = verdict.error_class == ERROR_CLASS_CANCELED
    termination_reason = (verdict.termination_reason
                          if verdict.records_reason else "")
    bedrock_error_code = (verdict.error_code
                          if verdict.records_error_code else "")
    # Additive, and empty for every verdict except a transport give-up (task
    # 7.4). Absence keeps today's record shape exactly; presence says "the 0 we
    # settled may not be what was spent" (R6.4, U5).
    usage_source = verdict.usage_source
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Reservation (R7.5). Same swallow-and-continue as before: a failure here
    #    is picked up by the TTL sweep, which task 5.1 taught to respect live
    #    jobs, and must not cost us the record write.
    try:
        month = current_month_kst()
        pk = f"{ctx.principal_id}#{month}"
        ctx.usage_table.delete_item(
            Key={"principal_id_month": pk,
                 "model_id": f"__reserved__{ctx.job_id}"})
    except Exception:
        pass

    # 2. JobState.
    record_written = False
    try:
        expr_values = {
            ":status": verdict.job_status, ":err": error_message[:500],
            ":ts": now_iso, ":rc": retry_count,
        }
        kwargs = {}
        if canceled:
            # `if_not_exists(error_message, ...)` follows task 5.2's decision for
            # the same field: the cancel Lambda's "canceled by user" is a better
            # message for a user than "SIGTERM received", so ours only fills a
            # gap. `reclaimed_by` and `termination_reason` are unconditional —
            # they are what makes the stop auditable.
            update_expr = (
                "SET #s = :status, "
                "error_message = if_not_exists(error_message, :err), "
                "completed_at = :ts, updated_at = :ts, retry_count = :rc, "
                "termination_reason = :tr, reclaimed_by = :rb")
            expr_values[":tr"] = termination_reason
            expr_values[":rb"] = RECLAIMED_BY_SIGTERM
            guards = []
            for index, status in enumerate(_FOREIGN_TERMINAL_STATUSES):
                placeholder = f":fin{index}"
                guards.append(placeholder)
                expr_values[placeholder] = status
            kwargs["ConditionExpression"] = (
                "attribute_not_exists(#s) OR NOT #s IN (%s)"
                % ", ".join(guards))
        else:
            update_expr = ("SET #s = :status, error_message = :err, "
                           "completed_at = :ts, updated_at = :ts, "
                           "retry_count = :rc")
            if termination_reason:
                update_expr += ", termination_reason = :tr"
                expr_values[":tr"] = termination_reason
            if bedrock_error_code:
                update_expr += ", bedrock_error_code = :bec"
                expr_values[":bec"] = bedrock_error_code
        # Outside the branch on purpose: both callers write it if the verdict has
        # one. Nothing produces `usage_source` on the canceled path today, so the
        # SIGTERM record is unchanged — but the field is not the failure path's
        # private property, and putting it in one branch is how the two copies of
        # this cleanup drifted apart before they were merged.
        if usage_source:
            update_expr += ", usage_source = :us"
            expr_values[":us"] = usage_source
        ctx.job_table.update_item(
            Key={"job_id": ctx.job_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues=expr_values,
            **kwargs)
        record_written = True
    except Exception as e:
        # The guard firing is not an error: it means a terminal record already
        # exists and ours would be less informed. Say so, because "nothing was
        # written" and "something better was already written" are different
        # facts and only one of them needs looking at.
        if canceled:
            code = ""
            if isinstance(e, ClientError):
                code = str(((getattr(e, 'response', None) or {}).get('Error')
                            or {}).get('Code', '') or '')
            log_structured(
                "warning",
                "sigterm_record_skipped" if code == "ConditionalCheckFailedException"
                else "sigterm_record_failed",
                job_id=ctx.job_id, error=str(e)[:200], error_code=code)

    # 3. Ledger — PutItem only, so the ledger stays append-only (R11.2).
    try:
        if canceled:
            ledger_item = {
                "request_id": f"{ctx.request_id}#TASK_CANCELED",
                "timestamp": now_iso,
                "principal_id": ctx.principal_id, "model_id": ctx.model_id,
                "event_type": "TASK_CANCELED", "job_id": ctx.job_id,
                "decision": "CANCELED",
                "denial_reason": error_message[:200],
                "source_path": "gateway-async",
                "duration_ms": duration_s * 1000,
                "reclaimed_by": RECLAIMED_BY_SIGTERM,
            }
        else:
            ledger_item = {
                "request_id": f"{ctx.request_id}#TASK_FAILED",
                "timestamp": now_iso,
                "principal_id": ctx.principal_id, "model_id": ctx.model_id,
                "event_type": "TASK_FAILED", "job_id": ctx.job_id,
                "decision": "DENY", "denial_reason": error_message[:200],
                "source_path": "gateway-async",
                "duration_ms": duration_s * 1000,
            }
        if termination_reason:
            ledger_item["termination_reason"] = termination_reason
        if bedrock_error_code:
            # R5.4: the code Bedrock returned, verbatim, in the ledger too.
            # For 408 this is the only place U2 can be measured from.
            ledger_item["bedrock_error_code"] = bedrock_error_code
        if usage_source:
            # R6.4 / R6.7. The ledger is the append-only record the spend is
            # audited from, so the "we may not know what this cost" tag has to be
            # here and not only on the mutable JobState row.
            ledger_item["usage_source"] = usage_source
        ctx.ledger_table.put_item(Item=ledger_item)
    except Exception:
        pass

    # 4. Semaphore slot.
    _release_semaphore_slot(ctx.dynamodb, ctx.semaphore_table, ctx.job_id)

    return termination_reason, bedrock_error_code, record_written


# ---------------------------------------------------------------------------
# SIGTERM handling (task 5.3, D4, R9.1/R9.2, R7.5)
#
# Why this exists: the worker had no handler, and Fargate's default stop grace is
# 30s. `handle_converse_job_cancel` calls `stop_execution`, which stops the task,
# so **every user cancel** used to end with the container killed mid-call — no
# termination record, and the reservation left for the TTL sweep to find. The
# window grows in proportion to the generation ceiling, which is why this lands
# before task 7 raises it.
#
# Two runtime facts shape the design, both measured rather than assumed (a small
# probe: main thread blocked in a botocore socket read against a server that
# accepts and never answers, SIGTERM fired from a timer thread):
#
#  * **The handler does run, promptly, mid-call.** It fired at +1.000s of a 1.0s
#    timer while the process sat in `recv()`. PEP 475 turns the interrupted
#    syscall into a handler call and then resumes the syscall, so a buffered
#    Converse does not delay delivery.
#  * **Doing the cleanup inside the handler works; raising out of it does not.**
#    A boto3 call issued from inside the handler completed in 5ms — including on
#    the *same client* whose request was mid-flight, so the connection pool does
#    not deadlock (botocore's pool is built with `block=False`, so a second
#    request opens a second connection rather than waiting). A raised exception,
#    by contrast, is swallowed and re-raised as `HTTPClientError` by
#    `botocore/httpsession.py` — see :class:`WorkerSigterm`.
#
# **Why the reason is always `canceled`, and not sometimes `duration_limit`.**
# The question is whether this process can tell a user cancel (`stop_execution`)
# from any other task stop (`StopTask`). It cannot, and the reasons are worth
# writing down rather than rediscovering:
#
#  * The signal carries no cause. A Python handler receives ``(signum, frame)``
#    and no ``siginfo``, and ECS delivers the identical SIGTERM whichever door it
#    came through.
#  * Reading JobState would not settle it either — and would be wrong in the
#    common case. `handle_converse_job_cancel` calls `stop_execution` *before* it
#    writes `CANCELED`, so at signal time the row is usually still `RUNNING`: a
#    read would answer "not a cancel" precisely when it is one.
#  * The producers are enumerable, and one dominates. These are one-shot
#    `RunTask` tasks with `LaunchType = "FARGATE"` (`stepfunctions.tf`) — no
#    service deployment, no scale-in, no Spot reclaim. That leaves the cancel
#    path, a Step Functions timeout abort, and AWS infrastructure maintenance,
#    and the cancel path is the one that fires routinely.
#  * For the other two, a better-informed writer follows us. A `States.Timeout`
#    abort is caught by the state machine, which writes `TIMED_OUT` +
#    `duration_limit` itself (task 5.4); an execution that vanishes is the
#    watchdog's to label (`reclaimed_by = "watchdog"`, task 11.1). Ordering
#    settles the disagreement in favour of whoever knows the cause.
#
# So `canceled` is the accurate label for the dominant producer, and
# `reclaimed_by = "sigterm"` keeps the residual ambiguity visible in the record
# instead of hiding it behind a guess. design.md's mapping table asks for exactly
# this pair.
#
# Honest limits, since the point of measuring is to know where it stops working:
#
#  * A signal cannot be delivered while the main thread is inside a C call that
#    does not return on `EINTR` — `getaddrinfo` is the realistic one. Delivery
#    waits for it, which can be seconds.
#  * The in-flight Bedrock request is *abandoned*, not canceled: we stop
#    listening and exit. The server may complete and bill it, exactly the U5
#    ambiguity that makes the mantle transport timeout non-retryable. Nothing in
#    this stack can cancel a Converse call server-side.
#  * SIGKILL (`stopTimeout` later) cannot be handled at all. That is what the
#    120s in `ecs.tf` buys: 3 DynamoDB writes + 1 ledger write have to fit.
#  * Re-entrancy is real, not theoretical — the probe re-entered the handler
#    while it was still running. Hence the flag below.
# ---------------------------------------------------------------------------

#: Generation has not produced anything yet, so a SIGTERM means "abandon and
#: record `canceled`". Covers startup, the payload read and the whole retry loop.
_PHASE_GENERATION = "generation"
#: A Bedrock response is in hand. A SIGTERM here is **deferred**: interrupting
#: settlement would drop the usage we were just billed for and leave the spend
#: out of the ledger, which R6.1/R6.2 care about far more than a prompt exit.
#: Settlement is 3 DynamoDB writes + 1 S3 write; 120s of grace covers it many
#: times over.
_PHASE_SETTLING = "settling"
#: A termination record is being written (or already was). Nothing left to do,
#: and re-running cleanup would be the double-record R6.1 forbids.
_PHASE_TERMINATING = "terminating"


class _SigtermState:
    """Module state the handler reads. Owned by ``main()``, mutated in place.

    Not a global for convenience: a signal handler receives only ``(signum,
    frame)``, so anything it needs has to be reachable from module scope.
    """

    __slots__ = ("phase", "context", "signal_count", "deferred_signals",
                 "handling", "first_received_at")

    def __init__(self):
        self.reset()

    def reset(self):
        self.phase = _PHASE_GENERATION
        self.context = None
        self.signal_count = 0
        self.deferred_signals = 0
        self.handling = False
        self.first_received_at = None


_SIGTERM_STATE = _SigtermState()


def _terminate_process(code):
    """Exit now, flushing the log first.

    ``os._exit`` skips interpreter shutdown on purpose: the main thread is parked
    somewhere inside botocore, and unwinding it is what the measurement above
    showed to be unreliable. It also skips buffered-stream flushing, which
    matters here — under ECS the log is a pipe, so `print` is block-buffered and
    the termination log lines would be lost. Hence the explicit flush.

    A seam, not indirection for its own sake: tests call the handler directly and
    replace this function, because a real ``os._exit`` would take the test runner
    with it.
    """
    try:
        sys.stdout.flush()
    except Exception:
        pass
    os._exit(code)


def _log_sigterm(event, state, **fields):
    """Log from inside a signal handler without letting logging be fatal.

    ``print`` re-entered on the same thread raises ``RuntimeError: reentrant
    call`` (CPython guards buffered streams rather than deadlocking). Tiny
    window, but the cleanup must not be lost to it.
    """
    try:
        ctx = state.context
        log_structured("warning", event,
                       job_id=(ctx.job_id if ctx is not None else ""),
                       phase=state.phase, signal_count=state.signal_count,
                       **fields)
    except Exception:
        pass


def _handle_sigterm(signum, frame):
    """SIGTERM: record `canceled`, give back both resources, exit 143.

    Phase decides. During generation this terminates the job; during settlement
    it steps aside and lets the settled record be the record; once a termination
    record is being written it does nothing at all. Second and later signals are
    ignored — ECS sends one SIGTERM and then SIGKILL, so a second one means we
    are already inside the work it is asking for.
    """
    state = _SIGTERM_STATE
    state.signal_count += 1
    if state.first_received_at is None:
        try:
            state.first_received_at = time.time()
        except Exception:
            pass

    if state.handling or state.phase != _PHASE_GENERATION:
        state.deferred_signals += 1
        _log_sigterm("sigterm_deferred", state, signum=int(signum))
        return

    state.handling = True
    state.phase = _PHASE_TERMINATING
    ctx = state.context
    try:
        _log_sigterm("worker_sigterm", state, signum=int(signum),
                     retry_count=(ctx.retry_count if ctx is not None else 0))
        if ctx is not None:
            exc = WorkerSigterm(
                f"SIGTERM received after "
                f"{int(time.time() - ctx.started_at)}s; generation abandoned "
                f"(job {ctx.job_id})")
            # `classify_termination` since task 4.4, so this path reads the same
            # source as every other termination. `canceled=True` states what the
            # handler knows; the `WorkerSigterm` value is passed as well and
            # delegation answers the identical row, so the two cannot disagree.
            # `stop_reason=""` because a signal during generation means no
            # response was accepted — and by phase, one in hand defers the signal
            # instead of reaching here.
            reason, _code, record_written = finalize_termination(
                ctx, classify_termination("", exc, False, True), str(exc),
                ctx.retry_count, int(time.time() - ctx.started_at))
            # Logged after the writes on purpose: this line landing is the proof
            # that the cleanup finished inside the stop grace. Its absence, with
            # `worker_sigterm` present, says SIGKILL arrived first — the one
            # thing `stopTimeout = 120` exists to prevent.
            _log_sigterm("sigterm_terminated", state,
                         termination_reason=reason,
                         record_written=record_written)
    except BaseException as e:  # noqa: BLE001 — exiting either way
        _log_sigterm("sigterm_cleanup_failed", state, error=str(e)[:200])
    _terminate_process(EXIT_CODE_SIGTERM)


def _install_sigterm_handler(ctx=None):
    """Arm the handler and publish ``ctx`` to it.

    Worth stating plainly: the container runs `python main.py` as PID 1, and the
    kernel does not apply default signal dispositions to PID 1. Without a handler
    installed, SIGTERM is *ignored* — the stop grace elapses in full and SIGKILL
    does the work. So this call is not a refinement of an existing graceful stop;
    it is the whole of it.
    """
    state = _SIGTERM_STATE
    state.reset()
    state.context = ctx
    try:
        signal.signal(signal.SIGTERM, _handle_sigterm)
    except (ValueError, OSError) as e:
        # `signal.signal` only works on the main thread. If we are somehow not
        # on it, say so instead of dying: the job can still run, it just loses
        # the graceful stop.
        log_structured("error", "sigterm_handler_install_failed",
                       error=str(e))
        return False
    return True


def main():
    # Absolute deadline, fixed on entry (task 4.2, R1.5).
    #
    # Taken here — before any client is built or any row is read — because the
    # budget has to cover everything the process does, not only the generation
    # call. `start_time` below is left exactly as it was: it feeds `duration_s`
    # in the logs and the ledger, and moving it would change an existing
    # meaning.
    process_started_at = time.time()
    total_deadline_s = _env_seconds('WORKER_TOTAL_DEADLINE_SECONDS',
                                    DEFAULT_WORKER_TOTAL_DEADLINE_SECONDS)
    settlement_reserve_s = _env_seconds('SETTLEMENT_RESERVE_SECONDS',
                                        DEFAULT_SETTLEMENT_RESERVE_SECONDS)
    min_viable_attempt_s = _env_seconds('MIN_VIABLE_ATTEMPT_SECONDS',
                                        MIN_VIABLE_ATTEMPT_SECONDS)
    deadline_at = process_started_at + total_deadline_s

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

    # Per-attempt ceiling — per-model since task 7.1, and resolved here because
    # this is the first point at which `model_id` is known.
    #
    # `min(model Duration_Ceiling, injected cap)`, and the injected value is a
    # **cap rather than an override** — the reasoning is in
    # `attempt_ceiling_seconds`. In one line: task 5.5 injects
    # PER_ATTEMPT_TIMEOUT_SECONDS = 1800 from the task definition, so the
    # effective ceiling is still today's 1800 and this task changes no
    # behaviour; task 7.2 raises the injected value to 7200 and that is the
    # revision where a single generation can actually run longer. Rollback stays
    # what tasks.md promises — put the task-definition value back to 1800 and
    # the cap alone restores today's ceiling for every model, without rebuilding
    # the image.
    #
    # `_env_seconds`' default is the model ceiling, so an absent, unparseable or
    # negative variable leaves the model's own value standing.
    model_ceiling_s = model_duration_ceiling(model_id)
    attempt_ceiling_s = attempt_ceiling_seconds(
        model_id,
        env_cap=_env_seconds('PER_ATTEMPT_TIMEOUT_SECONDS', model_ceiling_s))

    dynamodb = boto3.resource('dynamodb', region_name=region)
    # The bedrock-runtime client is now built per attempt, because its
    # read_timeout is derived from the remaining budget (see
    # _bedrock_client_for_attempt). Cache keyed on the granted timeout.
    bedrock_clients = {}
    s3 = boto3.client('s3', region_name=region)

    job_table = dynamodb.Table(table_job_state)
    usage_table = dynamodb.Table(table_monthly_usage)
    pricing_table = dynamodb.Table(table_model_pricing)
    ledger_table = dynamodb.Table(table_request_ledger)

    start_time = time.time()
    retry_count = 0

    # Cleanup context + SIGTERM handler (task 5.3). Installed here, after the
    # tables exist and before the first write, so the handler can never fire with
    # a half-built context: from this line on, every termination path — success,
    # failure, deadline, signal — has the same four writes available to it.
    termination_ctx = TerminationContext(
        job_id=job_id, request_id=request_id, principal_id=principal_id,
        model_id=model_id, job_table=job_table, usage_table=usage_table,
        ledger_table=ledger_table, dynamodb=dynamodb,
        semaphore_table=table_concurrency_semaphore, started_at=start_time)
    _install_sigterm_handler(termination_ctx)

    # `model_duration_ceiling_s` alongside the effective ceiling is what makes a
    # log line answer "which term bound this job?" — the model's declaration or
    # the task definition's cap. Without both, a job granted 1800 is
    # indistinguishable from a job whose model declares 1800.
    log_structured("info", "worker_started", job_id=job_id, model_id=model_id,
                   principal_id=principal_id, deadline_at=int(deadline_at),
                   total_deadline_s=total_deadline_s,
                   settlement_reserve_s=settlement_reserve_s,
                   per_attempt_ceiling_s=attempt_ceiling_s,
                   model_duration_ceiling_s=model_ceiling_s)

    try:
        # Update job state → RUNNING.
        # `deadline_at` is ADDITIVE (design.md §JobState 신규 필드): it is what
        # lets a reader — or the watchdog of task 11.1 — tell "still working" from
        # "stuck past its own deadline" without guessing. Existing fields keep
        # their names, types and meanings.
        job_table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :status, updated_at = :ts, deadline_at = :dl",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "RUNNING", ":ts": datetime.now(timezone.utc).isoformat(),
                                       ":dl": int(deadline_at)},
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
            # Time gate (task 4.2). Every attempt is granted
            # min(per-attempt ceiling, remaining budget); `None` means the
            # budget can no longer fund a viable attempt, so we stop instead of
            # paying for a call that would die on the same wall (R1.5).
            remaining_s = remaining_budget(deadline_at, time.time(),
                                           settlement_reserve_s)
            attempt_timeout_s = next_attempt_timeout(
                remaining_s, attempt_ceiling_s, min_viable_attempt_s)
            if attempt_timeout_s is None:
                log_structured("warning", "worker_deadline_exceeded",
                               job_id=job_id, attempt=attempt,
                               remaining_s=round(remaining_s, 3),
                               deadline_at=int(deadline_at),
                               elapsed_s=int(time.time() - process_started_at),
                               min_viable_s=min_viable_attempt_s,
                               last_error=str(last_error) if last_error else "")
                raise WorkerDeadlineExceeded(
                    f"worker total deadline reached before attempt {attempt}: "
                    f"{remaining_s:.1f}s left of {total_deadline_s}s "
                    f"(reserve {settlement_reserve_s}s, minimum viable "
                    f"{min_viable_attempt_s}s)"
                    + (f"; last error: {last_error}" if last_error else ""))
            try:
                log_structured("info", "bedrock_invoke_attempt", job_id=job_id, attempt=attempt, model_id=model_id,
                               attempt_timeout_s=attempt_timeout_s,
                               remaining_s=round(remaining_s, 3))

                # Ledger: BEDROCK_INVOKED
                ledger_table.put_item(Item={
                    "request_id": f"{request_id}#BEDROCK_INVOKED#{attempt}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "principal_id": principal_id, "model_id": model_id,
                    "event_type": "BEDROCK_INVOKED" if attempt == 0 else "RETRY_ATTEMPT",
                    "job_id": job_id, "decision": "ALLOW",
                    "source_path": "gateway-async", "retry_count": attempt,
                })

                if _is_responses_model(model_id):
                    # mantle receives the same derived grant as converse since
                    # task 7.4 (D6): `min(model ceiling, injected cap,
                    # remaining)`. With `openai.*` declaring 7200 and the task
                    # definition injecting 7200, a gpt-5.6 attempt now gets 7200
                    # where it used to get a static 1800 — the raised ceiling is
                    # model-independent, which is the whole point of this step.
                    # The function makes exactly one HTTP call; this loop is the
                    # only retry loop.
                    bedrock_response = _invoke_mantle_responses(
                        model_id, converse_params, attempt_timeout_s)
                elif _is_image_model(model_id):
                    # Image InvokeModel keeps `BEDROCK_CONFIG`'s 1800 and does
                    # not receive the granted timeout — task 7.1's decision, with
                    # the measurements behind it in `_invoke_image_model`. The
                    # gate above still decides whether this attempt starts.
                    bedrock_response = _invoke_image_model(model_id, converse_params, region)
                else:
                    bedrock = _bedrock_client_for_attempt(
                        region, attempt_timeout_s, bedrock_clients)
                    bedrock_response = bedrock.converse(**{k: v for k, v in converse_params.items()
                                                           if k in ('modelId', 'messages', 'system', 'inferenceConfig', 'toolConfig',
                                                                    'additionalModelRequestFields')})
                break  # Success

            # Exactly the four types `classify_bedrock_error` can decide a
            # retry for, and no more. **Not `except Exception`**: an exception
            # the classifier does not know is a condition we have not reasoned
            # about, and retrying it blind would spend money on a guess. Letting
            # it propagate to the outer handler — which settles, releases the
            # reservation and frees the slot — is the fail-closed choice and is
            # today's behaviour for everything except the two transport types.
            #
            # `MantleHTTPError` joined the tuple in task 7.4, when the mantle
            # path's own inner retry loop was removed: a mantle 5xx is still
            # retried, but here, under one backoff policy and the time gate,
            # instead of in a loop the gate could not see. A mantle **transport**
            # timeout is deliberately absent — it is an `OSError`, terminal by
            # classification, and it must reach the outer handler on the first
            # occurrence (R8.3, U5).
            #
            # `WorkerDeadlineExceeded` is deliberately not in this tuple: the
            # time gate raises it, and catching what the gate throws would turn
            # "out of budget" back into "retry once more".
            except (ClientError, ReadTimeoutError, ConnectTimeoutError,
                    MantleHTTPError) as e:
                last_error = e
                # Single classification source (task 4.3). The loop no longer
                # compares code strings: throttling still keeps the long
                # aggressive backoff, 5xx are still capped short, and a read
                # timeout is now retryable at all — subject to the budget gate
                # below, which is what usually refuses it.
                verdict = classify_bedrock_error(e)
                code = verdict.error_code
                if verdict.retryable and attempt < verdict.retry_cap:
                    delay = backoff_delay(attempt)
                    # Check the budget *before* sleeping, against the clock as
                    # it will read once the backoff is over. Sleeping first and
                    # gating at the top of the loop would spend up to MAX_DELAY
                    # of the deadline on a retry that the gate then refuses —
                    # backoff the process paid for and could not use.
                    if next_attempt_timeout(
                            remaining_budget(deadline_at, time.time() + delay,
                                             settlement_reserve_s),
                            attempt_ceiling_s, min_viable_attempt_s) is None:
                        log_structured("warning", "worker_deadline_exceeded",
                                       job_id=job_id, attempt=attempt,
                                       error=str(e), error_code=code,
                                       backoff_s=delay,
                                       deadline_at=int(deadline_at),
                                       elapsed_s=int(time.time() - process_started_at),
                                       reason="no budget for a retry after backoff")
                        raise WorkerDeadlineExceeded(
                            f"worker total deadline reached after attempt "
                            f"{attempt} ({code or type(e).__name__}): a "
                            f"{delay:.0f}s backoff would leave less than the "
                            f"{min_viable_attempt_s}s minimum viable attempt "
                            f"of the {total_deadline_s}s budget") from e
                    log_structured("warning", "bedrock_retryable_error",
                                   job_id=job_id, attempt=attempt, error=str(e),
                                   delay=delay, error_code=code,
                                   retry_cap=verdict.retry_cap,
                                   error_class=verdict.error_class)
                    retry_count = attempt + 1
                    # Kept in step so a SIGTERM landing in the next attempt
                    # records the count it actually reached, not 0 (task 5.3).
                    termination_ctx.retry_count = retry_count
                    time.sleep(delay)
                else:
                    raise

        # A response is in hand: from here on a SIGTERM is deferred rather than
        # acted on (task 5.3). Interrupting settlement would abandon usage we
        # have already been billed for — the spend would exist at Bedrock and
        # nowhere in our ledger. Settlement is 3 DynamoDB writes + 1 S3 write and
        # the stop grace is 120s, so deferring costs nothing.
        _SIGTERM_STATE.phase = _PHASE_SETTLING

        if bedrock_response is None:
            raise last_error or Exception("bedrock invocation failed with no response")

        # Extract usage — fail-closed: if usage is missing, do not write zero
        # accounting (R6.3). Same rule, same message, now stated once in
        # `require_usage_tokens` and read from there by `compute_settled_cost`
        # too, so the settlement arithmetic cannot be reached with counts this
        # check would have rejected. `UsageMissingError` is what makes the
        # failure record carry `usage_source = "missing"` (task 4.5).
        usage = bedrock_response.get('usage')
        counts = require_usage_tokens(usage, job_id)
        input_tokens = counts.input_tokens
        output_tokens = counts.output_tokens
        stop_reason = bedrock_response.get('stopReason', '')

        # Lookup pricing.
        #
        # Pending-pricing safety (bedrock-model-auto-sync, Property 9 / Req 8.1-8.3):
        # When the daily Sync_Lambda has not yet resolved a price for this Model_Id
        # — for example a brand-new model that AWS just released and the Price List
        # API has not yet published — the row exists with `pricing_status = "pending"`
        # and null prices. The worker MUST NOT raise on Pending pricing; it writes
        # zero cost with `pricing_source_at_charge = "pending"` and emits the
        # `BedrockAutoSync/PendingPricingCostCharged` metric. The next sync's
        # backfill pass (scripts/auto_sync_models/backfill.py) recomputes the
        # cost on this row once Tier_1 / Tier_2 lands.
        pricing_resp = pricing_table.get_item(Key={"model_id": model_id})
        pricing = pricing_resp.get('Item') or {}

        # The three branches that used to be spelled out here — pending, image,
        # tokens — are `compute_settled_cost` (task 4.5). Same arithmetic, same
        # order, same Decimal expressions; what moved is only that they are now
        # reachable without DynamoDB, which is what lets Property 1 state R6.3
        # over a generated cross product instead of over one hand-built job.
        #
        # `pending_pricing` is still asked here because two writes below need the
        # answer — the `pricing_source_at_charge` tag and this metric — and the
        # cost alone cannot carry it: a resolved row that genuinely costs 0
        # (0-token usage, or a zero-priced model) must not be tagged as Pending.
        pending_pricing = is_pending_pricing(pricing)
        if pending_pricing:
            try:
                cw = boto3.client("cloudwatch", region_name=region)
                cw.put_metric_data(
                    Namespace="BedrockAutoSync",
                    MetricData=[{
                        "MetricName": "PendingPricingCostCharged",
                        "Value": 0,
                        "Unit": "Count",
                        "Dimensions": [{"Name": "model_id", "Value": str(model_id) or "unknown"}],
                    }],
                )
            except Exception:
                pass

        actual_cost = compute_settled_cost(
            usage, pricing,
            image_count=(int(bedrock_response.get("_image_count", 0) or 0)
                         if bedrock_response.get("_is_image") else 0))

        # Settlement: remove reservation, add actual cost
        month = current_month_kst()
        pk = f"{principal_id}#{month}"

        # Delete reservation
        try:
            usage_table.delete_item(Key={"principal_id_month": pk, "model_id": f"__reserved__{job_id}"})
        except Exception as e:
            log_structured("error", "reservation_delete_failed", job_id=job_id, error=str(e))

        # Add actual usage. When the row was charged at zero because pricing was
        # Pending, tag it so the auto-sync backfill (Task 10.2 / 10.3) can find
        # and overwrite it once the real prices land in DynamoDB.
        ttl_val = int(time.time()) + 35 * 24 * 3600
        update_expression = "ADD cost_krw :c, input_tokens :i, output_tokens :o SET #t = :ttl"
        expr_values = {
            ":c": actual_cost,
            ":i": input_tokens,
            ":o": output_tokens,
            ":ttl": ttl_val,
        }
        if pending_pricing:
            update_expression += ", pricing_source_at_charge = :psac"
            expr_values[":psac"] = PRICING_SOURCE_PENDING

        usage_table.update_item(
            Key={"principal_id_month": pk, "model_id": model_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames={"#t": "ttl"},
            ExpressionAttributeValues=expr_values,
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

        # The success path's termination, from the same source every other path
        # reads (task 4.4). This is the gap the task closes: a job that ended
        # normally used to carry no Termination_Reason at all, while R5.1 asks
        # for exactly one of six on *every* termination, and `complete` /
        # `max_tokens` are the two no exception can produce.
        #
        # `:status` reads the verdict instead of the literal it used to hold, and
        # the value written is unchanged: with no exception and neither flag set,
        # both reachable branches answer SUCCEEDED — `max_tokens` included, which
        # is R5.2's point that a truncated generation is a *successful* job.
        #
        # `stop_reason` is written exactly as before (additive discipline), and
        # `truncated` is deliberately NOT stored: design.md C6 derives it from
        # `stop_reason` at read time (task 14.1), so a stored copy would be a
        # second source that can disagree with the field it comes from.
        termination = classify_termination(stop_reason)

        # Update job state → SUCCEEDED
        job_table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :status, settled_cost_krw = :cost, "
                             "input_tokens = :inp, output_tokens = :out, "
                             "result_ref = :ref, retry_count = :rc, "
                             "completed_at = :ts, updated_at = :ts, "
                             "stop_reason = :sr, termination_reason = :tr",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": termination.job_status, ":cost": actual_cost,
                ":inp": input_tokens, ":out": output_tokens,
                ":ref": f"s3://{payload_bucket}/{result_key}",
                ":rc": retry_count,
                ":ts": datetime.now(timezone.utc).isoformat(),
                ":sr": stop_reason,
                ":tr": termination.reason,
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

        # `truncated` is logged though it is not stored: `None` here is the
        # "unknown" state (an empty `stop_reason`, e.g. from the mantle path), and
        # a log line is where that distinction can be counted without adding a
        # field whose only source is another field.
        log_structured("info", "worker_completed", job_id=job_id, model_id=model_id,
                       input_tokens=input_tokens, output_tokens=output_tokens,
                       cost_krw=float(actual_cost), duration_s=duration_s,
                       stop_reason=stop_reason,
                       termination_reason=termination.reason,
                       truncated=termination.truncated, retry_count=retry_count)

        # Async warning check: invoke Lambda to check warning thresholds
        try:
            warning_fn = os.environ.get('WARNING_CHECK_FUNCTION_NAME', '')
            if warning_fn:
                # Read current total usage after settlement to get accurate post-settlement usage
                usage_after_settlement = float(actual_cost)
                try:
                    usage_resp = usage_table.query(
                        KeyConditionExpression="principal_id_month = :pk",
                        ExpressionAttributeValues={":pk": pk},
                    )
                    total_cost = sum(
                        float(item.get("cost_krw", 0))
                        for item in usage_resp.get("Items", [])
                        if not str(item.get("model_id", "")).startswith("__reserved__")
                    )
                    usage_after_settlement = total_cost
                except Exception as e:
                    log_structured("warning", "warning_check_usage_read_failed",
                                   job_id=job_id, error=str(e))

                lambda_client = boto3.client('lambda', region_name=region)
                lambda_client.invoke(
                    FunctionName=warning_fn,
                    InvocationType='Event',
                    Payload=json.dumps({
                        "_internal_route": "warning-check",
                        "principal_id": principal_id,
                        "usage_after_settlement_krw": usage_after_settlement,
                        "source": "gateway-async",
                        "job_id": job_id,
                    }).encode()
                )
                log_structured("info", "warning_check_invoked", job_id=job_id, principal_id=principal_id)
        except Exception as e:
            log_structured("warning", "warning_check_invoke_failed", job_id=job_id, error=str(e))

        # Release semaphore slot on success
        _release_semaphore_slot(dynamodb, table_concurrency_semaphore, job_id)

        # Terminal record written and both resources returned. A SIGTERM from
        # here on must not write anything: the job is SUCCEEDED and `canceled`
        # over it would be a false statement (task 5.3).
        _SIGTERM_STATE.phase = _PHASE_TERMINATING
        if _SIGTERM_STATE.signal_count:
            log_structured("info", "worker_completed_after_sigterm",
                           job_id=job_id,
                           signal_count=_SIGTERM_STATE.signal_count)

    except Exception as e:
        # Cleanup is starting: a SIGTERM arriving now would only duplicate it, so
        # the handler steps aside from this line (task 5.3). The verdict already
        # in hand — deadline, 408, throttle exhaustion — is better informed than
        # a signal, and this is what keeps it.
        _SIGTERM_STATE.phase = _PHASE_TERMINATING
        duration_s = int(time.time() - start_time)
        error_msg = str(e)
        # Task 4.2 classified exactly one termination here (the time gate). This
        # generalizes that to design.md's whole mapping table by asking the
        # classifier, **without changing what 4.2 decided**: a
        # `WorkerDeadlineExceeded` still yields `duration_limit` + `TIMED_OUT`,
        # and the precedence it established still holds — a throttle chain that
        # runs out of *time* raises the gate's exception, so the gate's verdict
        # wins over `throttled` because the gate is what stopped it.
        #
        # What the table adds beyond 4.2: 408 and read timeouts join TIMED_OUT /
        # `duration_limit`; exhausted throttling records `throttled`; 5xx and
        # connect timeouts record `server_error`. Request errors and unknown
        # exceptions keep today's record exactly — FAILED, no
        # `termination_reason` — because R5.1's six values contain no
        # request-error value and mislabelling one `server_error` is precisely
        # what design.md's table forbids.
        #
        # `bedrock_error_code` is additive (R5.4): it is what makes a failure
        # class searchable in the ledger at all. The audit could only date the
        # 1800s cluster by timestamp arithmetic because no code was ever stored.
        #
        # Task 4.4 routes this through `classify_termination` so every
        # termination path reads one source. Nothing about the recorded verdict
        # moves: with `stop_reason=""` and `canceled=False`, the only branch that
        # can fire for a `WorkerDeadlineExceeded` is the deadline one — which
        # yields the same `duration_limit` / `TIMED_OUT` that delegation does —
        # and every other exception falls through to branch 4, i.e. to
        # `classify_bedrock_error` unchanged.
        #
        # The two arguments that are not the exception, and why:
        #
        #  * `stop_reason=""` — a response whose *settlement* then failed is not a
        #    completed job. Passing the `stopReason` we happened to hold would let
        #    branch 1 record SUCCEEDED for a job whose result was never written to
        #    S3, which is both a behaviour change and a false statement. The
        #    reason a failure ended is the exception, and the `stop_reason` a
        #    successful generation reported is written by the path that accepted
        #    it.
        #  * `deadline_exceeded` is *derived from the exception type* rather than
        #    tracked as a separate flag, so the flag and the exception cannot
        #    disagree about the same fact.
        verdict = classify_termination(
            "", e, isinstance(e, WorkerDeadlineExceeded), False)
        job_status = verdict.job_status
        termination_reason = (verdict.termination_reason
                              if verdict.records_reason else "")
        bedrock_error_code = (verdict.error_code
                              if verdict.records_error_code else "")
        log_structured("error", "worker_failed", job_id=job_id, error=error_msg, duration_s=duration_s,
                       status=job_status, termination_reason=termination_reason,
                       bedrock_error_code=bedrock_error_code,
                       error_class=verdict.error_class,
                       http_status=verdict.http_status,
                       # Task 7.4: empty except on a transport give-up, where it
                       # says the 0 we settled may not be what was spent (U5).
                       usage_source=verdict.usage_source,
                       retry_count=retry_count)

        # Reservation → JobState → ledger → semaphore. The four writes that used
        # to be spelled out here now live in `finalize_termination` (task 5.3),
        # because the SIGTERM handler has to perform the same four in the same
        # order and a second copy of them would drift from this one. Same order,
        # same fields, same swallow-and-continue behaviour as before.
        finalize_termination(termination_ctx, verdict, error_msg, retry_count,
                             duration_s)

        sys.exit(1)


if __name__ == "__main__":
    main()
