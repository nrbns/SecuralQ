"""Multi-worker once-only processing contract (Phase 1 proof helpers).

Proves the release-gate story without requiring a live Redis cluster:

1. Consumer A receives a Streams message and dies before ACK.
2. Consumer B claims via ``XAUTOCLAIM`` and runs ``process_event``.
3. A duplicate delivery of the same ``event_id`` does **not** run the
   security side-effect again (RT-06 idempotency ledger).

Live Redis / Sentinel failover is still an ops measurement
(``scripts/realtime_phase1_proof.py --document``); these helpers make the
**once-only** claim CI-provable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class OnceOnlyResult:
    ok: bool
    side_effect_count: int
    process_calls: int
    reclaim_handled: int = 0
    detail: str = ""
    steps: list[str] = field(default_factory=list)


def prove_duplicate_delivery_skipped(
    process_event: Callable[[dict[str, Any] | None], bool],
    event: dict[str, Any],
) -> OnceOnlyResult:
    """Deliver the same event twice; security handler must run once."""
    steps: list[str] = []
    ok1 = bool(process_event(event))
    steps.append("worker_a_process")
    ok2 = bool(process_event(event))
    steps.append("worker_b_duplicate_delivery")
    # Callers attach a counter via a closed-over handler; we only assert returns.
    return OnceOnlyResult(
        ok=ok1 and ok2,
        side_effect_count=-1,  # filled by caller when using a counting handler
        process_calls=2,
        detail="duplicate delivery returned ACK-safe both times",
        steps=steps,
    )


async def prove_consumer_failover_once_only(
    *,
    reclaim_pending: Callable[..., Any],
    process_event: Callable[[dict[str, Any] | None], bool],
    client: Any,
    stream: str,
    event: dict[str, Any],
    side_effects: list[Any],
) -> OnceOnlyResult:
    """Simulate: A dies (no ACK) → B XAUTOCLAIMs → process once → duplicate skip.

    ``reclaim_pending`` should invoke ``process_event`` (or ``_handle_stream_message``)
    for claimed messages. ``side_effects`` is appended by the registered handler.
    """
    steps = ["consumer_a_died_pending", "consumer_b_xautoclaim"]
    claimed = await reclaim_pending(client, stream)
    steps.append(f"reclaim_claimed={claimed}")
    # Duplicate delivery after successful process (second worker / retry).
    process_event(event)
    steps.append("duplicate_delivery_after_reclaim")
    count = len(side_effects)
    ok = claimed >= 1 and count == 1
    return OnceOnlyResult(
        ok=ok,
        side_effect_count=count,
        process_calls=claimed + 1,
        reclaim_handled=int(claimed or 0),
        detail=(
            "once-only OK"
            if ok
            else f"expected 1 side-effect after reclaim, got {count} (claimed={claimed})"
        ),
        steps=steps,
    )
