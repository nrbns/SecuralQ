"""Soft in-process check-in ladder — lab measure for 250/500 without live HTTP 500+.

Honesty: this exercises enroll+checkin in-process (same code path as HTTP handlers
after auth). It does **not** replace measured HTTP waves in CAPACITY-LAB.md.
HTTP 500+ remains unmeasured until a live lab run fills the table.
"""

from __future__ import annotations

import statistics
import time
from typing import Any


def soft_checkin_wave(user_id: str, n_agents: int) -> dict[str, Any]:
    """Enroll N agents and check them in once; return latency stats."""
    from app.agents import checkin, enroll_agent

    n = max(1, min(int(n_agents), 2000))
    tokens: list[str] = []
    enroll_ms: list[float] = []
    checkin_ms: list[float] = []
    ok = 0
    for i in range(n):
        t0 = time.perf_counter()
        agent = enroll_agent(user_id, name=f"soft-cap-{n}-{i}")
        enroll_ms.append((time.perf_counter() - t0) * 1000.0)
        tokens.append(agent["agent_id"])
    for aid in tokens:
        t0 = time.perf_counter()
        try:
            out = checkin(
                aid,
                {
                    "hostname": f"host-{aid[:8]}",
                    "os": "lab",
                    "sequence": 1,
                },
            )
            if out.get("ok") is not False and "error" not in out:
                ok += 1
        except Exception:
            pass
        checkin_ms.append((time.perf_counter() - t0) * 1000.0)

    def _pct(vals: list[float], p: float) -> float | None:
        if not vals:
            return None
        ordered = sorted(vals)
        idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
        return round(ordered[idx], 3)

    return {
        "ok": True,
        "mode": "in_process_checkin",
        "agents": n,
        "success": ok,
        "success_pct": round(100.0 * ok / n, 2) if n else 0.0,
        "enroll_p50_ms": _pct(enroll_ms, 50),
        "enroll_p95_ms": _pct(enroll_ms, 95),
        "checkin_p50_ms": _pct(checkin_ms, 50),
        "checkin_p95_ms": _pct(checkin_ms, 95),
        "checkin_mean_ms": round(statistics.mean(checkin_ms), 3) if checkin_ms else None,
        "note": (
            "Soft in-process ladder — not HTTP wave proof. "
            "Do not market as HTTP 500+ capacity."
        ),
    }


def soft_checkin_ladder(
    user_id: str,
    rungs: list[int] | None = None,
) -> dict[str, Any]:
    rungs = rungs or [100, 250, 500]
    results = []
    for n in rungs:
        results.append(soft_checkin_wave(user_id, n))
    return {
        "ok": all(r.get("ok") for r in results),
        "rungs": results,
        "http_500_measured": False,
        "note": "Lab soft ladder only; HTTP 500+ still unmeasured in CAPACITY-LAB.",
    }
