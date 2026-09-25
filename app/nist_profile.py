"""NIST CSF Current vs Target profile — not a fake maturity score.

Tiers are operator-declared characteristics (Partial → Adaptive), never computed
from a live % . Current % is live operating-effectiveness only.
"""

from __future__ import annotations

from typing import Any

from app.db import get_conn, now

NIST_TIERS: dict[int, dict[str, str]] = {
    1: {
        "name": "Partial",
        "governance": "Ad hoc risk decisions; limited awareness of cyber risk.",
        "risk": "Reactive response; informal practices.",
    },
    2: {
        "name": "Risk Informed",
        "governance": "Risk is considered by approved priorities; some organization-wide awareness.",
        "risk": "Objectives are approved; practices are informed but not always repeatable.",
    },
    3: {
        "name": "Repeatable",
        "governance": "Policies and procedures are defined and consistently applied.",
        "risk": "Practices are regular and updated from lessons learned.",
    },
    4: {
        "name": "Adaptive",
        "governance": "Continuous improvement informed by predictive indicators and changing threats.",
        "risk": "Practices adapt in near-real time from lessons and emerging risk.",
    },
}


def ensure_profile_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_org_profiles (
            user_id TEXT PRIMARY KEY,
            target_percent REAL NOT NULL DEFAULT 90,
            current_tier INTEGER NOT NULL DEFAULT 2,
            target_tier INTEGER NOT NULL DEFAULT 3,
            updated_at REAL NOT NULL
        )
        """
    )
    c.commit()


def _clamp_tier(n: Any, default: int) -> int:
    try:
        v = int(n)
    except (TypeError, ValueError):
        return default
    return min(4, max(1, v))


def get_org_profile(user_id: str) -> dict[str, Any]:
    ensure_profile_schema()
    row = get_conn().execute(
        "SELECT * FROM securaiq_org_profiles WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    if not row:
        return {
            "target_percent": 90.0,
            "current_tier": 2,
            "target_tier": 3,
        }
    return {
        "target_percent": float(row["target_percent"] or 90),
        "current_tier": _clamp_tier(row["current_tier"], 2),
        "target_tier": _clamp_tier(row["target_tier"], 3),
    }


def set_org_profile(
    user_id: str,
    *,
    target_percent: float | None = None,
    current_tier: int | None = None,
    target_tier: int | None = None,
) -> dict[str, Any]:
    ensure_profile_schema()
    cur = get_org_profile(user_id)
    tgt_pct = float(target_percent if target_percent is not None else cur["target_percent"])
    tgt_pct = min(100.0, max(0.0, tgt_pct))
    ct = _clamp_tier(current_tier if current_tier is not None else cur["current_tier"], 2)
    tt = _clamp_tier(target_tier if target_tier is not None else cur["target_tier"], 3)
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_org_profiles (user_id, target_percent, current_tier, target_tier, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            target_percent = excluded.target_percent,
            current_tier = excluded.current_tier,
            target_tier = excluded.target_tier,
            updated_at = excluded.updated_at
        """,
        (user_id, tgt_pct, ct, tt, now()),
    )
    c.commit()
    return get_org_profile(user_id)


def organizational_profile(user_id: str) -> dict[str, Any]:
    from app.control_truth import truth_indicators
    from app.controls.live_compliance import compute_live_compliance

    live = compute_live_compliance(user_id)
    truth = truth_indicators(user_id)
    stored = get_org_profile(user_id)
    current = live.get("live_percent")
    current_n = float(current) if current is not None else 0.0
    target = float(stored["target_percent"])
    gap = round(max(0.0, target - current_n), 1)
    ct = stored["current_tier"]
    tt = stored["target_tier"]
    return {
        "ok": True,
        "current_percent": current,
        "target_percent": target,
        "gap_percent": gap if current is not None else None,
        "truth": truth,
        "tiers": {
            "current": {"tier": ct, **NIST_TIERS[ct]},
            "target": {"tier": tt, **NIST_TIERS[tt]},
            "note": (
                "Tiers are operator-declared NIST CSF characteristics — "
                "not computed from live %. Not a maturity score."
            ),
        },
        "live": {
            "passing": live.get("passing"),
            "failing": live.get("failing"),
            "unknown": live.get("unknown"),
        },
        "disclaimer": (
            "Current % is live PASS/FAIL after freshness + agent availability. "
            "Target % is an operator goal. Not a NIST/CMMC certification."
        ),
    }
