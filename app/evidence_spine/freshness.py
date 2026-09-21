"""Control evidence freshness policies.

PASS cannot last forever — evidence ages into STALE and requires recollection.
"""

from __future__ import annotations

from typing import Any

# Default stale_after seconds by live test / canonical control id
DEFAULT_FRESHNESS: dict[str, dict[str, Any]] = {
    "host_firewall": {
        "label": "Host firewall",
        "stale_after_sec": 15 * 60,
        "collection_interval_sec": 15 * 60,
    },
    "host_defender": {
        "label": "Windows Defender",
        "stale_after_sec": 15 * 60,
        "collection_interval_sec": 15 * 60,
    },
    "host_disk_encryption": {
        "label": "Disk encryption",
        "stale_after_sec": 6 * 3600,
        "collection_interval_sec": 6 * 3600,
    },
    "host_ssh_root": {
        "label": "SSH root login",
        "stale_after_sec": 15 * 60,
        "collection_interval_sec": 15 * 60,
    },
    "host_risky_listeners": {
        "label": "Risky listeners",
        "stale_after_sec": 15 * 60,
        "collection_interval_sec": 15 * 60,
    },
    "mfa": {
        "label": "MFA",
        "stale_after_sec": 24 * 3600,
        "collection_interval_sec": 24 * 3600,
    },
    "vulnerability_management": {
        "label": "Patch / vulnerability state",
        "stale_after_sec": 6 * 3600,
        "collection_interval_sec": 6 * 3600,
    },
    "security_policy": {
        "label": "Security policy (document)",
        "stale_after_sec": 365 * 86400,
        "collection_interval_sec": 365 * 86400,
    },
    "user_access_review": {
        "label": "User access review",
        "stale_after_sec": 30 * 86400,
        "collection_interval_sec": 30 * 86400,
    },
    "vendor_assessment": {
        "label": "Vendor assessment",
        "stale_after_sec": 90 * 86400,
        "collection_interval_sec": 90 * 86400,
    },
}


def list_freshness_policies() -> list[dict[str, Any]]:
    out = []
    for key, meta in DEFAULT_FRESHNESS.items():
        out.append(
            {
                "id": key,
                "label": meta["label"],
                "stale_after_sec": meta["stale_after_sec"],
                "collection_interval_sec": meta["collection_interval_sec"],
                "stale_after_human": _human(meta["stale_after_sec"]),
            }
        )
    return out


def freshness_for(control_or_test: str) -> dict[str, Any]:
    key = (control_or_test or "").strip()
    meta = DEFAULT_FRESHNESS.get(key) or {
        "label": key or "unknown",
        "stale_after_sec": 48 * 3600,
        "collection_interval_sec": 48 * 3600,
    }
    return {
        "id": key or "default",
        "label": meta["label"],
        "stale_after_sec": int(meta["stale_after_sec"]),
        "collection_interval_sec": int(meta["collection_interval_sec"]),
        "stale_after_human": _human(meta["stale_after_sec"]),
    }


def apply_freshness_to_result(
    *,
    result: str,
    last_observed: float | None,
    control_or_test: str,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """If PASS/FAIL evidence is older than policy → STALE."""
    from app.db import now as _now

    ts = float(now_ts if now_ts is not None else _now())
    policy = freshness_for(control_or_test)
    st = (result or "unknown").strip().lower()
    last = float(last_observed) if last_observed else None
    age = (ts - last) if last else None
    stale_after = int(policy["stale_after_sec"])
    is_stale = bool(age is not None and age > stale_after and st in {"pass", "fail", "partial"})
    effective = "stale" if is_stale else st
    return {
        "result": st,
        "effective_result": effective,
        "stale": is_stale,
        "age_sec": age,
        "last_observed": last,
        "policy": policy,
        "note": (
            f"Evidence older than {policy['stale_after_human']} — recollect required."
            if is_stale
            else "Within freshness window."
        ),
    }


def _human(sec: int) -> str:
    if sec < 3600:
        return f"{max(1, sec // 60)} min"
    if sec < 86400:
        return f"{sec // 3600} hr"
    return f"{sec // 86400} days"
