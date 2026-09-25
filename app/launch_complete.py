"""One board: launch P0s + world-class 1–5 + master-build 1–46 + checklists.

Engineering-complete when every numbered row is lab-unblocked and open_count=0.
Ops/frozen leftovers stay listed and are never claimed done.
"""

from __future__ import annotations

from typing import Any

# Collapse alias leftovers so the remaining list stays short.
_COMPACT_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("scale_5k", ("http_5k", "kill_at_5k", "chaos_at_5k", "http_5k_100k", "http_5k_100k_unmeasured")),
    ("ha_cluster", ("cluster_kill_rto", "postgres_restore", "postgres_ha", "multi_az")),
    ("macos_m1_m2", ("friend_hardware", "macos_m1_m2_live")),
    ("signing", ("ev_notarize", "signed_stores", "ev_authenticode", "apple_notarize")),
    ("identity", ("live_idp", "exclusive_redis_acls")),
    ("attest", ("c3pao", "cloud_object_lock", "third_party_pentest")),
    ("digital_twin", ("digital_twin", "digital_twin_depth")),
)


def compact_leftovers(items: list[str] | None) -> list[str]:
    raw = {str(x) for x in (items or []) if x}
    out: list[str] = []
    used: set[str] = set()
    for label, keys in _COMPACT_GROUPS:
        hit = raw & set(keys)
        if hit:
            out.append(label)
            used |= hit
    out.extend(sorted(raw - used))
    return out


def launch_complete_board() -> dict[str, Any]:
    from app.checklist_board import all_checklists_board
    from app.launch_plan import launch_plan_board
    from app.measured_ops import measured_ops_board
    from app.phase_board import all_phases_board

    plan = launch_plan_board()
    phases = all_phases_board()
    checklists = all_checklists_board()
    measured = measured_ops_board()
    total = plan.get("total_phase") or {}
    engineering = bool(
        plan.get("ok")
        and plan.get("open_count") == 0
        and plan.get("all_lab_unblocked")
        and phases.get("all_lab")
        and total.get("all_lab")
        and checklists.get("all_complete")
        and checklists.get("ok")
    )
    return {
        "ok": engineering,
        "engineering_complete": engineering,
        "launch": {
            "ok": plan.get("ok"),
            "open_count": plan.get("open_count"),
            "lab_count": plan.get("lab_count"),
            "ops_count": plan.get("ops_count"),
            "frozen_count": plan.get("frozen_count"),
            "all_lab_unblocked": plan.get("all_lab_unblocked"),
            "p0_count": len(plan.get("p0") or []),
        },
        "world_class": {
            "ok": phases.get("ok"),
            "all_lab": phases.get("all_lab"),
            "lab_ids": phases.get("lab_ids"),
        },
        "total_phase": {
            "ok": total.get("ok"),
            "all_lab": total.get("all_lab"),
            "master_build_count": total.get("master_build_count"),
        },
        "checklists": {
            "ok": checklists.get("ok"),
            "all_complete": checklists.get("all_complete"),
            "items": [
                {
                    "id": c.get("id"),
                    "complete": c.get("complete"),
                    "engineering_complete": c.get("engineering_complete"),
                }
                for c in (checklists.get("checklists") or [])
            ],
        },
        "measured_ops": {
            "sqlite_rto_ms": (measured.get("sqlite_dr") or {}).get("rto_ms"),
            "sqlite_rpo_ms": (measured.get("sqlite_dr") or {}).get("rpo_ms"),
            "sqlite_published": (measured.get("sqlite_dr") or {}).get("published"),
            "restart_reclaim_ms": (measured.get("restart_reclaim") or {}).get("reclaim_ms"),
            "http_top_measured": (measured.get("http_capacity") or {}).get("http_top_measured"),
            "sentinel_inject": (measured.get("sentinel") or {}).get("live_inject_measured"),
            "stage_latency": measured.get("stage_latency") or {},
        },
        "still_ops": compact_leftovers(plan.get("ops_blocked") or []),
        "still_ops_detail": plan.get("ops_blocked") or [],
        "disclaimer": (
            "engineering_complete means launch P0s, world-class 1–5, master-build 1–46, "
            "and every in-repo checklist are lab-unblocked. "
            "EV/notarize, cloud Object Lock, live IdP, C3PAO, 5k–100k HTTP, "
            "macOS M1/M2 live, Postgres restore, and digital twin remain ops/frozen."
        ),
    }
