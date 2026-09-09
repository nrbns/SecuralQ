"""Thin live-test wrapper around ``app.services.control_testing``.

Runs only explicitly mapped tests, records last results, and publishes
realtime events (dotted control.* + flat ``type=compliance`` for UI).
"""

from __future__ import annotations

from typing import Any


_DETAIL_WHY_KEYS = (
    "failing_agents",
    "sla_breaches",
    "observed",
    "expected",
    "actual",
    "deviations",
    "hostname",
    "agent_id",
    "backend",
    "enabled",
    "permit_root_login",
)


def _deviations_from_detail(detail: dict[str, Any]) -> list[str]:
    """Extract human-readable deviation lines from a result detail dict."""
    out: list[str] = []
    raw = detail.get("deviations")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                setting = item.get("setting") or item.get("key") or ""
                exp = item.get("expected")
                act = item.get("actual") or item.get("observed")
                if setting:
                    out.append(f"{setting}: expected={exp!r} actual={act!r}")
                else:
                    out.append(str(item))
            elif item not in (None, ""):
                out.append(str(item))
    elif isinstance(raw, dict) and raw:
        out.append(f"deviations={raw!r}")
    if "expected" in detail and "actual" in detail:
        out.append(f"expected={detail.get('expected')!r} actual={detail.get('actual')!r}")
    elif "expected" in detail and "observed" in detail:
        out.append(f"expected={detail.get('expected')!r} observed={detail.get('observed')!r}")
    return out


def _why_failing(result: dict[str, Any]) -> list[str]:
    status = (result.get("status") or "").lower()
    if status not in ("fail", "partial"):
        return []
    test_key = result.get("test") or result.get("test_name") or ""
    why = [
        f"Live test `{test_key}` status={status}",
        str(result.get("summary") or "").strip(),
    ]
    detail = result.get("detail") or {}
    if isinstance(detail, dict):
        for key in _DETAIL_WHY_KEYS:
            if key == "deviations":
                continue
            if key in detail and detail[key] not in (None, "", [], {}):
                why.append(f"{key}={detail[key]!r}")
        why.extend(_deviations_from_detail(detail))
    return [w for w in why if w]


def _publish_results(
    user_id: str,
    framework_id: str,
    control_id: str,
    results: list[dict[str, Any]],
) -> None:
    """Publish control.test.completed + pass/fail/unknown, dual-write compliance."""
    try:
        from app.realtime_bus import publish
    except Exception:
        return

    for r in results:
        status = (r.get("status") or "unknown").lower()
        test_name = r.get("test") or ""
        base = {
            "user_id": user_id,
            "framework_id": framework_id,
            "control_id": control_id,
            "test": test_name,
            "status": status,
            "summary": r.get("summary") or "",
            "detail": r.get("detail") or {},
            "why_failing": _why_failing(r),
            "source": "control_engine",
        }

        # Always: completed
        try:
            publish(event_type="control.test.completed", type="control.test.completed", **base)
        except Exception:
            pass

        # Status-specific dotted event
        if status == "pass":
            status_event = "control.passed"
        elif status == "fail":
            status_event = "control.failed"
        else:
            status_event = "control.unknown"
        try:
            publish(event_type=status_event, type=status_event, **base)
        except Exception:
            pass

        if status == "fail":
            try:
                from app.controls.poam import open_poam_from_control_fail_result

                open_poam_from_control_fail_result(
                    user_id,
                    framework_id=framework_id,
                    control_id=control_id,
                    result=r,
                )
            except Exception:
                pass

        # Dual-write flat compliance for existing UI / SSE filters
        try:
            publish(
                type="compliance",
                event_type="compliance",
                **base,
            )
        except Exception:
            pass


def run_control_tests(
    user_id: str,
    framework_id: str,
    control_id: str,
    *,
    record_evidence: bool = True,
    persist: bool = True,
) -> dict[str, Any]:
    """Run live tests for one control; record + publish. Empty if unmapped."""
    from app.controls.catalog import get_control, normalize_control_id
    from app.services.control_testing import run_live_tests_for_control

    ctrl = get_control(framework_id, control_id)
    if not ctrl:
        return {
            "ok": False,
            "error": "control_not_found",
            "framework_id": framework_id,
            "control_id": control_id,
            "results": [],
        }

    fid = ctrl.framework_id
    cid = normalize_control_id(fid, ctrl.id)
    raw_results = run_live_tests_for_control(
        user_id, fid, cid, record_evidence=record_evidence
    )

    # Also try original map key if normalize changed nothing useful
    if not raw_results and cid != control_id:
        raw_results = run_live_tests_for_control(
            user_id, fid, control_id, record_evidence=record_evidence
        )

    enriched: list[dict[str, Any]] = []
    for r in raw_results:
        item = dict(r)
        item["framework_id"] = fid
        item["control_id"] = cid
        item["why_failing"] = _why_failing(item)
        item["why"] = item["why_failing"]
        item["deviations"] = _deviations_from_detail(
            item.get("detail") if isinstance(item.get("detail"), dict) else {}
        ) if (item.get("status") or "").lower() in ("fail", "partial") else []
        enriched.append(item)
        if persist:
            try:
                from app.controls.results import record_test_result

                record_test_result(
                    user_id,
                    fid,
                    cid,
                    test_name=str(item.get("test") or ""),
                    status=str(item.get("status") or "unknown"),
                    summary=str(item.get("summary") or ""),
                    detail=item.get("detail") if isinstance(item.get("detail"), dict) else {},
                    tested_at=item.get("tested_at"),
                )
            except Exception:
                pass

    _publish_results(user_id, fid, cid, enriched)

    return {
        "ok": True,
        "framework_id": fid,
        "control_id": cid,
        "title": ctrl.title,
        "verifiability": ctrl.verifiability,
        "results": enriched,
        "disclaimer": (
            "Live tests are telemetry signals — not certification or SPRS submission."
        ),
    }


def get_control_with_live_results(
    user_id: str, framework_id: str, control_id: str
) -> dict[str, Any] | None:
    """Catalog control + last stored results + why / deviations when failing."""
    from app.controls.catalog import get_control
    from app.controls.results import get_results_for_control

    ctrl = get_control(framework_id, control_id)
    if not ctrl:
        return None

    stored = get_results_for_control(user_id, ctrl.framework_id, ctrl.id)
    live_results = []
    aggregate_why: list[str] = []
    aggregate_deviations: list[str] = []
    for row in stored:
        st = (row.get("status") or "").lower()
        detail = row.get("detail") if isinstance(row.get("detail"), dict) else {}
        shaped = {
            "test": row.get("test_name"),
            "test_name": row.get("test_name"),
            "status": st,
            "summary": row.get("summary") or "",
            "detail": detail or {},
        }
        why = _why_failing(shaped)
        deviations = _deviations_from_detail(detail or {}) if st in ("fail", "partial") else []
        if why:
            aggregate_why.extend(why)
        if deviations:
            aggregate_deviations.extend(deviations)
        live_results.append(
            {
                "test": row.get("test_name"),
                "status": st,
                "summary": row.get("summary") or "",
                "detail": detail or {},
                "tested_at": row.get("tested_at"),
                "why": why,
                "why_failing": why,
                "deviations": deviations,
            }
        )

    return {
        **ctrl.to_dict(),
        "live_results": live_results,
        "why": aggregate_why,
        "why_failing": aggregate_why,
        "deviations": aggregate_deviations,
        "has_live_tests": bool(ctrl.tests),
        "disclaimer": (
            "Results reflect last stored live-test outcomes when present — "
            "not a compliance certification."
        ),
    }
