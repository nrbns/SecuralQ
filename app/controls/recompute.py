"""Affected-controls-only recompute (P1) — no full framework scan on every event."""

from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger("securaiq.controls.recompute")

# Event type → which curated tests to refresh
_SOFTWARE_TESTS = ("patch_management", "vulnerability_management", "asset_inventory")
_HOST_TESTS = ("host_firewall", "host_defender", "host_ssh_root", "host_disk_encryption")
_CONFIG_TESTS = _HOST_TESTS


def tests_for_event_type(event_type: str) -> tuple[str, ...]:
    et = (event_type or "").strip().lower()
    if et.startswith("software.") or et in {"inventory", "software_inventory", "software.inventory.updated"}:
        return _SOFTWARE_TESTS
    if et.startswith("configuration.") or et == "configuration.drift_detected":
        return _CONFIG_TESTS
    if et.startswith("privacy.") or et.startswith("data_governance"):
        # Privacy inventory changes affect asset/inventory-style evidence only —
        # never invent PASS for notice/consent from endpoint telemetry.
        return ("asset_inventory",)
    if et.startswith("control.") or et == "compliance" or et == "compliance.updated":
        return ()
    return ()


def recompute_affected_controls(user_id: str, event: dict[str, Any] | None) -> dict[str, Any]:
    """Re-run only the tests implicated by ``event``; never raises."""
    out: dict[str, Any] = {"ok": True, "tests": [], "results": [], "skipped": False}
    if not user_id or not isinstance(event, dict):
        return {"ok": False, "error": "user_id and event required", "tests": []}
    et = str(event.get("event_type") or event.get("type") or "").strip()
    tests = tests_for_event_type(et)
    if not tests:
        out["skipped"] = True
        return out
    out["tests"] = list(tests)
    agent_id = str(event.get("agent_id") or "").strip()

    # Host telemetry path — need last check-in payload
    host_needed = [t for t in tests if t.startswith("host_")]
    if host_needed and agent_id:
        try:
            from app.agents import get_agent
            from app.services.control_testing import evaluate_agent_host_controls

            agent = get_agent(agent_id)
            payload = (agent or {}).get("last_payload") or {}
            if not isinstance(payload, dict):
                payload = {}
            asset_id = str(event.get("asset_id") or (agent or {}).get("asset_id") or "")
            ev_out = evaluate_agent_host_controls(
                user_id,
                agent_id,
                payload,
                asset_id=asset_id,
                only_tests=set(host_needed),
            )
            out["results"].extend(ev_out.get("results") or [])
        except Exception as exc:
            _log.debug("host recompute skipped: %s", exc)

    # User-scoped catalog tests (patch / vuln / inventory)
    user_tests = [t for t in tests if not t.startswith("host_")]
    if user_tests:
        try:
            from app.controls.results import record_test_result
            from app.controls.test_registry import control_bindings_for_test
            from app.services import control_testing as ct

            runners = {
                "patch_management": getattr(ct, "_test_patch_management", None),
                "vulnerability_management": getattr(ct, "_test_vulnerability_management", None),
                "asset_inventory": getattr(ct, "_test_asset_inventory", None),
            }
            for tname in user_tests:
                fn = runners.get(tname)
                if not callable(fn):
                    continue
                try:
                    result = fn(user_id)
                except Exception as exc:
                    _log.debug("test %s failed: %s", tname, exc)
                    continue
                if not isinstance(result, dict):
                    continue
                out["results"].append(result)
                status = str(result.get("status") or "unknown")
                for binding in control_bindings_for_test(tname) or []:
                    fid = str(binding.get("framework_id") or "").strip()
                    cid = str(binding.get("control_id") or "").strip()
                    if not fid or not cid:
                        continue
                    try:
                        record_test_result(
                            user_id,
                            fid,
                            cid,
                            test_name=tname,
                            status=status,
                            summary=str(result.get("summary") or "")[:500],
                            detail={
                                "agent_id": agent_id or None,
                                "recompute_reason": et,
                                **(result.get("detail") or {}),
                            },
                        )
                    except Exception:
                        pass
        except Exception as exc:
            _log.debug("user-scoped recompute skipped: %s", exc)

    return out
