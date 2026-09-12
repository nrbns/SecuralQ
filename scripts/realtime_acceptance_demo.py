"""REALTIME v1 RT-10/11 acceptance harness — lab only.

Simulates host-control fail → evidence → risk → POA&M → approved rem command →
pass for **firewall**, **Defender**, and **SSH** **without** mutating a real host.

Local mode asserts the full in-process closed loop per control:

  1. Control FAIL (synthetic telemetry)
  2. Evidence created (observed)
  3. Compliance / control.failed event published (capture bus)
  4. POA&M / gap_remediation OPEN (or rem exists)
  5. risk event published (and risk.changed if available)
  6. rem command pending → approve → lab-simulated agent result
  7. Control PASS (synthetic payload)
  8. Evidence PASS
  9. POA&M CLOSED / rem done
 10. risk reduction hint / risk.changed
 11. command verification_status=verified (after PASS check-in)

Modes:
  --local (default)  In-process via evaluate_agent_host_controls + temp DB
  --server URL       Live HTTP check-in against a lab server you own

Honest disclaimer (always printed):
  lab acceptance harness — not a 5k/HA proof

Usage:

  python scripts/realtime_acceptance_demo.py --local
  python scripts/realtime_acceptance_demo.py --server http://127.0.0.1:8080 --token <admin_jwt>
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

DISCLAIMER = "lab acceptance harness — not a 5k/HA proof"

# Firewall step names (stable for older tests / docs).
LOCAL_STEP_NAMES = [
    "1_firewall_off_host_control_fail",
    "2_evidence_created_observed",
    "3_compliance_or_control_failed_event",
    "4_poam_gap_remediation_open",
    "5_risk_event_published",
    "6_enable_firewall_command",
    "7_firewall_on_pass",
    "8_evidence_pass",
    "9_poam_closed_rem_done",
    "10_risk_reduction_hint",
]
OPTIONAL_ENABLE_FW_STEP = "6_enable_firewall_command"
LOCAL_VERIFY_STEP = "11_command_verification_verified"

PayloadFn = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class HostLoopSpec:
    test_id: str
    command_kind: str
    api_path: str  # e.g. enable-firewall
    fail_payload: PayloadFn
    pass_payload: PayloadFn
    request_fn_name: str
    step_names: tuple[str, ...]  # 10 core steps (1–10); verify appended separately
    status_key: str  # data key for fail/pass status (firewall_status / …)


def _base_payload(*, hostname: str, os_name: str) -> dict[str, Any]:
    return {
        "hostname": hostname,
        "ip": "127.0.0.1",
        "os": os_name,
        "os_version": "lab",
        "agent_version": "realtime-acceptance",
        "listening_ports": [],
        "processes": [],
        "packages": [],
        "firewall_status": {"collected": True, "enabled": True, "backend": "ufw"},
        "defender_status": {"collected": False, "reason": "Not applicable"},
        "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "no"}},
    }


def firewall_disabled_payload(*, hostname: str = "rt-accept-host") -> dict[str, Any]:
    p = _base_payload(hostname=hostname, os_name="linux")
    p["firewall_status"] = {"collected": True, "enabled": False, "backend": "ufw"}
    p["defender_status"] = {"collected": False, "reason": "Not applicable on linux"}
    return p


def firewall_enabled_payload(*, hostname: str = "rt-accept-host") -> dict[str, Any]:
    base = firewall_disabled_payload(hostname=hostname)
    base["firewall_status"] = {"collected": True, "enabled": True, "backend": "ufw"}
    return base


def defender_disabled_payload(*, hostname: str = "rt-accept-host") -> dict[str, Any]:
    p = _base_payload(hostname=hostname, os_name="windows")
    p["firewall_status"] = {"collected": True, "enabled": True, "backend": "windows"}
    p["defender_status"] = {
        "collected": True,
        "realtime_protection_enabled": False,
        "antivirus_enabled": True,
    }
    p["ssh_config"] = {"collected": False, "reason": "Not applicable on windows"}
    return p


def defender_enabled_payload(*, hostname: str = "rt-accept-host") -> dict[str, Any]:
    base = defender_disabled_payload(hostname=hostname)
    base["defender_status"] = {
        "collected": True,
        "realtime_protection_enabled": True,
        "antivirus_enabled": True,
    }
    return base


def ssh_root_allowed_payload(*, hostname: str = "rt-accept-host") -> dict[str, Any]:
    p = _base_payload(hostname=hostname, os_name="linux")
    p["ssh_config"] = {"collected": True, "settings": {"PermitRootLogin": "yes"}}
    p["defender_status"] = {"collected": False, "reason": "Not applicable on linux"}
    return p


def ssh_root_denied_payload(*, hostname: str = "rt-accept-host") -> dict[str, Any]:
    base = ssh_root_allowed_payload(hostname=hostname)
    base["ssh_config"] = {"collected": True, "settings": {"PermitRootLogin": "no"}}
    return base


def _defender_step_names() -> tuple[str, ...]:
    return (
        "1_defender_off_host_control_fail",
        "2_evidence_created_observed",
        "3_compliance_or_control_failed_event",
        "4_poam_gap_remediation_open",
        "5_risk_event_published",
        "6_enable_defender_command",
        "7_defender_on_pass",
        "8_evidence_pass",
        "9_poam_closed_rem_done",
        "10_risk_reduction_hint",
    )


def _ssh_step_names() -> tuple[str, ...]:
    return (
        "1_ssh_permit_root_host_control_fail",
        "2_evidence_created_observed",
        "3_compliance_or_control_failed_event",
        "4_poam_gap_remediation_open",
        "5_risk_event_published",
        "6_disable_ssh_root_command",
        "7_ssh_permit_root_pass",
        "8_evidence_pass",
        "9_poam_closed_rem_done",
        "10_risk_reduction_hint",
    )


HOST_LOOPS: tuple[HostLoopSpec, ...] = (
    HostLoopSpec(
        test_id="host_firewall",
        command_kind="enable_firewall",
        api_path="enable-firewall",
        fail_payload=firewall_disabled_payload,
        pass_payload=firewall_enabled_payload,
        request_fn_name="request_enable_firewall_command",
        step_names=tuple(LOCAL_STEP_NAMES),
        status_key="firewall_status",
    ),
    HostLoopSpec(
        test_id="host_defender",
        command_kind="enable_defender",
        api_path="enable-defender",
        fail_payload=defender_disabled_payload,
        pass_payload=defender_enabled_payload,
        request_fn_name="request_enable_defender_command",
        step_names=_defender_step_names(),
        status_key="defender_status",
    ),
    HostLoopSpec(
        test_id="host_ssh_root",
        command_kind="disable_ssh_root",
        api_path="disable-ssh-root",
        fail_payload=ssh_root_allowed_payload,
        pass_payload=ssh_root_denied_payload,
        request_fn_name="request_disable_ssh_root_command",
        step_names=_ssh_step_names(),
        status_key="ssh_status",
    ),
)


@dataclass
class StepResult:
    name: str
    ok: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AcceptanceReport:
    mode: str
    steps: list[StepResult] = field(default_factory=list)
    disclaimer: str = DISCLAIMER

    @property
    def ok(self) -> bool:
        return bool(self.steps) and all(s.ok for s in self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "ok": self.ok,
            "disclaimer": self.disclaimer,
            "steps": [asdict(s) for s in self.steps],
        }


def _test_result(out: dict[str, Any], test_id: str) -> dict[str, Any] | None:
    for r in out.get("results") or []:
        if (r.get("test") or "") == test_id:
            return r
    return None


def _event_type(evt: dict[str, Any]) -> str:
    return str(evt.get("event_type") or evt.get("type") or "").strip().lower()


def _event_status(evt: dict[str, Any]) -> str:
    return str(evt.get("status") or "").strip().lower()


def _event_test(evt: dict[str, Any]) -> str:
    return str(evt.get("test") or "").strip()


@contextmanager
def _capture_bus() -> Iterator[list[dict[str, Any]]]:
    """Record realtime_bus.publish kwargs while still invoking the real publish."""
    import app.realtime_bus as bus

    captured: list[dict[str, Any]] = []
    orig = bus.publish

    def _wrapped(event: dict[str, Any] | None = None, **kwargs: Any) -> None:
        payload = dict(event or {})
        payload.update(kwargs)
        captured.append(dict(payload))
        if event is not None:
            return orig(event, **kwargs)
        return orig(**kwargs)

    bus.publish = _wrapped  # type: ignore[assignment]
    try:
        yield captured
    finally:
        bus.publish = orig  # type: ignore[assignment]


def _markers(test_id: str, agent_id: str) -> tuple[str, str]:
    from app.controls.poam import poam_marker

    return poam_marker(test_id, agent_id), f"{test_id}:{agent_id}"


def _rem_matches(rem: dict[str, Any], test_id: str, agent_id: str) -> bool:
    marker, legacy = _markers(test_id, agent_id)
    notes = rem.get("notes") or ""
    rec = rem.get("recommendation") or ""
    return marker in notes or marker in rec or legacy in notes or legacy in rec


def _list_rems(
    user_id: str, agent_id: str, test_id: str, *, status: str | None = None
) -> list[dict[str, Any]]:
    from app.enterprise import list_remediations

    rows = list_remediations(user_id, status=status) if status else list_remediations(user_id)
    return [r for r in rows if _rem_matches(r, test_id, agent_id)]


def _evidence_has_status(rows: list[dict[str, Any]], *, test_id: str, want: str) -> bool:
    want = want.lower()
    for row in rows:
        detail = row.get("detail") or {}
        if isinstance(detail, dict) and (detail.get("status") or "").lower() == want:
            return True
        summary = (row.get("summary") or "").lower()
        if f"{test_id}:{want}" in summary:
            return True
        if (row.get("source") or "").lower() == "observed" and want in summary:
            return True
    return False


def _compliance_fail_on_bus(events: list[dict[str, Any]], test_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in events:
        et = _event_type(e)
        test = _event_test(e)
        if test and test != test_id:
            continue
        if et == "control.failed":
            out.append(e)
            continue
        if et in ("compliance", "control.test.completed") and _event_status(e) == "fail":
            if not test or test == test_id:
                out.append(e)
    return out


def _risk_events(
    events: list[dict[str, Any]], test_id: str, *, reduction: bool = False
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in events:
        et = _event_type(e)
        if et not in ("risk", "risk.changed") and not et.startswith("risk"):
            continue
        test = _event_test(e)
        if test and test != test_id:
            continue
        if reduction:
            hint = str(e.get("risk_hint") or e.get("hint") or "").lower()
            reason = str(e.get("reason") or "").lower()
            if hint == "reduction" or "pass_after_fail" in reason or et == "risk.changed":
                out.append(e)
        else:
            out.append(e)
    return out


def _risk_changed_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if _event_type(e) == "risk.changed"]


def _command_supported(kind: str) -> bool:
    try:
        import app.agents as agents_mod

        kinds = getattr(agents_mod, "SUPPORTED_COMMAND_KINDS", None)
        if kinds is None:
            from importlib import reload

            agents_mod = reload(agents_mod)
            kinds = getattr(agents_mod, "SUPPORTED_COMMAND_KINDS", set())
        return kind in kinds
    except Exception:
        return False


def _run_rem_command(
    report: AcceptanceReport,
    loop: HostLoopSpec,
    *,
    user_id: str,
    agent_id: str,
    step_name: str,
) -> str:
    """Request → approve → lab-simulated agent result. Returns command_id or ''."""
    if not _command_supported(loop.command_kind):
        report.steps.append(
            StepResult(
                name=step_name,
                ok=False,
                detail=f"FAIL: {loop.command_kind} missing from SUPPORTED_COMMAND_KINDS",
                data={"skipped": False, "supported": False},
            )
        )
        return ""

    import app.agents as agents_mod
    from app.db import get_conn

    request_fn = getattr(agents_mod, loop.request_fn_name)
    try:
        cmd = request_fn(user_id, agent_id, requested_by=user_id)
        cid = str(cmd.get("id") or "")
        pending_ok = bool(cid) and (cmd.get("status") or "") == "pending_approval"
        approved = agents_mod.approve_command(user_id, agent_id, cid, approver_id=user_id)
        approve_ok = (approved.get("status") or "") == "queued"
        get_conn().execute(
            "UPDATE securaiq_agent_commands SET status = 'sent' WHERE id = ?",
            (cid,),
        )
        get_conn().commit()
        result = agents_mod.report_command_result(
            agent_id,
            cid,
            status="done",
            result={"ok": True, "summary": f"lab simulated {loop.command_kind}", "lab": True},
        )
        result_ok = bool(result.get("ok"))
        row = get_conn().execute(
            "SELECT status, verification_status FROM securaiq_agent_commands WHERE id = ?",
            (cid,),
        ).fetchone()
        row_d = dict(row) if row else {}
        final_status = row_d.get("status") or ""
        v_pending = (row_d.get("verification_status") or "") == "pending"
        done_ok = final_status == "done"
        step_ok = pending_ok and approve_ok and result_ok and done_ok and v_pending
        report.steps.append(
            StepResult(
                name=step_name,
                ok=step_ok,
                detail=(
                    f"pending={pending_ok} approved={approve_ok} "
                    f"result_ok={result_ok} status={final_status!r} "
                    f"verification_pending={v_pending}"
                ),
                data={
                    "command_id": cid,
                    "pending_ok": pending_ok,
                    "approve_ok": approve_ok,
                    "result_ok": result_ok,
                    "final_status": final_status,
                    "verification_status": row_d.get("verification_status"),
                    "lab_simulated_agent_result": True,
                },
            )
        )
        return cid if step_ok else cid
    except Exception as exc:
        report.steps.append(
            StepResult(
                name=step_name,
                ok=False,
                detail=f"{loop.command_kind} loop error: {exc}"[:240],
            )
        )
        return ""


def run_local_host_loop(
    user_id: str,
    agent_id: str,
    loop: HostLoopSpec,
    *,
    report: AcceptanceReport | None = None,
    step_prefix: str = "",
) -> AcceptanceReport:
    """One FAIL → evidence → bus → POA&M → risk → approve rem → PASS → verified."""
    from app.db import get_conn
    from app.services.control_testing import evaluate_agent_host_controls
    from app.services.evidence import get_evidence_for

    report = report or AcceptanceReport(mode="local")
    names = loop.step_names
    prefix = f"{step_prefix}:" if step_prefix else ""

    def _n(i: int) -> str:
        return f"{prefix}{names[i]}"

    disabled = loop.fail_payload()
    enabled = loop.pass_payload()
    entity_id = f"{agent_id}:{loop.test_id}"
    test_id = loop.test_id

    with _capture_bus() as bus_fail:
        out_fail = evaluate_agent_host_controls(user_id, agent_id, disabled, asset_id="")
    tr_fail = _test_result(out_fail, test_id) or {}

    fail_ok = bool(out_fail.get("ok")) and (tr_fail.get("status") or "").lower() == "fail"
    report.steps.append(
        StepResult(
            name=_n(0),
            ok=fail_ok,
            detail=f"status={tr_fail.get('status')!r} summary={tr_fail.get('summary') or ''}"[:240],
            data={
                "evaluator_ok": out_fail.get("ok"),
                loop.status_key: tr_fail.get("status"),
                "test_id": test_id,
                "events": out_fail.get("events") or [],
                "evidence_ids": out_fail.get("evidence_ids") or [],
                "remediation_id": out_fail.get("remediation_id"),
            },
        )
    )

    trail_fail = get_evidence_for(
        user_id, entity_type="agent_host_control", entity_id=entity_id, limit=20
    )
    observed = any((r.get("source") or "").lower() == "observed" for r in trail_fail)
    evidence_fail_ok = bool(trail_fail) and (
        observed
        or bool(out_fail.get("evidence_ids"))
        or _evidence_has_status(trail_fail, test_id=test_id, want="fail")
    )
    report.steps.append(
        StepResult(
            name=_n(1),
            ok=evidence_fail_ok,
            detail=(
                f"rows={len(trail_fail)} observed={observed} "
                f"evidence_ids={len(out_fail.get('evidence_ids') or [])}"
            ),
            data={
                "evidence_count": len(trail_fail),
                "observed": observed,
                "evidence_ids": out_fail.get("evidence_ids") or [],
            },
        )
    )

    bus_comp = _compliance_fail_on_bus(bus_fail, test_id)
    out_comp = [
        e
        for e in (out_fail.get("events") or [])
        if e.get("type") == "compliance"
        and e.get("test") == test_id
        and (e.get("status") or "").lower() == "fail"
    ]
    report.steps.append(
        StepResult(
            name=_n(2),
            ok=bool(bus_comp) or bool(out_comp),
            detail=(
                f"bus_compliance_or_control_failed={len(bus_comp)} "
                f"evaluator_compliance_fail={len(out_comp)}"
            ),
            data={
                "bus_events": [
                    {"type": _event_type(e), "status": _event_status(e), "test": _event_test(e)}
                    for e in bus_comp[:8]
                ],
                "evaluator_events": out_comp,
            },
        )
    )

    open_rems = _list_rems(user_id, agent_id, test_id, status="open")
    rem_id = out_fail.get("remediation_id") or ((out_fail.get("remediation_ids") or [None])[0])
    report.steps.append(
        StepResult(
            name=_n(3),
            ok=bool(open_rems) or bool(rem_id),
            detail=f"open_rems={len(open_rems)} remediation_id={rem_id!r}",
            data={
                "open_count": len(open_rems),
                "remediation_id": rem_id,
                "open_ids": [r.get("id") for r in open_rems],
            },
        )
    )

    bus_risk = _risk_events(bus_fail, test_id, reduction=False)
    out_risk = [e for e in (out_fail.get("events") or []) if e.get("type") == "risk"]
    risk_changed = _risk_changed_events(bus_fail)
    report.steps.append(
        StepResult(
            name=_n(4),
            ok=bool(bus_risk) or bool(out_risk),
            detail=(
                f"bus_risk={len(bus_risk)} evaluator_risk={len(out_risk)} "
                f"risk_changed={'yes' if risk_changed else 'n/a'}"
            ),
            data={
                "bus_risk_count": len(bus_risk),
                "evaluator_risk": out_risk,
                "risk_changed_available": bool(risk_changed),
                "risk_changed_count": len(risk_changed),
            },
        )
    )

    cid = _run_rem_command(
        report, loop, user_id=user_id, agent_id=agent_id, step_name=_n(5)
    )

    with _capture_bus() as bus_pass:
        out_pass = evaluate_agent_host_controls(user_id, agent_id, enabled, asset_id="")
    tr_pass = _test_result(out_pass, test_id) or {}
    pass_ok = bool(out_pass.get("ok")) and (tr_pass.get("status") or "").lower() == "pass"
    report.steps.append(
        StepResult(
            name=_n(6),
            ok=pass_ok,
            detail=f"status={tr_pass.get('status')!r} summary={tr_pass.get('summary') or ''}"[:240],
            data={
                "evaluator_ok": out_pass.get("ok"),
                loop.status_key: tr_pass.get("status"),
                "events": out_pass.get("events") or [],
                "evidence_ids": out_pass.get("evidence_ids") or [],
            },
        )
    )

    trail_pass = get_evidence_for(
        user_id, entity_type="agent_host_control", entity_id=entity_id, limit=20
    )
    evidence_pass_ok = _evidence_has_status(trail_pass, test_id=test_id, want="pass")
    report.steps.append(
        StepResult(
            name=_n(7),
            ok=evidence_pass_ok,
            detail=f"rows={len(trail_pass)} has_pass={evidence_pass_ok}",
            data={"evidence_count": len(trail_pass), "has_pass": evidence_pass_ok},
        )
    )

    still_open = _list_rems(user_id, agent_id, test_id, status="open")
    done_rems = _list_rems(user_id, agent_id, test_id, status="done")
    had_open = bool(open_rems) or bool(rem_id)
    report.steps.append(
        StepResult(
            name=_n(8),
            ok=had_open and not still_open,
            detail=f"still_open={len(still_open)} done={len(done_rems)} had_open={had_open}",
            data={
                "still_open": len(still_open),
                "done_count": len(done_rems),
                "done_ids": [r.get("id") for r in done_rems],
            },
        )
    )

    bus_reduce = _risk_events(bus_pass, test_id, reduction=True)
    out_reduce = [
        e
        for e in (out_pass.get("events") or [])
        if e.get("type") == "risk" and (e.get("hint") or "").lower() == "reduction"
    ]
    risk_changed_pass = _risk_changed_events(bus_pass)
    report.steps.append(
        StepResult(
            name=_n(9),
            ok=bool(bus_reduce) or bool(out_reduce) or bool(risk_changed_pass),
            detail=(
                f"bus_reduction={len(bus_reduce)} evaluator_reduction={len(out_reduce)} "
                f"risk_changed={'yes' if risk_changed_pass else 'n/a'}"
            ),
            data={
                "bus_reduction": len(bus_reduce),
                "evaluator_events": out_reduce,
                "risk_changed_available": bool(risk_changed_pass),
            },
        )
    )

    vstat = ""
    if cid:
        row = get_conn().execute(
            "SELECT verification_status FROM securaiq_agent_commands WHERE id = ?",
            (cid,),
        ).fetchone()
        vstat = (dict(row).get("verification_status") if row else "") or ""
    report.steps.append(
        StepResult(
            name=f"{prefix}{LOCAL_VERIFY_STEP}",
            ok=bool(cid) and vstat == "verified",
            detail=f"command_id={cid[:16] if cid else ''} verification_status={vstat}",
            data={"command_id": cid, "verification_status": vstat},
        )
    )
    return report


def run_local_chain(user_id: str, agent_id: str) -> AcceptanceReport:
    """Firewall-only closed loop (backward compatible)."""
    return run_local_host_loop(user_id, agent_id, HOST_LOOPS[0])


def run_local_all_host_loops(user_id: str, agent_id: str) -> AcceptanceReport:
    """RT-11 triple host: firewall + Defender + SSH on one lab agent."""
    report = AcceptanceReport(mode="local")
    for loop in HOST_LOOPS:
        run_local_host_loop(
            user_id,
            agent_id,
            loop,
            report=report,
            step_prefix=loop.test_id,
        )
    return report


def _patch_settings_for_temp_data(data_dir: Path) -> None:
    """Point live Settings singletons at a throwaway data dir (CLI local mode)."""
    import app.db as db_mod

    data_dir.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(data_dir)
    os.environ.setdefault("WORKSPACE_ZERO_START", "false")
    os.environ.setdefault("AUTH_ENABLED", "true")

    _required = ("auth_enabled", "data_dir", "database_url")
    seen: set[int] = set()
    for mod in list(sys.modules.values()):
        s = getattr(mod, "settings", None)
        if (
            s is not None
            and all(hasattr(s, a) for a in _required)
            and id(s) not in seen
        ):
            seen.add(id(s))
            try:
                s.data_dir = str(data_dir)
                s.workspace_zero_start = False
                s.auth_enabled = True
                s.deployment_mode = "lab"
                s.database_url = ""
            except Exception:
                pass
    db_mod.reset_conn_for_tests()


def run_local_acceptance(*, data_dir: Path | None = None) -> AcceptanceReport:
    """CLI-friendly local run with an isolated temp DB (all three host loops)."""
    td_ctx = None
    if data_dir is None:
        td_ctx = tempfile.TemporaryDirectory(prefix="rt-accept-", ignore_cleanup_errors=True)
        data_dir = Path(td_ctx.name) / "data"

    try:
        _patch_settings_for_temp_data(data_dir)
        from app.agents import enroll_agent
        from app.auth import login, register_user
        from app.db import reset_conn_for_tests
        from app.tenancy import ensure_tenant_schema

        ensure_tenant_schema()
        username = f"rt_accept_{int(time.time())}"
        register_user(username, "password123", role="admin")
        user, _token = login(username, "password123")
        agent = enroll_agent(user.id, name="rt-accept-local")
        report = run_local_all_host_loops(user.id, agent["agent_id"])
        reset_conn_for_tests()
        return report
    finally:
        try:
            from app.db import reset_conn_for_tests

            reset_conn_for_tests()
        except Exception:
            pass
        if td_ctx is not None:
            td_ctx.cleanup()


def _request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    insecure: bool = False,
    timeout: float = 30.0,
) -> tuple[int, Any]:
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw) if raw else {}
            except Exception:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, raw


def _evidence_status(rows: list[dict[str, Any]], *, test_id: str, want: str) -> bool:
    want = want.lower()
    for row in rows:
        detail = row.get("detail") or {}
        st = (detail.get("status") or "").lower()
        if st == want:
            return True
        summary = (row.get("summary") or "").lower()
        if f"{test_id}:{want}" in summary:
            return True
    return False


def _run_server_host_loop(
    report: AcceptanceReport,
    *,
    base: str,
    agent_id: str,
    agent_auth: dict[str, str],
    auth_user: dict[str, str],
    loop: HostLoopSpec,
    hostname: str,
    insecure: bool,
) -> None:
    prefix = loop.test_id
    code_fail, resp_fail = _request(
        "POST",
        f"{base}/api/agents/checkin",
        headers=agent_auth,
        body=loop.fail_payload(hostname=hostname),
        insecure=insecure,
    )
    checkin_fail_ok = code_fail == 200 and isinstance(resp_fail, dict) and bool(resp_fail.get("ok"))
    report.steps.append(
        StepResult(
            name=f"{prefix}:disabled_checkin",
            ok=checkin_fail_ok,
            detail=f"http={code_fail} response_ok={checkin_fail_ok}",
            data={"http_status": code_fail, "response_ok": checkin_fail_ok},
        )
    )
    if not checkin_fail_ok:
        return

    time.sleep(0.3)
    code_ev, ev_data = _request(
        "GET",
        f"{base}/api/evidence/agent_host_control/{agent_id}:{loop.test_id}",
        headers=auth_user,
        insecure=insecure,
    )
    rows = (ev_data.get("evidence") if isinstance(ev_data, dict) else None) or []
    code_live, live = _request(
        "GET",
        f"{base}/api/compliance/live-failures",
        headers=auth_user,
        insecure=insecure,
    )
    failures = (live.get("failures") if isinstance(live, dict) else None) or []
    live_fail = any(
        isinstance(f, dict)
        and (f.get("test") or "") == loop.test_id
        and (f.get("status") or "").lower() == "fail"
        for f in failures
    )
    evidence_fail_ok = code_ev == 200 and _evidence_status(rows, test_id=loop.test_id, want="fail")
    report.steps.append(
        StepResult(
            name=f"{prefix}:evidence_and_compliance_fail",
            ok=evidence_fail_ok or (code_live == 200 and live_fail),
            detail=(
                f"evidence_http={code_ev} evidence_fail={evidence_fail_ok} "
                f"live_http={code_live} live_fail={live_fail}"
            ),
            data={
                "evidence_http": code_ev,
                "evidence_rows": len(rows),
                "live_failures_http": code_live,
                "live_fail": live_fail,
            },
        )
    )

    code_cmd, cmd_body = _request(
        "POST",
        f"{base}/api/agents/{agent_id}/commands/{loop.api_path}",
        headers=auth_user,
        body={},
        insecure=insecure,
    )
    cmd_id = str(cmd_body.get("id") or "") if isinstance(cmd_body, dict) else ""
    cmd_ok = code_cmd in (200, 201) and bool(cmd_id)
    report.steps.append(
        StepResult(
            name=f"{prefix}:request_{loop.command_kind}",
            ok=cmd_ok,
            detail=f"http={code_cmd} cmd={cmd_id[:16]}",
            data={"http_status": code_cmd, "command_id": cmd_id},
        )
    )
    if cmd_ok:
        code_appr, appr = _request(
            "POST",
            f"{base}/api/agents/{agent_id}/commands/{cmd_id}/approve",
            headers=auth_user,
            body={},
            insecure=insecure,
        )
        report.steps.append(
            StepResult(
                name=f"{prefix}:approve_{loop.command_kind}",
                ok=code_appr == 200,
                detail=f"http={code_appr} status={(appr or {}).get('status') if isinstance(appr, dict) else None}",
            )
        )
        code_res, res = _request(
            "POST",
            f"{base}/api/agents/commands/{cmd_id}/result",
            headers=agent_auth,
            body={"status": "done", "result": {"ok": True, "lab": True, "simulated": True}},
            insecure=insecure,
        )
        report.steps.append(
            StepResult(
                name=f"{prefix}:agent_command_result",
                ok=code_res == 200,
                detail=f"http={code_res} body={str(res)[:120]}",
            )
        )

    code_pass, resp_pass = _request(
        "POST",
        f"{base}/api/agents/checkin",
        headers=agent_auth,
        body=loop.pass_payload(hostname=hostname),
        insecure=insecure,
    )
    checkin_pass_ok = code_pass == 200 and isinstance(resp_pass, dict) and bool(resp_pass.get("ok"))
    if not checkin_pass_ok:
        report.steps.append(
            StepResult(
                name=f"{prefix}:enabled_compliance_pass",
                ok=False,
                detail=f"check-in failed http={code_pass}",
                data={"http_status": code_pass},
            )
        )
        return

    time.sleep(0.3)
    code_ev2, ev_data2 = _request(
        "GET",
        f"{base}/api/evidence/agent_host_control/{agent_id}:{loop.test_id}",
        headers=auth_user,
        insecure=insecure,
    )
    rows2 = (ev_data2.get("evidence") if isinstance(ev_data2, dict) else None) or []
    pass_ok = checkin_pass_ok and code_ev2 == 200 and _evidence_status(
        rows2, test_id=loop.test_id, want="pass"
    )
    report.steps.append(
        StepResult(
            name=f"{prefix}:enabled_compliance_pass",
            ok=pass_ok,
            detail=(
                f"checkin_http={code_pass} evidence_http={code_ev2} "
                f"has_pass={_evidence_status(rows2, test_id=loop.test_id, want='pass')}"
            ),
            data={
                "http_status": code_pass,
                "evidence_http": code_ev2,
                "evidence_rows": len(rows2),
            },
        )
    )

    if cmd_id:
        code_cmds, cmds = _request(
            "GET",
            f"{base}/api/agents/{agent_id}/commands?limit=40",
            headers=auth_user,
            insecure=insecure,
        )
        rows_c = (cmds.get("commands") if isinstance(cmds, dict) else None) or []
        mine = next((c for c in rows_c if isinstance(c, dict) and c.get("id") == cmd_id), None)
        vstat = (mine or {}).get("verification_status") or ""
        report.steps.append(
            StepResult(
                name=f"{prefix}:command_verification_verified",
                ok=code_cmds == 200 and vstat == "verified",
                detail=f"http={code_cmds} verification_status={vstat}",
                data={"verification_status": vstat},
            )
        )


def run_server_acceptance(
    server: str,
    admin_token: str,
    *,
    insecure: bool = False,
) -> AcceptanceReport:
    """Live HTTP check-in against a lab server; firewall + Defender + SSH loops."""
    report = AcceptanceReport(mode="server")
    base = server.rstrip("/")
    auth_user = {"Authorization": f"Bearer {admin_token}"}

    code, enrolled = _request(
        "POST",
        f"{base}/api/agents/enroll",
        headers=auth_user,
        body={"name": f"rt-accept-{int(time.time())}"},
        insecure=insecure,
    )
    if code != 200 or not isinstance(enrolled, dict) or not enrolled.get("agent_token"):
        report.steps.append(
            StepResult(name="enroll", ok=False, detail=f"enroll failed: {code} {enrolled}")
        )
        return report

    agent_token = str(enrolled["agent_token"])
    agent_id = str(enrolled.get("agent_id") or agent_token.split(".", 1)[0])
    agent_auth = {"Authorization": f"Bearer {agent_token}"}
    hostname = f"rt-accept-{agent_id[:8]}"

    for loop in HOST_LOOPS:
        _run_server_host_loop(
            report,
            base=base,
            agent_id=agent_id,
            agent_auth=agent_auth,
            auth_user=auth_user,
            loop=loop,
            hostname=hostname,
            insecure=insecure,
        )

    code_h, health = _request(
        "GET",
        f"{base}/api/health",
        headers=auth_user,
        insecure=insecure,
    )
    bus = (health.get("realtime_bus") if isinstance(health, dict) else None) or {}
    mode = str(bus.get("mode") or "")
    report.steps.append(
        StepResult(
            name="realtime_bus_mode",
            ok=code_h == 200
            and mode in ("in_process", "redis_streams_fanout", "redis_streams+pubsub"),
            detail=f"http={code_h} mode={mode}",
            data={"mode": mode},
        )
    )
    return report


def print_report(report: AcceptanceReport) -> None:
    print(f"[rt-accept] {DISCLAIMER}", flush=True)
    print(f"[rt-accept] mode={report.mode} overall={'PASS' if report.ok else 'FAIL'}", flush=True)
    for step in report.steps:
        mark = "PASS" if step.ok else "FAIL"
        print(f"  [{mark}] {step.name}: {step.detail}", flush=True)
    print(json.dumps(report.to_dict(), indent=2), flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="SecuraIQ RT-10/11 host fail→pass acceptance (firewall+Defender+SSH, lab only)"
    )
    ap.add_argument(
        "--local",
        action="store_true",
        default=False,
        help="In-process unit path with temp DB (default when --server not set)",
    )
    ap.add_argument(
        "--firewall-only",
        action="store_true",
        help="Local mode: only host_firewall loop (legacy)",
    )
    ap.add_argument(
        "--server",
        default="",
        help="Lab server base URL (e.g. http://127.0.0.1:8080)",
    )
    ap.add_argument(
        "--token",
        default=os.environ.get("SECURAIQ_ADMIN_TOKEN", ""),
        help="Admin JWT for enroll + evidence (or SECURAIQ_ADMIN_TOKEN)",
    )
    ap.add_argument("--admin-token", default="", help="Alias for --token")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verify for https lab servers")
    args = ap.parse_args(argv)

    token = (args.admin_token or args.token or "").strip()

    if args.server:
        if not token:
            print("[rt-accept] --token / SECURAIQ_ADMIN_TOKEN required for --server", flush=True)
            return 2
        report = run_server_acceptance(args.server, token, insecure=args.insecure)
    elif args.firewall_only:
        # Legacy single-loop CLI path
        td_ctx = tempfile.TemporaryDirectory(prefix="rt-accept-", ignore_cleanup_errors=True)
        try:
            data_dir = Path(td_ctx.name) / "data"
            _patch_settings_for_temp_data(data_dir)
            from app.agents import enroll_agent
            from app.auth import login, register_user
            from app.db import reset_conn_for_tests
            from app.tenancy import ensure_tenant_schema

            ensure_tenant_schema()
            username = f"rt_accept_{int(time.time())}"
            register_user(username, "password123", role="admin")
            user, _token = login(username, "password123")
            agent = enroll_agent(user.id, name="rt-accept-fw")
            report = run_local_chain(user.id, agent["agent_id"])
            reset_conn_for_tests()
        finally:
            try:
                from app.db import reset_conn_for_tests

                reset_conn_for_tests()
            except Exception:
                pass
            td_ctx.cleanup()
    else:
        report = run_local_acceptance()

    print_report(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
