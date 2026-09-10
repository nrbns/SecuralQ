"""REALTIME v1 RT-10/11 acceptance harness — lab only.

Simulates the master-plan firewall fail → evidence → risk → POA&M →
approved enable_firewall → pass chain **without** changing a real Windows firewall.

Local mode asserts the full in-process closed loop:

  1. Firewall OFF → host control FAIL
  2. Evidence created (observed)
  3. Compliance / control.failed event published (capture bus)
  4. POA&M / gap_remediation OPEN (or rem exists)
  5. risk event published (and risk.changed if available)
  6. enable_firewall pending → approve → lab-simulated agent result
  7. Firewall ON → PASS (synthetic payload)
  8. Evidence PASS
  9. POA&M CLOSED / rem done
 10. risk reduction hint / risk.changed

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
from typing import Any, Iterator

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

DISCLAIMER = "lab acceptance harness — not a 5k/HA proof"

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
# Backward-compatible alias (older tests / docs may still import this name).
OPTIONAL_ENABLE_FW_STEP = "6_enable_firewall_command"


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


def firewall_disabled_payload(*, hostname: str = "rt-accept-host") -> dict[str, Any]:
    return {
        "hostname": hostname,
        "ip": "127.0.0.1",
        "os": "linux",
        "os_version": "lab",
        "agent_version": "realtime-acceptance",
        "listening_ports": [],
        "processes": [],
        "packages": [],
        "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
        "defender_status": {"collected": False, "reason": "Not applicable on linux"},
        "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "no"}},
    }


def firewall_enabled_payload(*, hostname: str = "rt-accept-host") -> dict[str, Any]:
    base = firewall_disabled_payload(hostname=hostname)
    base["firewall_status"] = {"collected": True, "enabled": True, "backend": "ufw"}
    return base


def _fw_result(out: dict[str, Any]) -> dict[str, Any] | None:
    for r in out.get("results") or []:
        if (r.get("test") or "") == "host_firewall":
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


def _fw_markers(agent_id: str) -> tuple[str, str]:
    from app.controls.poam import poam_marker

    return poam_marker("host_firewall", agent_id), f"host_firewall:{agent_id}"


def _rem_matches_fw(rem: dict[str, Any], agent_id: str) -> bool:
    marker, legacy = _fw_markers(agent_id)
    notes = rem.get("notes") or ""
    rec = rem.get("recommendation") or ""
    return marker in notes or marker in rec or legacy in notes or legacy in rec


def _list_fw_rems(user_id: str, agent_id: str, *, status: str | None = None) -> list[dict[str, Any]]:
    from app.enterprise import list_remediations

    rows = list_remediations(user_id, status=status) if status else list_remediations(user_id)
    return [r for r in rows if _rem_matches_fw(r, agent_id)]


def _evidence_has_status(rows: list[dict[str, Any]], *, want: str) -> bool:
    want = want.lower()
    for row in rows:
        detail = row.get("detail") or {}
        if isinstance(detail, dict) and (detail.get("status") or "").lower() == want:
            return True
        summary = (row.get("summary") or "").lower()
        if f"host_firewall:{want}" in summary:
            return True
        if (row.get("source") or "").lower() == "observed" and want in summary:
            return True
    return False


def _compliance_fail_on_bus(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in events:
        et = _event_type(e)
        test = _event_test(e)
        if test and test != "host_firewall":
            continue
        if et == "control.failed":
            out.append(e)
            continue
        if et in ("compliance", "control.test.completed") and _event_status(e) == "fail":
            if not test or test == "host_firewall":
                out.append(e)
    return out


def _risk_events(events: list[dict[str, Any]], *, reduction: bool = False) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in events:
        et = _event_type(e)
        if et not in ("risk", "risk.changed") and not et.startswith("risk"):
            continue
        test = _event_test(e)
        if test and test != "host_firewall":
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


def _enable_firewall_supported() -> bool:
    """Resolve enable_firewall after app.agents is fully initialized (avoid import-timing miss)."""
    try:
        import app.agents as agents_mod

        kinds = getattr(agents_mod, "SUPPORTED_COMMAND_KINDS", None)
        if kinds is None:
            # Module still initializing — re-import attribute once package load finishes.
            from importlib import reload

            agents_mod = reload(agents_mod)
            kinds = getattr(agents_mod, "SUPPORTED_COMMAND_KINDS", set())
        return "enable_firewall" in kinds
    except Exception:
        return False


def _run_enable_firewall_command(
    report: AcceptanceReport,
    *,
    user_id: str,
    agent_id: str,
) -> None:
    """Step 6 — request → approve → lab-simulated agent result for enable_firewall.

    Local mode does not mutate a real host firewall; the next step still
    evaluates a synthetic ON payload (honest lab verify).
    """
    step_name = LOCAL_STEP_NAMES[5]  # 6_enable_firewall_command
    if not _enable_firewall_supported():
        report.steps.append(
            StepResult(
                name=step_name,
                ok=False,
                detail="FAIL: enable_firewall missing from SUPPORTED_COMMAND_KINDS",
                data={"skipped": False, "supported": False},
            )
        )
        return

    from app.agents import approve_command, report_command_result, request_enable_firewall_command
    from app.db import get_conn

    try:
        cmd = request_enable_firewall_command(
            user_id,
            agent_id,
            requested_by=user_id,
        )
        cid = str(cmd.get("id") or "")
        pending_ok = bool(cid) and (cmd.get("status") or "") == "pending_approval"
        approved = approve_command(user_id, agent_id, cid, approver_id=user_id)
        approve_ok = (approved.get("status") or "") == "queued"
        # Simulate dispatch so agent result can be recorded (queued → sent).
        get_conn().execute(
            "UPDATE securaiq_agent_commands SET status = 'sent' WHERE id = ?",
            (cid,),
        )
        get_conn().commit()
        result = report_command_result(
            agent_id,
            cid,
            status="done",
            result={"ok": True, "summary": "lab simulated enable_firewall", "lab": True},
        )
        result_ok = bool(result.get("ok"))
        row = get_conn().execute(
            "SELECT status FROM securaiq_agent_commands WHERE id = ?",
            (cid,),
        ).fetchone()
        final_status = (dict(row).get("status") if row else "") or ""
        done_ok = final_status == "done"
        step_ok = pending_ok and approve_ok and result_ok and done_ok
        report.steps.append(
            StepResult(
                name=step_name,
                ok=step_ok,
                detail=(
                    f"pending={pending_ok} approved={approve_ok} "
                    f"result_ok={result_ok} status={final_status!r}"
                ),
                data={
                    "command_id": cid,
                    "pending_ok": pending_ok,
                    "approve_ok": approve_ok,
                    "result_ok": result_ok,
                    "final_status": final_status,
                    "lab_simulated_agent_result": True,
                },
            )
        )
    except Exception as exc:
        report.steps.append(
            StepResult(
                name=step_name,
                ok=False,
                detail=f"enable_firewall loop error: {exc}"[:240],
            )
        )


def run_local_chain(user_id: str, agent_id: str) -> AcceptanceReport:
    """Full FAIL → evidence → bus → POA&M → risk → approve enable_firewall → PASS.

    Caller must have already pointed the app at an isolated DB (test fixture
    or CLI temp dir). No network. Local PASS uses a synthetic ON payload
    (does not mutate a real Windows/Linux firewall).
    """
    from app.services.control_testing import evaluate_agent_host_controls
    from app.services.evidence import get_evidence_for

    report = AcceptanceReport(mode="local")
    disabled = firewall_disabled_payload()
    enabled = firewall_enabled_payload()
    entity_id = f"{agent_id}:host_firewall"

    with _capture_bus() as bus_fail:
        out_fail = evaluate_agent_host_controls(user_id, agent_id, disabled, asset_id="")
    fw_fail = _fw_result(out_fail) or {}

    # 1 — Firewall OFF → host control FAIL
    fail_ok = bool(out_fail.get("ok")) and (fw_fail.get("status") or "").lower() == "fail"
    report.steps.append(
        StepResult(
            name=LOCAL_STEP_NAMES[0],
            ok=fail_ok,
            detail=f"status={fw_fail.get('status')!r} summary={fw_fail.get('summary') or ''}"[:240],
            data={
                "evaluator_ok": out_fail.get("ok"),
                "firewall_status": fw_fail.get("status"),
                "events": out_fail.get("events") or [],
                "evidence_ids": out_fail.get("evidence_ids") or [],
                "remediation_id": out_fail.get("remediation_id"),
            },
        )
    )

    # 2 — Evidence created (observed)
    trail_fail = get_evidence_for(
        user_id, entity_type="agent_host_control", entity_id=entity_id, limit=20
    )
    observed = any((r.get("source") or "").lower() == "observed" for r in trail_fail)
    evidence_fail_ok = bool(trail_fail) and (
        observed or bool(out_fail.get("evidence_ids")) or _evidence_has_status(trail_fail, want="fail")
    )
    report.steps.append(
        StepResult(
            name=LOCAL_STEP_NAMES[1],
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

    # 3 — Compliance / control.failed on bus
    bus_comp = _compliance_fail_on_bus(bus_fail)
    out_comp = [
        e
        for e in (out_fail.get("events") or [])
        if e.get("type") == "compliance"
        and e.get("test") == "host_firewall"
        and (e.get("status") or "").lower() == "fail"
    ]
    step3_ok = bool(bus_comp) or bool(out_comp)
    report.steps.append(
        StepResult(
            name=LOCAL_STEP_NAMES[2],
            ok=step3_ok,
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

    # 4 — POA&M / gap_remediation OPEN
    open_rems = _list_fw_rems(user_id, agent_id, status="open")
    rem_id = out_fail.get("remediation_id") or (
        (out_fail.get("remediation_ids") or [None])[0]
    )
    poam_open_ok = bool(open_rems) or bool(rem_id)
    report.steps.append(
        StepResult(
            name=LOCAL_STEP_NAMES[3],
            ok=poam_open_ok,
            detail=f"open_fw_rems={len(open_rems)} remediation_id={rem_id!r}",
            data={
                "open_count": len(open_rems),
                "remediation_id": rem_id,
                "open_ids": [r.get("id") for r in open_rems],
            },
        )
    )

    # 5 — risk event (risk.changed if available)
    bus_risk = _risk_events(bus_fail, reduction=False)
    out_risk = [e for e in (out_fail.get("events") or []) if e.get("type") == "risk"]
    risk_changed = _risk_changed_events(bus_fail)
    risk_ok = bool(bus_risk) or bool(out_risk)
    report.steps.append(
        StepResult(
            name=LOCAL_STEP_NAMES[4],
            ok=risk_ok,
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

    # 6 — enable_firewall request → approve → lab-simulated agent result
    # (causal remediation before verify PASS; does not mutate a real host firewall)
    _run_enable_firewall_command(report, user_id=user_id, agent_id=agent_id)

    # 7 — Firewall ON → PASS (synthetic payload = lab verify after remediation)
    with _capture_bus() as bus_pass:
        out_pass = evaluate_agent_host_controls(user_id, agent_id, enabled, asset_id="")
    fw_pass = _fw_result(out_pass) or {}
    pass_ok = bool(out_pass.get("ok")) and (fw_pass.get("status") or "").lower() == "pass"
    report.steps.append(
        StepResult(
            name=LOCAL_STEP_NAMES[6],
            ok=pass_ok,
            detail=f"status={fw_pass.get('status')!r} summary={fw_pass.get('summary') or ''}"[:240],
            data={
                "evaluator_ok": out_pass.get("ok"),
                "firewall_status": fw_pass.get("status"),
                "events": out_pass.get("events") or [],
                "evidence_ids": out_pass.get("evidence_ids") or [],
            },
        )
    )

    # 8 — Evidence PASS
    trail_pass = get_evidence_for(
        user_id, entity_type="agent_host_control", entity_id=entity_id, limit=20
    )
    evidence_pass_ok = _evidence_has_status(trail_pass, want="pass")
    report.steps.append(
        StepResult(
            name=LOCAL_STEP_NAMES[7],
            ok=evidence_pass_ok,
            detail=f"rows={len(trail_pass)} has_pass={evidence_pass_ok}",
            data={"evidence_count": len(trail_pass), "has_pass": evidence_pass_ok},
        )
    )

    # 9 — POA&M CLOSED / rem done
    still_open = _list_fw_rems(user_id, agent_id, status="open")
    done_rems = _list_fw_rems(user_id, agent_id, status="done")
    had_open = bool(open_rems) or bool(rem_id)
    poam_closed_ok = had_open and not still_open
    report.steps.append(
        StepResult(
            name=LOCAL_STEP_NAMES[8],
            ok=poam_closed_ok,
            detail=f"still_open={len(still_open)} done={len(done_rems)} had_open={had_open}",
            data={
                "still_open": len(still_open),
                "done_count": len(done_rems),
                "done_ids": [r.get("id") for r in done_rems],
            },
        )
    )

    # 10 — risk reduction hint / risk.changed
    bus_reduce = _risk_events(bus_pass, reduction=True)
    out_reduce = [
        e
        for e in (out_pass.get("events") or [])
        if e.get("type") == "risk" and (e.get("hint") or "").lower() == "reduction"
    ]
    risk_changed_pass = _risk_changed_events(bus_pass)
    reduce_ok = bool(bus_reduce) or bool(out_reduce) or bool(risk_changed_pass)
    report.steps.append(
        StepResult(
            name=LOCAL_STEP_NAMES[9],
            ok=reduce_ok,
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
    """CLI-friendly local run with an isolated temp DB."""
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
        report = run_local_chain(user.id, agent["agent_id"])
        # Release SQLite before temp-dir cleanup (Windows file locks).
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


def _evidence_status(rows: list[dict[str, Any]], *, want: str) -> bool:
    want = want.lower()
    for row in rows:
        detail = row.get("detail") or {}
        st = (detail.get("status") or "").lower()
        if st == want:
            return True
        summary = (row.get("summary") or "").lower()
        if f"host_firewall:{want}" in summary:
            return True
    return False


def run_server_acceptance(
    server: str,
    admin_token: str,
    *,
    insecure: bool = False,
) -> AcceptanceReport:
    """Live HTTP check-in against a lab server; assert via evidence / live-failures."""
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
            StepResult(
                name="enroll",
                ok=False,
                detail=f"enroll failed: {code} {enrolled}",
            )
        )
        return report

    agent_token = str(enrolled["agent_token"])
    agent_id = str(enrolled.get("agent_id") or agent_token.split(".", 1)[0])
    agent_auth = {"Authorization": f"Bearer {agent_token}"}
    hostname = f"rt-accept-{agent_id[:8]}"

    # Step 1 — check-in firewall disabled
    code_fail, resp_fail = _request(
        "POST",
        f"{base}/api/agents/checkin",
        headers=agent_auth,
        body=firewall_disabled_payload(hostname=hostname),
        insecure=insecure,
    )
    checkin_fail_ok = code_fail == 200 and isinstance(resp_fail, dict) and bool(resp_fail.get("ok"))
    report.steps.append(
        StepResult(
            name="firewall_disabled_checkin",
            ok=checkin_fail_ok,
            detail=f"http={code_fail} response_ok={checkin_fail_ok} agent_id={agent_id}",
            data={"http_status": code_fail, "response_ok": checkin_fail_ok, "agent_id": agent_id},
        )
    )
    if not checkin_fail_ok:
        return report

    # Step 2 — evidence / live-failures show firewall FAIL
    time.sleep(0.3)
    code_ev, ev_data = _request(
        "GET",
        f"{base}/api/evidence/agent_host_control/{agent_id}:host_firewall",
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
    live_fw_fail = False
    for f in failures:
        if not isinstance(f, dict):
            continue
        if (f.get("test") or "") != "host_firewall":
            continue
        if (f.get("status") or "").lower() != "fail":
            continue
        live_fw_fail = True
        break

    evidence_fail_ok = code_ev == 200 and _evidence_status(rows, want="fail")
    step2_ok = evidence_fail_ok or (code_live == 200 and live_fw_fail)
    report.steps.append(
        StepResult(
            name="evidence_and_compliance_event",
            ok=step2_ok,
            detail=(
                f"evidence_http={code_ev} evidence_fail={evidence_fail_ok} "
                f"live_http={code_live} live_fw_fail={live_fw_fail} evidence_rows={len(rows)}"
            ),
            data={
                "evidence_http": code_ev,
                "evidence_rows": len(rows),
                "live_failures_http": code_live,
                "live_fw_fail": live_fw_fail,
            },
        )
    )

    # Step 3 — check-in firewall enabled → PASS evidence
    code_pass, resp_pass = _request(
        "POST",
        f"{base}/api/agents/checkin",
        headers=agent_auth,
        body=firewall_enabled_payload(hostname=hostname),
        insecure=insecure,
    )
    checkin_pass_ok = code_pass == 200 and isinstance(resp_pass, dict) and bool(resp_pass.get("ok"))
    if not checkin_pass_ok:
        report.steps.append(
            StepResult(
                name="firewall_enabled_compliance_pass",
                ok=False,
                detail=f"check-in failed http={code_pass}",
                data={"http_status": code_pass},
            )
        )
        return report

    time.sleep(0.3)
    code_ev2, ev_data2 = _request(
        "GET",
        f"{base}/api/evidence/agent_host_control/{agent_id}:host_firewall",
        headers=auth_user,
        insecure=insecure,
    )
    rows2 = (ev_data2.get("evidence") if isinstance(ev_data2, dict) else None) or []
    pass_ok = checkin_pass_ok and code_ev2 == 200 and _evidence_status(rows2, want="pass")
    report.steps.append(
        StepResult(
            name="firewall_enabled_compliance_pass",
            ok=pass_ok,
            detail=f"checkin_http={code_pass} evidence_http={code_ev2} has_pass={_evidence_status(rows2, want='pass')}",
            data={
                "http_status": code_pass,
                "evidence_http": code_ev2,
                "evidence_rows": len(rows2),
            },
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
        description="SecuraIQ RT-10/11 firewall fail→pass acceptance (lab only)"
    )
    ap.add_argument(
        "--local",
        action="store_true",
        default=False,
        help="In-process unit path with temp DB (default when --server not set)",
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
    ap.add_argument(
        "--admin-token",
        default="",
        help="Alias for --token",
    )
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verify for https lab servers")
    args = ap.parse_args(argv)

    token = (args.admin_token or args.token or "").strip()
    server = (args.server or "").strip()

    if server:
        if not token:
            print("[rt-accept] --server requires --token (admin JWT)", flush=True)
            print(f"[rt-accept] {DISCLAIMER}", flush=True)
            return 2
        report = run_server_acceptance(server, token, insecure=args.insecure)
    else:
        # --local is default when no --server
        report = run_local_acceptance()

    print_report(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
