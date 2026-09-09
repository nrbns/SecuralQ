"""REALTIME v1 RT-10/11 acceptance harness — lab only.

Simulates the master-plan firewall fail → evidence → pass chain **without**
changing a real Windows firewall.

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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

DISCLAIMER = "lab acceptance harness — not a 5k/HA proof"


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


def run_local_chain(user_id: str, agent_id: str) -> AcceptanceReport:
    """Core FAIL → evidence → PASS path using evaluate_agent_host_controls.

    Caller must have already pointed the app at an isolated DB (test fixture
    or CLI temp dir). No network.
    """
    from app.services.control_testing import evaluate_agent_host_controls
    from app.services.evidence import get_evidence_for

    report = AcceptanceReport(mode="local")
    disabled = firewall_disabled_payload()
    enabled = firewall_enabled_payload()

    # Step 1 — firewall disabled → compliance FAIL
    out_fail = evaluate_agent_host_controls(user_id, agent_id, disabled, asset_id="")
    fw_fail = _fw_result(out_fail) or {}
    fail_ok = (
        bool(out_fail.get("ok"))
        and (fw_fail.get("status") or "").lower() == "fail"
    )
    report.steps.append(
        StepResult(
            name="firewall_disabled_compliance_fail",
            ok=fail_ok,
            detail=f"status={fw_fail.get('status')!r} summary={fw_fail.get('summary') or ''}"[:240],
            data={
                "evaluator_ok": out_fail.get("ok"),
                "firewall_status": fw_fail.get("status"),
                "events": out_fail.get("events") or [],
                "evidence_ids": out_fail.get("evidence_ids") or [],
            },
        )
    )

    # Step 2 — evidence recorded / compliance event published
    trail = get_evidence_for(
        user_id,
        entity_type="agent_host_control",
        entity_id=f"{agent_id}:host_firewall",
        limit=10,
    )
    compliance_events = [
        e
        for e in (out_fail.get("events") or [])
        if e.get("type") == "compliance" and e.get("test") == "host_firewall"
    ]
    evidence_ok = bool(trail) and (
        bool(out_fail.get("evidence_ids")) or (trail[0].get("source") == "observed")
    )
    events_ok = any((e.get("status") or "").lower() == "fail" for e in compliance_events)
    step2_ok = evidence_ok and events_ok
    report.steps.append(
        StepResult(
            name="evidence_and_compliance_event",
            ok=step2_ok,
            detail=(
                f"evidence_rows={len(trail)} evidence_ids={len(out_fail.get('evidence_ids') or [])} "
                f"compliance_fail_events={sum(1 for e in compliance_events if (e.get('status') or '').lower() == 'fail')}"
            ),
            data={
                "evidence_count": len(trail),
                "evidence_ids": out_fail.get("evidence_ids") or [],
                "compliance_events": compliance_events,
            },
        )
    )

    # Step 3 — firewall enabled → PASS
    out_pass = evaluate_agent_host_controls(user_id, agent_id, enabled, asset_id="")
    fw_pass = _fw_result(out_pass) or {}
    pass_ok = (
        bool(out_pass.get("ok"))
        and (fw_pass.get("status") or "").lower() == "pass"
    )
    report.steps.append(
        StepResult(
            name="firewall_enabled_compliance_pass",
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
