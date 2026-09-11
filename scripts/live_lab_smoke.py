"""Live lab smoke — real HTTP against a running SecuraIQ (AUTH_ENABLED=false OK).

Authorized labs / owned hosts only. Not a 5k/HA proof.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080").rstrip("/")


def req(method: str, path: str, *, body: dict | None = None, token: str | None = None) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(f"{BASE}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=90) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw) if raw.strip() else {"detail": raw}
        except Exception:
            return e.code, {"detail": raw[:500]}


def main() -> int:
    steps: list[tuple[str, bool, str]] = []

    code, health = req("GET", "/api/health")
    ok = code == 200 and (health.get("status") == "ok" or health.get("prototype", {}).get("realtime"))
    steps.append(("health", ok, f"http={code} realtime={health.get('prototype', {}).get('realtime')}"))

    code, enrolled = req("POST", "/api/agents/enroll", body={"name": f"live-smoke-{int(time.time())}"})
    agent_token = (enrolled or {}).get("agent_token") or ""
    agent_id = (enrolled or {}).get("agent_id") or (agent_token.split(".", 1)[0] if agent_token else "")
    steps.append(("enroll", code == 200 and bool(agent_token), f"http={code} agent_id={agent_id[:12]}"))

    if not agent_token:
        _print(steps)
        return 1

    fail_body = {
        "hostname": f"live-{agent_id[:8]}",
        "os": "linux",
        "os_version": "lab",
        "agent_version": "live-smoke",
        "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
        "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "no"}},
        "disk_encryption_status": {"collected": True, "encrypted": False, "backend": "none"},
        "file_integrity": [{"path": "/etc/hosts", "status": "modified", "hash": "deadbeef"}],
        "security_logs": {
            "collected": True,
            "backend": "journalctl",
            "items": [{"line": "sshd: Failed password for root from 10.0.0.2"}],
        },
    }
    code, ci = req("POST", "/api/agents/checkin", body=fail_body, token=agent_token)
    asset_id = (ci or {}).get("asset_id") or ""
    steps.append(("checkin_fail_telemetry", code == 200 and bool(ci.get("ok")), f"http={code} asset={asset_id[:12]}"))

    time.sleep(0.8)

    code, threats = req("GET", f"/api/agents/{agent_id}/threats?limit=20")
    threat_rows = (threats or {}).get("threats") or []
    if not threat_rows:
        code2, threats2 = req("GET", "/api/agents/threats?limit=50")
        code = code if code == 200 else code2
        threat_rows = [
            t for t in ((threats2 or {}).get("threats") or []) if t.get("agent_id") == agent_id
        ]
    steps.append(
        (
            "native_threats_from_fim_logs",
            code == 200 and len(threat_rows) >= 1,
            f"http={code} agent_threats={len(threat_rows)}",
        )
    )

    code, live = req("GET", "/api/compliance/live-failures")
    fails = (live or {}).get("failures") or []
    fw = [f for f in fails if f.get("test") == "host_firewall" and (f.get("status") or "").lower() == "fail"]
    steps.append(("live_failures_firewall", code == 200 and bool(fw), f"http={code} fw_fails={len(fw)}"))

    code, prio = req("GET", "/api/risk/priority?limit=10")
    items = (prio or {}).get("items") or []
    steps.append(("risk_priority", code == 200, f"http={code} items={len(items)}"))

    code, inv = req(
        "POST",
        "/api/ai/investigate",
        body={"mode": "secops_tools", "limit": 5, "asset_id": asset_id or None},
    )
    summary = (inv or {}).get("summary") or {}
    tools_ok = summary.get("tools_ok")
    steps.append(
        (
            "secops_investigate",
            code == 200 and inv.get("mode") == "secops_tools" and int(tools_ok or 0) >= 1,
            f"http={code} mode={inv.get('mode')} tools_ok={tools_ok}",
        )
    )

    code, ver = req(
        "POST",
        "/api/ai/secops/verify-host",
        body={"agent_id": agent_id, "test_name": "host_firewall"},
    )
    steps.append(
        (
            "verify_host_firewall",
            code == 200 and ver.get("ok") is True and ver.get("status") == "fail",
            f"http={code} status={ver.get('status')} verified={ver.get('verified')}",
        )
    )

    code, cmd = req(
        "POST",
        f"/api/agents/{agent_id}/commands/enable-firewall",
        body={},
    )
    cmd_id = ""
    if isinstance(cmd, dict):
        cmd_id = str(cmd.get("id") or cmd.get("command_id") or "")
        if not cmd_id and isinstance(cmd.get("command"), dict):
            cmd_id = str(cmd["command"].get("id") or "")
    steps.append(
        (
            "request_enable_firewall",
            code in (200, 201) and bool(cmd_id),
            f"http={code} cmd={cmd_id[:16]} keys={list((cmd or {}).keys())[:8]}",
        )
    )

    if cmd_id:
        code, appr = req("POST", f"/api/agents/{agent_id}/commands/{cmd_id}/approve", body={})
        steps.append(
            (
                "approve_enable_firewall",
                code == 200,
                f"http={code} status={(appr or {}).get('status')}",
            )
        )
        code, res = req(
            "POST",
            f"/api/agents/commands/{cmd_id}/result",
            body={"status": "done", "result": {"ok": True, "lab": True, "simulated": True}},
            token=agent_token,
        )
        steps.append(("agent_command_result", code == 200, f"http={code} detail={str(res)[:120]}"))

    fail_body["firewall_status"] = {"collected": True, "enabled": True, "backend": "ufw"}
    fail_body["disk_encryption_status"] = {"collected": True, "encrypted": True, "backend": "luks"}
    fail_body["file_integrity"] = []
    fail_body["security_logs"] = {"collected": True, "backend": "journalctl", "items": []}
    code, ci2 = req("POST", "/api/agents/checkin", body=fail_body, token=agent_token)
    steps.append(("checkin_pass_telemetry", code == 200 and bool(ci2.get("ok")), f"http={code}"))

    time.sleep(0.3)
    code, ver2 = req(
        "POST",
        "/api/ai/secops/verify-host",
        body={"agent_id": agent_id, "test_name": "host_firewall"},
    )
    steps.append(
        (
            "verify_host_firewall_pass",
            code == 200 and ver2.get("status") == "pass" and ver2.get("verified") is True,
            f"http={code} status={ver2.get('status')}",
        )
    )

    # Command verification_status must flip to verified after observed PASS
    if cmd_id:
        code, cmds = req("GET", f"/api/agents/{agent_id}/commands?limit=20")
        rows = (cmds or {}).get("commands") or []
        mine = next((c for c in rows if c.get("id") == cmd_id), None)
        vstat = (mine or {}).get("verification_status") or ""
        steps.append(
            (
                "command_verification_verified",
                code == 200 and vstat == "verified",
                f"http={code} verification_status={vstat}",
            )
        )

    # Realtime bus health — when Redis configured, prefer Streams fan-out mode
    code, health2 = req("GET", "/api/health")
    bus = (health2 or {}).get("realtime_bus") or {}
    mode = str(bus.get("mode") or "")
    redis_ok = mode in ("in_process", "redis_streams_fanout", "redis_streams+pubsub")
    steps.append(
        (
            "realtime_bus_mode",
            code == 200 and redis_ok,
            f"http={code} mode={mode} streams_fanout={bus.get('streams_fanout')}",
        )
    )

    return _print(steps)


def _print(steps: list[tuple[str, bool, str]]) -> int:
    ok_all = all(s[1] for s in steps)
    print(f"[live-smoke] server={BASE} overall={'PASS' if ok_all else 'FAIL'}")
    for name, ok, detail in steps:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    print(json.dumps({"ok": ok_all, "steps": [{"name": n, "ok": o, "detail": d} for n, o, d in steps]}, indent=2))
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
