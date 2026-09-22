"""Live lab verification — prove Phase-1 / sellable loop against a running server.

Does NOT fake Docker Sentinel, EV Authenticode, or cloud WORM.
Marks owned-host live when SECURAIQ_OWNED_HOST=1 or --i-own-this-host.

Usage:
  python scripts/live_lab_verify.py --server http://127.0.0.1:8080 --i-own-this-host
  python scripts/live_lab_verify.py --server http://127.0.0.1:8080 --i-own-this-host --http-1000
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

LOG = _ROOT / "data" / "ops" / "live_lab_verify.jsonl"


def _append(row: dict[str, Any]) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")


def _http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> tuple[int, Any]:
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
    except Exception as exc:
        return 0, {"error": str(exc)[:300]}


def step_health(server: str) -> dict[str, Any]:
    code, body = _http("GET", f"{server.rstrip('/')}/api/health", timeout=25)
    ok = code == 200 and isinstance(body, dict) and body.get("status") == "ok"
    return {"name": "health", "ok": ok, "code": code, "status": (body or {}).get("status") if isinstance(body, dict) else None}


def step_ready(server: str) -> dict[str, Any]:
    code, body = _http("GET", f"{server.rstrip('/')}/ready", timeout=15)
    ok = code == 200 and isinstance(body, dict) and body.get("ready") is True
    return {
        "name": "ready",
        "ok": ok,
        "code": code,
        "ready": (body or {}).get("ready") if isinstance(body, dict) else None,
        "redis": ((body or {}).get("checks") or {}).get("redis") if isinstance(body, dict) else None,
    }


def step_enroll_checkin(server: str, token: str) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    code, enrolled = _http(
        "POST",
        f"{server.rstrip('/')}/api/agents/enroll",
        headers=headers,
        body={"name": f"live-verify-{int(time.time())}"},
        timeout=60,
    )
    if code != 200 or not isinstance(enrolled, dict):
        return {"name": "enroll_checkin", "ok": False, "enroll_code": code, "detail": enrolled}
    agent_tok = enrolled.get("agent_token") or enrolled.get("token")
    if not agent_tok:
        # auth-off may return agent_id + token differently
        agent_tok = enrolled.get("agent", {}).get("token") if isinstance(enrolled.get("agent"), dict) else None
    if not agent_tok and enrolled.get("id") and enrolled.get("api_key"):
        agent_tok = f"{enrolled['id']}.{enrolled['api_key']}"
    if not agent_tok:
        return {"name": "enroll_checkin", "ok": False, "enroll_code": code, "detail": list(enrolled.keys())}
    t0 = time.perf_counter()
    c2, chk = _http(
        "POST",
        f"{server.rstrip('/')}/api/agents/checkin",
        headers={"Authorization": f"Bearer {agent_tok}"},
        body={
            "hostname": "live-verify-host",
            "os": "lab",
            "truncated": True,
            "sequence": 1,
        },
        timeout=90,
    )
    dt = round(time.perf_counter() - t0, 3)
    ok = c2 == 200 and isinstance(chk, dict) and bool(chk.get("ok"))
    return {
        "name": "enroll_checkin",
        "ok": ok,
        "enroll_code": code,
        "checkin_code": c2,
        "checkin_sec": dt,
        "asset_id": (chk or {}).get("asset_id") if isinstance(chk, dict) else None,
    }


def step_phase1_board() -> dict[str, Any]:
    from app.phase1_ops_remaining import phase1_ops_remaining

    board = phase1_ops_remaining()
    return {
        "name": "phase1_board",
        "ok": bool(board.get("code_unblocked_complete")),
        "ops_still_open": board.get("ops_still_open"),
        "http_500": next(
            (i.get("http_500_measured") for i in board.get("items") or [] if i.get("id") == "http_capacity_ladder"),
            None,
        ),
        "http_1000": next(
            (i.get("http_1000_measured") for i in board.get("items") or [] if i.get("id") == "http_capacity_ladder"),
            None,
        ),
    }


def step_acceptance_local() -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "realtime_acceptance_demo.py"), "--local", "--firewall-only"],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    return {
        "name": "acceptance_local",
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": (proc.stdout or "")[-400:],
    }


def step_acceptance_server(server: str, token: str) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(_ROOT / "scripts" / "realtime_acceptance_demo.py"),
        "--server",
        server,
        "--i-own-this-host",
    ]
    if token:
        cmd.extend(["--token", token])
    env = os.environ.copy()
    env["SECURAIQ_OWNED_HOST"] = "1"
    proc = subprocess.run(cmd, cwd=str(_ROOT), capture_output=True, text=True, timeout=600, env=env)
    return {
        "name": "acceptance_server_owned",
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": ((proc.stdout or "") + (proc.stderr or ""))[-600:],
    }


def step_http_ladder(server: str, token: str, max_agents: int, workers: int) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(_ROOT / "scripts" / "realtime_load_test.py"),
        "--server",
        server,
        "--ladder",
        "--max-agents",
        str(max_agents),
        "--workers",
        str(workers),
        "--persist",
        "--sse-sample",
    ]
    if token:
        cmd.extend(["--admin-token", token])
    proc = subprocess.run(cmd, cwd=str(_ROOT), capture_output=True, text=True, timeout=10800)
    return {
        "name": f"http_ladder_{max_agents}",
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": (proc.stdout or "")[-900:],
    }


def step_phase1_complete() -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "phase1_ops_complete_lab.py"), "--skip-soft"],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    return {
        "name": "phase1_ops_complete",
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": (proc.stdout or "")[-500:],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--server", default="http://127.0.0.1:8080")
    ap.add_argument("--token", default=os.environ.get("SECURAIQ_ADMIN_TOKEN", ""))
    ap.add_argument("--i-own-this-host", action="store_true")
    ap.add_argument("--http-1000", action="store_true")
    ap.add_argument("--skip-acceptance-server", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    if args.i_own_this_host:
        os.environ["SECURAIQ_OWNED_HOST"] = "1"

    steps: list[dict[str, Any]] = []
    print("=== LIVE LAB VERIFY ===", flush=True)
    print(f"server={args.server} owned={bool(args.i_own_this_host)}", flush=True)

    for fn in (
        lambda: step_health(args.server),
        lambda: step_ready(args.server),
        lambda: step_enroll_checkin(args.server, args.token),
        step_phase1_board,
        step_acceptance_local,
        step_phase1_complete,
    ):
        s = fn()
        steps.append(s)
        print(f"  [{'PASS' if s.get('ok') else 'FAIL'}] {s.get('name')}", flush=True)

    if args.i_own_this_host and not args.skip_acceptance_server:
        s = step_acceptance_server(args.server, args.token)
        steps.append(s)
        print(f"  [{'PASS' if s.get('ok') else 'FAIL'}] {s.get('name')}", flush=True)

    if args.http_1000:
        s = step_http_ladder(args.server, args.token, 1000, args.workers)
        steps.append(s)
        print(f"  [{'PASS' if s.get('ok') else 'FAIL'}] {s.get('name')}", flush=True)
        steps.append(step_phase1_board())
        print(f"  [{'PASS' if steps[-1].get('ok') else 'FAIL'}] phase1_board_after_http", flush=True)

    overall = all(bool(s.get("ok")) for s in steps)
    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "ok": overall,
        "server": args.server,
        "owned_host": bool(args.i_own_this_host),
        "steps": steps,
        "disclaimer": (
            "Live lab verify — not commercial HA/EV/WORM certification. "
            "Docker Sentinel inject still requires Docker Desktop."
        ),
    }
    _append(row)
    print(json.dumps({k: v for k, v in row.items() if k != "steps"}, indent=2), flush=True)
    print("RESULT:", "LIVE LAB GREEN" if overall else "LIVE LAB INCOMPLETE", flush=True)
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
