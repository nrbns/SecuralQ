"""Complete remaining Phase-1 ops that this host can finish (no faking).

Runs:
  1) Sentinel pipeline self-test (always)
  2) Lab Authenticode sign of dist/agent-packages/*.exe when PFX present
  3) Local FS WORM marker proof
  4) Optional Docker Sentinel inject when docker is available
  5) Phase-1 board dump

Usage:
  python scripts/remaining_ops_complete.py
  python scripts/remaining_ops_complete.py --try-docker-inject
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

LOG = _ROOT / "data" / "ops" / "remaining_ops_complete.jsonl"


def _append(row: dict[str, Any]) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")


def step_sentinel_self_test() -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "sentinel_failover_measure.py"), "--pipeline-self-test"],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    return {
        "name": "sentinel_pipeline_self_test",
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": (proc.stdout or "")[-300:],
    }


def step_lab_authenticode() -> dict[str, Any]:
    pfx = _ROOT / "tools" / "lab-certs" / "securaiq-lab-codesign.pfx"
    if not pfx.is_file():
        # Generate via remaining full proof
        subprocess.run(
            [sys.executable, str(_ROOT / "scripts" / "realtime_remaining_full_proof.py")],
            cwd=str(_ROOT),
            capture_output=True,
            text=True,
            timeout=180,
        )
    env = os.environ.copy()
    env["SIGN_WINDOWS"] = "1"
    env["CODE_SIGN_PFX_PATH"] = str(pfx)
    env["CODE_SIGN_PFX_PASSWORD"] = env.get("CODE_SIGN_PFX_PASSWORD") or "securaiq-lab-only"
    proc = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-File",
            str(_ROOT / "scripts" / "packaging" / "sign_windows.ps1"),
            "-ArtifactDir",
            str(_ROOT / "dist" / "agent-packages"),
        ],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    from app.phase1_ops_remaining import authenticode_status

    st = authenticode_status()
    return {
        "name": "lab_authenticode_sign",
        "ok": bool(st.get("lab_artifact_signed")) or proc.returncode == 0,
        "returncode": proc.returncode,
        "lab_artifact_signed": st.get("lab_artifact_signed"),
        "tail": ((proc.stdout or "") + (proc.stderr or ""))[-500:],
        "disclaimer": "Lab self-signed — not EV / SmartScreen trusted",
    }


def step_local_worm() -> dict[str, Any]:
    from app.evidence_spine.worm import apply_local_fs_worm, record_worm_lock, worm_backend_status

    payload = b"securaiq-lab-worm-proof-v1"
    digest = hashlib.sha256(payload).hexdigest()
    local = apply_local_fs_worm(digest, content=payload)
    row = record_worm_lock("lab-ops", content_hash=digest, content=payload, meta={"lab": True})
    st = worm_backend_status()
    ok = bool(local.get("readonly")) and row.get("status") in {
        "local_fs_immutable",
        "local_marker",
    }
    return {
        "name": "local_fs_worm",
        "ok": ok,
        "status": row.get("status"),
        "readonly": local.get("readonly"),
        "path": local.get("path"),
        "backend": st.get("backend"),
        "disclaimer": "local_fs readonly — not cloud Object Lock",
    }


def step_docker_inject() -> dict[str, Any]:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        cand = Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe")
        docker_bin = str(cand) if cand.is_file() else None
    if not docker_bin:
        return {
            "name": "docker_sentinel_inject",
            "ok": False,
            "skipped": True,
            "reason": "docker_not_on_path",
            "hint": "Install Docker Desktop, start it, then re-run with --try-docker-inject",
        }
    # Ensure daemon up
    info = subprocess.run([docker_bin, "info"], capture_output=True, text=True, timeout=60)
    if info.returncode != 0:
        return {
            "name": "docker_sentinel_inject",
            "ok": False,
            "skipped": True,
            "reason": "docker_daemon_not_running",
            "tail": (info.stderr or info.stdout or "")[:300],
        }
    env = os.environ.copy()
    # Compose still interpolates unrelated services; provide lab placeholders.
    env.setdefault("POSTGRES_PASSWORD", "lab-only-not-for-prod")
    env.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "lab-only-not-for-prod")
    env.setdefault("BOOTSTRAP_ADMIN_USERNAME", "admin")
    env.setdefault("REDIS_SENTINEL_HOSTS", "127.0.0.1:26379")
    env.setdefault("REDIS_SENTINEL_MASTER", "mymaster")
    env["PATH"] = str(Path(docker_bin).parent) + os.pathsep + env.get("PATH", "")
    up = subprocess.run(
        [
            docker_bin,
            "compose",
            "--profile",
            "redis-ha",
            "up",
            "-d",
            "redis-primary",
            "redis-replica",
            "redis-sentinel",
        ],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    if up.returncode != 0:
        return {
            "name": "docker_sentinel_inject",
            "ok": False,
            "returncode": up.returncode,
            "tail": ((up.stdout or "") + (up.stderr or ""))[-500:],
        }
    meas = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "scripts" / "sentinel_failover_measure.py"),
            "--inject-stop",
            "--record",
        ],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    return {
        "name": "docker_sentinel_inject",
        "ok": meas.returncode == 0,
        "returncode": meas.returncode,
        "tail": ((meas.stdout or "") + (meas.stderr or ""))[-800:],
        "disclaimer": "Lab compose quorum=1 — not commercial HA certification",
    }


def step_board() -> dict[str, Any]:
    from app.phase1_ops_remaining import phase1_ops_remaining

    board = phase1_ops_remaining()
    return {
        "name": "phase1_board",
        "ok": bool(board.get("code_unblocked_complete")),
        "ops_still_open": board.get("ops_still_open"),
        "items": [{k: i.get(k) for k in ("id", "status")} for i in board.get("items") or []],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--try-docker-inject", action="store_true")
    ap.add_argument("--skip-sign", action="store_true")
    args = ap.parse_args()

    steps: list[dict[str, Any]] = []
    print("=== REMAINING OPS COMPLETE ===", flush=True)
    for fn in (step_sentinel_self_test, step_local_worm):
        s = fn()
        steps.append(s)
        print(f"  [{'PASS' if s.get('ok') else 'FAIL'}] {s.get('name')}", flush=True)

    if not args.skip_sign:
        s = step_lab_authenticode()
        steps.append(s)
        print(f"  [{'PASS' if s.get('ok') else 'FAIL'}] {s.get('name')}", flush=True)

    if args.try_docker_inject:
        s = step_docker_inject()
        steps.append(s)
        mark = "PASS" if s.get("ok") else ("SKIP" if s.get("skipped") else "FAIL")
        print(f"  [{mark}] {s.get('name')}", flush=True)

    s = step_board()
    steps.append(s)
    print(f"  [{'PASS' if s.get('ok') else 'FAIL'}] {s.get('name')} ops={s.get('ops_still_open')}", flush=True)

    # Docker inject skip should not fail overall when not requested / unavailable
    check = [
        x
        for x in steps
        if not (x.get("name") == "docker_sentinel_inject" and x.get("skipped"))
    ]
    overall = all(bool(x.get("ok")) for x in check)
    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "ok": overall,
        "steps": steps,
        "disclaimer": (
            "Remaining ops close on this host. EV Authenticode and cloud Object Lock "
            "still require commercial certs / object-store infrastructure."
        ),
    }
    _append(row)
    print(json.dumps({k: v for k, v in row.items() if k != "steps"}, indent=2), flush=True)
    print("RESULT:", "REMAINING COMPLETE" if overall else "REMAINING INCOMPLETE", flush=True)
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
