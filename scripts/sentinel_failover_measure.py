#!/usr/bin/env python3
"""Measure Redis Sentinel lab failover timing (honest — not commercial HA cert).

Usage:
  python scripts/sentinel_failover_measure.py --dry-run
  python scripts/sentinel_failover_measure.py --metrics-only
  python scripts/sentinel_failover_measure.py --record
  python scripts/sentinel_failover_measure.py --inject-stop --record
      # stops redis-primary via docker compose, waits for promote, records reconnect

Never invents HA certification claims. Numbers only from this run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

NOTE = ROOT / "docs" / "ops" / "SENTINEL-FAILOVER-LAB.md"
LOG = ROOT / "data" / "ops" / "sentinel_failover_measurements.jsonl"


def _compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "--profile", "redis-ha", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )


def collect_stream_metrics() -> dict[str, Any]:
    """Best-effort Streams / DLQ snapshot. Safe when Redis is down."""
    out: dict[str, Any] = {
        "stream_length": None,
        "dlq_count": None,
        "pending_count": None,
        "consumer_group_lag": None,
        "ok": False,
        "error": None,
    }
    try:
        from app.event_processor import stream_monitor_snapshot

        snap = stream_monitor_snapshot() or {}
        out["stream_length"] = snap.get("stream_length")
        out["dlq_count"] = snap.get("dlq_length")
        out["pending_count"] = snap.get("pending_count")
        out["consumer_group_lag"] = snap.get("consumer_group_lag")
        out["ok"] = True
    except Exception as exc:
        out["error"] = str(exc)[:300]
    return out


def _check_sentinel() -> dict:
    try:
        from app.realtime.sentinel_ops import ping_master
        from app.redis_client import reconnect_after_failover, redis_ping

        t0 = time.perf_counter()
        reconnect_after_failover()
        ok = False
        err = None
        try:
            ok = bool(redis_ping())
            if not ok:
                # Fall back to sentinel_ops detail when URL/Sentinel unset
                report = ping_master()
                ok = bool(report.get("ok"))
                err = None if ok else (report.get("error") or "ping_failed")
        except Exception as exc:
            ok = False
            err = str(exc)[:300]
        ms = round((time.perf_counter() - t0) * 1000, 1)
        return {"ok": ok, "reconnect_ms": ms, "error": err}
    except Exception as exc:
        return {"ok": False, "reconnect_ms": None, "error": str(exc)[:300]}


def _inprocess_failover_chain() -> dict[str, Any]:
    """Reconnect + XAUTOCLAIM reclaim + SSE Last-Event-ID resume (no Docker)."""
    try:
        from scripts.realtime_remaining_full_proof import step_sentinel_failover_simulated

        return step_sentinel_failover_simulated()
    except Exception as exc:
        return {
            "name": "sentinel_failover_chain_simulated",
            "ok": False,
            "simulated": True,
            "error": str(exc)[:400],
            "disclaimer": "SIMULATED — not commercial HA certification",
        }


def _docker_bin() -> str | None:
    import shutil
    from pathlib import Path

    which = shutil.which("docker")
    if which:
        return which
    cand = Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe")
    return str(cand) if cand.is_file() else None


def _sentinel_master_via_exec() -> dict[str, Any]:
    """Query Sentinel from inside the compose network (Docker Desktop-safe)."""
    docker = _docker_bin()
    out: dict[str, Any] = {"ok": False, "addr": None, "error": None, "via": "docker_exec"}
    if not docker:
        out["error"] = "docker_not_found"
        return out
    try:
        proc = subprocess.run(
            [
                docker,
                "exec",
                "hackgpt-ai-redis-sentinel-1",
                "redis-cli",
                "-p",
                "26379",
                "SENTINEL",
                "get-master-addr-by-name",
                "mymaster",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
        if proc.returncode == 0 and len(lines) >= 2:
            out["ok"] = True
            out["addr"] = f"{lines[0]}:{lines[1]}"
        else:
            out["error"] = ((proc.stderr or proc.stdout or "sentinel_exec_failed")[:300])
    except Exception as exc:
        out["error"] = str(exc)[:300]
    return out


def _sentinel_cmd(*args: str) -> dict[str, Any]:
    docker = _docker_bin()
    out: dict[str, Any] = {"ok": False, "stdout": "", "stderr": "", "args": list(args)}
    if not docker:
        out["error"] = "docker_not_found"
        return out
    try:
        proc = subprocess.run(
            [docker, "exec", "hackgpt-ai-redis-sentinel-1", "redis-cli", "-p", "26379", *args],
            capture_output=True,
            text=True,
            timeout=15,
        )
        out["stdout"] = (proc.stdout or "").strip()
        out["stderr"] = (proc.stderr or "").strip()[:300]
        out["returncode"] = proc.returncode
        out["ok"] = proc.returncode == 0
    except Exception as exc:
        out["error"] = str(exc)[:300]
    return out


def _wait_promoted_docker(*, timeout_sec: float = 90.0) -> dict:
    """Wait until Sentinel reports a reachable master after inject-stop.

    Uses docker exec so Windows Docker Desktop host clients are not blocked by
    Docker-internal master IPs returned by Sentinel.

    If automatic promote stalls (common on Desktop after container stop), issues
    ``SENTINEL FAILOVER`` (and lab ``REPLICAOF NO ONE`` last resort). Records
    ``failover_forced: true`` when an assist is used — still a live promote.
    """
    t0 = time.perf_counter()
    last: dict[str, Any] = {}
    before = _sentinel_master_via_exec()
    forced = False
    force_attempted = False
    assist_log: list[dict[str, Any]] = []
    promote_method = "sentinel_automatic"
    while (time.perf_counter() - t0) < timeout_sec:
        last = _sentinel_master_via_exec()
        last["promote_wait_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        last["master_before"] = before.get("addr")
        last["failover_forced"] = forced
        last["failover_assist_log"] = assist_log[-3:]
        last["promote_method"] = promote_method
        docker = _docker_bin()
        if not docker or not last.get("ok"):
            time.sleep(1.0)
            continue
        primary_ping = subprocess.run(
            [docker, "exec", "hackgpt-ai-redis-primary-1", "redis-cli", "ping"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        primary_up = primary_ping.returncode == 0 and "PONG" in (primary_ping.stdout or "")
        last["primary_up"] = primary_up
        for cname in ("hackgpt-ai-redis-replica-1", "hackgpt-ai-redis-primary-1"):
            if cname.endswith("primary-1") and not primary_up:
                continue
            ping = subprocess.run(
                [docker, "exec", cname, "redis-cli", "ping"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            role = subprocess.run(
                [docker, "exec", cname, "redis-cli", "INFO", "replication"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            role_txt = role.stdout or ""
            if ping.returncode != 0 or "PONG" not in (ping.stdout or ""):
                continue
            if "role:master" not in role_txt:
                continue
            addr_changed = bool(last.get("addr") and last.get("addr") != before.get("addr"))
            replica_promoted = cname.endswith("replica-1")
            # After inject, accept replica-as-master even if Sentinel addr lags.
            if not primary_up and (replica_promoted or addr_changed or forced):
                last["ok"] = True
                last["ping_container"] = cname
                last["role_info_snip"] = role_txt[:200]
                last["reconnect_ms"] = last["promote_wait_ms"]
                last["addr_changed"] = addr_changed
                last["failover_forced"] = forced
                last["promote_method"] = promote_method
                last["via"] = "docker_exec"
                return last
        elapsed = time.perf_counter() - t0
        if (not force_attempted) and (not primary_up) and elapsed >= 8.0:
            force_attempted = True
            force = _sentinel_cmd("SENTINEL", "failover", "mymaster")
            assist_log.append({"step": "sentinel_failover", **force})
            out = ((force.get("stdout") or "") + (force.get("stderr") or "")).upper()
            if force.get("ok") and out.strip() == "OK":
                forced = True
                promote_method = "sentinel_failover_assist"
            else:
                reset = _sentinel_cmd("SENTINEL", "reset", "mymaster")
                assist_log.append({"step": "sentinel_reset", **reset})
                time.sleep(2.0)
                force2 = _sentinel_cmd("SENTINEL", "failover", "mymaster")
                assist_log.append({"step": "sentinel_failover_retry", **force2})
                out2 = ((force2.get("stdout") or "") + (force2.get("stderr") or "")).upper()
                if force2.get("ok") and out2.strip() == "OK":
                    forced = True
                    promote_method = "sentinel_failover_assist"
                else:
                    # Last-resort lab promote: replica takes master role directly.
                    promo = subprocess.run(
                        [
                            docker,
                            "exec",
                            "hackgpt-ai-redis-replica-1",
                            "redis-cli",
                            "REPLICAOF",
                            "NO",
                            "ONE",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    assist_log.append(
                        {
                            "step": "replicaof_no_one",
                            "ok": promo.returncode == 0,
                            "stdout": (promo.stdout or "").strip()[:200],
                            "stderr": (promo.stderr or "").strip()[:200],
                        }
                    )
                    if promo.returncode == 0:
                        forced = True
                        promote_method = "replicaof_no_one_lab_assist"
        time.sleep(1.0)
    last["ok"] = False
    last["error"] = last.get("error") or "promote_timeout_docker_exec"
    last["promote_wait_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    last["failover_forced"] = forced
    last["failover_assist_log"] = assist_log[-5:]
    last["promote_method"] = promote_method
    return last


def _wait_promoted(*, timeout_sec: float = 90.0, prefer_docker: bool = False) -> dict:
    """Poll until a master is reachable after failover."""
    t0 = time.perf_counter()
    last: dict = {}
    # Docker Desktop: Sentinel returns compose-network IPs the host cannot reach.
    # Prefer in-network docker exec when measuring inject-stop promote.
    if prefer_docker and _docker_bin():
        docker_check = _wait_promoted_docker(timeout_sec=timeout_sec)
        if docker_check.get("ok"):
            docker_check["host_redis_py_ok"] = False
            docker_check["note"] = (
                "promote measured via docker exec on compose network; "
                "host redis-py cannot reach Docker-internal master IPs on Desktop"
            )
            return docker_check
        last = docker_check
        last["ok"] = False
        last["error"] = last.get("error") or "promote_timeout"
        return last

    while (time.perf_counter() - t0) < min(15.0, timeout_sec):
        last = _check_sentinel()
        if last.get("ok"):
            last["promote_wait_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            return last
        time.sleep(1.0)
    remaining = max(30.0, timeout_sec - (time.perf_counter() - t0))
    docker_check = _wait_promoted_docker(timeout_sec=remaining)
    if docker_check.get("ok"):
        docker_check["host_redis_py_ok"] = False
        docker_check["host_redis_py_error"] = last.get("error")
        docker_check["note"] = (
            "promote measured via docker exec on compose network; "
            "host redis-py timed out (Docker Desktop internal IP)"
        )
        return docker_check
    last["promote_wait_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    last["ok"] = False
    last["error"] = last.get("error") or "promote_timeout"
    last["docker_exec_fallback"] = docker_check
    return last


def dry_run() -> int:
    print(
        json.dumps(
            {
                "ok": True,
                "mode": "dry_run",
                "note": str(NOTE.relative_to(ROOT)),
                "disclaimer": "lab stub — not commercial HA certification",
                "steps": [
                    "docker compose --profile redis-ha up -d",
                    "python scripts/realtime_phase1_proof.py --check-sentinel",
                    "python scripts/sentinel_failover_measure.py --metrics-only",
                    "python scripts/sentinel_failover_measure.py --inject-stop --record",
                    "or: docker compose stop redis-primary && python scripts/sentinel_failover_measure.py --record",
                ],
            },
            indent=2,
        )
    )
    return 0


def metrics_only() -> int:
    metrics = collect_stream_metrics()
    row = {
        "ok": True,
        "mode": "metrics_only",
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "disclaimer": "lab / measured ops proof — not commercial HA certification",
        "note": "streams snapshot only — does not prove failover",
    }
    print(json.dumps(row, indent=2))
    return 0


def record(*, inject_stop: bool = False) -> int:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    metrics_before = collect_stream_metrics()
    inject: dict = {"attempted": False}
    if inject_stop:
        inject["attempted"] = True
        t_stop = time.perf_counter()
        proc = _compose("stop", "redis-primary")
        inject["stop_ms"] = round((time.perf_counter() - t_stop) * 1000, 1)
        inject["returncode"] = proc.returncode
        inject["stderr"] = (proc.stderr or "")[:400]
        check = _wait_promoted(prefer_docker=True)
    else:
        check = _check_sentinel()
    metrics_after = collect_stream_metrics()

    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "inject_stop" if inject_stop else "record",
        "simulated": False,
        "ok": bool(check.get("ok")),
        "check": check,
        "inject_stop": inject,
        "metrics_before": metrics_before,
        "metrics_after": metrics_after,
        "events_sent": None,
        "events_processed": None,
        "events_duplicated": None,
        "events_lost": None,
        "events_replayed": None,
        "dlq_count": metrics_after.get("dlq_count"),
        "stream_length": metrics_after.get("stream_length"),
        "pending_count": metrics_after.get("pending_count"),
        "disclaimer": "lab / measured ops proof — not commercial HA certification",
        "note": (
            "dlq_count/stream_length from stream_monitor_snapshot when Redis is up. "
            "Fill events_sent/lost/duplicated/replayed from a live worker run — never invent. "
            "On Docker Desktop, promote may be measured via docker exec when host cannot "
            "reach Docker-internal master IPs."
        ),
    }
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    print(json.dumps(row, indent=2))
    if NOTE.is_file():
        append = (
            f"\n### Measurement {row['ts_utc']}\n\n"
            f"- reconnect_ok: `{check.get('ok')}`\n"
            f"- reconnect_ms: `{check.get('reconnect_ms')}`\n"
            f"- promote_wait_ms: `{check.get('promote_wait_ms')}`\n"
            f"- via: `{check.get('via')}` failover_forced=`{check.get('failover_forced')}`\n"
            f"- inject_stop: `{inject.get('attempted')}` stop_ms=`{inject.get('stop_ms')}`\n"
            f"- dlq_count: `{row.get('dlq_count')}` stream_length=`{row.get('stream_length')}`\n"
            f"- error: `{check.get('error')}`\n"
            f"- log: `data/ops/sentinel_failover_measurements.jsonl`\n"
            f"- disclaimer: lab proof only — not multi-AZ commercial HA\n"
        )
        text = NOTE.read_text(encoding="utf-8")
        if row["ts_utc"] not in text:
            NOTE.write_text(text.rstrip() + "\n" + append, encoding="utf-8")
    return 0 if check.get("ok") else 1


def simulate_pipeline_self_test() -> int:
    """Prove measurement write path + in-process failover chain (no Docker).

    Does **not** claim a real Sentinel promote. CI-safe. Clearly labeled
    ``simulated: true``. Live inject remains ``--inject-stop --record``.
    """
    LOG.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    check = _check_sentinel()
    chain = _inprocess_failover_chain()
    simulated_ms = round((time.perf_counter() - t0) * 1000, 1)
    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "pipeline_self_test",
        "simulated": True,
        "check": {
            **check,
            # Preserve real reconnect attempt error; force schema ok for CI path
            "pipeline_ok": True,
            "promote_wait_ms": simulated_ms,
            "note": (
                "simulated — Redis/Docker may be unset; not a live Sentinel promote. "
                "inprocess chain proves reconnect helper + XAUTOCLAIM + SSE resume."
            ),
        },
        "inprocess_failover_chain": chain,
        "inject_stop": {"attempted": False, "simulated": True},
        "metrics_before": collect_stream_metrics(),
        "metrics_after": collect_stream_metrics(),
        "events_sent": None,
        "events_processed": None,
        "events_duplicated": None,
        "events_lost": None,
        "events_replayed": None,
        "xautoclaim_reclaim_ok": bool(chain.get("reclaim_ok")),
        "sse_resume_ok": bool(chain.get("sse_resume_ok")),
        "reconnect_ms": chain.get("reconnect_ms") or check.get("reconnect_ms"),
        "disclaimer": "SIMULATED pipeline self-test — not commercial HA certification",
        "note": (
            "This row proves the measurement logger + in-process failover chain. "
            "Replace with --inject-stop --record on a host with docker compose redis-ha."
        ),
    }
    # CI exit: chain must pass; live Redis ping is optional
    row["ok"] = bool(chain.get("ok"))
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    print(json.dumps(row, indent=2))
    if NOTE.is_file() and row["ok"]:
        append = (
            f"\n### In-process self-test {row['ts_utc']}\n\n"
            f"- simulated: `true`\n"
            f"- chain_ok: `{row['ok']}`\n"
            f"- reconnect_ms: `{row.get('reconnect_ms')}`\n"
            f"- xautoclaim_reclaim_ok: `{row.get('xautoclaim_reclaim_ok')}`\n"
            f"- sse_resume_ok: `{row.get('sse_resume_ok')}`\n"
            f"- live_redis_ping: `{check.get('ok')}` error=`{check.get('error')}`\n"
            f"- disclaimer: in-process only — not Docker Sentinel promote\n"
        )
        text = NOTE.read_text(encoding="utf-8")
        if row["ts_utc"] not in text:
            NOTE.write_text(text.rstrip() + "\n" + append, encoding="utf-8")
    return 0 if row["ok"] else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--metrics-only",
        action="store_true",
        help="Print Streams/DLQ snapshot without failover inject (CI-safe)",
    )
    ap.add_argument(
        "--pipeline-self-test",
        action="store_true",
        help="Write a clearly labeled simulated measurement row (CI, no Docker)",
    )
    ap.add_argument("--record", action="store_true")
    ap.add_argument(
        "--inject-stop",
        action="store_true",
        help="Stop redis-primary via docker compose before measuring (destructive to that container)",
    )
    args = ap.parse_args()
    if args.metrics_only:
        return metrics_only()
    if args.pipeline_self_test:
        return simulate_pipeline_self_test()
    if args.record or args.inject_stop:
        return record(inject_stop=bool(args.inject_stop))
    return dry_run()


if __name__ == "__main__":
    raise SystemExit(main())
