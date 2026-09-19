"""REALTIME v1 load ladder (Task H) — lab measurements only.

Scale ladder 100 → 500 → 1000 (optional flags). Measures check-in p50/p95 and
optionally samples SSE subscribe latency.

Honest output: **not production proof**. Does NOT claim 5k-agent support.

Usage (against a lab server you own):

  python scripts/realtime_load_test.py --server http://127.0.0.1:8080 --ladder
  python scripts/realtime_load_test.py --agents 100 --duration 30 --sse-sample
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import statistics
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# Reuse helpers from the existing harness when available.
try:
    from scripts.load_test_agents import checkin_once, enroll  # type: ignore
except Exception:
    checkin_once = None  # type: ignore
    enroll = None  # type: ignore


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


def _enroll(server: str, admin_token: str, name: str, *, insecure: bool = False) -> str:
    if enroll is not None:
        try:
            return enroll(server, admin_token, name, insecure=insecure)
        except Exception:
            pass  # fall through to local path with longer timeout
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            code, data = _request(
                "POST",
                server.rstrip("/") + "/api/agents/enroll",
                headers={"Authorization": f"Bearer {admin_token}"},
                body={"name": name},
                insecure=insecure,
                timeout=60.0,
            )
            if code == 200 and isinstance(data, dict) and data.get("agent_token"):
                return str(data["agent_token"])
            last_err = RuntimeError(f"enroll failed: {code} {data}")
        except Exception as exc:
            last_err = exc
        time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(f"enroll failed after retries: {last_err}")


def _enroll_many(
    server: str,
    admin_token: str,
    need: int,
    *,
    insecure: bool,
    workers: int = 4,
) -> list[str]:
    tokens: list[str] = []
    lock = threading.Lock()
    errors: list[str] = []

    def one(i: int) -> None:
        try:
            tok = _enroll(server, admin_token or "lab-local", f"rt-load-{i}", insecure=insecure)
            with lock:
                tokens.append(tok)
        except Exception as exc:
            with lock:
                errors.append(f"{i}:{exc}")

    print(f"[rt-load] enrolling {need} agents (workers={workers})...", flush=True)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = [pool.submit(one, i) for i in range(need)]
        for f in as_completed(futs):
            f.result()
    if errors:
        print(f"[rt-load] enroll errors ({len(errors)}): {errors[:5]}", flush=True)
    if len(tokens) < need:
        print(f"[rt-load] enrolled {len(tokens)}/{need}", flush=True)
    return tokens


def _checkin(server: str, token: str, *, insecure: bool = False, timeout: float = 90.0) -> tuple[bool, float]:
    """One HTTP check-in; timeouts/errors count as fail (never raise)."""
    t0 = time.perf_counter()
    payload = {
        "hostname": f"rt-load-{token.split('.', 1)[0][:8]}",
        "ip": "127.0.0.1",
        "os": "loadtest",
        "os_version": "0",
        "agent_version": "realtime-load",
        "listening_ports": [],
        "processes": [],
        "packages": [],
    }
    try:
        code, data = _request(
            "POST",
            server.rstrip("/") + "/api/agents/checkin",
            headers={"Authorization": f"Bearer {token}"},
            body=payload,
            insecure=insecure,
            timeout=timeout,
        )
        dt = time.perf_counter() - t0
        ok = code == 200 and isinstance(data, dict) and bool(data.get("ok"))
        return ok, dt
    except Exception:
        return False, time.perf_counter() - t0


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    if pct <= 50:
        return statistics.median(ordered)
    # nearest-rank for p95
    k = min(len(ordered) - 1, max(0, int(round(pct / 100.0 * (len(ordered) - 1)))))
    return ordered[k]


def sample_sse_latency(server: str, *, token: str = "", insecure: bool = False, wait_sec: float = 5.0) -> float | None:
    """Open EventSource-style GET /api/realtime and time until first event/comment."""
    url = server.rstrip("/") + "/api/realtime"
    hdrs = {"Accept": "text/event-stream"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, method="GET", headers=hdrs)
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=wait_sec + 2.0, context=ctx) as resp:
            deadline = time.time() + wait_sec
            while time.time() < deadline:
                line = resp.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if text.startswith(":") or text.startswith("data:") or text.startswith("event:"):
                    return time.perf_counter() - t0
    except Exception:
        return None
    return None


def run_wave(
    *,
    server: str,
    tokens: list[str],
    agents: int,
    workers: int,
    insecure: bool,
    timeout: float = 90.0,
) -> dict[str, Any]:
    """One check-in per agent (honest HTTP capacity rung; respects min-interval intent)."""
    use = tokens[: max(1, agents)]
    lock = threading.Lock()
    stats: dict[str, Any] = {"ok": 0, "fail": 0, "lat": []}
    t0 = time.perf_counter()

    def one(token: str) -> None:
        ok, dt = _checkin(server, token, insecure=insecure, timeout=timeout)
        with lock:
            if ok:
                stats["ok"] += 1
                stats["lat"].append(dt)
            else:
                stats["fail"] += 1

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(use)))) as pool:
        futs = [pool.submit(one, t) for t in use]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as exc:
                print(f"[rt-load] worker error: {exc}", flush=True)
                with lock:
                    stats["fail"] += 1

    elapsed = time.perf_counter() - t0
    total = stats["ok"] + stats["fail"]
    rate = (100.0 * stats["ok"] / total) if total else 0.0
    p50 = _percentile(stats["lat"], 50)
    p95 = _percentile(stats["lat"], 95)
    return {
        "agents": len(use),
        "mode": "wave",
        "elapsed_sec": round(elapsed, 3),
        "checkin_ok": stats["ok"],
        "checkin_fail": stats["fail"],
        "success_rate_pct": round(rate, 2),
        "events_per_sec": round(stats["ok"] / max(elapsed, 1e-9), 2),
        "latency_p50_sec": round(p50, 4) if p50 is not None else None,
        "latency_p95_sec": round(p95, 4) if p95 is not None else None,
        "workers": max(1, min(workers, len(use))),
    }


def run_rung(
    *,
    server: str,
    tokens: list[str],
    agents: int,
    duration: int,
    workers: int,
    insecure: bool,
) -> dict[str, Any]:
    use = tokens[: max(1, agents)]
    stop_at = time.time() + max(5, duration)
    lock = threading.Lock()
    stats: dict[str, Any] = {"ok": 0, "fail": 0, "lat": []}

    def worker(token: str) -> None:
        while time.time() < stop_at:
            ok, dt = _checkin(server, token, insecure=insecure, timeout=60.0)
            with lock:
                if ok:
                    stats["ok"] += 1
                    stats["lat"].append(dt)
                else:
                    stats["fail"] += 1
            # Honor typical agent_checkin_min_interval_sec (~30s) between repeats
            time.sleep(30.0)

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(use)))) as pool:
        futs = [pool.submit(worker, t) for t in use]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as exc:
                print(f"[rt-load] worker error: {exc}", flush=True)

    total = stats["ok"] + stats["fail"]
    rate = (100.0 * stats["ok"] / total) if total else 0.0
    p50 = _percentile(stats["lat"], 50)
    p95 = _percentile(stats["lat"], 95)
    return {
        "agents": len(use),
        "mode": "duration",
        "duration_sec": duration,
        "checkin_ok": stats["ok"],
        "checkin_fail": stats["fail"],
        "success_rate_pct": round(rate, 2),
        "latency_p50_sec": round(p50, 4) if p50 is not None else None,
        "latency_p95_sec": round(p95, 4) if p95 is not None else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="SecuraIQ REALTIME load ladder (not production proof)")
    ap.add_argument("--server", default=os.environ.get("SECURAIQ_SERVER", "http://127.0.0.1:8080"))
    ap.add_argument("--admin-token", default=os.environ.get("SECURAIQ_ADMIN_TOKEN", "lab-local"))
    ap.add_argument("--token-file", default="")
    ap.add_argument("--agents", type=int, default=100)
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--ladder", action="store_true", help="Run 25 → 50 → 100 → 500 → 1000 sequentially")
    ap.add_argument(
        "--to-5k",
        action="store_true",
        help="Extend ladder with 2500 and 5000 rungs (MEASURE ONLY — never claim capacity from empty table)",
    )
    ap.add_argument("--max-agents", type=int, default=1000, help="Cap ladder top rung (default 1000; use --to-5k for higher)")
    ap.add_argument(
        "--wave",
        action="store_true",
        default=True,
        help="One check-in per agent per rung (default; honest vs min-interval)",
    )
    ap.add_argument(
        "--duration-mode",
        action="store_true",
        help="Repeat check-ins for --duration seconds (sleeps 30s between repeats)",
    )
    ap.add_argument("--sse-sample", action="store_true", help="Sample SSE first-byte latency once")
    ap.add_argument("--user-token", default=os.environ.get("SECURAIQ_USER_TOKEN", ""), help="Optional bearer for SSE")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument(
        "--persist",
        action="store_true",
        help="Append results to data/ops/capacity_measurements.jsonl",
    )
    args = ap.parse_args()
    if args.duration_mode:
        args.wave = False

    if args.to_5k and args.max_agents < 5000:
        args.max_agents = 5000

    print(
        "[rt-load] NOT PRODUCTION PROOF — lab ladder only; do not claim 5k-agent capacity "
        "until data/ops/capacity_measurements.jsonl has a real filled run.",
        flush=True,
    )

    tokens: list[str] = []
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as fh:
            tokens = [ln.strip() for ln in fh if ln.strip()]
    else:
        if args.ladder or args.to_5k:
            planned = [25, 50, 100, 500, 1000]
            if args.to_5k:
                planned.extend([2500, 5000])
            need = max([r for r in planned if r <= max(1, args.max_agents)] or [args.agents])
        else:
            need = args.agents
        tokens = _enroll_many(
            args.server,
            args.admin_token,
            need,
            insecure=args.insecure,
            workers=min(4, max(2, args.workers // 2 or 2)),
        )

    if args.ladder or args.to_5k:
        rungs = [25, 50, 100, 500, 1000]
        if args.to_5k:
            rungs.extend([2500, 5000])
    else:
        rungs = [args.agents]
    rungs = [r for r in rungs if r <= max(1, args.max_agents)]
    if not rungs:
        rungs = [min(len(tokens), max(1, args.agents))]

    results: list[dict[str, Any]] = []
    for n in rungs:
        if n > len(tokens):
            print(f"[rt-load] skip rung {n}: only {len(tokens)} tokens enrolled", flush=True)
            continue
        print(
            f"[rt-load] rung agents={n} mode={'wave' if args.wave else 'duration'} "
            f"workers={args.workers}",
            flush=True,
        )
        if args.wave:
            results.append(
                run_wave(
                    server=args.server,
                    tokens=tokens,
                    agents=n,
                    workers=args.workers,
                    insecure=args.insecure,
                )
            )
        else:
            results.append(
                run_rung(
                    server=args.server,
                    tokens=tokens,
                    agents=n,
                    duration=args.duration,
                    workers=min(args.workers, n),
                    insecure=args.insecure,
                )
            )
        row = results[-1]
        print(
            f"[rt-load]   ok={row.get('checkin_ok')} fail={row.get('checkin_fail')} "
            f"success={row.get('success_rate_pct')}% "
            f"p50={row.get('latency_p50_sec')}s p95={row.get('latency_p95_sec')}s",
            flush=True,
        )

    sse_lat = None
    if args.sse_sample:
        sse_lat = sample_sse_latency(
            args.server, token=args.user_token or args.admin_token, insecure=args.insecure
        )

    summary = {
        "tool": "realtime_load_test",
        "mode": "wave" if args.wave else "duration",
        "server": args.server,
        "rungs": results,
        "sse_first_event_sec": round(sse_lat, 4) if sse_lat is not None else None,
        "note": "not production proof — measured lab HTTP check-in ladder; no 5k claim without filled ops log",
        "disclaimer": "Do not market 5k agents until CAPACITY-LAB.md table is filled from this harness.",
    }
    print(json.dumps(summary, indent=2))
    if args.persist:
        from datetime import datetime, timezone
        from pathlib import Path

        log = Path(__file__).resolve().parents[1] / "data" / "ops" / "capacity_measurements.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        row = {"ts_utc": datetime.now(timezone.utc).isoformat(), **summary}
        with log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
        print(f"[rt-load] persisted -> {log}", flush=True)
    # Soft pass: any rung below 90% success still exits 1 for CI signal.
    bad = [r for r in results if float(r.get("success_rate_pct") or 0) < 90.0]
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
