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
        return enroll(server, admin_token, name, insecure=insecure)
    code, data = _request(
        "POST",
        server.rstrip("/") + "/api/agents/enroll",
        headers={"Authorization": f"Bearer {admin_token}"},
        body={"name": name},
        insecure=insecure,
    )
    if code != 200 or not isinstance(data, dict) or not data.get("agent_token"):
        raise RuntimeError(f"enroll failed: {code} {data}")
    return str(data["agent_token"])


def _checkin(server: str, token: str, *, insecure: bool = False) -> tuple[bool, float]:
    if checkin_once is not None:
        return checkin_once(server, token, insecure=insecure)
    t0 = time.perf_counter()
    payload = {
        "hostname": "rt-load",
        "ip": "127.0.0.1",
        "os": "loadtest",
        "os_version": "0",
        "agent_version": "realtime-load",
        "listening_ports": [],
        "processes": [],
        "packages": [],
    }
    code, data = _request(
        "POST",
        server.rstrip("/") + "/api/agents/checkin",
        headers={"Authorization": f"Bearer {token}"},
        body=payload,
        insecure=insecure,
        timeout=20.0,
    )
    dt = time.perf_counter() - t0
    ok = code == 200 and isinstance(data, dict) and bool(data.get("ok"))
    return ok, dt


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
            ok, dt = _checkin(server, token, insecure=insecure)
            with lock:
                if ok:
                    stats["ok"] += 1
                    stats["lat"].append(dt)
                else:
                    stats["fail"] += 1
            time.sleep(0.25)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = [pool.submit(worker, t) for t in use]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as exc:
                print(f"[rt-load] worker error: {exc}")

    total = stats["ok"] + stats["fail"]
    rate = (100.0 * stats["ok"] / total) if total else 0.0
    p50 = _percentile(stats["lat"], 50)
    p95 = _percentile(stats["lat"], 95)
    return {
        "agents": len(use),
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
    ap.add_argument("--admin-token", default=os.environ.get("SECURAIQ_ADMIN_TOKEN", ""))
    ap.add_argument("--token-file", default="")
    ap.add_argument("--agents", type=int, default=100)
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--ladder", action="store_true", help="Run 100 → 500 → 1000 sequentially")
    ap.add_argument("--max-agents", type=int, default=1000, help="Cap ladder top rung (default 1000, not 5k)")
    ap.add_argument("--sse-sample", action="store_true", help="Sample SSE first-byte latency once")
    ap.add_argument("--user-token", default=os.environ.get("SECURAIQ_USER_TOKEN", ""), help="Optional bearer for SSE")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    print(
        "[rt-load] NOT PRODUCTION PROOF — lab ladder only; do not claim 5k-agent capacity.",
        flush=True,
    )

    tokens: list[str] = []
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as fh:
            tokens = [ln.strip() for ln in fh if ln.strip()]
    elif args.admin_token:
        need = max(args.agents, args.max_agents if args.ladder else args.agents)
        print(f"[rt-load] enrolling up to {need} agents…", flush=True)
        for i in range(need):
            tokens.append(_enroll(args.server, args.admin_token, f"rt-load-{i}", insecure=args.insecure))
    else:
        print("Need --admin-token or --token-file", flush=True)
        return 2

    rungs = [100, 500, 1000] if args.ladder else [args.agents]
    rungs = [r for r in rungs if r <= max(1, args.max_agents)]
    if not rungs:
        rungs = [min(len(tokens), max(1, args.agents))]

    results: list[dict[str, Any]] = []
    for n in rungs:
        if n > len(tokens):
            print(f"[rt-load] skip rung {n}: only {len(tokens)} tokens enrolled", flush=True)
            continue
        print(f"[rt-load] rung agents={n} duration={args.duration}s workers={args.workers}", flush=True)
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

    sse_lat = None
    if args.sse_sample:
        sse_lat = sample_sse_latency(
            args.server, token=args.user_token or args.admin_token, insecure=args.insecure
        )

    summary = {
        "rungs": results,
        "sse_first_event_sec": round(sse_lat, 4) if sse_lat is not None else None,
        "note": "not production proof — measured lab ladder ≤1k; no 5k claim",
    }
    print(json.dumps(summary, indent=2))
    # Soft pass: any rung below 90% success still exits 1 for CI signal.
    bad = [r for r in results if float(r.get("success_rate_pct") or 0) < 90.0]
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
