"""Synthetic agent load / failure harness for Agent Platform v1.

Does NOT claim production scale. Records check-in success rate for N agents
over a short window so readiness gates have measured numbers.

Usage (against a lab server you own):

  python scripts/load_test_agents.py --server http://127.0.0.1:8080 --agents 100 --duration 60

Requires AUTH_ENABLED=true and a user bearer token (or set --token from enroll).
When --admin-token is provided, agents are enrolled via the API; otherwise
pass pre-enrolled tokens via --token-file (one token per line).
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


def enroll(server: str, admin_token: str, name: str, *, insecure: bool = False) -> str:
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


def checkin_once(server: str, token: str, *, insecure: bool = False) -> tuple[bool, float]:
    t0 = time.perf_counter()
    payload = {
        "hostname": f"load-{token.split('.', 1)[0][:8]}",
        "ip": "127.0.0.1",
        "os": "loadtest",
        "os_version": "0",
        "agent_version": "load-test",
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


def gateway_wait_once(server: str, token: str, *, insecure: bool = False) -> tuple[bool, float]:
    t0 = time.perf_counter()
    code, data = _request(
        "POST",
        server.rstrip("/") + "/api/agents/gateway/wait",
        headers={"Authorization": f"Bearer {token}"},
        body={"timeout_sec": 2.0, "limit": 1},
        insecure=insecure,
        timeout=15.0,
    )
    dt = time.perf_counter() - t0
    ok = code == 200 and isinstance(data, dict) and "commands" in data
    return ok, dt


def main() -> int:
    ap = argparse.ArgumentParser(description="SecuraIQ agent load/failure harness")
    ap.add_argument("--server", default=os.environ.get("SECURAIQ_SERVER", "http://127.0.0.1:8080"))
    ap.add_argument("--admin-token", default=os.environ.get("SECURAIQ_ADMIN_TOKEN", ""))
    ap.add_argument("--token-file", default="", help="One agent token per line (skip enroll)")
    ap.add_argument("--agents", type=int, default=50)
    ap.add_argument("--duration", type=int, default=30, help="Seconds to keep checking in")
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--gateway", action="store_true", help="Also exercise gateway/wait")
    args = ap.parse_args()

    tokens: list[str] = []
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as fh:
            tokens = [ln.strip() for ln in fh if ln.strip()]
    elif args.admin_token:
        print(f"[load] enrolling {args.agents} agents…")
        for i in range(args.agents):
            tokens.append(enroll(args.server, args.admin_token, f"load-{i}", insecure=args.insecure))
    else:
        print("Need --admin-token or --token-file", flush=True)
        return 2

    tokens = tokens[: max(1, args.agents)]
    print(f"[load] running {len(tokens)} agents for {args.duration}s with {args.workers} workers")

    stop_at = time.time() + max(5, args.duration)
    lock = threading.Lock()
    stats = {"ok": 0, "fail": 0, "lat": [], "gw_ok": 0, "gw_fail": 0}

    def worker(token: str) -> None:
        while time.time() < stop_at:
            ok, dt = checkin_once(args.server, token, insecure=args.insecure)
            with lock:
                if ok:
                    stats["ok"] += 1
                    stats["lat"].append(dt)
                else:
                    stats["fail"] += 1
            if args.gateway:
                gok, _ = gateway_wait_once(args.server, token, insecure=args.insecure)
                with lock:
                    if gok:
                        stats["gw_ok"] += 1
                    else:
                        stats["gw_fail"] += 1
            else:
                time.sleep(0.5)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futs = [pool.submit(worker, t) for t in tokens]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as exc:
                print(f"[load] worker error: {exc}")

    total = stats["ok"] + stats["fail"]
    rate = (100.0 * stats["ok"] / total) if total else 0.0
    p50 = statistics.median(stats["lat"]) if stats["lat"] else None
    p95 = (
        statistics.quantiles(stats["lat"], n=20)[18]
        if len(stats["lat"]) >= 20
        else (max(stats["lat"]) if stats["lat"] else None)
    )
    summary = {
        "agents": len(tokens),
        "duration_sec": args.duration,
        "checkin_ok": stats["ok"],
        "checkin_fail": stats["fail"],
        "success_rate_pct": round(rate, 2),
        "latency_p50_sec": round(p50, 4) if p50 is not None else None,
        "latency_p95_sec": round(p95, 4) if p95 is not None else None,
        "gateway_ok": stats["gw_ok"],
        "gateway_fail": stats["gw_fail"],
        "note": "Measured lab harness only — not a 5k-agent capacity claim.",
    }
    print(json.dumps(summary, indent=2))
    return 0 if rate >= 95.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
