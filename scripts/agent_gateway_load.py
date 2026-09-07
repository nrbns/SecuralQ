"""Synth harness for native-agent load (NOT a 5k-agent proof).

Default: enroll N agents (user bearer) then concurrent HTTP check-ins.
Optional --ws does WebSocket hello+heartbeat instead.

  python scripts/agent_gateway_load.py --server http://127.0.0.1:8080 --agents 100
  python scripts/agent_gateway_load.py --server http://127.0.0.1:8080 --agents 50 --ws

Do not claim 5,000 agents until this (or a successor) has been measured at that scale.

Authorized labs / owned hosts only.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


def _req(url: str, *, method: str = "GET", data: dict | None = None, headers: dict | None = None, timeout: float = 30) -> dict[str, Any]:
    body = None if data is None else json.dumps(data).encode("utf-8")
    hdrs = {"User-Agent": "SecuraIQ-load/1.0", **(headers or {})}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def _enroll(server: str, user_token: str, name: str) -> str:
    out = _req(
        server.rstrip("/") + "/api/agents/enroll",
        method="POST",
        data={"name": name},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    token = out.get("agent_token") or ""
    if not token:
        raise RuntimeError(f"enroll failed: {out}")
    return token


def _checkin(server: str, agent_token: str) -> bool:
    try:
        out = _req(
            server.rstrip("/") + "/api/agents/checkin",
            method="POST",
            data={"hostname": "load-synth", "os": "linux", "agent_version": "load"},
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        return bool(out.get("ok"))
    except Exception:
        return False


def _ws_hello(server: str, agent_token: str) -> bool:
    try:
        from scripts.securaiq_agent import _ws_connect, _ws_recv_text, _ws_send_text
    except Exception:
        # Running as a file, not a package
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from scripts.securaiq_agent import _ws_connect, _ws_recv_text, _ws_send_text  # type: ignore

    conn = _ws_connect(server, agent_token)
    if not conn:
        return False
    sock, rest = conn
    leftover = bytearray(rest)
    try:
        _ws_send_text(sock, json.dumps({"type": "hello", "token": agent_token}))
        raw = _ws_recv_text(sock, leftover, 10.0)
        if not raw:
            return False
        msg = json.loads(raw)
        ok = msg.get("type") == "welcome"
        _ws_send_text(sock, json.dumps({"type": "heartbeat", "ts": time.time()}))
        return ok
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(description="SecuraIQ agent gateway synth load (lab)")
    ap.add_argument("--server", default=os.environ.get("SECURAIQ_SERVER", "http://127.0.0.1:8080"))
    ap.add_argument("--agents", type=int, default=100, help="How many synth agents (default 100; not 5k)")
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--token", default=os.environ.get("SECURAIQ_USER_TOKEN", ""), help="User bearer for enroll (auth-on)")
    ap.add_argument("--ws", action="store_true", help="WebSocket hello instead of HTTP check-in")
    ap.add_argument("--skip-enroll", action="store_true", help="Use --token-file list of existing agent tokens")
    ap.add_argument("--kill-reconnect", action="store_true", help="Second pass after a short pause (reconnect/fallback)")
    args = ap.parse_args()
    n = max(1, min(int(args.agents), 500))
    if n >= 1000:
        print("Refusing --agents >= 1000 in this harness. Measure 100 first; do not claim 5k.", file=sys.stderr)
        return 2

    tokens: list[str] = []
    if args.token:
        print(f"Enrolling {n} synth agents…")
        for i in range(n):
            tokens.append(_enroll(args.server, args.token, f"synth-{i:04d}"))
    else:
        print("AUTH off / no --token: enroll as anonymous local (AUTH_ENABLED=false).", file=sys.stderr)
        try:
            for i in range(n):
                tokens.append(_enroll(args.server, "", f"synth-{i:04d}"))
        except urllib.error.HTTPError as exc:
            print(f"Enroll failed HTTP {exc.code}. Pass --token for a user session when auth is on.", file=sys.stderr)
            return 1

    fn = _ws_hello if args.ws else _checkin
    t0 = time.time()
    ok = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = [ex.submit(fn, args.server, tok) for tok in tokens]
        for fut in as_completed(futs):
            if fut.result():
                ok += 1
    elapsed = time.time() - t0
    print(f"pass1 ok={ok}/{len(tokens)} in {elapsed:.2f}s workers={args.workers} ws={bool(args.ws)}")
    if args.kill_reconnect:
        time.sleep(1.0)
        t1 = time.time()
        ok2 = 0
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            futs = [ex.submit(fn, args.server, tok) for tok in tokens]
            for fut in as_completed(futs):
                if fut.result():
                    ok2 += 1
        print(f"pass2 (reconnect) ok={ok2}/{len(tokens)} in {time.time() - t1:.2f}s")
    print("This is a synth lab run. Do not claim 5,000 agents from these numbers.")
    return 0 if ok == len(tokens) else 1


if __name__ == "__main__":
    raise SystemExit(main())
