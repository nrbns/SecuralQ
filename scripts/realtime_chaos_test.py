"""REALTIME v1 soft chaos scaffolding (Task I) — not production proof.

Documents and runs soft chaos:
  1. Simulate agent disconnect (buffer locally, no check-in)
  2. Enqueue offline telemetry events
  3. Reconnect / flush and verify server ACK + local buffer drain

Redis kill is **manual** and documented only — this script will not stop Redis.

Usage:

  # Pure local buffer unit path (no server):
  python scripts/realtime_chaos_test.py --local-only

  # Against a lab server you own:
  python scripts/realtime_chaos_test.py --server http://127.0.0.1:8080 --admin-token <tok>
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
from pathlib import Path
from typing import Any

# Ensure repo root on path for `app.*` imports when run as a script.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


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


def run_local_buffer_chaos() -> dict[str, Any]:
    """Disconnect → enqueue → reconnect flush (in-process) → ACK drain."""
    from app.agent_offline_buffer import OfflineTelemetryBuffer

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "offline.json"
        buf = OfflineTelemetryBuffer("chaos-agent", path=path, max_events=100)
        # Soft disconnect: events spool locally.
        for i in range(5):
            buf.enqueue("telemetry", {"i": i, "note": "offline"})
        assert buf.pending_count == 5
        ext = buf.build_checkin_extension(flush_limit=10)
        assert len(ext.get("buffered_events") or []) == 5
        # Simulate server ACK of contiguous sequences 1..5
        fake_resp = {"last_acked_seq": 5, "acked_sequences": [1, 2, 3, 4, 5]}
        removed = buf.apply_server_ack(fake_resp)
        return {
            "mode": "local-only",
            "enqueued": 5,
            "flushed_fields": list(ext.keys()),
            "removed_after_ack": removed,
            "pending_after_ack": buf.pending_count,
            "ok": buf.pending_count == 0 and removed >= 5,
            "note": "not production proof — soft buffer chaos only",
        }


def run_server_chaos(
    server: str,
    admin_token: str,
    *,
    insecure: bool = False,
) -> dict[str, Any]:
    from app.agent_offline_buffer import OfflineTelemetryBuffer

    code, enrolled = _request(
        "POST",
        server.rstrip("/") + "/api/agents/enroll",
        headers={"Authorization": f"Bearer {admin_token}"},
        body={"name": f"chaos-{int(time.time())}"},
        insecure=insecure,
    )
    if code != 200 or not isinstance(enrolled, dict) or not enrolled.get("agent_token"):
        return {"ok": False, "error": f"enroll failed: {code} {enrolled}"}

    token = str(enrolled["agent_token"])
    agent_id = str(enrolled.get("agent_id") or token.split(".", 1)[0])

    with tempfile.TemporaryDirectory() as td:
        buf = OfflineTelemetryBuffer(agent_id, path=Path(td) / "offline.json")
        # Soft disconnect window: do not check in; spool events.
        for i in range(3):
            buf.enqueue("telemetry", {"i": i})
        ext = buf.build_checkin_extension()
        body = {
            "hostname": "chaos-host",
            "ip": "127.0.0.1",
            "os": "chaos",
            "os_version": "0",
            "agent_version": "realtime-chaos",
            "listening_ports": [],
            "processes": [],
            "packages": [],
            **ext,
        }
        code, resp = _request(
            "POST",
            server.rstrip("/") + "/api/agents/checkin",
            headers={"Authorization": f"Bearer {token}"},
            body=body,
            insecure=insecure,
        )
        removed = buf.apply_server_ack(resp if isinstance(resp, dict) else {})
        ok = (
            code == 200
            and isinstance(resp, dict)
            and bool(resp.get("ok"))
            and int(resp.get("last_acked_seq") or 0) >= 1
            and buf.pending_count == 0
        )
        return {
            "mode": "server",
            "http_status": code,
            "last_acked_seq": (resp or {}).get("last_acked_seq") if isinstance(resp, dict) else None,
            "acked_sequences": (resp or {}).get("acked_sequences") if isinstance(resp, dict) else None,
            "removed_after_ack": removed,
            "pending_after_ack": buf.pending_count,
            "ok": ok,
            "note": "not production proof — soft reconnect/replay only",
        }


def print_manual_redis_notes() -> None:
    print(
        """
=== Manual Redis chaos (operator-owned — not automated) ===
1. With REDIS_URL configured and multi-worker uvicorn, note SSE fan-out working.
2. Stop Redis: `docker compose stop redis` (or kill the redis process).
3. Observe: in-process bus still works on each worker; cross-worker fan-out drops.
4. Restart Redis and confirm pub/sub resumes.
5. Durable Streams / Sentinel failover are NOT covered here (REALTIME Task B/G ops).
Honest verdict: soft chaos scaffolding only — not production proof.
""".strip()
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="SecuraIQ REALTIME soft chaos (not production proof)")
    ap.add_argument("--server", default=os.environ.get("SECURAIQ_SERVER", "http://127.0.0.1:8080"))
    ap.add_argument("--admin-token", default=os.environ.get("SECURAIQ_ADMIN_TOKEN", ""))
    ap.add_argument("--local-only", action="store_true")
    ap.add_argument("--document-redis", action="store_true", help="Print Redis kill runbook and exit")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    print("[rt-chaos] NOT PRODUCTION PROOF — soft chaos scaffolding.", flush=True)

    if args.document_redis:
        print_manual_redis_notes()
        return 0

    if args.local_only or not args.admin_token:
        result = run_local_buffer_chaos()
        if not args.admin_token and not args.local_only:
            print("[rt-chaos] no --admin-token; ran --local-only path", flush=True)
            print_manual_redis_notes()
    else:
        result = run_server_chaos(args.server, args.admin_token, insecure=args.insecure)
        print_manual_redis_notes()

    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
