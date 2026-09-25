#!/usr/bin/env python3
"""Verify a customer / other-device install. Does not invent EV or public-internet HA.

  python scripts/customer_install_check.py
  python scripts/customer_install_check.py --summary
  python scripts/customer_install_check.py --url http://192.168.0.10:8080
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_REMOTE_PROBES = (
    "/ready",
    "/api/health",
    "/api/install/customer-check",
    "/api/agents/install-script/windows",
    "/api/agents/install-script/linux",
    "/api/agents/install-script/macos",
    "/",
)


def _local_board() -> dict:
    from app.customer_install import customer_install_board

    return customer_install_board()


def _remote_board(url: str) -> dict:
    base = url.rstrip("/")
    checks = []
    remote: dict | None = None
    for path in _REMOTE_PROBES:
        try:
            with urlopen(base + path, timeout=30) as resp:
                body = resp.read()
                ok = 200 <= resp.status < 300
                checks.append({"path": path, "ok": ok, "status": resp.status})
                if path.endswith("customer-check") and ok:
                    remote = json.loads(body.decode())
        except URLError as exc:
            checks.append({"path": path, "ok": False, "error": str(exc)})
        except Exception as exc:
            checks.append({"path": path, "ok": False, "error": str(exc)})
    core_ok = all(
        c.get("ok")
        for c in checks
        if c.get("path") in {"/api/install/customer-check", "/api/agents/install-script/windows", "/"}
    )
    probes_ok = all(c.get("ok") for c in checks)
    if remote is None:
        return {
            "ok": False,
            "customer_ready": False,
            "http_probes": checks,
            "http_probes_ok": probes_ok,
            "note": "Could not load /api/install/customer-check from that URL.",
        }
    remote["http_probes"] = checks
    remote["http_probes_ok"] = probes_ok
    # /ready and /api/health can stall on first SQLite lock after LAN boot scan.
    # Customer-ready requires the install URL, Windows script, and UI — not a perfect first health hit.
    remote["ok"] = bool(remote.get("ok")) and core_ok
    remote["customer_ready"] = bool(remote.get("customer_ready")) and core_ok
    return remote


def _print_summary(board: dict) -> None:
    ready = bool(board.get("customer_ready") or board.get("ok"))
    print(f"customer_ready={ready}  server={board.get('server_url') or ''}")
    open_url = (board.get("other_device") or {}).get("open")
    if open_url:
        print(f"other_device_open={open_url}")
    never = (board.get("other_device") or {}).get("never")
    if never:
        print(f"never={never}")
    for fn in board.get("functions") or []:
        mark = "ok" if fn.get("ok") else "FAIL"
        print(f"  {mark:4}  {fn.get('id')}  {fn.get('note') or ''}")
    for probe in board.get("http_probes") or []:
        mark = "ok" if probe.get("ok") else "FAIL"
        extra = probe.get("status") or probe.get("error") or ""
        print(f"  {mark:4}  http {probe.get('path')}  {extra}")


def main() -> int:
    parser = argparse.ArgumentParser(description="SecuraIQ customer / other-device install check")
    parser.add_argument("--url", default="", help="Remote console URL (from another device)")
    parser.add_argument("--summary", action="store_true", help="Print one line per function instead of JSON")
    args = parser.parse_args()
    board = _remote_board(args.url) if args.url else _local_board()
    if args.summary:
        _print_summary(board)
    else:
        print(json.dumps(board, indent=2, default=str))
    if not board.get("reachable_from_other_hosts"):
        print("\nOther devices will fail if they use localhost.", file=sys.stderr)
        print("On the SecuraIQ host: .\\start_lan.cmd   or   python run.py --lan", file=sys.stderr)
    return 0 if board.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
