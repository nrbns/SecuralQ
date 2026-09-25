#!/usr/bin/env python3
"""Wait until SecuraIQ answers, then open the UI.

Used by start.cmd / start.sh so the browser does not wait on a slow /api/health.
Opens the browser quickly (do not block 35s) and still reports ready when
/api/alive answers.
Exit 0 if /api/alive (or /) responded; 2 if we opened after timeout.
"""

from __future__ import annotations

import argparse
import sys
import time
import urllib.request
import webbrowser


def _ok(url: str, timeout: float = 1.5) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return 200 <= int(resp.status) < 300
    except Exception:
        return False


def wait_ready(base: str, timeout: float) -> bool:
    deadline = time.time() + max(2.0, timeout)
    alive = base.rstrip("/") + "/api/alive"
    home = base.rstrip("/") + "/"
    while time.time() < deadline:
        if _ok(alive, 0.8) or _ok(home, 0.8):
            return True
        time.sleep(0.25)
    return False


def _open(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Wait for SecuraIQ /api/alive and open the browser.")
    p.add_argument("--url", default="http://127.0.0.1:8080")
    p.add_argument("--timeout", type=float, default=12)
    p.add_argument("--open-after", type=float, default=1.5, help="Open the browser after this many seconds even if alive is still starting.")
    p.add_argument("--no-browser", action="store_true")
    args = p.parse_args(argv)
    base = args.url.rstrip("/")
    home = base + "/"
    opened = False
    started = time.time()
    deadline = started + max(2.0, args.timeout)
    ok = False
    while time.time() < deadline:
        if _ok(base + "/api/alive", 0.8) or _ok(home, 0.8):
            ok = True
            break
        if not args.no_browser and not opened and (time.time() - started) >= max(0.0, args.open_after):
            _open(home)
            opened = True
            print("opening " + base, flush=True)
        time.sleep(0.25)
    if not args.no_browser and not opened:
        _open(home)
    print(("ready" if ok else "starting") + " " + base, flush=True)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
