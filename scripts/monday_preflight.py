#!/usr/bin/env python3
"""Monday demo preflight — scanners, alive, AI limits. Does not claim HA."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.monday_demo import scanner_preflight  # noqa: E402


def main() -> int:
    out = scanner_preflight()
    out["ai"] = {"hint": "DEMO_DISABLE_AI=true keeps chat off the scan path"}
    out["alive"] = None
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/api/alive", timeout=2) as resp:
            out["alive"] = {"ok": 200 <= int(resp.status) < 300, "status": int(resp.status)}
    except Exception as exc:
        out["alive"] = {"ok": False, "error": str(exc)[:200]}
    print(json.dumps(out, indent=2))
    if not out["nmap"]["on_path"]:
        print("WARN: nmap not on PATH — Discovery/Nmap will be unavailable.", file=sys.stderr)
    if not out["nuclei"]["on_path"]:
        print("WARN: nuclei not on PATH — Nuclei engine unavailable (built-in + web still work).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
