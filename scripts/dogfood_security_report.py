#!/usr/bin/env python3
"""Generate SecuraIQ self-security dogfood report (Bandit productized)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow `python scripts/...` from repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser(description="SecuraIQ self-security dogfood report")
    ap.add_argument("--skip-scan", action="store_true", help="Persist scaffolding without Bandit")
    ap.add_argument("--write-docs", action="store_true", help="Also write docs/ops/SELF-SECURITY-DOGFOOD.md")
    args = ap.parse_args()

    from app.self_security import build_markdown, generate_dogfood_report

    report = generate_dogfood_report(run_scan=not args.skip_scan)
    print(json.dumps({k: v for k, v in report.items() if k != "markdown"}, indent=2, default=str))
    if args.write_docs:
        docs = ROOT / "docs" / "ops" / "SELF-SECURITY-DOGFOOD.md"
        docs.parent.mkdir(parents=True, exist_ok=True)
        docs.write_text(build_markdown(report), encoding="utf-8")
        print(f"[dogfood] wrote {docs}", file=sys.stderr)
    return 0 if report.get("ok") or report.get("available") is False else 1


if __name__ == "__main__":
    raise SystemExit(main())
