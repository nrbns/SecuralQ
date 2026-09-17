"""Export FastAPI OpenAPI schema to docs/openapi.json (#236)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    from app.main import app

    schema = app.openapi()
    out = ROOT / "docs" / "openapi.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths = len(schema.get("paths") or {})
    print(f"Wrote {out} ({paths} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
