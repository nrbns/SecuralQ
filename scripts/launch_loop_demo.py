"""Run the SecuraIQ launch closed-loop demonstration.

Usage:
  python scripts/launch_loop_demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def main() -> int:
    from app.auth import register_user
    from app.db import init_schema
    from app.launch_loop import run_launch_loop
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    try:
        u = register_user("launch_demo", "password123")
        uid = u.id
    except Exception:
        from app.auth import login

        user, _tok = login("launch_demo", "password123")
        uid = user.id
    out = run_launch_loop(uid)
    print(json.dumps({k: out.get(k) for k in ("ok", "missing", "disclaimer", "decision_drawer")}, indent=2, default=str))
    print("RESULT:", "LAUNCH LOOP GREEN" if out.get("ok") else "LAUNCH LOOP INCOMPLETE")
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
