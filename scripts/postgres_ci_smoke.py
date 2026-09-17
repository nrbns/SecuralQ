"""#252 — real Postgres smoke: connect, migrate marker, audit chain insert/verify."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    url = (os.environ.get("DATABASE_URL") or "").strip()
    if not url.startswith("postgres"):
        print({"ok": False, "error": "DATABASE_URL must be postgresql://..."})
        return 2
    # Force settings before app imports cache
    os.environ["DATABASE_URL"] = url
    from app.config import settings

    object.__setattr__(settings, "database_url", url)
    from app.db import audit, get_conn, init_schema, reset_conn_for_tests

    reset_conn_for_tests()
    init_schema()
    c = get_conn()
    c.execute("SELECT 1").fetchone()
    from app.audit_chain import append_chained, verify_chain

    append_chained("postgres_ci_smoke", "ci", {"ok": True})
    v = verify_chain(limit=100)
    audit("postgres_ci_smoke_done", "ci", {"verify": v.get("ok")})
    print({"ok": True, "backend": "postgresql", "verify": v})
    return 0 if v.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
