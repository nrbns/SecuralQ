"""Run DB migrations then start SecuraIQ (SaaS / production entrypoint)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    os.chdir(ROOT)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    url = (os.environ.get("DATABASE_URL") or "").strip()
    if url.startswith("postgres://") or url.startswith("postgresql://"):
        print("Running Alembic migrations…", flush=True)
        rc = subprocess.call([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=str(ROOT))
        if rc != 0:
            print("Alembic failed — refusing to start", flush=True)
            sys.exit(rc)
    else:
        print("No Postgres DATABASE_URL — skipping Alembic (SQLite/lab mode)", flush=True)
    run_py = ROOT / "run.py"
    os.execv(sys.executable, [sys.executable, str(run_py)])


if __name__ == "__main__":
    main()
