"""Staging deploy readiness + rollback checklist (#245). Exit 0 when green."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str]) -> dict:
    p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    return {"cmd": " ".join(cmd), "code": p.returncode, "ok": p.returncode == 0}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="Skip long acceptance demos")
    args = parser.parse_args()
    checks = [
        _run([sys.executable, "-m", "pytest", "-q", "tests/test_master_checklist_p0.py", "tests/test_master_checklist_phases.py"]),
        _run([sys.executable, "scripts/backup_restore_drill.py"]),
        _run([sys.executable, "scripts/rotate_secrets.py", "--dry-run"]),
    ]
    if not args.quick:
        checks.append(
            _run([sys.executable, "scripts/realtime_acceptance_demo.py", "--local", "--firewall-only"])
        )
    failed = [c for c in checks if not c["ok"]]
    print({"ok": not failed, "checks": checks, "rollback_doc": "docs/staging-rollback.md"})
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
