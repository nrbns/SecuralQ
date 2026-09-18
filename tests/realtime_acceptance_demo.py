"""Pytest / CLI entry for the golden realtime acceptance harness.

Preferred invocation (same as CI):

  python scripts/realtime_acceptance_demo.py --local --firewall-only
  pytest tests/test_realtime_acceptance_local.py -q

This module re-exports the script API so docs that say
``tests/realtime_acceptance_demo.py`` resolve to the same harness.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "realtime_acceptance_demo.py"

# Re-export public harness symbols for imports / older docs.
from scripts.realtime_acceptance_demo import (  # noqa: E402
    LOCAL_STEP_NAMES,
    LOCAL_VERIFY_STEP,
    OPTIONAL_ENABLE_FW_STEP,
    AcceptanceReport,
    run_local_chain,
    run_local_host_loop,
)


def main(argv: list[str] | None = None) -> int:
    """Delegate to ``scripts/realtime_acceptance_demo.py`` as __main__."""
    if argv is not None:
        sys.argv = [str(_SCRIPT), *argv]
    runpy.run_path(str(_SCRIPT), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
