"""SecuraIQ Continuous Posture Engine.

Realtime detection remains event-driven. This package owns the scheduled
**posture refresh** reconciliation cycle (default 30 minutes) — NOT full
Nmap/Nuclei/ZAP scans. Deep scans stay on their own schedules.

Honesty: platform reconciliation + evidence/risk/compliance ticks. Does not
claim multi-AZ HA workers or measured 100K capacity.
"""

from __future__ import annotations

from app.posture.orchestrator import run_posture_refresh
from app.posture.refresh_policy import get_refresh_policy, list_refresh_policies
from app.posture.refresh_run import get_refresh_run, list_refresh_runs
from app.posture.schema import ensure_posture_schema
from app.posture.views import posture_dashboard, posture_health

__all__ = [
    "ensure_posture_schema",
    "run_posture_refresh",
    "get_refresh_run",
    "list_refresh_runs",
    "get_refresh_policy",
    "list_refresh_policies",
    "posture_dashboard",
    "posture_health",
]
