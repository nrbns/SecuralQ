"""Framework effective-date helpers (DPDP Rules phased commencement, etc.)."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any


def _parse_day(value: str | None) -> date | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        return date.fromisoformat(raw[:10])
    except ValueError:
        return None


def as_of_date(as_of: str | date | datetime | None = None) -> date:
    if isinstance(as_of, datetime):
        return as_of.date()
    if isinstance(as_of, date):
        return as_of
    if isinstance(as_of, str) and as_of.strip():
        parsed = _parse_day(as_of)
        if parsed:
            return parsed
    return date.today()


def control_is_in_force(control: dict[str, Any], *, as_of: str | date | datetime | None = None) -> bool:
    """True when control has no effective_from, or effective_from <= as_of."""
    eff = _parse_day(str(control.get("effective_from") or ""))
    if eff is None:
        return True
    return eff <= as_of_date(as_of)


def filter_controls_in_force(
    framework: dict[str, Any],
    *,
    as_of: str | date | datetime | None = None,
) -> list[dict[str, Any]]:
    controls = framework.get("controls") or []
    day = as_of_date(as_of)
    return [c for c in controls if isinstance(c, dict) and control_is_in_force(c, as_of=day)]


def framework_commencement_summary(
    framework: dict[str, Any],
    *,
    as_of: str | date | datetime | None = None,
) -> dict[str, Any]:
    day = as_of_date(as_of)
    controls = [c for c in (framework.get("controls") or []) if isinstance(c, dict)]
    in_force = [c for c in controls if control_is_in_force(c, as_of=day)]
    future = [c for c in controls if not control_is_in_force(c, as_of=day)]
    return {
        "framework_id": framework.get("id"),
        "as_of": day.isoformat(),
        "total_controls": len(controls),
        "in_force": len(in_force),
        "not_yet_in_force": len(future),
        "phased_commencement": framework.get("phased_commencement"),
        "legal_disclaimer": framework.get("legal_disclaimer"),
        "future_control_ids": [c.get("id") for c in future[:50]],
    }
