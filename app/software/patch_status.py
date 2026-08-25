"""Patch state calculation — never fabricate latest version."""

from __future__ import annotations

import re

from app.software.models import (
    PATCH_CRITICAL,
    PATCH_EOL,
    PATCH_KEV,
    PATCH_SECURITY_UPDATE,
    PATCH_UNKNOWN,
    PATCH_UPDATE_AVAILABLE,
    PATCH_UP_TO_DATE,
)


def compare_versions(installed: str, other: str) -> int | None:
    """Return -1 if installed < other, 0 if equal, 1 if greater, None if incomparable."""
    a = (installed or "").strip()
    b = (other or "").strip()
    if not a or not b:
        return None

    def parts(v: str) -> list[int]:
        nums: list[int] = []
        for seg in re.split(r"[._\-+]", v):
            if seg.isdigit():
                nums.append(int(seg))
            elif seg:
                break
        return nums

    pa, pb = parts(a), parts(b)
    if not pa or not pb:
        return None
    for i in range(max(len(pa), len(pb))):
        va = pa[i] if i < len(pa) else 0
        vb = pb[i] if i < len(pb) else 0
        if va < vb:
            return -1
        if va > vb:
            return 1
    return 0


def compute_patch_status(
    *,
    installed: str,
    latest: str | None,
    latest_source: str | None,
    raw_status: str = "",
    severity: str = "",
    cve: str = "",
    kev: bool = False,
) -> tuple[str, str, str]:
    """Returns (status, target_version, reason). target_version empty when unknown."""
    st = (raw_status or "").lower()
    sev = (severity or "").lower()

    if kev or (cve and "kev" in (cve or "").lower()):
        return PATCH_KEV, (latest or "").strip(), "Listed in CISA KEV"

    if st == "eol" or cve == "EOL":
        return PATCH_EOL, (latest or "").strip(), "Product or OS is end-of-life"

    if st == "missing_patch":
        if sev == "critical":
            return PATCH_CRITICAL, (latest or "").strip(), "Missing security patch (critical)"
        return PATCH_SECURITY_UPDATE, (latest or "").strip(), "Missing security patch"

    latest_clean = (latest or "").strip()
    if latest_clean and latest_source:
        cmp = compare_versions(installed, latest_clean)
        if cmp is not None:
            if cmp >= 0:
                return PATCH_UP_TO_DATE, latest_clean, f"At or above latest ({latest_source})"
            if sev in {"critical", "high"} or st == "outdated":
                return PATCH_CRITICAL if sev == "critical" else PATCH_SECURITY_UPDATE, latest_clean, (
                    f"Below latest {latest_clean} ({latest_source})"
                )
            return PATCH_UPDATE_AVAILABLE, latest_clean, f"Update available ({latest_source})"

    if st in {"current", "up_to_date", "installed"}:
        return PATCH_UP_TO_DATE, "", "No newer version on record"

    if st == "outdated":
        return PATCH_UPDATE_AVAILABLE, "", "Marked outdated by policy/heuristics"

    return PATCH_UNKNOWN, "", "Latest version not resolved"
