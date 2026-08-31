"""Engagement scope + tool policy — deterministic allow/deny before scanners run.

AI must never bypass this. Empty scope_json keeps today's private/authorized_target rules.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def normalize_scope_json(raw: Any) -> list[str]:
    """Accept list, JSON string, or newline/comma-separated notes → list of tokens."""
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        s = raw.strip()
        if not s:
            return []
        if s.startswith("["):
            try:
                parsed = json.loads(s)
                items = parsed if isinstance(parsed, list) else [s]
            except json.JSONDecodeError:
                items = re.split(r"[\n,;]+", s)
        else:
            items = re.split(r"[\n,;]+", s)
    else:
        items = [str(raw)]
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        tok = str(item).strip().lower().rstrip(".")
        if not tok or tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
    return out


# External engine scanners always need structured scope. Builtin discovery/web may
# keep legacy empty-scope auth; vulnerability/full profiles require scope too.
_SCOPE_REQUIRED_SCANNERS = frozenset({"nmap", "nuclei", "zap"})
_SCOPE_REQUIRED_PROFILES = frozenset({"vulnerability", "full"})


def requires_structured_scope(scanner_id: str, profile: str = "discovery") -> bool:
    sid = (scanner_id or "").strip().lower()
    prof = (profile or "discovery").strip().lower()
    if sid in _SCOPE_REQUIRED_SCANNERS:
        return True
    if prof in _SCOPE_REQUIRED_PROFILES:
        return True
    return False


def assert_structured_scope(
    *,
    scanner_id: str,
    profile: str,
    scope: list[str],
) -> tuple[bool, str]:
    """Return (ok, reason). Fail closed when scope is required but empty."""
    if not requires_structured_scope(scanner_id, profile):
        return True, "legacy_empty_scope_ok"
    if scope:
        return True, "structured_scope_present"
    return (
        False,
        "Structured engagement scope required for this scanner/profile "
        "(CIDR, IP, or hostname list). Empty scope is not allowed.",
    )


def scope_to_storage(raw: Any) -> str:
    return json.dumps(normalize_scope_json(raw))


def parse_engagement_scope(engagement: dict[str, Any] | None) -> list[str]:
    if not engagement:
        return []
    return normalize_scope_json(engagement.get("scope_json") or "")


def _url_to_host(value: str) -> str:
    """Extract a bare host from a value that may be a full URL.

    Real bug found live: scope entries and targets containing a full URL
    (scheme://host[:port][/path]) never matched target_in_scope's exact-IP
    or hostname comparisons below, which expect bare hosts. Since the UI
    auto-seeds the Scope field from Target verbatim, and web scans pass a
    URL as the target, every URL-based scan with scope populated was
    silently rejected as "out_of_scope" even when the host genuinely was
    in scope. Mirrors the same scheme/path/port stripping already used in
    app/net_assess.py resolve_and_authorize for the same class of bug.
    """
    v = (value or "").strip()
    if not v:
        return v
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", v)
    if m:
        v = v[m.end():]
    v = v.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    v = v.rsplit("@", 1)[-1]
    if v.startswith("["):
        v = v.split("]")[0].lstrip("[")
    else:
        v = v.split(":")[0]
    return v.strip()


def _host_matches(candidate: str, pattern: str) -> bool:
    c = (candidate or "").strip().lower().rstrip(".")
    p = (pattern or "").strip().lower().rstrip(".")
    if not c or not p:
        return False
    if c == p:
        return True
    # *.example.com style
    if p.startswith("*."):
        suffix = p[1:]  # .example.com
        return c.endswith(suffix) or c == p[2:]
    return False


def target_in_scope(
    *,
    target: str | None,
    ip: str | None,
    scope: list[str],
) -> tuple[bool, str]:
    """Return (allowed, reason). Empty scope → allowed (caller keeps legacy auth)."""
    if not scope:
        return True, "no_structured_scope"

    candidates: list[str] = []
    for v in (target, ip):
        if v and str(v).strip():
            raw = str(v).strip().lower().rstrip(".")
            candidates.append(_url_to_host(raw) or raw)

    if not candidates:
        return False, "no_target_to_check"

    for entry in scope:
        entry = (entry or "").strip()
        if not entry:
            continue
        # A URL's scheme/path also contains "/", which used to be
        # misdetected as CIDR notation below (ipaddress.ip_network() then
        # raised and the entry was silently skipped) — check for an actual
        # URL scheme first so "http://host/path" and "10.0.0.0/24" aren't
        # both routed into the CIDR branch.
        looks_like_url = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", entry))
        if not looks_like_url and "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            for cand in candidates:
                try:
                    if ipaddress.ip_address(cand) in net:
                        return True, f"matched_cidr:{entry}"
                except ValueError:
                    continue
            continue
        entry_host = _url_to_host(entry) or entry
        # Exact IP
        try:
            ipaddress.ip_address(entry_host)
            for cand in candidates:
                try:
                    if ipaddress.ip_address(cand) == ipaddress.ip_address(entry_host):
                        return True, f"matched_ip:{entry_host}"
                except ValueError:
                    if cand == entry_host:
                        return True, f"matched_ip:{entry_host}"
            continue
        except ValueError:
            pass
        # Hostname / wildcard
        for cand in candidates:
            if _host_matches(cand, entry_host):
                return True, f"matched_host:{entry_host}"

    return False, "out_of_scope"


def assert_tool_target_allowed(
    *,
    user_id: str,
    engagement_id: str | None,
    target: str | None,
    ip: str | None,
    authorized: bool,
) -> dict[str, Any]:
    """Policy gate used by the tool runner.

    Returns a small dict for audit: {ok, engagement_id, reason, scope_size}.
    Raises ValueError with a clear message when blocked.
    """
    from app.workspace import get_engagement

    if not engagement_id:
        return {
            "ok": True,
            "engagement_id": None,
            "reason": "no_engagement",
            "scope_size": 0,
            "enforced": False,
        }

    eng = get_engagement(user_id, engagement_id)
    if not eng:
        raise ValueError("Engagement not found or not visible to this user")

    status = (eng.get("status") or "active").lower()
    if status in {"archived", "completed"}:
        raise ValueError(f"Engagement is '{status}' — reopen or choose an active engagement before scanning")

    scope = parse_engagement_scope(eng)
    if not scope:
        # Backward compatible: structured scope not set → legacy authorized/private rules only
        return {
            "ok": True,
            "engagement_id": engagement_id,
            "reason": "empty_scope_legacy_auth",
            "scope_size": 0,
            "enforced": False,
            "engagement_name": eng.get("name"),
        }

    # Path-based SAST targets (local folders) — allow if scope contains the path token
    # or an explicit "*" / "local" marker; otherwise require authorized + path-like target
    t = (target or "").strip()
    if t and ("/" in t or "\\" in t):
        allowed, reason = target_in_scope(target=t, ip=None, scope=scope)
        if allowed:
            return {
                "ok": True,
                "engagement_id": engagement_id,
                "reason": reason,
                "scope_size": len(scope),
                "enforced": True,
            }
        if "local" in scope or "*" in scope or "path" in scope:
            if not authorized:
                raise ValueError("Local path scan requires Auth confirmation for this engagement")
            return {
                "ok": True,
                "engagement_id": engagement_id,
                "reason": "local_path_marker",
                "scope_size": len(scope),
                "enforced": True,
            }
        raise ValueError(
            f"Target path is outside engagement scope. Allowed entries: {', '.join(scope[:12])}"
            + ("…" if len(scope) > 12 else "")
        )

    allowed, reason = target_in_scope(target=target, ip=ip, scope=scope)
    if not allowed:
        raise ValueError(
            f"Target out of engagement scope ({reason}). "
            f"In-scope: {', '.join(scope[:12])}"
            + ("…" if len(scope) > 12 else "")
        )
    if not authorized:
        # Structured scope is consent for those hosts, but still require the Auth checkbox
        # for public/internet-facing scans as an explicit operator acknowledgment.
        pass

    return {
        "ok": True,
        "engagement_id": engagement_id,
        "reason": reason,
        "scope_size": len(scope),
        "enforced": True,
        "engagement_name": eng.get("name"),
    }
