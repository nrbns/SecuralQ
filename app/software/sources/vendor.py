"""Vendor / registry latest-version resolution — never fabricate when unknown."""

from __future__ import annotations

import re
from typing import Any

import httpx

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")

_USER_AGENT = "SecuraIQ-Inventory/1.0"


def _extract_version(text: str) -> str | None:
    if not text:
        return None
    m = _VERSION_RE.search(text)
    return m.group(0) if m else None


def fetch_latest_github(repo: str, *, client: httpx.Client | None = None) -> str | None:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": _USER_AGENT}
    try:
        if client is None:
            with httpx.Client(timeout=8.0, follow_redirects=True) as c:
                resp = c.get(url, headers=headers)
        else:
            resp = client.get(url, headers=headers)
        if resp.status_code != 200:
            return None
        tag = (resp.json() or {}).get("tag_name") or ""
        return _extract_version(tag)
    except Exception:
        return None


def fetch_latest_pypi(package: str, *, client: httpx.Client | None = None) -> str | None:
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        if client is None:
            with httpx.Client(timeout=8.0, follow_redirects=True) as c:
                resp = c.get(url, headers={"User-Agent": _USER_AGENT})
        else:
            resp = client.get(url, headers={"User-Agent": _USER_AGENT})
        if resp.status_code != 200:
            return None
        version = ((resp.json() or {}).get("info") or {}).get("version") or ""
        return _extract_version(version)
    except Exception:
        return None


def fetch_latest_npm(package: str, *, client: httpx.Client | None = None) -> str | None:
    url = f"https://registry.npmjs.org/{package}/latest"
    try:
        if client is None:
            with httpx.Client(timeout=8.0, follow_redirects=True) as c:
                resp = c.get(url, headers={"User-Agent": _USER_AGENT})
        else:
            resp = client.get(url, headers={"User-Agent": _USER_AGENT})
        if resp.status_code != 200:
            return None
        version = (resp.json() or {}).get("version") or ""
        return _extract_version(version)
    except Exception:
        return None


def fetch_latest_endoflife(product: str, *, client: httpx.Client | None = None) -> str | None:
    """Latest stable cycle from endoflife.date (Python, Node.js, browsers, …)."""
    slug = (product or "").strip().lower()
    if not slug:
        return None
    url = f"https://endoflife.date/api/{slug}.json"
    try:
        if client is None:
            with httpx.Client(timeout=8.0, follow_redirects=True) as c:
                resp = c.get(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"})
        else:
            resp = client.get(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"})
        if resp.status_code != 200:
            return None
        rows = resp.json() or []
        if not isinstance(rows, list):
            return None
        # Prefer an active LTS cycle when available (Node/Python), else newest cycle
        preferred: list[dict] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("lts") and row.get("latest"):
                preferred.append(row)
        for row in preferred + [r for r in rows if isinstance(r, dict)]:
            latest = row.get("latest") or row.get("cycle") or ""
            ver = _extract_version(str(latest))
            if ver:
                return ver
        return None
    except Exception:
        return None


def resolve_upstream_latest(upstream: dict[str, str], *, client: httpx.Client | None = None) -> dict[str, Any]:
    """Return {latest, source} or empty latest when unresolved."""
    kind = (upstream.get("source") or "").lower()
    if kind == "github" and upstream.get("repo"):
        ver = fetch_latest_github(upstream["repo"], client=client)
        if ver:
            return {"latest": ver, "source": "github"}
    if kind == "pypi" and upstream.get("package"):
        ver = fetch_latest_pypi(upstream["package"], client=client)
        if ver:
            return {"latest": ver, "source": "pypi"}
    if kind == "npm" and upstream.get("package"):
        ver = fetch_latest_npm(upstream["package"], client=client)
        if ver:
            return {"latest": ver, "source": "npm"}
    if kind == "endoflife" and upstream.get("product"):
        ver = fetch_latest_endoflife(upstream["product"], client=client)
        if ver:
            return {"latest": ver, "source": "endoflife"}
    return {"latest": None, "source": None}
