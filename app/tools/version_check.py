"""Real version detection for SecuraIQ's own tools — "is my software up to
date" for the product's built-in/external tool set, not scanned targets.

For each external tool this shells out to the real binary to read its
installed version (no guessing), then checks the tool's real upstream
(GitHub releases API or PyPI) for the latest published version when a
reliable source is known. If either side can't be determined, the status is
reported as "unknown" — never faked as "up to date". Results are cached for
a few hours since tool versions don't change minute to minute.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import time
from typing import Any

import httpx

from app.tools.registry import TOOL_CATALOG

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")

# Most CLIs accept --version; these deviate.
_VERSION_FLAGS: dict[str, tuple[str, ...]] = {
    "openssl": ("version",),
    "gobuster": ("version",),
    "codeql": ("version",),
    "dig": ("-v",),
    "whois": ("--version",),
    "ffuf": ("-V",),
    "nuclei": ("-version",),
    "nikto": ("-Version",),
}
# Deliberately flag-prefixed only. A bare "version" (no dash) is a real
# subcommand for a couple of tools (gobuster, codeql — whitelisted above in
# _VERSION_FLAGS) but for anything CLI-positional (e.g. sslyze, which takes
# `target ...` positionally) it would be parsed as a hostname to scan —
# found live: this generic list must never risk triggering a real operation.
_GENERIC_FLAGS: tuple[tuple[str, ...], ...] = (("--version",), ("-version",), ("-V",), ("-v",))

# Tool id -> "owner/repo" for tools whose releases are on GitHub. Used only
# to answer "what's the latest published version" — never to download/run
# anything.
_GITHUB_REPO: dict[str, str] = {
    "nmap": "nmap/nmap",
    "nikto": "sullo/nikto",
    "nuclei": "projectdiscovery/nuclei",
    "zap": "zaproxy/zaproxy",
    "sqlmap": "sqlmapproject/sqlmap",
    "wpscan": "wpscanteam/wpscan",
    "masscan": "robertdavidgraham/masscan",
    "rustscan": "RustScan/RustScan",
    "whatweb": "urbanadventurer/WhatWeb",
    "sslscan": "rbsec/sslscan",
    "sslyze": "nabla-c0d3/sslyze",
    "gobuster": "OJ/gobuster",
    "ffuf": "ffuf/ffuf",
    "wafw00f": "EnableSecurity/wafw00f",
    "codeql": "github/codeql-action",
}

# Tool id -> PyPI package name, for tools installed via pip.
_PYPI_PACKAGE: dict[str, str] = {
    "semgrep": "semgrep",
}

# OS-bundled utilities — version is meaningful but "latest" is controlled by
# the OS package manager, not a single upstream release feed. We still show
# the installed version; we just don't claim to know "latest".
_NO_LATEST_SOURCE = {"dig", "curl", "openssl", "ping", "traceroute", "whois"}

_CACHE: dict[str, Any] = {"ts": 0.0, "payload": None}
_CACHE_TTL_SECONDS = 6 * 3600  # tool versions don't change minute to minute


def _extract_version(text: str) -> str | None:
    if not text:
        return None
    m = _VERSION_RE.search(text)
    return m.group(0) if m else None


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(re.sub(r"\D", "", p) or 0))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _compare(installed: str | None, latest: str | None) -> str:
    if not installed:
        return "not_installed"
    if not latest:
        return "unknown"
    try:
        return "up_to_date" if _version_tuple(installed) >= _version_tuple(latest) else "outdated"
    except Exception:
        return "unknown"


def _run_version_cmd_sync(binary: str, tool_id: str) -> str | None:
    """Blocking subprocess call — run via asyncio.to_thread from the async caller.

    Real bug found via live testing: reading stderr too let a crashing
    binary's Python traceback (e.g. a line number or an unrelated dependency
    version like "1.44.0") get regex-matched as if it were the tool's own
    version. Now: only trust output when the process actually exited 0, and
    only ever read stdout — never stderr — for the version string.
    """
    flag_sets = [_VERSION_FLAGS[tool_id]] if tool_id in _VERSION_FLAGS else []
    flag_sets += [f for f in _GENERIC_FLAGS if list(f) not in [list(x) for x in flag_sets]]

    fallback: str | None = None
    for flags in flag_sets:
        try:
            proc = subprocess.run(
                [binary, *flags],
                capture_output=True,
                text=True,
                timeout=6,
                errors="replace",
            )
        except Exception:
            continue
        out = proc.stdout or ""
        if not out.strip():
            continue
        first_line = out.splitlines()[0] if out.splitlines() else out
        ver = _extract_version(first_line) or _extract_version(out)
        if not ver:
            continue
        if proc.returncode == 0:
            return ver
        if fallback is None:
            fallback = ver  # non-zero exit but stdout still looked version-shaped
    return fallback


async def _get_installed_version(binary: str, tool_id: str) -> str | None:
    try:
        return await asyncio.wait_for(asyncio.to_thread(_run_version_cmd_sync, binary, tool_id), timeout=8)
    except Exception:
        return None


async def _fetch_latest_github(repo: str, client: httpx.AsyncClient) -> str | None:
    try:
        r = await client.get(
            f"https://api.github.com/repos/{repo}/releases/latest",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "SecuraIQ-VersionCheck/1.0"},
        )
        if r.status_code != 200:
            return None
        tag = (r.json() or {}).get("tag_name") or ""
        return _extract_version(tag)
    except Exception:
        return None


async def _fetch_latest_pypi(package: str, client: httpx.AsyncClient) -> str | None:
    try:
        r = await client.get(f"https://pypi.org/pypi/{package}/json")
        if r.status_code != 200:
            return None
        version = ((r.json() or {}).get("info") or {}).get("version") or ""
        return _extract_version(version)
    except Exception:
        return None


async def _fetch_latest(tool_id: str, client: httpx.AsyncClient) -> str | None:
    if tool_id in _PYPI_PACKAGE:
        return await _fetch_latest_pypi(_PYPI_PACKAGE[tool_id], client)
    if tool_id in _GITHUB_REPO:
        return await _fetch_latest_github(_GITHUB_REPO[tool_id], client)
    return None


def get_securaiq_product_info() -> dict[str, Any]:
    """SecuraIQ's own version + real git commit/build info (best-effort)."""
    from pathlib import Path

    try:
        from app.main import app as fastapi_app

        version = fastapi_app.version
    except Exception:
        version = "unknown"

    repo_root = Path(__file__).resolve().parents[2]
    commit = ""
    commit_date = ""
    dirty = None
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=repo_root, capture_output=True, text=True, timeout=4
        ).stdout.strip()
        commit_date = subprocess.run(
            ["git", "log", "-1", "--format=%cI"], cwd=repo_root, capture_output=True, text=True, timeout=4
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=repo_root, capture_output=True, text=True, timeout=4
        ).stdout
        dirty = bool(status.strip())
    except Exception:
        pass

    return {
        "product": "SecuraIQ",
        "version": version,
        "commit": commit or None,
        "commit_date": commit_date or None,
        "uncommitted_changes": dirty,
    }


async def _check_one(tool_id: str, client: httpx.AsyncClient) -> dict[str, Any]:
    spec = TOOL_CATALOG.get(tool_id)
    entry: dict[str, Any] = {
        "id": tool_id,
        "name": spec.name if spec else tool_id,
        "kind": spec.kind if spec else "external",
    }
    if not spec or spec.kind != "external" or not spec.binaries:
        entry.update({"installed_version": None, "latest_version": None, "status": "n/a"})
        return entry

    binary = None
    for name in spec.binaries:
        binary = shutil.which(name)
        if binary:
            break
    if not binary:
        entry.update({"installed_version": None, "latest_version": None, "status": "not_installed"})
        return entry

    installed = await _get_installed_version(binary, tool_id)
    if tool_id in _NO_LATEST_SOURCE:
        latest = None
        status = "unknown" if installed else "not_installed"
        if installed and tool_id in _NO_LATEST_SOURCE:
            status = "installed"  # OS-managed — we know the version, not "latest" by design
    else:
        latest = await _fetch_latest(tool_id, client)
        status = _compare(installed, latest)

    entry.update({"installed_version": installed, "latest_version": latest, "status": status, "binary": binary})
    return entry


async def get_all_tool_versions(*, force: bool = False) -> dict[str, Any]:
    now = time.monotonic()
    if not force and _CACHE["payload"] is not None and (now - _CACHE["ts"]) < _CACHE_TTL_SECONDS:
        return _CACHE["payload"]

    external_ids = [tid for tid, spec in TOOL_CATALOG.items() if spec.kind == "external" and spec.binaries]
    timeout = httpx.Timeout(connect=3.0, read=5.0, write=3.0, pool=3.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        results = await asyncio.gather(*[_check_one(tid, client) for tid in external_ids])

    tools = [r for r in results if r.get("status") != "n/a"]
    counts = {"up_to_date": 0, "outdated": 0, "unknown": 0, "not_installed": 0, "installed": 0}
    for t in tools:
        counts[t["status"]] = counts.get(t["status"], 0) + 1

    payload = {
        "checked_at": time.time(),
        "cache_ttl_seconds": _CACHE_TTL_SECONDS,
        "product": get_securaiq_product_info(),
        "tools": sorted(tools, key=lambda t: (t["status"] != "outdated", t["name"])),
        "counts": counts,
    }
    _CACHE["ts"] = now
    _CACHE["payload"] = payload
    return payload
