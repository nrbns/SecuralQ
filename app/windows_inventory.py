"""Windows Control Panel registry software + Windows Update (local host).

Control Panel / Apps & Features = Uninstall registry hives (not Win32_Product).
Pending updates = Windows Update COM searcher; installed KBs = Get-HotFix.
Authorized local inventory for the SecuraIQ host only.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import time
from typing import Any

_PROBE_TIMEOUT = 60
_UPDATE_TIMEOUT = 25  # COM Update searcher can hang; keep dashboard responsive
_MAX_PROGRAMS = 800
_CACHE: dict[str, Any] = {"ts": 0.0, "payload": None}
_UPDATE_CACHE: dict[str, Any] = {"ts": 0.0, "payload": None}
_CACHE_TTL = 300.0

# Same hive paths Control Panel "Programs and Features" / Settings > Apps uses.
_PS_CONTROL_PANEL = r"""
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'SilentlyContinue'
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = Get-ItemProperty $paths |
  Where-Object {
    $_.DisplayName -and
    -not $_.SystemComponent -and
    -not $_.ParentKeyName -and
    ($_.DisplayName -notmatch '^(KB\d+|Update for |Security Update for )')
  } |
  Select-Object -First 800 @{n='name';e={$_.DisplayName.Trim()}},
    @{n='version';e={$_.DisplayVersion}},
    @{n='publisher';e={$_.Publisher}},
    @{n='install_date';e={$_.InstallDate}}
if (-not $apps) { '[]'; exit 0 }
$apps | ConvertTo-Json -Compress
"""

# Pending Windows Updates (titles) + recent installed hotfixes for dashboard.
_PS_WINDOWS_UPDATES = r"""
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'SilentlyContinue'
$pending = @()
$lastPatch = ''
try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $searcher = $s.CreateUpdateSearcher()
  $r = $searcher.Search("IsInstalled=0 and Type='Software'")
  foreach ($u in @($r.Updates) | Select-Object -First 40) {
    $kb = ''
    try { if ($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0) { $kb = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ',' } } catch {}
    $pending += [pscustomobject]@{
      title = [string]$u.Title
      kb = $kb
      severity = [string]$u.MsrcSeverity
    }
  }
} catch {}
$hotfixes = @()
try {
  $hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 12
  foreach ($h in @($hf)) {
    $when = ''
    try { if ($h.InstalledOn) { $when = $h.InstalledOn.ToString('yyyy-MM-dd') } } catch {}
    if (-not $lastPatch -and $when) { $lastPatch = $when }
    $hotfixes += [pscustomobject]@{
      id = [string]$h.HotFixID
      name = [string]($h.Description)
      installed = $when
    }
  }
} catch {}
[pscustomobject]@{
  pending_count = $pending.Count
  pending = $pending
  hotfixes = $hotfixes
  last_patch = $lastPatch
} | ConvertTo-Json -Compress -Depth 4
"""


def _under_pytest() -> bool:
    return bool(os.environ.get("PYTEST_CURRENT_TEST")) and not os.environ.get("SECURAIQ_LIVE_CONTROL_PANEL")


def _parse_json_blob(raw: str) -> Any:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[")
        start_obj = text.find("{")
        if start_obj >= 0 and (start < 0 or start_obj < start):
            start = start_obj
        if start < 0:
            return None
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            return None


def parse_control_panel_json(raw: str) -> list[dict[str, str]]:
    data = _parse_json_blob(raw)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or row.get("DisplayName") or "").strip()
        if not name:
            continue
        version = str(row.get("version") or row.get("DisplayVersion") or "").strip()
        key = f"{name.lower()}|{version.lower()}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "name": name[:200],
                "version": version[:80],
                "publisher": str(row.get("publisher") or row.get("Publisher") or "").strip()[:120],
                "install_date": str(row.get("install_date") or row.get("InstallDate") or "").strip()[:32],
            }
        )
        if len(out) >= _MAX_PROGRAMS:
            break
    return out


def parse_windows_updates_json(raw: str) -> dict[str, Any]:
    data = _parse_json_blob(raw)
    if not isinstance(data, dict):
        data = {}
    pending_rows: list[dict[str, str]] = []
    for row in data.get("pending") or []:
        if not isinstance(row, dict):
            continue
        title = str(row.get("title") or "").strip()
        if not title:
            continue
        pending_rows.append(
            {
                "title": title[:240],
                "kb": str(row.get("kb") or "").strip()[:80],
                "severity": str(row.get("severity") or "").strip()[:40],
            }
        )
    hotfixes: list[dict[str, str]] = []
    for row in data.get("hotfixes") or []:
        if not isinstance(row, dict):
            continue
        hid = str(row.get("id") or "").strip()
        if not hid:
            continue
        hotfixes.append(
            {
                "id": hid[:40],
                "name": str(row.get("name") or hid).strip()[:200],
                "installed": str(row.get("installed") or "").strip()[:32],
            }
        )
    pending_count = int(data.get("pending_count") or len(pending_rows) or 0)
    if pending_rows and pending_count < len(pending_rows):
        pending_count = len(pending_rows)
    return {
        "pending_count": pending_count,
        "pending": pending_rows[:40],
        "hotfixes": hotfixes[:12],
        "last_patch": str(data.get("last_patch") or "").strip()[:64],
    }


def _run_powershell(script: str, *, timeout: int = _PROBE_TIMEOUT) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
        stdout = (p.stdout or b"").decode("utf-8", errors="replace").strip()
        stderr = (p.stderr or b"").decode("utf-8", errors="replace").strip()
        return p.returncode, stdout, stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return 1, "", str(exc)


def _host_label() -> str:
    return socket.gethostname() or "SecuraIQ host"


def probe_windows_control_panel(*, force: bool = False) -> dict[str, Any]:
    """List installed programs as shown in Control Panel / Apps & Features."""
    now = time.time()
    if not force and _CACHE["payload"] is not None and (now - float(_CACHE["ts"] or 0)) < _CACHE_TTL:
        return _CACHE["payload"]
    system = (platform.system() or "").lower()
    empty: dict[str, Any] = {
        "platform": system or "unknown",
        "host": _host_label(),
        "manager": "control-panel",
        "programs": [],
        "count": 0,
        "detail": "",
    }
    if system != "windows":
        empty["detail"] = "Control Panel inventory is Windows-only"
        _CACHE["payload"] = empty
        _CACHE["ts"] = now
        return empty
    if _under_pytest():
        empty["detail"] = "skipped under pytest"
        return empty
    code, stdout, stderr = _run_powershell(_PS_CONTROL_PANEL)
    programs = parse_control_panel_json(stdout)
    empty["programs"] = programs
    empty["count"] = len(programs)
    if code != 0 and not programs:
        empty["detail"] = (stderr or "PowerShell Control Panel query failed")[:300]
    elif not programs:
        empty["detail"] = "No Control Panel programs returned"
    _CACHE["payload"] = empty
    _CACHE["ts"] = now
    return empty


def probe_windows_updates(*, force: bool = False) -> dict[str, Any]:
    """Pending Windows Updates (with titles) + recent installed hotfixes."""
    now = time.time()
    if not force and _UPDATE_CACHE["payload"] is not None and (now - float(_UPDATE_CACHE["ts"] or 0)) < _CACHE_TTL:
        return _UPDATE_CACHE["payload"]
    system = (platform.system() or "").lower()
    out: dict[str, Any] = {
        "platform": system or "unknown",
        "host": _host_label(),
        "manager": "windows-update",
        "pending_count": 0,
        "pending": [],
        "packages": [],
        "hotfixes": [],
        "last_patch": "",
        "detail": "",
        "via": "local",
    }
    if system != "windows":
        out["detail"] = "Windows Update probe is Windows-only"
        _UPDATE_CACHE["payload"] = out
        _UPDATE_CACHE["ts"] = now
        return out
    if _under_pytest():
        out["detail"] = "skipped under pytest"
        return out
    code, stdout, stderr = _run_powershell(_PS_WINDOWS_UPDATES, timeout=_UPDATE_TIMEOUT)
    parsed = parse_windows_updates_json(stdout)
    out["pending_count"] = int(parsed.get("pending_count") or 0)
    out["pending"] = list(parsed.get("pending") or [])
    out["hotfixes"] = list(parsed.get("hotfixes") or [])
    out["last_patch"] = str(parsed.get("last_patch") or "")
    # Compatible shape for os_patches._ingest_os_probe — pending titles as packages when gaps exist
    if out["pending_count"] > 0:
        out["packages"] = [
            {
                "id": (p.get("kb") or p.get("title") or "update")[:80],
                "name": (p.get("title") or "Windows Update")[:200],
                "version": (p.get("kb") or "pending")[:80],
                "severity": p.get("severity") or "",
            }
            for p in out["pending"]
        ]
    else:
        out["packages"] = [
            {"id": h.get("id") or "", "name": h.get("name") or h.get("id") or "", "installed": h.get("installed") or ""}
            for h in out["hotfixes"]
        ]
    if code != 0 and out["pending_count"] == 0 and not out["hotfixes"]:
        out["detail"] = (stderr or "Windows Update probe failed")[:300]
    _UPDATE_CACHE["payload"] = out
    _UPDATE_CACHE["ts"] = now
    return out


def ingest_local_control_panel_software(user_id: str, *, force: bool = False) -> dict[str, Any]:
    """Write Control Panel installed software into asset_software for this host."""
    from app.software_inventory import upsert_software_row

    probe = probe_windows_control_panel(force=force)
    host = str(probe.get("host") or "SecuraIQ host")
    n = 0
    for app in probe.get("programs") or []:
        name = str(app.get("name") or "").strip()
        if not name:
            continue
        when = str(app.get("install_date") or "").strip()
        publisher = str(app.get("publisher") or "").strip()
        detail_bits = [p for p in ("Control Panel", publisher, f"installed {when}" if when else "") if p]
        upsert_software_row(
            user_id,
            asset_name=host,
            product=name,
            version=str(app.get("version") or ""),
            vendor=publisher,
            source="control_panel:uninstall",
            status="installed",
            detail=" · ".join(detail_bits)[:500],
        )
        n += 1
    return {"ingested": n, "total": int(probe.get("count") or n), "probe": probe}


def ingest_local_windows_updates(user_id: str, *, force: bool = False) -> dict[str, Any]:
    """Write pending Windows Updates + recent hotfixes into asset_software."""
    from app.software_inventory import upsert_software_row

    probe = probe_windows_updates(force=force)
    host = str(probe.get("host") or "SecuraIQ host")
    n = 0
    pending = int(probe.get("pending_count") or 0)
    if pending > 0:
        upsert_software_row(
            user_id,
            asset_name=host,
            product="Windows Update",
            version=f"{pending} pending",
            source="os:windows-update",
            status="missing_patch",
            severity="high" if pending > 5 else "medium",
            detail=f"{pending} pending Windows Update(s) on {host}",
        )
        n += 1
        for p in (probe.get("pending") or [])[:25]:
            title = str(p.get("title") or "").strip()
            if not title:
                continue
            kb = str(p.get("kb") or "").strip()
            sev = str(p.get("severity") or "").lower()
            severity = "critical" if sev == "critical" else "high" if sev == "important" else "medium"
            upsert_software_row(
                user_id,
                asset_name=host,
                product=title[:200],
                version=kb or "pending",
                source="os:windows-update",
                status="missing_patch",
                severity=severity,
                detail=f"Pending Windows Update · {kb or 'no KB'}"[:500],
            )
            n += 1
    else:
        upsert_software_row(
            user_id,
            asset_name=host,
            product="Windows Update",
            version=str(probe.get("last_patch") or "current"),
            source="os:windows-update",
            status="up_to_date",
            detail="No pending Windows Updates detected",
        )
        n += 1
    for h in (probe.get("hotfixes") or [])[:8]:
        hid = str(h.get("id") or "").strip()
        if not hid:
            continue
        upsert_software_row(
            user_id,
            asset_name=host,
            product=str(h.get("name") or hid)[:200],
            version=hid,
            source="os:windows-hotfix",
            status="up_to_date",
            detail=f"Installed hotfix {hid}" + (f" · {h.get('installed')}" if h.get("installed") else ""),
        )
        n += 1
    return {"ingested": n, "pending": pending, "probe": probe}


def windows_host_snapshot(user_id: str | None = None) -> dict[str, Any]:
    """Dashboard snapshot from in-process cache; falls back to DB counts after restart."""
    system = (platform.system() or "").lower()
    cp = _CACHE.get("payload") if isinstance(_CACHE.get("payload"), dict) else {}
    up = _UPDATE_CACHE.get("payload") if isinstance(_UPDATE_CACHE.get("payload"), dict) else {}
    programs = list((cp or {}).get("programs") or [])
    pending = list((up or {}).get("pending") or [])
    installed = int((cp or {}).get("count") or len(programs))
    pending_n = int((up or {}).get("pending_count") or len(pending))
    host = (cp or up or {}).get("host") or _host_label()
    last_patch = str((up or {}).get("last_patch") or "")
    detail = (cp or {}).get("detail") or (up or {}).get("detail") or ""

    # After server restart the PowerShell cache is empty even when inventory is in DB.
    if user_id and system == "windows" and installed == 0:
        try:
            from app.db import get_conn

            c = get_conn()
            row = c.execute(
                "SELECT COUNT(*) AS n FROM asset_software WHERE user_id=? AND source LIKE 'control_panel%'",
                (user_id,),
            ).fetchone()
            installed = int(row["n"] if row and hasattr(row, "keys") else (row[0] if row else 0))
            if not pending_n:
                prow = c.execute(
                    """
                    SELECT COUNT(*) AS n FROM asset_software
                    WHERE user_id=? AND source LIKE 'os:windows-update%' AND status='missing_patch'
                      AND product != 'Windows Update'
                    """,
                    (user_id,),
                ).fetchone()
                pending_n = int(prow["n"] if prow and hasattr(prow, "keys") else (prow[0] if prow else 0))
            if not programs and installed:
                preview = c.execute(
                    """
                    SELECT product AS name, version, vendor AS publisher, '' AS install_date
                    FROM asset_software
                    WHERE user_id=? AND source LIKE 'control_panel%'
                    ORDER BY updated_at DESC LIMIT 8
                    """,
                    (user_id,),
                ).fetchall()
                programs = [dict(r) for r in preview]
            if not host or host == _host_label():
                hrow = c.execute(
                    """
                    SELECT asset_name FROM asset_software
                    WHERE user_id=? AND source LIKE 'control_panel%' AND asset_name != ''
                    LIMIT 1
                    """,
                    (user_id,),
                ).fetchone()
                if hrow:
                    host = str(hrow["asset_name"] if hasattr(hrow, "keys") else hrow[0] or host)
        except Exception:
            pass

    return {
        "platform": system or "unknown",
        "host": host,
        "installed_apps": installed,
        "pending_updates": pending_n,
        "last_patch": last_patch,
        "programs_preview": programs[:8],
        "pending_preview": pending[:8],
        "detail": detail,
        "needs_refresh": system == "windows" and installed == 0 and not detail,
    }


def refresh_local_windows_host(user_id: str, *, force: bool = False) -> dict[str, Any]:
    """Ingest Control Panel first (fast), then Windows Updates (COM — may be slow)."""
    from app.software_inventory import publish_software_realtime

    cp = ingest_local_control_panel_software(user_id, force=force)
    snap_cp = windows_host_snapshot(user_id)
    try:
        publish_software_realtime(
            user_id,
            {
                "control_panel": int(cp.get("ingested") or 0),
                "installed_apps": snap_cp.get("installed_apps"),
                "pending_updates": snap_cp.get("pending_updates"),
            },
            action="sync",
            message=f"Control Panel · {snap_cp.get('installed_apps') or 0} apps on this PC",
        )
    except Exception:
        pass

    upd: dict[str, Any] = {"ingested": 0, "pending": 0, "probe": {}}
    try:
        upd = ingest_local_windows_updates(user_id, force=force)
    except Exception as exc:
        upd = {"ingested": 0, "pending": 0, "probe": {"detail": str(exc)[:200]}}

    snap = windows_host_snapshot(user_id)
    try:
        publish_software_realtime(
            user_id,
            {
                "control_panel": int(cp.get("ingested") or 0),
                "windows_updates": int(upd.get("ingested") or 0),
                "installed_apps": snap.get("installed_apps"),
                "pending_updates": snap.get("pending_updates"),
            },
            action="sync",
            message=(
                f"Local Windows · {snap.get('installed_apps') or 0} Control Panel apps"
                + (
                    f" · {snap.get('pending_updates')} update(s) pending"
                    if snap.get("pending_updates")
                    else " · updates current"
                )
            ),
        )
    except Exception:
        pass
    return {
        "control_panel": cp,
        "windows_updates": upd,
        "windows_host": snap,
        "ingested": int(cp.get("ingested") or 0) + int(upd.get("ingested") or 0),
    }


ingest_local_control_panel_software = ingest_local_control_panel_software
probe_windows_control_panel = probe_windows_control_panel
parse_control_panel_json = parse_control_panel_json
