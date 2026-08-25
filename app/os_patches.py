"""Local and remote OS patch / package-manager status."""

from __future__ import annotations

import platform
import re
import subprocess
from typing import Any

from app.asset_names import asset_meta_from_record, is_ipv4

_PROBE_TIMEOUT = 45
_SERVER_CATEGORIES = frozenset({"server", "computer", "endpoint", "database", "web"})


def _run(cmd: list[str], *, timeout: int = _PROBE_TIMEOUT) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return 1, "", str(exc)


def _parse_apt_upgradable(stdout: str) -> list[dict[str, str]]:
    pkgs: list[dict[str, str]] = []
    for ln in (stdout or "").splitlines():
        if not ln or ln.startswith("Listing"):
            continue
        m = re.match(r"([^/\s]+)/\S+\s+(\S+)\s+(\S+)", ln)
        if m:
            pkgs.append({"id": m.group(1), "name": m.group(1), "version": m.group(2), "target": m.group(3)})
    return pkgs


def _parse_dnf_upgradable(stdout: str) -> list[dict[str, str]]:
    pkgs: list[dict[str, str]] = []
    for ln in (stdout or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("Last metadata"):
            continue
        parts = ln.split()
        if len(parts) >= 2:
            pkgs.append({"id": parts[0], "name": parts[0], "version": parts[1]})
    return pkgs


def _probe_from_apt_stdout(stdout: str) -> dict[str, Any]:
    pkgs = _parse_apt_upgradable(stdout)
    return {
        "platform": "linux",
        "pending_count": len(pkgs),
        "packages": pkgs[:80],
        "manager": "apt",
        "detail": "",
    }


def _probe_from_dnf_stdout(stdout: str, code: int) -> dict[str, Any]:
    pkgs = _parse_dnf_upgradable(stdout)
    return {
        "platform": "linux",
        "pending_count": len(pkgs),
        "packages": pkgs[:80],
        "manager": "dnf",
        "detail": "" if code in (0, 100) else f"dnf exit {code}",
    }


def probe_windows_patches() -> dict[str, Any]:
    """Recent hotfixes + pending Windows Update count (local host only)."""
    out: dict[str, Any] = {
        "platform": "windows",
        "pending_count": 0,
        "packages": [],
        "last_patch": "",
        "detail": "",
        "manager": "windows-update",
    }
    ps_pending = (
        "$s=New-Object -ComObject Microsoft.Update.Session;"
        "$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Software'\");"
        "$r.Updates.Count"
    )
    code, stdout, stderr = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_pending])
    if code == 0 and stdout.isdigit():
        out["pending_count"] = int(stdout)
    elif stderr:
        out["detail"] = stderr[:300]

    ps_hotfix = (
        "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 8 | "
        "ForEach-Object { \"$($_.HotFixID)|$($_.Description)|$($_.InstalledOn)\" }"
    )
    code2, stdout2, _ = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_hotfix])
    if code2 == 0 and stdout2:
        for line in stdout2.splitlines():
            parts = line.split("|", 2)
            if len(parts) >= 2:
                kb, desc = parts[0].strip(), parts[1].strip()
                when = parts[2].strip() if len(parts) > 2 else ""
                if not out["last_patch"] and when:
                    out["last_patch"] = when
                out["packages"].append({"id": kb, "name": desc or kb, "installed": when})
    return out


def probe_linux_patches() -> dict[str, Any]:
    """apt/dnf upgradable packages on local Linux host."""
    code, stdout, _ = _run(["apt", "list", "--upgradable"], timeout=60)
    if code == 0 and stdout:
        return _probe_from_apt_stdout(stdout)

    code, stdout, _ = _run(["dnf", "check-update", "-q"], timeout=90)
    if code in (0, 100) and stdout:
        return _probe_from_dnf_stdout(stdout, code)

    return {
        "platform": "linux",
        "pending_count": 0,
        "packages": [],
        "manager": "",
        "detail": "No supported package manager (apt/dnf) found on PATH",
    }


def probe_local_os_patches() -> dict[str, Any]:
    system = (platform.system() or "").lower()
    if system == "windows":
        return probe_windows_patches()
    if system == "linux":
        return probe_linux_patches()
    return {"platform": system or "unknown", "pending_count": 0, "packages": [], "detail": "Unsupported OS"}


def probe_remote_via_ssh(
    host: str,
    *,
    user: str = "root",
    key_path: str = "",
    port: int = 22,
) -> dict[str, Any]:
    """Probe patch status on a remote host over SSH (key-based, BatchMode)."""
    host = (host or "").strip()
    if not host or not is_ipv4(host):
        return {"platform": "unknown", "pending_count": 0, "packages": [], "detail": "invalid host", "host": host}

    ssh: list[str] = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=12",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-p",
        str(int(port) or 22),
    ]
    if key_path:
        ssh.extend(["-i", key_path])
    target = f"{user}@{host}"

    # Linux apt
    code, stdout, stderr = _run(ssh + [target, "apt list --upgradable 2>/dev/null | tail -n +2"], timeout=75)
    if code == 0 and stdout:
        out = _probe_from_apt_stdout("Listing...\n" + stdout)
        out["host"] = host
        out["via"] = "ssh"
        return out

    # Linux dnf
    code, stdout, stderr = _run(ssh + [target, "dnf check-update -q 2>/dev/null"], timeout=90)
    if code in (0, 100) and stdout:
        out = _probe_from_dnf_stdout(stdout, code)
        out["host"] = host
        out["via"] = "ssh"
        return out

    # Windows OpenSSH + PowerShell
    ps_pending = (
        "powershell -NoProfile -NonInteractive -Command "
        "\"try { (New-Object -ComObject Microsoft.Update.Session)"
        ".CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count } catch { -1 }\""
    )
    code, stdout, stderr = _run(ssh + [target, ps_pending], timeout=90)
    if code == 0 and stdout.lstrip("-").isdigit() and int(stdout) >= 0:
        pending = int(stdout)
        out: dict[str, Any] = {
            "platform": "windows",
            "pending_count": pending,
            "packages": [],
            "manager": "windows-update",
            "host": host,
            "via": "ssh",
            "detail": "",
        }
        _, hf_out, _ = _run(
            ssh
            + [
                target,
                "powershell -NoProfile -Command \"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3 | ForEach-Object { $_.HotFixID }\"",
            ],
            timeout=60,
        )
        if hf_out:
            out["last_patch"] = hf_out.splitlines()[0].strip()
            out["packages"] = [{"id": ln.strip(), "name": ln.strip()} for ln in hf_out.splitlines() if ln.strip()]
        return out

    return {
        "platform": "unknown",
        "pending_count": 0,
        "packages": [],
        "host": host,
        "via": "ssh",
        "detail": (stderr or "SSH probe failed — check key, user, and port 22")[:300],
    }


def _ingest_os_probe(
    user_id: str,
    probe: dict[str, Any],
    *,
    asset_id: str = "",
    asset_name: str = "",
    source_prefix: str = "os",
) -> int:
    from app.software_inventory import upsert_software_row

    n = 0
    plat = probe.get("platform") or "os"
    pending = int(probe.get("pending_count") or 0)
    mgr = probe.get("manager") or ("windows-update" if plat == "windows" else plat)
    via = probe.get("via") or "local"
    src_root = f"{source_prefix}:{mgr}" if via == "local" else f"{source_prefix}:ssh-{mgr or 'probe'}"
    host_label = asset_name or probe.get("host") or ("SecuraIQ host" if via == "local" else probe.get("host") or "")

    if pending > 0:
        upsert_software_row(
            user_id,
            asset_id=asset_id,
            asset_name=host_label,
            product=f"OS updates ({mgr or 'system'})",
            version=f"{pending} pending",
            source=src_root,
            status="missing_patch",
            severity="high" if pending > 5 else "medium",
            detail=f"{pending} pending update(s) via {via} on {host_label or 'host'}",
        )
        n += 1
    elif probe.get("packages") or probe.get("last_patch"):
        upsert_software_row(
            user_id,
            asset_id=asset_id,
            asset_name=host_label,
            product=f"OS patch level ({mgr or 'system'})",
            version=str(probe.get("last_patch") or "current"),
            source=src_root,
            status="up_to_date",
            detail=f"No pending OS updates detected via {via}",
        )
        n += 1

    for pkg in (probe.get("packages") or [])[:20]:
        if pending <= 0:
            break
        name = str(pkg.get("name") or pkg.get("id") or "package")
        ver = str(pkg.get("version") or pkg.get("target") or pkg.get("installed") or "")
        upsert_software_row(
            user_id,
            asset_id=asset_id,
            asset_name=host_label,
            product=name[:200],
            version=ver[:80],
            source=src_root,
            status="missing_patch",
            severity="medium",
            detail=f"Pending OS update via {via}",
        )
        n += 1
    return n


def ingest_local_os_patches(user_id: str) -> dict[str, Any]:
    probe = probe_local_os_patches()
    n = _ingest_os_probe(user_id, probe, asset_name="SecuraIQ host", source_prefix="os")
    return {"ingested": n, "probe": probe}


def ingest_remote_os_patches(user_id: str) -> dict[str, Any]:
    """SSH patch probes for inventoried servers (key-based; opt-in via settings)."""
    from app.asset_categories import asset_category_id
    from app.asset_names import parse_notes_meta
    from app.config import settings
    from app.enterprise import list_assets

    if not getattr(settings, "ssh_patch_enabled", False):
        return {"ingested": 0, "probed": 0, "skipped": "SSH patch probes disabled"}

    default_user = (getattr(settings, "ssh_patch_user", "") or "root").strip()
    key_path = (getattr(settings, "ssh_patch_key_path", "") or "").strip()
    max_hosts = max(1, min(int(getattr(settings, "ssh_patch_max_hosts", 15) or 15), 50))

    total_ingested = 0
    probed = 0
    results: list[dict[str, Any]] = []

    for asset in list_assets(user_id):
        if probed >= max_hosts:
            break
        cat = asset_category_id(asset)
        if cat not in _SERVER_CATEGORIES:
            continue
        meta_notes = parse_notes_meta(str(asset.get("notes") or ""))
        if meta_notes.get("ssh_disabled"):
            continue
        bits = asset_meta_from_record(asset)
        ip = bits.get("ip") or ""
        if not ip or not is_ipv4(ip):
            continue
        user = str(meta_notes.get("ssh_user") or default_user or "root").strip()
        port = int(meta_notes.get("ssh_port") or 22)
        asset_key = str(meta_notes.get("ssh_key") or key_path or "").strip()
        name = str(asset.get("display_name") or bits.get("name") or ip)
        aid = str(asset.get("id") or "")

        probe = probe_remote_via_ssh(ip, user=user, key_path=asset_key, port=port)
        probed += 1
        if probe.get("detail") and not probe.get("packages") and not probe.get("pending_count"):
            results.append({"host": ip, "ok": False, "detail": probe.get("detail")})
            continue
        n = _ingest_os_probe(
            user_id,
            probe,
            asset_id=aid,
            asset_name=name,
            source_prefix="os",
        )
        total_ingested += n
        results.append({"host": ip, "ok": True, "ingested": n, "pending": probe.get("pending_count", 0)})

    return {"ingested": total_ingested, "probed": probed, "results": results}
