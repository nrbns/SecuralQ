"""Open-AudIT-style live inventory during authorized LAN / VA scans.

Collects hostname, MAC, open ports, HTTP fingerprint, and SMB share names
for owned/lab hosts, then streams them into the Open Audit inventory list.
Optional: if an Open-AudIT server is configured, also trigger a subnet discovery.
See https://www.open-audit.org/
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
import subprocess
import sys
from typing import Any

AUDIT_PORTS = (22, 80, 135, 139, 443, 445, 3389, 5985, 8080, 8443)


def ptr_hostname(ip: str) -> str:
    try:
        name, _alias, _addrs = socket.gethostbyaddr(ip)
        return (name or "").strip().rstrip(".")
    except Exception:
        return ""


def list_smb_shares(ip: str) -> list[str]:
    """Authorized inventory of share names (not contents / not credentials)."""
    ip = (ip or "").strip()
    if not ip:
        return []
    if sys.platform.startswith("win"):
        argv = ["net", "view", f"\\\\{ip}"]
    else:
        argv = ["smbclient", "-L", ip, "-N", "-g"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=4, check=False)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return []
    blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
    names: list[str] = []
    seen: set[str] = set()
    for line in blob.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("-") or raw.lower().startswith("shared resources"):
            continue
        m = re.match(r"^([A-Za-z0-9._$ -]+?)\s+(Disk|Print|IPC|OK)\b", raw, re.I)
        if m:
            name = m.group(1).strip()
        elif raw.lower().startswith("disk|"):
            name = raw.split("|", 1)[-1].strip()
        else:
            continue
        key = name.lower()
        if not name or key in {"ipc$", "print$"} or key in seen:
            continue
        seen.add(key)
        names.append(name)
    return names[:20]


def guess_os_and_type(ports: list[int], http: list[dict[str, str]] | None = None) -> tuple[str, str]:
    from app.asset_categories import infer_asset_category

    http = http or []
    server = " ".join(str(h.get("server") or "") for h in http).lower()
    os_name = ""
    if any(p in ports for p in (135, 139, 445, 3389, 5985)):
        os_name = "Windows"
    elif 22 in ports:
        os_name = "Linux/Unix"
    if "iis" in server:
        os_name = os_name or "Windows"
    if "apache" in server or "nginx" in server:
        os_name = os_name or "Linux/Unix"
    dtype = infer_asset_category(ports=ports, http_server=server, os=os_name)
    return os_name, dtype


async def audit_host(ip: str, *, mac: str = "") -> dict[str, Any]:
    """Light Open-AudIT-class inventory probe of one authorized host."""
    from app.net_assess import _http_fingerprint, _probe_port

    ip = (ip or "").strip()
    hostname = ptr_hostname(ip)
    flags = await asyncio.gather(*[_probe_port(ip, p, timeout=0.28) for p in AUDIT_PORTS])
    ports = [p for p, ok in zip(AUDIT_PORTS, flags) if ok]
    http: list[dict[str, str]] = []
    if any(p in ports for p in (80, 443, 8080, 8443)):
        try:
            http = await _http_fingerprint(ip, ports)
        except Exception:
            http = []
    shares: list[str] = []
    if any(p in ports for p in (139, 445)):
        shares = await asyncio.to_thread(list_smb_shares, ip)
    os_name, dtype = guess_os_and_type(ports, http)
    title = next((h.get("title") for h in http if h.get("title")), "")
    server = next((h.get("server") for h in http if h.get("server")), "")
    desc_bits = []
    if ports:
        desc_bits.append("ports=" + ",".join(str(p) for p in ports))
    if shares:
        desc_bits.append("shares=" + ",".join(shares))
    if title:
        desc_bits.append(f"http={title}")
    return {
        "device_id": f"live:{ip}",
        "name": hostname or ip,
        "hostname": hostname,
        "ip": ip,
        "type": dtype,
        "status": "production",
        "os": os_name,
        "domain": "",
        "description": "; ".join(desc_bits),
        "manufacturer": "",
        "model": server or "",
        "raw": {
            "source": "securaiq_audit",
            "mac": mac,
            "open_ports": ports,
            "shares": shares,
            "http": http,
        },
    }


async def audit_hosts(hosts: list[dict[str, str]], *, user_id: str) -> dict[str, Any]:
    from app.enterprise import ensure_asset_for_target
    from app.openaudit import ingest_live_device

    audited = 0
    for row in hosts:
        ip = (row.get("ip") or "").strip()
        if not ip:
            continue
        try:
            item = await audit_host(ip, mac=row.get("mac") or "")
            ingest_live_device(user_id, item)
            hostname = (item.get("hostname") or "").strip()
            notes = json.dumps(
                {
                    "source": "securaiq_audit",
                    "ip": ip,
                    "hostname": hostname,
                    "host": hostname or ip,
                    "mac": row.get("mac") or "",
                    "os": item.get("os") or "",
                }
            )[:2000]
            from app.asset_names import canonical_asset_name

            from app.asset_categories import infer_asset_category

            ensure_asset_for_target(
                user_id,
                canonical_asset_name(name=item.get("name") or hostname or ip, ip=ip, hostname=hostname),
                notes=notes,
                asset_type=infer_asset_category(
                    asset_type=str(item.get("type") or ""),
                    os=str(item.get("os") or ""),
                    hostname=hostname,
                    ports=(item.get("raw") or {}).get("open_ports") or [],
                    http_server=str(item.get("model") or ""),
                    name=str(item.get("name") or hostname or ip),
                ),
                resolve_ptr=False,
            )
            audited += 1
            try:
                from app.realtime_bus import publish

                publish(
                    type="inventory",
                    source="openaudit",
                    action="host",
                    ip=ip,
                    hostname=item.get("hostname") or "",
                    ports=len((item.get("raw") or {}).get("open_ports") or []),
                    shares=len((item.get("raw") or {}).get("shares") or []),
                    user_id=user_id,
                )
            except Exception:
                pass
        except Exception:
            continue
    return {"ok": True, "audited": audited, "hosts": len(hosts)}
