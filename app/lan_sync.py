"""LAN / device-to-device helpers.

Phones and other PCs on the same Wi-Fi share one live workspace. Auto-scan
still probes THIS host only, but manual LAN refresh can warm the local `/24`
so neighbor devices show up as real assets instead of a demo-looking ARP cache.
"""

from __future__ import annotations

import json
import ipaddress
import re
import subprocess
import sys
from typing import Any

_ARP_WIN = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\w+)",
    re.I,
)
_ARP_UNIX = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+\S+\s+lladdr\s+"
    r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})",
    re.I,
)
_ARP_BSD = re.compile(
    r"^\S+\s+\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
    r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})",
    re.I,
)

_RECENT_SEC = 20 * 60
_IN_FLIGHT = {
    "queued",
    "scope_check",
    "running",
    "collecting",
    "parsing",
    "normalizing",
}


def is_lan_bind(host: str | None = None) -> bool:
    from app.config import settings

    h = (host if host is not None else settings.host or "").strip()
    return h in {"0.0.0.0", "::", "[::]"}


def host_scan_target() -> str:
    """Authorized target: this machine only (LAN IP preferred, else loopback)."""
    try:
        from app.platform_info import platform_info

        for url in platform_info().get("lan_urls") or []:
            raw = str(url).replace("https://", "").replace("http://", "")
            ip = raw.split("/")[0].split(":")[0].strip("[]")
            if ip and not ip.startswith("127.") and ip != "localhost":
                return ip
    except Exception:
        pass
    return "127.0.0.1"


def _normalize_mac(raw: str) -> str:
    hexes = re.findall(r"[0-9a-fA-F]{1,2}", raw or "")
    if len(hexes) != 6:
        return ""
    return ":".join(p.zfill(2).lower() for p in hexes)


def _skip_neighbor(ip: str, mac: str) -> bool:
    if not ip or ip.startswith("127.") or ip.endswith(".255") or ip.endswith(".0"):
        return True
    try:
        first = int(ip.split(".", 1)[0])
    except ValueError:
        return True
    if first >= 224:  # multicast / reserved
        return True
    if mac.replace(":", "").replace("-", "") in {"ffffffffffff", ""}:
        return True
    return False


def parse_arp_table(text: str) -> list[dict[str, str]]:
    """Parse `arp -a` / `ip neigh` output into live neighbor rows."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        ip = mac = ""
        m = _ARP_WIN.match(line) or _ARP_UNIX.match(line) or _ARP_BSD.match(line)
        if not m:
            continue
        ip = m.group(1)
        mac = _normalize_mac(m.group(2))
        if _skip_neighbor(ip, mac) or ip in seen:
            continue
        seen.add(ip)
        out.append({"ip": ip, "mac": mac})
    return out


def list_lan_neighbors() -> list[dict[str, str]]:
    """Hosts already on this machine's ARP cache — no subnet sweep."""
    commands = (
        ["arp", "-a"],
        ["ip", "neigh"],
    )
    for argv in commands:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=4, check=False)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
        rows = parse_arp_table(blob)
        if rows:
            return rows
    return []


def lan_subnet_hint() -> str:
    """Best-effort `/24` for the preferred LAN IP."""
    ip = host_scan_target()
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if obj.version != 4 or obj.is_loopback:
        return ""
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ""


def warm_lan_subnet(*, limit: int = 254) -> dict[str, Any]:
    """Light `/24` ping sweep to populate the local ARP cache.

    This does NOT run a vuln scan across the subnet. It only nudges hosts to
    answer one ping so they appear in neighbor inventory and Assets.
    Concurrent + short timeouts so a lab /24 finishes in seconds, not minutes.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    subnet = lan_subnet_hint()
    if not subnet:
        return {"ok": False, "subnet": "", "attempted": 0}
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return {"ok": False, "subnet": subnet, "attempted": 0}

    hosts = [str(ip) for ip in net.hosts()][:limit]
    this_ip = host_scan_target()
    hosts = [ip for ip in hosts if ip != this_ip]
    if not hosts:
        return {"ok": False, "subnet": subnet, "attempted": 0}

    if sys.platform.startswith("win"):
        def _argv(ip: str) -> list[str]:
            return ["ping", "-n", "1", "-w", "180", ip]
    else:
        def _argv(ip: str) -> list[str]:
            return ["ping", "-c", "1", "-W", "1", ip]

    def _one(ip: str) -> None:
        try:
            subprocess.run(
                _argv(ip),
                capture_output=True,
                text=True,
                timeout=0.8,
                check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return

    workers = min(64, max(8, len(hosts)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_one, ip) for ip in hosts]
        for fut in as_completed(futs):
            try:
                fut.result()
            except Exception:
                continue
    return {"ok": True, "subnet": subnet, "attempted": len(hosts)}


def refresh_lan_assets(user_id: str, *, queue_scan: bool = True) -> dict[str, Any]:
    """Upsert this host + current ARP neighbors, then queue live inventory in background.

    Subnet warm runs inside ``lan_inventory_audit`` so Refresh LAN returns immediately.
    """
    from app.enterprise import ensure_asset_for_target

    this_ip = host_scan_target()
    subnet = lan_subnet_hint()
    neighbors = list_lan_neighbors()
    upserted = 0
    from app.asset_names import resolve_target_labels

    this_labels = resolve_target_labels(this_ip, resolve_ptr=True)
    this_notes = json.dumps(
        {
            "source": "lan_live",
            "ip": this_ip,
            "hostname": this_labels["hostname"],
            "host": this_labels["host"],
            "role": "this_host",
        }
    )
    if ensure_asset_for_target(
        user_id,
        this_labels["asset_name"],
        notes=this_notes,
        asset_type="server",
        resolve_ptr=True,
    ):
        upserted += 1
    for row in neighbors:
        ip = row.get("ip") or ""
        if not ip or ip == this_ip:
            continue
        labels = resolve_target_labels(ip, resolve_ptr=False)
        notes = json.dumps(
            {
                "source": "lan_arp",
                "ip": ip,
                "hostname": labels["hostname"],
                "host": labels["host"],
                "mac": row.get("mac") or "",
            }
        )
        if ensure_asset_for_target(user_id, labels["asset_name"], notes=notes, asset_type="endpoint"):
            upserted += 1
    queued_scans: list[dict[str, Any]] = []
    if queue_scan:
        # Scan this host now; neighbors get VA after background warm expands ARP.
        queued_scans.append(
            queue_target_scan(this_ip, force=True, user_id=user_id, profile="vulnerability")
        )
        for row in neighbors:
            target = (row.get("ip") or "").strip()
            if target and target != this_ip:
                queued_scans.append(
                    queue_target_scan(target, force=True, user_id=user_id, profile="vulnerability")
                )
    inventory_job: dict[str, Any] = {"ok": False, "skipped": "not_requested"}
    try:
        from app.jobs import enqueue_job

        hosts = [{"ip": this_ip, "mac": ""}]
        for row in neighbors:
            ip = (row.get("ip") or "").strip()
            if ip and ip != this_ip:
                hosts.append({"ip": ip, "mac": row.get("mac") or ""})
        inventory_job = enqueue_job(
            "lan_inventory_audit",
            {
                "user_id": user_id,
                "hosts": hosts,
                "subnet": subnet,
                "warm": True,
                "queue_scan": bool(queue_scan),
            },
        )
        from app.realtime_bus import publish

        publish(
            type="inventory",
            source="openaudit",
            action="queued",
            count=len(hosts),
            subnet=subnet or "",
            user_id=user_id,
        )
    except Exception:
        inventory_job = {"ok": False, "skipped": "enqueue_failed"}
    scan = queued_scans[0] if queued_scans else {"ok": False, "skipped": "not_requested"}
    try:
        from app.realtime_bus import publish

        publish(type="asset", action="lan_refresh", count=upserted, target=this_ip)
    except Exception:
        pass
    return {
        "ok": True,
        "this_host": this_ip,
        "subnet": subnet or "",
        "sweep_attempted": 0,
        "sweep_queued": True,
        "neighbors": neighbors,
        "assets_upserted": upserted,
        "queued_scans": queued_scans,
        "inventory_job": inventory_job,
        "scan": scan,
    }


def queue_target_scan(
    target: str,
    *,
    force: bool = False,
    user_id: str = "local",
    profile: str = "vulnerability",
    scanner: str = "securaiq",
) -> dict[str, Any]:
    """Queue a live SecuraIQ scan for one authorized LAN target."""
    import app.scan_engine.jobs  # noqa: F401
    from app.db import now
    from app.scan_engine.executor import enqueue_scan_job
    from app.scan_engine.models import create_scan, list_scans

    target = (target or "").strip()
    if not target:
        return {"ok": False, "skipped": "no_target", "target": target}

    if not force:
        now_t = float(now())
        for scan in list_scans(user_id, limit=100):
            tgt = (scan.get("target") or "").strip()
            if tgt != target:
                continue
            status = (scan.get("status") or "").lower()
            created = float(scan.get("created_at") or 0)
            if status in _IN_FLIGHT:
                return {
                    "ok": False,
                    "skipped": "scan_in_flight",
                    "scan_id": scan.get("id"),
                    "target": target,
                }
            if status == "completed" and created and (now_t - created) < _RECENT_SEC:
                return {
                    "ok": False,
                    "skipped": "recent_completed",
                    "scan_id": scan.get("id"),
                    "target": target,
                }

    scan = create_scan(
        user_id=user_id,
        target=target,
        scanner=scanner,
        profile=profile,
        authorized=True,
    )
    job = enqueue_scan_job(scan["id"])
    try:
        from app.realtime_bus import publish

        publish(type="scan", id=scan["id"], status="queued", source="lan_live", target=target)
    except Exception:
        pass
    return {
        "ok": True,
        "scan_id": scan["id"],
        "job_id": job.get("id"),
        "target": target,
        "scanner": scanner,
        "profile": profile,
    }


def queue_this_host_scan(*, force: bool = False, user_id: str = "local") -> dict[str, Any]:
    """Queue a live SecuraIQ discovery scan of this host."""
    target = host_scan_target()
    return queue_target_scan(
        target,
        force=force,
        user_id=user_id,
        profile="discovery",
        scanner="securaiq",
    )


def maybe_queue_lan_auto_scan() -> dict[str, Any]:
    """Queue a discovery scan of this host when LAN mode is on.

    Skips localhost-only binds, explicit opt-out, in-flight scans, and a
    recent completed scan of the same host (restart spam).
    """
    from app.config import settings

    if not is_lan_bind():
        return {"ok": False, "skipped": "not_lan_bind"}
    if not getattr(settings, "lan_auto_scan", False):
        return {"ok": False, "skipped": "lan_auto_scan_off"}
    return queue_this_host_scan(force=False, user_id="local")
