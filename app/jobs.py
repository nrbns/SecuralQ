"""Lightweight in-process background job runner.

"Background jobs / workers" was listed as not-started in
docs/launch-readiness.md. Rather than pull in Celery/Redis/APScheduler for a
single-process local-first alpha, this gives SecuraIQ:

  * a durable `jobs` table (survives restarts — a job left "pending" or
    "running" when the process died is requeued on next boot),
  * an asyncio worker loop (single worker is enough for alpha; bump
    WORKER_CONCURRENCY if a heavier job type shows up),
  * a periodic scheduler for recurring work (currently: CISA KEV cache
    refresh so it doesn't only refresh when a user happens to hit the intel
    endpoint).

Once the Redis compose profile / Postgres lands (see docs/postgres-migration.md),
this queue can move to an RQ/Celery worker without changing the handler
registry below — `JOB_HANDLERS` is the seam.
"""

from __future__ import annotations

import asyncio
import json
import time
import traceback
from typing import Any, Awaitable, Callable

from app.db import get_conn, new_id, now, row_to_dict

JobHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]

JOB_HANDLERS: dict[str, JobHandler] = {}
_queue: "asyncio.Queue[str] | None" = None
_worker_task: asyncio.Task | None = None
_scheduler_task: asyncio.Task | None = None

KEV_SYNC_INTERVAL_SEC = 6 * 3600  # matches the 12h KEV cache TTL with margin
_SCHEDULER_TICK_SEC = 60  # wake scheduled syncs quickly for near-realtime connectors
_last_kev_sync = 0.0
_last_xdr_sync = 0.0
_last_wazuh_sync = 0.0
_last_openaudit_sync = 0.0
_last_thehive_sync = 0.0
_last_cloud_posture_sync = 0.0
_last_sonarqube_sync = 0.0
_last_software_sync = 0.0


def register_job(kind: str):
    """Decorator: @register_job("kev_sync") async def handler(payload) -> dict"""

    def _wrap(fn: JobHandler) -> JobHandler:
        JOB_HANDLERS[kind] = fn
        return fn

    return _wrap


def enqueue_job(
    kind: str,
    payload: dict[str, Any] | None = None,
    *,
    engine: str = "auto",
) -> dict[str, Any]:
    if kind not in JOB_HANDLERS:
        raise ValueError(f"Unknown job kind '{kind}'. Registered: {sorted(JOB_HANDLERS)}")
    body = dict(payload or {})
    eng = (engine or "auto").lower().strip()
    if eng == "auto":
        try:
            from app.prefect_bridge import prefect_status

            eng = "prefect" if prefect_status().get("ready") else "local"
        except Exception:
            eng = "local"
    if eng not in ("local", "prefect"):
        raise ValueError("engine must be local, prefect, or auto")
    body["_engine"] = eng
    jid = new_id()
    c = get_conn()
    c.execute(
        "INSERT INTO jobs (id, kind, status, payload_json, result_json, error, created_at) "
        "VALUES (?, ?, 'pending', ?, '{}', '', ?)",
        (jid, kind, json.dumps(body), now()),
    )
    c.commit()
    if _queue is not None:
        _queue.put_nowait(jid)
    try:
        from app.realtime_bus import publish

        publish(type="job", id=jid, kind=kind, status="pending")
    except Exception:
        pass
    return get_job(jid)  # type: ignore[return-value]


def get_job(job_id: str) -> dict[str, Any] | None:
    row = get_conn().execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    d = row_to_dict(row)
    if d:
        for key in ("payload_json", "result_json"):
            try:
                d[key.replace("_json", "")] = json.loads(d.get(key) or "{}")
            except Exception:
                pass
    return d


def list_jobs(limit: int = 50, kind: str | None = None) -> list[dict[str, Any]]:
    c = get_conn()
    q = "SELECT * FROM jobs"
    args: list[Any] = []
    if kind:
        q += " WHERE kind = ?"
        args.append(kind)
    q += " ORDER BY created_at DESC LIMIT ?"
    args.append(max(1, min(limit, 200)))
    out = []
    for row in c.execute(q, args).fetchall():
        d = dict(row)
        for key in ("payload_json", "result_json"):
            try:
                d[key.replace("_json", "")] = json.loads(d.get(key) or "{}")
            except Exception:
                pass
        out.append(d)
    return out


def _has_pending_or_running(kind: str) -> bool:
    row = get_conn().execute(
        "SELECT COUNT(*) AS n FROM jobs WHERE kind = ? AND status IN ('pending', 'running')",
        (kind,),
    ).fetchone()
    return bool(row and int(row["n"]) > 0)


async def wait_for_jobs(
    job_ids: list[str],
    *,
    timeout_sec: float = 180,
    poll_sec: float = 1.5,
) -> dict[str, str]:
    """Poll until queued jobs finish or timeout. Returns job_id -> terminal status."""
    import time

    pending = {jid for jid in job_ids if jid}
    results: dict[str, str] = {}
    deadline = time.time() + max(5.0, timeout_sec)
    while pending and time.time() < deadline:
        for jid in list(pending):
            job = get_job(jid)
            st = (job or {}).get("status") or ""
            if st in ("done", "error"):
                results[jid] = st
                pending.discard(jid)
        if pending:
            await asyncio.sleep(max(0.5, poll_sec))
    for jid in pending:
        results[jid] = "timeout"
    return results


async def _run_one(job_id: str) -> None:
    job = get_job(job_id)
    if not job or job.get("status") not in ("pending",):
        return
    c = get_conn()
    c.execute("UPDATE jobs SET status='running', started_at=? WHERE id=?", (now(), job_id))
    c.commit()
    try:
        from app.realtime_bus import publish

        publish(type="job", id=job_id, kind=job.get("kind"), status="running")
    except Exception:
        pass
    handler = JOB_HANDLERS.get(job["kind"])
    try:
        if not handler:
            raise ValueError(f"No handler registered for kind '{job['kind']}'")
        payload = json.loads(job.get("payload_json") or "{}")
        payload["_job_id"] = job_id
        engine = (payload.pop("_engine", None) or "local").lower()
        if engine == "prefect":
            from app.prefect_bridge import run_kind_via_prefect

            result = await run_kind_via_prefect(job["kind"], payload)
        else:
            result = await handler(payload)
            if isinstance(result, dict):
                result = {**result, "engine": "local"}
        c.execute(
            "UPDATE jobs SET status='done', result_json=?, finished_at=? WHERE id=?",
            (json.dumps(result or {}), now(), job_id),
        )
        c.commit()
        try:
            from app.realtime_bus import publish
            from app.realtime_events import publish_job_completion

            publish(type="job", id=job_id, kind=job.get("kind"), status="done")
            publish_job_completion(
                str(job.get("kind") or ""),
                result if isinstance(result, dict) else {},
                job_id=job_id,
                status="done",
            )
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001 — job errors must never crash the worker
        c.execute(
            "UPDATE jobs SET status='error', error=?, finished_at=? WHERE id=?",
            (f"{exc}\n{traceback.format_exc()[-2000:]}", now(), job_id),
        )
        c.commit()
        try:
            from app.realtime_bus import publish
            from app.realtime_events import publish_job_completion

            publish(type="job", id=job_id, kind=job.get("kind"), status="error")
            publish_job_completion(
                str(job.get("kind") or ""),
                {"error": str(exc)[:500]},
                job_id=job_id,
                status="error",
            )
        except Exception:
            pass


async def _worker_loop() -> None:
    assert _queue is not None
    while True:
        job_id = await _queue.get()
        try:
            await _run_one(job_id)
        finally:
            _queue.task_done()


async def _scheduler_loop() -> None:
    # Stagger first run slightly so it doesn't compete with app startup.
    await asyncio.sleep(15)
    global _last_kev_sync, _last_xdr_sync, _last_wazuh_sync, _last_openaudit_sync
    global _last_thehive_sync, _last_cloud_posture_sync, _last_sonarqube_sync, _last_software_sync
    while True:
        now_t = time.time()
        try:
            if (
                "kev_sync" in JOB_HANDLERS
                and now_t - _last_kev_sync >= KEV_SYNC_INTERVAL_SEC
                and not _has_pending_or_running("kev_sync")
            ):
                _last_kev_sync = now_t
                enqueue_job("kev_sync", {"scheduled": True})
        except Exception:
            pass
        try:
            from app.config import settings

            interval = max(300, int(settings.xdr_sync_interval_sec))
            if (
                "xdr_sync" in JOB_HANDLERS
                and now_t - _last_xdr_sync >= interval
                and not _has_pending_or_running("xdr_sync")
            ):
                _last_xdr_sync = now_t
                enqueue_job("xdr_sync", {"scheduled": True})
        except Exception:
            pass
        try:
            from app.config import settings

            from app.connectors import wazuh as wazuh_conn

            w_interval = max(300, int(getattr(settings, "wazuh_sync_interval_sec", 1800) or 1800))
            if (
                "wazuh_sync" in JOB_HANDLERS
                and wazuh_conn.is_configured()
                and now_t - _last_wazuh_sync >= w_interval
                and not _has_pending_or_running("wazuh_sync")
            ):
                _last_wazuh_sync = now_t
                enqueue_job("wazuh_sync", {"scheduled": True})
        except Exception:
            pass
        try:
            from app.config import settings

            from app.connectors import openaudit as oa_conn

            oa_interval = max(300, int(getattr(settings, "openaudit_sync_interval_sec", 3600) or 3600))
            if (
                "openaudit_sync" in JOB_HANDLERS
                and oa_conn.is_configured()
                and now_t - _last_openaudit_sync >= oa_interval
                and not _has_pending_or_running("openaudit_sync")
            ):
                _last_openaudit_sync = now_t
                enqueue_job("openaudit_sync", {"scheduled": True})
        except Exception:
            pass
        try:
            from app.config import settings

            from app.connectors import thehive as th_conn

            th_interval = max(300, int(getattr(settings, "thehive_sync_interval_sec", 1800) or 1800))
            if (
                "thehive_sync" in JOB_HANDLERS
                and th_conn.is_configured()
                and now_t - _last_thehive_sync >= th_interval
                and not _has_pending_or_running("thehive_sync")
            ):
                _last_thehive_sync = now_t
                enqueue_job("thehive_sync", {"scheduled": True, "user_id": "local"})
        except Exception:
            pass
        try:
            from app.config import settings

            from app.cloud_posture import status as cloud_status

            cp_interval = max(
                300, int(getattr(settings, "cloud_posture_sync_interval_sec", 3600) or 3600)
            )
            cp = cloud_status()
            if (
                "cloud_posture_sync" in JOB_HANDLERS
                and int(cp.get("configured_count") or 0) > 0
                and now_t - _last_cloud_posture_sync >= cp_interval
                and not _has_pending_or_running("cloud_posture_sync")
            ):
                _last_cloud_posture_sync = now_t
                enqueue_job("cloud_posture_sync", {"scheduled": True, "user_id": "local"})
        except Exception:
            pass
        try:
            from app.config import settings

            from app.connectors import sonarqube as sonar_conn

            sq_interval = max(300, int(getattr(settings, "sonarqube_sync_interval_sec", 3600) or 3600))
            if (
                "sonarqube_sync" in JOB_HANDLERS
                and sonar_conn.is_configured()
                and now_t - _last_sonarqube_sync >= sq_interval
                and not _has_pending_or_running("sonarqube_sync")
            ):
                _last_sonarqube_sync = now_t
                enqueue_job("sonarqube_sync", {"scheduled": True, "user_id": "local"})
        except Exception:
            pass
        try:
            from app.config import settings

            sw_interval = max(300, int(getattr(settings, "software_sync_interval_sec", 3600) or 3600))
            if (
                "software_sync_all" in JOB_HANDLERS
                and getattr(settings, "software_sync_auto_enabled", True)
                and now_t - _last_software_sync >= sw_interval
                and not _has_pending_or_running("software_sync_all")
            ):
                _last_software_sync = now_t
                enqueue_job("software_sync_all", {"scheduled": True, "user_id": "local"})
        except Exception:
            pass
        await asyncio.sleep(_SCHEDULER_TICK_SEC)


def start_background_jobs() -> None:
    """Call once from the FastAPI lifespan startup."""
    global _queue, _worker_task, _scheduler_task
    if _queue is not None:
        return  # already started (e.g. lifespan re-entered under --reload)
    _queue = asyncio.Queue()

    # Requeue anything left pending/running from a previous process that died mid-job.
    c = get_conn()
    c.execute("UPDATE jobs SET status='pending', started_at=NULL WHERE status='running'")
    c.commit()
    for row in c.execute(
        "SELECT id FROM jobs WHERE status='pending' ORDER BY created_at ASC LIMIT 100"
    ).fetchall():
        _queue.put_nowait(row["id"])

    _worker_task = asyncio.create_task(_worker_loop())
    _scheduler_task = asyncio.create_task(_scheduler_loop())


async def stop_background_jobs() -> None:
    global _worker_task, _scheduler_task
    for task in (_worker_task, _scheduler_task):
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    _worker_task = None
    _scheduler_task = None


# --- Built-in job handlers ---------------------------------------------------


@register_job("kev_sync")
async def _job_kev_sync(payload: dict[str, Any]) -> dict[str, Any]:
    from app.intel_feeds import alert_watchlist_on_kev, fetch_cisa_kev

    t0 = time.time()
    user_id = payload.get("user_id") or "local"
    feed = await fetch_cisa_kev(limit=payload.get("limit", 50))
    watch = await alert_watchlist_on_kev(user_id, feed=feed)
    try:
        from app.realtime_bus import publish

        publish(
            type="intel",
            source="kev_sync",
            count=feed.get("count"),
            cached=feed.get("cached"),
            watch_matches=watch.get("watch_matches"),
            user_id=user_id,
        )
    except Exception:
        pass
    return {
        "count": feed.get("count"),
        "cached": feed.get("cached"),
        "watch": watch,
        "duration_sec": round(time.time() - t0, 2),
    }


def _refresh_software(user_id: str, *sources: str) -> dict[str, int]:
    try:
        from app.software_inventory import refresh_after_sync

        return refresh_after_sync(user_id or "local", *sources)
    except Exception:
        return {}


@register_job("xdr_sync")
async def _job_xdr_sync(payload: dict[str, Any]) -> dict[str, Any]:
    """Poll all configured XDR/EDR vendors and ingest new detections/patch gaps."""
    from app.xdr import sync_all

    t0 = time.time()
    uid = payload.get("user_id", "local")
    result = await sync_all(uid)
    result["software_ingested"] = _refresh_software(uid, "xdr")
    result["duration_sec"] = round(time.time() - t0, 2)
    return result


@register_job("wazuh_sync")
async def _job_wazuh_sync(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull Wazuh agents + alerts into SecuraIQ (authorized manager/indexer)."""
    from app.wazuh import sync as wazuh_sync

    t0 = time.time()
    uid = payload.get("user_id", "local")
    result = await wazuh_sync(uid)
    syscol = 0
    try:
        from app.software.service import refresh_wazuh_syscollector

        syscol = await refresh_wazuh_syscollector(limit_agents=50)
    except Exception:
        pass
    result["syscollector_agents"] = syscol
    result["software_ingested"] = _refresh_software(uid, "wazuh", "xdr")
    result["duration_sec"] = round(time.time() - t0, 2)
    return result


@register_job("openaudit_sync")
async def _job_openaudit_sync(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull Open-AudIT devices into SecuraIQ assets."""
    from app.openaudit import sync as openaudit_sync

    t0 = time.time()
    uid = payload.get("user_id", "local")
    result = await openaudit_sync(uid)
    result["software_ingested"] = _refresh_software(uid, "openaudit")
    result["duration_sec"] = round(time.time() - t0, 2)
    return result


@register_job("lan_inventory_audit")
async def _job_lan_inventory_audit(payload: dict[str, Any]) -> dict[str, Any]:
    """Warm ARP (optional), expand hosts, then Open-AudIT-style live inventory."""
    import asyncio

    from app.connectors import openaudit as oa_conn
    from app.enterprise import ensure_asset_for_target
    from app.lan_inventory import audit_hosts
    from app.lan_sync import host_scan_target, list_lan_neighbors, queue_target_scan, warm_lan_subnet
    from app.openaudit import sync as openaudit_sync

    user_id = payload.get("user_id") or "local"
    hosts = list(payload.get("hosts") or [])
    subnet = payload.get("subnet") or ""
    t0 = time.time()
    warm_info: dict[str, Any] = {"ok": False, "skipped": "not_requested"}
    if payload.get("warm", True):
        warm_info = await asyncio.to_thread(warm_lan_subnet)
        subnet = warm_info.get("subnet") or subnet
        this_ip = host_scan_target()
        seen = {str(h.get("ip") or "").strip() for h in hosts}
        for row in list_lan_neighbors():
            ip = (row.get("ip") or "").strip()
            if not ip or ip in seen:
                continue
            seen.add(ip)
            hosts.append({"ip": ip, "mac": row.get("mac") or ""})
            notes = json.dumps({"source": "lan_arp", "ip": ip, "mac": row.get("mac") or ""})
            try:
                ensure_asset_for_target(user_id, ip, notes=notes, asset_type="endpoint")
            except Exception:
                pass
            if payload.get("queue_scan") and ip != this_ip:
                try:
                    queue_target_scan(ip, force=True, user_id=user_id, profile="vulnerability")
                except Exception:
                    pass
    discovery: dict[str, Any] = {"ok": False, "skipped": "not_requested"}
    if oa_conn.is_configured() and subnet:
        discovery = await oa_conn.trigger_subnet_discovery(subnet, name=f"SecuraIQ {subnet}")
        try:
            await openaudit_sync(user_id)
        except Exception:
            pass
    live = await audit_hosts(hosts, user_id=user_id)
    live["discovery"] = discovery
    live["warm"] = warm_info
    live["hosts"] = len(hosts)
    live["software_ingested"] = _refresh_software(user_id, "openaudit", "lan")
    live["duration_sec"] = round(time.time() - t0, 2)
    return live


@register_job("thehive_sync")
async def _job_thehive_sync(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull TheHive cases into SecuraIQ incidents."""
    from app.thehive import sync as thehive_sync

    t0 = time.time()
    result = await thehive_sync(payload.get("user_id", "local"))
    result["duration_sec"] = round(time.time() - t0, 2)
    return result


@register_job("cloud_posture_sync")
async def _job_cloud_posture_sync(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull AWS/Azure/GCP posture findings into vulnerabilities."""
    from app.cloud_posture import sync_all

    t0 = time.time()
    uid = payload.get("user_id", "local")
    result = await sync_all(uid)
    result["software_ingested"] = _refresh_software(uid, "vulns")
    result["duration_sec"] = round(time.time() - t0, 2)
    return result


@register_job("sonarqube_sync")
async def _job_sonarqube_sync(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull SonarQube / SonarCloud issues into the vulnerability register."""
    from app.sonarqube import sync as sonar_sync

    t0 = time.time()
    uid = payload.get("user_id", "local")
    result = await sonar_sync(uid)
    result["software_ingested"] = _refresh_software(uid, "vulns")
    result["duration_sec"] = round(time.time() - t0, 2)
    return result


@register_job("hardeningkitty_audit")
async def _job_hardeningkitty_audit(payload: dict[str, Any]) -> dict[str, Any]:
    """Run HardeningKitty Audit/Config on this Windows host (authorized labs)."""
    from app.hardeningkitty import run_audit

    t0 = time.time()
    uid = payload.get("user_id", "local")
    result = await run_audit(
        mode=payload.get("mode") or "Audit",
        finding_list=payload.get("finding_list") or None,
        import_findings=bool(payload.get("import_findings", True)),
        user_id=uid,
    )
    result["software_ingested"] = _refresh_software(uid, "vulns")
    result["duration_sec"] = round(time.time() - t0, 2)
    return result


@register_job("software_sync_all")
async def _job_software_sync_all(payload: dict[str, Any]) -> dict[str, Any]:
    """Scheduled full software sync: SIEM/XDR/inventory jobs, wait, rebuild, notify."""
    from app.os_patches import probe_local_os_patches
    from app.software_inventory import (
        posture_summary,
        queue_software_sync_jobs,
        rebuild_for_user,
    )

    t0 = time.time()
    uid = payload.get("user_id") or "local"
    queued = queue_software_sync_jobs(uid)
    job_ids = [j["id"] for j in queued if j.get("id")]
    wait_results: dict[str, str] = {}
    if job_ids:
        wait_results = await wait_for_jobs(job_ids, timeout_sec=180)

    local_os: dict[str, Any] = {"ingested": 0, "probe": {}}
    try:
        local_os["probe"] = probe_local_os_patches()
    except Exception:
        pass

    rebuilt = rebuild_for_user(uid)
    local_os["ingested"] = int(rebuilt.get("local_os") or 0)
    posture = posture_summary(uid, rebuild_if_empty=False)
    server_summary = posture.get("server_summary") or {}
    needs_update = int(server_summary.get("needs_update") or 0)

    if payload.get("scheduled") and needs_update > 0 and uid and uid != "local":
        try:
            from app.notifications import notify

            notify(
                uid,
                "patch_posture",
                f"{needs_update} server(s) need updates",
                (
                    f"Scheduled software sync found {needs_update} system(s) with patch gaps. "
                    f"Open Software & patch inventory to review."
                ),
                link="/#software",
            )
        except Exception:
            pass

    return {
        "jobs_queued": queued,
        "jobs_wait": wait_results,
        "local_os_patches": local_os,
        "rebuilt": rebuilt,
        "posture": posture,
        "duration_sec": round(time.time() - t0, 2),
    }


@register_job("software_version_refresh")
async def _job_software_version_refresh(payload: dict[str, Any]) -> dict[str, Any]:
    """Background batch: resolve latest versions from vendor/registry feeds."""
    from app.software.service import sync_inventory
    from app.software.versions import refresh_versions_for_user

    t0 = time.time()
    uid = payload.get("user_id") or "local"
    refresh = refresh_versions_for_user(uid)
    sync = sync_inventory(uid, publish=True)
    return {
        "refresh": refresh,
        "sync_installations": int(sync.get("installations") or 0),
        "duration_sec": round(time.time() - t0, 2),
    }


def _verify_patch_command(command_id: str) -> None:
    """Decide whether a completed patch command actually fixed the target,
    now that inventory + advisories have been re-synced. 'done' (agent
    executed successfully) and 'verified' (the fix is confirmed present)
    are different claims — this is what closes that gap. Best-effort: any
    failure here should never surface as an error on the refresh job
    itself, since a verification miss is informational, not a job failure.
    """
    from app.agents import get_agent, record_command_verification
    from app.software.models import PATCH_UNKNOWN, PATCH_UP_TO_DATE
    from app.software.models import ensure_schema as ensure_software_schema
    from app.software.patch_status import compare_versions

    ensure_software_schema()
    c = get_conn()
    cmd = c.execute("SELECT * FROM securaiq_agent_commands WHERE id = ?", (command_id,)).fetchone()
    if not cmd:
        return
    cmd = dict(cmd)
    try:
        payload_d = json.loads(cmd.get("payload_json") or "{}")
    except Exception:
        payload_d = {}
    package = (payload_d.get("package") or "").strip()
    target_version = (payload_d.get("target_version") or "").strip()
    agent = get_agent(cmd.get("agent_id") or "")
    asset_id = (agent or {}).get("asset_id") or ""
    if not package or not asset_id:
        record_command_verification(command_id, verified=None, detail="Missing package or asset linkage — cannot verify")
        return

    row = c.execute(
        """
        SELECT ps.status AS patch_status, i.version AS installed_version, p.name AS product_name
        FROM software_installations i
        JOIN software_products p ON p.id = i.software_product_id
        LEFT JOIN patch_status ps ON ps.software_installation_id = i.id AND ps.user_id = i.user_id
        WHERE i.user_id = ? AND i.asset_id = ? AND (LOWER(p.name) LIKE ? OR LOWER(p.canonical_id) LIKE ?)
        ORDER BY i.updated_at DESC LIMIT 1
        """,
        (cmd.get("user_id") or "local", asset_id, f"%{package.lower()}%", f"%{package.lower()}%"),
    ).fetchone()
    if not row:
        record_command_verification(
            command_id, verified=None, detail=f"Package '{package}' not found in software inventory for this asset yet"
        )
        return
    row = dict(row)
    patch_status = row.get("patch_status") or ""
    installed_version = row.get("installed_version") or ""

    if patch_status == PATCH_UP_TO_DATE:
        record_command_verification(command_id, verified=True, detail=f"Installed version {installed_version} confirmed up to date")
        return
    if target_version:
        cmp = compare_versions(installed_version, target_version)
        if cmp is not None and cmp >= 0:
            record_command_verification(
                command_id, verified=True, detail=f"Installed version {installed_version} meets target {target_version}"
            )
            return
    # Prefer the agent's reported new_version when inventory already shows it —
    # common when no advisory feed contradicts the install yet.
    try:
        result_json = json.loads(cmd.get("result_json") or "{}")
    except Exception:
        result_json = {}
    reported_new = str(result_json.get("new_version") or "").strip()
    if reported_new and installed_version:
        cmp_r = compare_versions(installed_version, reported_new)
        if cmp_r is not None and cmp_r >= 0 and patch_status in ("", PATCH_UNKNOWN, "installed"):
            record_command_verification(
                command_id,
                verified=True,
                detail=f"Installed version {installed_version} matches agent-reported post-patch version {reported_new}",
            )
            return
    if patch_status in ("", PATCH_UNKNOWN) and installed_version and not target_version:
        # Package present after patch; no advisory signal either way.
        record_command_verification(
            command_id,
            verified=True,
            detail=f"Installed version {installed_version} present in inventory after patch (no advisory contradiction)",
        )
        return
    record_command_verification(
        command_id,
        verified=False,
        detail=f"Advisory still flags this installation after refresh (status={patch_status or 'unknown'}, installed={installed_version})",
    )


@register_job("software_advisory_refresh")
async def _job_software_advisory_refresh(payload: dict[str, Any]) -> dict[str, Any]:
    """Refresh CVE/KEV advisory matches and recalculate patch priority."""
    from app.software.advisories import publish_vulnerability_events, refresh_advisories_for_user
    from app.software.service import sync_inventory

    t0 = time.time()
    uid = payload.get("user_id") or "local"
    try:
        from app.intel_feeds import fetch_cisa_kev

        await fetch_cisa_kev(limit=500)
    except Exception:
        pass
    refresh = refresh_advisories_for_user(uid, limit=int(payload.get("limit") or 80))
    publish_vulnerability_events(uid, refresh)
    sync_inventory(uid, publish=True)
    command_id = payload.get("command_id") or ""
    if command_id and payload.get("reason") == "patch_verify":
        try:
            _verify_patch_command(command_id)
        except Exception:
            pass
    return {"advisory_refresh": refresh, "duration_sec": round(time.time() - t0, 2)}


@register_job("report_export")
async def _job_report_export(payload: dict[str, Any]) -> dict[str, Any]:
    """Offload a heavy executive PDF build off the request thread."""
    from pathlib import Path

    from app.commercial_ext import build_executive_pdf

    user_id = payload.get("user_id", "local")
    pdf_bytes = await asyncio.to_thread(build_executive_pdf, user_id)
    out_dir = Path(payload.get("data_dir", "data")) / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"executive-{new_id()}.pdf"
    out_path.write_bytes(pdf_bytes)

    if user_id and user_id != "local":
        from app.notifications import notify

        notify(
            user_id,
            "system",
            "Executive report ready",
            f"Your executive PDF report finished generating ({len(pdf_bytes)} bytes).",
            link=str(out_path),
        )

    return {"path": str(out_path), "bytes": len(pdf_bytes)}
