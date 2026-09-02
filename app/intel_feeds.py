"""Threat intel feeds: CISA KEV (primary) + NVD CVE lookup (ToS-aware, rate-limited)."""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.db import audit, get_conn, new_id, now
from app.ops import add_intel_watch, list_intel_watch

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def ensure_intel_cache_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS intel_feed_cache (
            id TEXT PRIMARY KEY,
            feed TEXT NOT NULL,
            key TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            fetched_at REAL NOT NULL,
            UNIQUE(feed, key)
        );
        """
    )
    c.commit()


def _cache_put(feed: str, key: str, payload: dict[str, Any]) -> None:
    ensure_intel_cache_schema()
    c = get_conn()
    existing = c.execute(
        "SELECT id FROM intel_feed_cache WHERE feed = ? AND key = ?", (feed, key)
    ).fetchone()
    if existing:
        c.execute(
            "UPDATE intel_feed_cache SET payload_json = ?, fetched_at = ? WHERE id = ?",
            (json.dumps(payload), now(), existing["id"]),
        )
    else:
        c.execute(
            "INSERT INTO intel_feed_cache (id, feed, key, payload_json, fetched_at) VALUES (?, ?, ?, ?, ?)",
            (new_id(), feed, key, json.dumps(payload), now()),
        )
    c.commit()


def _cache_get(feed: str, key: str, max_age_sec: float = 86400) -> dict[str, Any] | None:
    ensure_intel_cache_schema()
    row = get_conn().execute(
        "SELECT * FROM intel_feed_cache WHERE feed = ? AND key = ?", (feed, key)
    ).fetchone()
    if not row:
        return None
    if now() - float(row["fetched_at"]) > max_age_sec:
        return None
    try:
        return json.loads(row["payload_json"])
    except json.JSONDecodeError:
        return None


def _normalize_kev_items(raw_vulns: list[Any], *, limit: int = 40) -> list[dict[str, Any]]:
    """Always return the same shape — cached raw CISA rows used to leak `cveID` vs `cve`."""
    vulns = [v for v in (raw_vulns or []) if isinstance(v, dict)]
    vulns = sorted(vulns, key=lambda x: x.get("dateAdded") or x.get("date_added") or "", reverse=True)
    out: list[dict[str, Any]] = []
    for v in vulns[: max(1, min(limit, 500))]:
        # Fresh API rows use cveID; already-normalized cache rows use cve
        cve = (v.get("cve") or v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        out.append(
            {
                "cve": cve,
                "vendor": v.get("vendor") or v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("name") or v.get("vulnerabilityName"),
                "date_added": v.get("date_added") or v.get("dateAdded"),
                "ransomware": v.get("ransomware") or v.get("knownRansomwareCampaignUse"),
                "notes": (v.get("notes") or v.get("shortDescription") or "")[:400],
            }
        )
    return out


async def fetch_cisa_kev(*, limit: int = 40) -> dict[str, Any]:
    cached = _cache_get("kev", "catalog", max_age_sec=43200)
    if cached:
        items = _normalize_kev_items(cached.get("vulnerabilities") or cached.get("items") or [], limit=limit)
        return {
            "source": "cisa_kev",
            "cached": True,
            "catalog_version": cached.get("catalogVersion"),
            "count": len(items),
            "items": items,
        }

    async with httpx.AsyncClient(timeout=45.0, follow_redirects=True) as client:
        r = await client.get(KEV_URL)
        r.raise_for_status()
        data = r.json()
    _cache_put("kev", "catalog", data)
    items = _normalize_kev_items(data.get("vulnerabilities") or [], limit=limit)
    return {
        "source": "cisa_kev",
        "cached": False,
        "catalog_version": data.get("catalogVersion"),
        "count": len(items),
        "items": items,
    }


async def lookup_nvd_cve(cve_id: str) -> dict[str, Any]:
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        raise ValueError("Provide a CVE-ID (e.g. CVE-2024-1234)")
    cached = _cache_get("nvd", cve, max_age_sec=604800)
    if cached:
        return {"source": "nvd", "cached": True, **cached}

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        r = await client.get(NVD_CVE_URL, params={"cveId": cve})
        if r.status_code == 404:
            raise ValueError("CVE not found in NVD")
        r.raise_for_status()
        data = r.json()

    items = data.get("vulnerabilities") or []
    if not items:
        raise ValueError("CVE not found in NVD")
    cve_obj = items[0].get("cve") or {}
    metrics = cve_obj.get("metrics") or {}
    cvss = None
    severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            cvss_data = (arr[0].get("cvssData") or {})
            cvss = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or arr[0].get("baseSeverity")
            break
    descs = cve_obj.get("descriptions") or []
    desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "") or (
        descs[0].get("value") if descs else ""
    )
    out = {
        "cve": cve,
        "cvss": cvss,
        "severity": severity,
        "description": (desc or "")[:1200],
        "published": cve_obj.get("published"),
        "last_modified": cve_obj.get("lastModified"),
    }
    _cache_put("nvd", cve, out)
    return {"source": "nvd", "cached": False, **out}


async def sync_kev_to_watchlist(user_id: str, *, limit: int = 25) -> dict[str, Any]:
    """Add newest KEV CVEs to the user's watchlist (skip duplicates)."""
    feed = await fetch_cisa_kev(limit=limit)
    existing = {(w.get("value") or "").upper() for w in list_intel_watch(user_id)}
    added = 0
    for item in feed.get("items") or []:
        cve = (item.get("cve") or "").upper()
        if not cve or cve in existing:
            continue
        notes = f"CISA KEV · {item.get('vendor')} {item.get('product')} · {item.get('name')}"[:400]
        add_intel_watch(user_id, kind="kev", value=cve, notes=notes)
        existing.add(cve)
        added += 1
    audit("intel_kev_sync", user_id, {"added": added, "limit": limit})
    try:
        from app.realtime_bus import publish

        publish(type="intel", source="kev_sync", added=added, user_id=user_id)
    except Exception:
        pass
    return {"ok": True, "added": added, "feed_count": feed.get("count"), "cached": feed.get("cached")}


async def alert_watchlist_on_kev(user_id: str = "local", *, feed: dict[str, Any] | None = None) -> dict[str, Any]:
    """Match intel watchlist CVEs against CISA KEV; notify + publish on hits / newly added KEV rows."""
    feed = feed or await fetch_cisa_kev(limit=200)
    items = [i for i in (feed.get("items") or []) if isinstance(i, dict) and i.get("cve")]
    by_cve = {(i.get("cve") or "").upper(): i for i in items}

    # Track catalog membership so we can detect *new* KEV CVEs between syncs
    prev = _cache_get("kev", "cve_set", max_age_sec=10**9) or {}
    prev_set = {str(x).upper() for x in (prev.get("cves") or []) if x}
    cur_set = set(by_cve.keys())
    newly_added = (cur_set - prev_set) if prev_set else set()
    _cache_put("kev", "cve_set", {"cves": sorted(cur_set)[:8000], "catalog_version": feed.get("catalog_version")})

    watch = list_intel_watch(user_id)
    watch_cves = {
        (w.get("value") or "").upper(): w
        for w in watch
        if (w.get("value") or "").upper().startswith("CVE-")
    }
    matches = [by_cve[c] for c in watch_cves if c in by_cve]
    new_hits = [by_cve[c] for c in newly_added if c in watch_cves]

    if matches or newly_added:
        try:
            from app.realtime_bus import publish

            publish(
                type="intel",
                source="kev",
                watch_matches=len(matches),
                newly_added=len(newly_added),
                new_watch_hits=len(new_hits),
                cached=bool(feed.get("cached")),
                user_id=user_id,
            )
        except Exception:
            pass

    if new_hits or (matches and not prev_set):
        # Notify on first-ever match set, or when a watched CVE newly enters KEV
        from app.notifications import notify

        hit_list = new_hits or matches[:5]
        for item in hit_list[:8]:
            cve = item.get("cve") or "?"
            notify(
                user_id,
                "intel_watch",
                f"Watchlist CVE on CISA KEV: {cve}",
                f"{item.get('vendor') or ''} {item.get('product') or ''} · {item.get('name') or ''}".strip()[:400],
                link="/#intel",
                email=False,
            )

    audit(
        "intel_kev_watch_check",
        user_id,
        {"matches": len(matches), "newly_added": len(newly_added), "new_hits": len(new_hits)},
    )
    return {
        "ok": True,
        "watch_matches": len(matches),
        "newly_added_kev": len(newly_added),
        "new_watch_hits": len(new_hits),
        "match_cves": [m.get("cve") for m in matches[:20]],
        "cached": feed.get("cached"),
    }
