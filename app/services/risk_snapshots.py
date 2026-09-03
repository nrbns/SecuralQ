"""Risk snapshots — the before/after half of the remediation feedback loop.

Detect -> Prioritize -> Approve -> Execute -> Verify closes the loop only
if the last step feeds back into the first number the user saw: the
organizational risk score. A snapshot is just that score (from
app.services.risk_priority.compute_org_risk_score) captured at a point in
time and tagged with a label ('before'/'after') and, optionally, the patch
campaign that triggered it — so a campaign detail view can show "Risk 82 ->
61" using two real, reproducible computations rather than a claimed number.
"""

from __future__ import annotations

from typing import Any

from app.db import get_conn, new_id, now


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_risk_snapshots (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'local',
            campaign_id TEXT NOT NULL DEFAULT '',
            label TEXT NOT NULL DEFAULT '',
            score REAL NOT NULL DEFAULT 0,
            band TEXT NOT NULL DEFAULT '',
            total_open INTEGER NOT NULL DEFAULT 0,
            kev_count INTEGER NOT NULL DEFAULT 0,
            critical_high_count INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_risk_snapshots_campaign ON securaiq_risk_snapshots(campaign_id, label)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_risk_snapshots_user ON securaiq_risk_snapshots(user_id, created_at)"
    )
    c.commit()


def snapshot_risk(user_id: str, *, campaign_id: str = "", label: str = "") -> dict[str, Any]:
    """Compute the current organizational risk score and record it. Callers
    (campaign creation for 'before', campaign terminal-state transitions
    for 'after') are expected to treat this as best-effort — a scoring
    hiccup should never block a campaign action, so callers wrap this in
    try/except themselves."""
    from app.services.risk_priority import compute_org_risk_score

    ensure_schema()
    result = compute_org_risk_score(user_id)
    sid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_risk_snapshots
        (id, user_id, campaign_id, label, score, band, total_open, kev_count, critical_high_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sid, user_id, campaign_id, label,
            result["score"], result["band"], result["total_open"],
            result["kev_count"], result["critical_high_count"], ts,
        ),
    )
    c.commit()
    return {"id": sid, "campaign_id": campaign_id, "label": label, "created_at": ts, **result}


_PERIODIC_MIN_INTERVAL_SEC = 24 * 3600  # at most one 'periodic' snapshot per day per user


def maybe_snapshot_periodic(user_id: str) -> dict[str, Any] | None:
    """Take a label='periodic' snapshot of the CURRENT real org risk score,
    but only if the most recent snapshot of any label is more than 24h old
    (or none exists yet). This is what gives the executive dashboard a
    trend line even for tenants with no patch-campaign activity -- without
    it, score_history would only ever have points where a campaign
    happened to run. Throttled to avoid unbounded row growth from every
    dashboard page load; best-effort, like snapshot_risk itself."""
    ensure_schema()
    c = get_conn()
    last = c.execute(
        "SELECT created_at FROM securaiq_risk_snapshots WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    if last and (now() - float(last["created_at"])) < _PERIODIC_MIN_INTERVAL_SEC:
        return None
    return snapshot_risk(user_id, label="periodic")


def get_score_history(user_id: str, *, days: int = 90, limit: int = 200) -> list[dict[str, Any]]:
    """Every snapshot (any label -- 'before'/'after' from campaigns and
    'periodic' from maybe_snapshot_periodic) in the last `days`, oldest
    first. This is real, reproducible history -- each point is an actual
    compute_org_risk_score() result at the time it was taken, not an
    interpolated or synthetic value. Sparse history (few or zero campaigns,
    dashboard not opened in a while) means a sparse or empty list; callers
    must not fabricate points to fill gaps."""
    ensure_schema()
    c = get_conn()
    cutoff = now() - days * 86400
    rows = c.execute(
        "SELECT * FROM securaiq_risk_snapshots WHERE user_id = ? AND created_at >= ? ORDER BY created_at ASC LIMIT ?",
        (user_id, cutoff, max(1, min(limit, 1000))),
    ).fetchall()
    return [dict(r) for r in rows]


def get_campaign_risk_delta(user_id: str, campaign_id: str) -> dict[str, Any] | None:
    """Returns {risk_before, risk_after, risk_reduction_pct, ...} for a
    campaign that has both a 'before' and 'after' snapshot, or None fields
    for whichever side hasn't happened yet (a still-active campaign has a
    'before' but no 'after')."""
    ensure_schema()
    c = get_conn()
    before = c.execute(
        "SELECT * FROM securaiq_risk_snapshots WHERE user_id = ? AND campaign_id = ? AND label = 'before' "
        "ORDER BY created_at ASC LIMIT 1",
        (user_id, campaign_id),
    ).fetchone()
    after = c.execute(
        "SELECT * FROM securaiq_risk_snapshots WHERE user_id = ? AND campaign_id = ? AND label = 'after' "
        "ORDER BY created_at DESC LIMIT 1",
        (user_id, campaign_id),
    ).fetchone()
    if not before and not after:
        return None
    before_d = dict(before) if before else None
    after_d = dict(after) if after else None
    reduction_pct = None
    if before_d and after_d and before_d["score"]:
        reduction_pct = round((before_d["score"] - after_d["score"]) / before_d["score"] * 100, 1)
    return {
        "risk_before": before_d["score"] if before_d else None,
        "risk_before_band": before_d["band"] if before_d else None,
        "risk_after": after_d["score"] if after_d else None,
        "risk_after_band": after_d["band"] if after_d else None,
        "risk_reduction_pct": reduction_pct,
    }
