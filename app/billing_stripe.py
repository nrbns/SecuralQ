"""Stripe checkout + webhook plumbing.

Inert until `STRIPE_SECRET_KEY` is set — this is the piece of billing that
genuinely cannot be finished without you: a real Stripe account, chosen
price IDs, and pricing decisions. What's here is real, working integration
code (direct REST calls — no stripe SDK dependency added), not a mock; it
just has nothing to talk to until configured.

Setup once you have a Stripe account:
  1. Create Products/Prices in the Stripe dashboard for each paid plan
     (pro, team) and set STRIPE_PRICE_PRO / STRIPE_PRICE_TEAM.
  2. Set STRIPE_SECRET_KEY (sk_live_... or sk_test_...).
  3. Add a webhook endpoint in Stripe pointing at
     POST /api/billing/webhook, subscribe to `checkout.session.completed`,
     and set STRIPE_WEBHOOK_SECRET to the signing secret Stripe gives you.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

import httpx

from app.config import settings

STRIPE_API = "https://api.stripe.com/v1"

PRICE_ENV_BY_PLAN = {
    "pro": "stripe_price_pro",
    "team": "stripe_price_team",
}


def is_configured() -> bool:
    return bool(settings.stripe_secret_key)


async def create_checkout_session(
    *,
    plan: str,
    customer_email: str,
    success_url: str,
    cancel_url: str,
    user_id: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    if not is_configured():
        raise RuntimeError(
            "Stripe not configured. Set STRIPE_SECRET_KEY (and STRIPE_PRICE_PRO / "
            "STRIPE_PRICE_TEAM) in Settings/.env — see app/billing_stripe.py docstring."
        )
    price_field = PRICE_ENV_BY_PLAN.get(plan)
    price_id = getattr(settings, price_field, "") if price_field else ""
    if not price_id:
        raise ValueError(f"No Stripe price configured for plan '{plan}' (set STRIPE_PRICE_{plan.upper()}).")

    data = {
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "customer_email": customer_email,
        "metadata[plan]": plan,
    }
    if user_id:
        data["metadata[user_id]"] = user_id
        data["client_reference_id"] = user_id
    if org_id:
        data["metadata[org_id]"] = org_id
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(
            f"{STRIPE_API}/checkout/sessions",
            data=data,
            auth=(settings.stripe_secret_key, ""),
        )
    if resp.status_code >= 400:
        raise ValueError(f"Stripe error {resp.status_code}: {resp.text[:400]}")
    session = resp.json()
    return {"checkout_url": session.get("url"), "session_id": session.get("id")}


def apply_checkout_completed(session: dict[str, Any]) -> dict[str, Any]:
    """Map Stripe checkout.session.completed → plan + signed license refresh."""
    from app.billing import set_user_plan
    from app.db import get_conn
    from app.license_service import issue_license

    meta = session.get("metadata") or {}
    plan = (meta.get("plan") or "").strip().lower()
    user_id = (meta.get("user_id") or session.get("client_reference_id") or "").strip()
    org_id = (meta.get("org_id") or "").strip() or None
    email = (
        session.get("customer_email")
        or (session.get("customer_details") or {}).get("email")
        or ""
    )
    email = str(email).strip().lower()

    if not plan:
        return {"ok": False, "reason": "missing_plan"}

    row = None
    c = get_conn()
    if user_id:
        row = c.execute("SELECT id, email, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row and email:
        row = c.execute(
            "SELECT id, email, username FROM users WHERE lower(username) = ? OR lower(email) = ?",
            (email, email),
        ).fetchone()
    if not row:
        return {"ok": False, "reason": "user_not_found", "email": email or None}

    uid = row["id"]
    set_user_plan(uid, plan)
    # ~1 year subscription window; Stripe subscription.updated can refresh later.
    expires_at = time.time() + 365 * 86400
    lic = issue_license(uid, org_id=org_id, plan=plan, expires_at=expires_at, grace_days=14)
    return {
        "ok": True,
        "user_id": uid,
        "plan": plan,
        "org_id": org_id,
        "license_id": lic.get("id"),
    }

def verify_webhook_signature(payload: bytes, sig_header: str, tolerance_sec: int = 300) -> bool:
    """Verify Stripe's `Stripe-Signature` header per their documented scheme
    (HMAC-SHA256 over `{timestamp}.{payload}`) — stdlib hmac, no SDK needed."""
    if not settings.stripe_webhook_secret or not sig_header:
        return False
    parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
    timestamp = parts.get("t")
    signature = parts.get("v1")
    if not timestamp or not signature:
        return False
    try:
        if abs(time.time() - int(timestamp)) > tolerance_sec:
            return False
    except ValueError:
        return False
    signed_payload = f"{timestamp}.{payload.decode('utf-8')}".encode("utf-8")
    expected = hmac.new(
        settings.stripe_webhook_secret.encode("utf-8"), signed_payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
