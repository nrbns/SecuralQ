"""Billing/usage API — plans, usage snapshot, Stripe checkout + webhook."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth import AuthUser
from app.billing import PLANS, usage_snapshot
from app.commercial_api import require_user

router = APIRouter(prefix="/api/billing", tags=["billing"])


@router.get("/plans")
async def billing_plans():
    return {"plans": PLANS}


@router.get("/usage")
async def billing_usage(user: Annotated[AuthUser, Depends(require_user)]):
    return usage_snapshot(user.id)


class CheckoutRequest(BaseModel):
    plan: str
    success_url: str
    cancel_url: str


class PortalRequest(BaseModel):
    return_url: str


@router.post("/checkout")
async def billing_checkout(req: CheckoutRequest, user: Annotated[AuthUser, Depends(require_user)]):
    from app.billing_stripe import create_checkout_session, is_configured

    if not is_configured():
        raise HTTPException(
            status_code=501,
            detail=(
                "Billing isn't configured yet — this requires a Stripe account and pricing "
                "decisions that only the SecuraIQ operator can make. See app/billing_stripe.py."
            ),
        )
    if req.plan not in PLANS or req.plan == "free":
        raise HTTPException(status_code=400, detail=f"plan must be a paid plan: {[p for p in PLANS if p != 'free']}")
    try:
        email = user.username if "@" in user.username else f"{user.username}@localhost"
        return await create_checkout_session(
            plan=req.plan,
            customer_email=email,
            success_url=req.success_url,
            cancel_url=req.cancel_url,
            user_id=user.id,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/portal")
async def billing_portal(req: PortalRequest, user: Annotated[AuthUser, Depends(require_user)]):
    """Stripe Customer Portal — manage subscription / payment methods / invoices."""
    from app.billing_stripe import create_billing_portal_session, is_configured

    if not is_configured():
        raise HTTPException(status_code=501, detail="Stripe not configured")
    email = user.username if "@" in getattr(user, "username", "") else f"{user.username}@localhost"
    try:
        return await create_billing_portal_session(
            customer_email=email,
            return_url=req.return_url,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/downloads")
async def billing_downloads(user: Annotated[AuthUser, Depends(require_user)]):
    """Entitlement-gated agent package catalog for the Billing download portal."""
    from app.agents_api import list_built_packages
    from app.license_service import effective_entitlements

    ents = effective_entitlements(user.id) or {}
    packages = list_built_packages()
    return {
        "ok": True,
        "plan": ents.get("plan") or "free",
        "plan_label": ents.get("plan_label"),
        "max_agents": ents.get("max_agents"),
        "mode": ents.get("mode"),
        "packages": packages,
        "download_base": "/api/agents/packages",
        "note": "Auth-gated package list — same artifacts as Agents → packages. Signing requires CI secrets.",
    }


@router.post("/webhook")
async def billing_webhook(request: Request):
    from app.billing_stripe import apply_checkout_completed, verify_webhook_signature

    body = await request.body()
    sig = request.headers.get("stripe-signature", "")
    if not verify_webhook_signature(body, sig):
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")

    import json

    event = json.loads(body)
    etype = event.get("type") or ""
    if etype == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        result = apply_checkout_completed(session if isinstance(session, dict) else {})
        return {"received": True, "license": result}
    if etype in (
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.paid",
        "invoice.payment_failed",
    ):
        try:
            from app.realtime_events import publish_aliased

            obj = event.get("data", {}).get("object") or {}
            publish_aliased(
                "license.updated",
                aliases=["entitlement.changed"],
                stripe_event=etype,
                status=obj.get("status"),
                customer=obj.get("customer"),
                source="stripe_webhook",
            )
        except Exception:
            pass
        return {"received": True, "handled": etype}
    return {"received": True}
