"""Billing/usage API — plans, usage snapshot, Stripe checkout + webhook."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth import AuthUser
from app.billing import PLANS, set_user_plan, usage_snapshot
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
        return await create_checkout_session(
            plan=req.plan,
            customer_email=user.username if "@" in user.username else f"{user.username}@localhost",
            success_url=req.success_url,
            cancel_url=req.cancel_url,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/webhook")
async def billing_webhook(request: Request):
    from app.billing_stripe import verify_webhook_signature

    body = await request.body()
    sig = request.headers.get("stripe-signature", "")
    if not verify_webhook_signature(body, sig):
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")

    import json

    event = json.loads(body)
    if event.get("type") == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        plan = (session.get("metadata") or {}).get("plan")
        email = session.get("customer_email") or session.get("customer_details", {}).get("email")
        if plan and email:
            from app.db import get_conn

            row = get_conn().execute("SELECT id FROM users WHERE username = ?", (email.lower(),)).fetchone()
            if row:
                set_user_plan(row["id"], plan)
    return {"received": True}
