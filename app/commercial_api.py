"""Commercial workspace APIs: auth, engagements, chats, files, memory, export, audit."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from app.auth import (
    AuthUser,
    complete_mfa_login,
    create_api_key,
    ensure_bootstrap_admin,
    list_api_keys,
    login,
    logout,
    register_user,
    request_password_reset,
    reset_password_with_token,
    resolve_user,
    revoke_api_key,
    session_cookie_kwargs,
)
from app.config import settings
from app.db import get_conn, now as db_now
from app.export_report import export_chat_markdown, export_engagement_summary
from app.model_router import route_task
from app.uploads import list_files, save_upload
from app.workspace import (
    ENGAGEMENT_STATUSES,
    append_message,
    create_chat,
    create_engagement,
    delete_chat,
    get_chat,
    list_audit,
    list_chats,
    list_engagements,
    list_memories,
    list_messages,
    set_memory,
    transition_engagement_status,
    update_engagement,
)

router = APIRouter(prefix="/api", tags=["workspace"])


class LoginRequest(BaseModel):
    username: str
    password: str
    totp: str | None = None


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    totp: str


class MfaConfirmRequest(BaseModel):
    code: str


class MfaDisableRequest(BaseModel):
    code: str


class RegisterRequest(BaseModel):
    username: str
    password: str = Field(min_length=8)
    email: str | None = None


class PasswordResetRequest(BaseModel):
    username: str


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=8)


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope_notes: str = ""
    scope_json: list[str] | str | None = None
    status: str = "active"


class EngagementUpdate(BaseModel):
    name: str | None = None
    scope_notes: str | None = None
    scope_json: list[str] | str | None = None


class EngagementStatusUpdate(BaseModel):
    status: str


class ChatCreate(BaseModel):
    title: str = "New chat"
    mode: str = "default"
    engagement_id: str | None = None


class MessageCreate(BaseModel):
    role: str
    content: str


class MemorySet(BaseModel):
    key: str
    value: str


class RouteRequest(BaseModel):
    message: str
    mode: str = "default"


class ApiKeyCreate(BaseModel):
    name: str = "default"


def _attach_session_cookie(response: Response, token: str) -> None:
    kw = session_cookie_kwargs()
    name = kw.pop("key")
    response.set_cookie(name, token, **kw)


def _clear_session_cookie(response: Response) -> None:
    name = session_cookie_kwargs()["key"]
    response.delete_cookie(name, path="/")


def current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_securaiq_key: Annotated[str | None, Header(alias="X-SecuraIQ-Key")] = None,
    x_hackgpt_key: Annotated[str | None, Header(alias="X-HackGPT-Key")] = None,
) -> AuthUser | None:
    cookie_name = getattr(settings, "session_cookie_name", "securaiq_session") or "securaiq_session"
    cookie_val = request.cookies.get(cookie_name)
    return resolve_user(authorization, x_securaiq_key or x_hackgpt_key, cookie_val)


_MFA_ENFORCEMENT_EXEMPT_PATHS = {
    "/api/auth/status",
    "/api/auth/logout",
    "/api/auth/mfa/enroll",
    "/api/auth/mfa/confirm",
    "/api/auth/mfa/disable",
}


def require_user(
    request: Request,
    user: Annotated[AuthUser | None, Depends(current_user)],
) -> AuthUser:
    if not settings.auth_enabled:
        # Anonymous local mode — synthetic user for workspace when auth off
        if user:
            return user
        return AuthUser(id="local", username="local", role="admin")
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Operational gap fix: MFA_REQUIRED_FOR_ADMIN was only ever surfaced as a
    # UI hint (auth_status.mfa_enrollment_required) — nothing actually blocked
    # API access for an admin who ignored the prompt. Enforce it server-side,
    # exempting the handful of endpoints an admin needs to complete enrollment.
    if (
        settings.mfa_required_for_admin
        and user.role == "admin"
        and request.url.path not in _MFA_ENFORCEMENT_EXEMPT_PATHS
    ):
        from app.mfa import mfa_status

        if not mfa_status(user.id).get("enabled"):
            raise HTTPException(
                status_code=403,
                detail=(
                    "MFA enrollment required for admin accounts before continuing. "
                    "Enroll via POST /api/auth/mfa/enroll, confirm via POST /api/auth/mfa/confirm."
                ),
            )

    return user


@router.get("/auth/status")
async def auth_status(user: Annotated[AuthUser | None, Depends(current_user)]):
    from app.mfa import mfa_status
    from app.oidc import oidc_configured

    mfa = mfa_status(user.id) if user and user.id != "local" else {"enabled": False, "enrolled": False}
    admin_must_mfa = (
        settings.mfa_required_for_admin
        and user
        and user.role == "admin"
        and not mfa.get("enabled")
        and settings.auth_enabled
    )
    return {
        "auth_enabled": settings.auth_enabled,
        "allow_register": settings.auth_allow_register,
        "authenticated": bool(user) or not settings.auth_enabled,
        "oidc_enabled": oidc_configured(),
        "mfa": mfa,
        "mfa_enrollment_required": admin_must_mfa,
        "user": {"id": user.id, "username": user.username, "role": user.role} if user else (
            {"id": "local", "username": "local", "role": "admin"} if not settings.auth_enabled else None
        ),
    }


@router.post("/auth/register")
async def auth_register(req: RegisterRequest):
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Auth disabled")
    if not settings.auth_allow_register:
        raise HTTPException(status_code=403, detail="Registration closed")
    try:
        u = register_user(req.username, req.password, email=req.email)
        result = login(req.username, req.password)
        if isinstance(result, dict):
            return {"user": {"id": u.id, "username": u.username, "role": u.role}, **result}
        user, token = result
        body = {"user": {"id": user.id, "username": user.username, "role": user.role}, "token": token}
        resp = JSONResponse(body)
        _attach_session_cookie(resp, token)
        return resp
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/auth/login")
async def auth_login(req: LoginRequest):
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Auth disabled — set AUTH_ENABLED=true")
    try:
        result = login(req.username, req.password, totp=req.totp)
        if isinstance(result, dict):
            return result
        user, token = result
        body = {"user": {"id": user.id, "username": user.username, "role": user.role}, "token": token}
        resp = JSONResponse(body)
        _attach_session_cookie(resp, token)
        return resp
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.post("/auth/password-reset/request")
async def auth_password_reset_request(req: PasswordResetRequest):
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Auth disabled — set AUTH_ENABLED=true")
    return request_password_reset(req.username)


@router.post("/auth/password-reset/confirm")
async def auth_password_reset_confirm(req: PasswordResetConfirm):
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Auth disabled — set AUTH_ENABLED=true")
    try:
        reset_password_with_token(req.token, req.new_password)
        return {"ok": True, "message": "Password updated — sign in with the new password"}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/auth/mfa/verify")
async def auth_mfa_verify(req: MfaVerifyRequest):
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Auth disabled")
    try:
        user, token = complete_mfa_login(req.mfa_token, req.totp)
        body = {"user": {"id": user.id, "username": user.username, "role": user.role}, "token": token}
        resp = JSONResponse(body)
        _attach_session_cookie(resp, token)
        return resp
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.post("/auth/mfa/enroll")
async def auth_mfa_enroll(user: Annotated[AuthUser, Depends(require_user)]):
    if user.id == "local":
        raise HTTPException(status_code=400, detail="Enable AUTH_ENABLED first")
    from app.mfa import mfa_enroll_start

    return mfa_enroll_start(user.id, username=user.username)


@router.post("/auth/mfa/confirm")
async def auth_mfa_confirm(req: MfaConfirmRequest, user: Annotated[AuthUser, Depends(require_user)]):
    from app.mfa import mfa_enroll_confirm

    try:
        mfa_enroll_confirm(user.id, req.code)
        return {"ok": True, "mfa_enabled": True}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/auth/mfa/disable")
async def auth_mfa_disable(req: MfaDisableRequest, user: Annotated[AuthUser, Depends(require_user)]):
    from app.mfa import mfa_disable

    try:
        mfa_disable(user.id, req.code)
        return {"ok": True, "mfa_enabled": False}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/auth/oidc/login")
async def auth_oidc_login():
    from app.oidc import build_authorize_url, oidc_configured

    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Enable AUTH_ENABLED for SSO")
    if not oidc_configured():
        raise HTTPException(status_code=503, detail="OIDC not configured — set OIDC_* in .env")
    from fastapi.responses import RedirectResponse

    url = await build_authorize_url()
    return RedirectResponse(url=url, status_code=302)


@router.get("/auth/oidc/callback")
async def auth_oidc_callback(code: str | None = None, state: str | None = None, error: str | None = None):
    from app.oidc import (
        consume_oidc_state,
        create_session_for_user,
        exchange_code,
        oidc_configured,
        provision_oidc_user,
    )

    if error:
        raise HTTPException(status_code=400, detail=f"OIDC error: {error}")
    if not code or not state or not consume_oidc_state(state):
        raise HTTPException(status_code=400, detail="Invalid OIDC state")
    if not oidc_configured():
        raise HTTPException(status_code=503, detail="OIDC not configured")
    try:
        profile = await exchange_code(code)
        user = provision_oidc_user(profile)
        token = create_session_for_user(user)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OIDC login failed: {exc}") from exc
    from fastapi.responses import HTMLResponse

    # Return minimal page that stores token for SPA
    html = f"""<!DOCTYPE html><html><body><p>Signing in…</p><script>
localStorage.setItem('securaiq.authToken', {json.dumps(token)});
window.location.href = '/';
</script></body></html>"""
    return HTMLResponse(html)


@router.post("/auth/logout")
async def auth_logout(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
):
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token:
        cookie_name = getattr(settings, "session_cookie_name", "securaiq_session") or "securaiq_session"
        token = request.cookies.get(cookie_name)
    logout(token)
    resp = JSONResponse({"ok": True})
    _clear_session_cookie(resp)
    return resp


@router.post("/auth/api-keys")
async def auth_api_key(req: ApiKeyCreate, user: Annotated[AuthUser, Depends(require_user)]):
    if user.id == "local" and not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Enable AUTH_ENABLED to create API keys")
    raw, meta = create_api_key(user.id, req.name)
    return {"api_key": raw, **meta, "note": "Store this key now — it will not be shown again."}


@router.get("/auth/api-keys")
async def auth_api_keys_list(user: Annotated[AuthUser, Depends(require_user)]):
    if user.id == "local" and not settings.auth_enabled:
        return {"api_keys": []}
    return {"api_keys": list_api_keys(user.id)}


@router.delete("/auth/api-keys/{key_id}")
async def auth_api_key_revoke(key_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not revoke_api_key(user.id, key_id):
        raise HTTPException(status_code=404, detail="API key not found")
    return {"ok": True}


@router.get("/engagements")
async def eng_list(
    user: Annotated[AuthUser, Depends(require_user)],
    status: str | None = None,
):
    if status and status not in ENGAGEMENT_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(ENGAGEMENT_STATUSES)}")
    return {"engagements": list_engagements(user.id, status), "statuses": list(ENGAGEMENT_STATUSES)}


@router.post("/engagements")
async def eng_create(req: EngagementCreate, user: Annotated[AuthUser, Depends(require_user)]):
    if req.status not in ENGAGEMENT_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(ENGAGEMENT_STATUSES)}")
    return create_engagement(user.id, req.name, req.scope_notes, req.status, scope_json=req.scope_json)


@router.patch("/engagements/{engagement_id}")
async def eng_update(engagement_id: str, req: EngagementUpdate, user: Annotated[AuthUser, Depends(require_user)]):
    out = update_engagement(user.id, engagement_id, req.name, req.scope_notes, scope_json=req.scope_json)
    if not out:
        raise HTTPException(status_code=404, detail="Not found")
    return out


@router.post("/engagements/{engagement_id}/status")
async def eng_status(
    engagement_id: str,
    req: EngagementStatusUpdate,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """Move an engagement through its lifecycle (draft → active → on_hold/completed → archived).
    on_hold represents a partial/paused engagement — distinct from completed or archived.
    """
    try:
        return transition_engagement_status(user.id, engagement_id, req.status)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/chats")
async def chats_list(user: Annotated[AuthUser, Depends(require_user)], engagement_id: str | None = None):
    return {"chats": list_chats(user.id, engagement_id)}


@router.post("/chats")
async def chats_create(req: ChatCreate, user: Annotated[AuthUser, Depends(require_user)]):
    return create_chat(user.id, req.title, req.mode, req.engagement_id)


@router.get("/chats/{chat_id}")
async def chats_get(chat_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    chat = get_chat(user.id, chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Not found")
    return {"chat": chat, "messages": list_messages(user.id, chat_id)}


@router.delete("/chats/{chat_id}")
async def chats_delete(chat_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_chat(user.id, chat_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.post("/chats/{chat_id}/messages")
async def chats_message(chat_id: str, req: MessageCreate, user: Annotated[AuthUser, Depends(require_user)]):
    if req.role not in {"user", "assistant", "system"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    msg = append_message(user.id, chat_id, req.role, req.content)
    if not msg:
        raise HTTPException(status_code=404, detail="Chat not found")
    return msg


@router.get("/engagements/{engagement_id}/memories")
async def mem_list(engagement_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    return {"memories": list_memories(user.id, engagement_id)}


@router.post("/engagements/{engagement_id}/memories")
async def mem_set(engagement_id: str, req: MemorySet, user: Annotated[AuthUser, Depends(require_user)]):
    out = set_memory(user.id, engagement_id, req.key, req.value)
    if not out:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return out


@router.post("/files")
async def files_upload(
    user: Annotated[AuthUser, Depends(require_user)],
    file: UploadFile = File(...),
    engagement_id: str | None = None,
    ingest: bool = True,
):
    data = await file.read()
    try:
        return save_upload(user.id, file.filename or "upload.bin", data, engagement_id, ingest)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/files")
async def files_list(user: Annotated[AuthUser, Depends(require_user)], engagement_id: str | None = None):
    return {"files": list_files(user.id, engagement_id)}


@router.get("/chats/{chat_id}/export")
async def chat_export(chat_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        md = export_chat_markdown(user.id, chat_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return PlainTextResponse(md, media_type="text/markdown; charset=utf-8")


@router.get("/engagements/{engagement_id}/export")
async def eng_export(engagement_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return export_engagement_summary(user.id, engagement_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/router")
async def model_route(req: RouteRequest):
    return route_task(req.message, req.mode)


@router.get("/notifications")
async def notifications_list(
    user: Annotated[AuthUser, Depends(require_user)],
    unread_only: bool = False,
    limit: int = 50,
):
    from app.notifications import list_notifications, unread_count

    return {
        "notifications": list_notifications(user.id, unread_only, limit),
        "unread_count": unread_count(user.id),
    }


@router.post("/notifications/{notification_id}/read")
async def notifications_mark_read(notification_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    from app.notifications import mark_read

    if not mark_read(user.id, notification_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.post("/notifications/read-all")
async def notifications_mark_all_read(user: Annotated[AuthUser, Depends(require_user)]):
    from app.notifications import mark_all_read

    return {"ok": True, "marked": mark_all_read(user.id)}


@router.get("/audit")
async def audit_list(user: Annotated[AuthUser, Depends(require_user)], limit: int = 100):
    if settings.auth_enabled and user.role != "admin" and user.id != "local":
        raise HTTPException(status_code=403, detail="Admin only")
    return {"events": list_audit(limit)}


@router.get("/audit/export")
async def audit_export(user: Annotated[AuthUser, Depends(require_user)], limit: int = 500):
    if settings.auth_enabled and user.role != "admin" and user.id != "local":
        raise HTTPException(status_code=403, detail="Admin only")
    from fastapi.responses import PlainTextResponse

    events = list_audit(min(500, max(1, limit)))
    lines = ["id,user_id,action,created_at,detail"]
    for ev in events:
        detail = json.dumps(ev.get("detail") or {}, ensure_ascii=False).replace('"', '""')
        lines.append(
            f"{ev.get('id')},{ev.get('user_id') or ''},{ev.get('action')},{ev.get('created_at')},\"{detail}\""
        )
    return PlainTextResponse("\n".join(lines), media_type="text/csv; charset=utf-8")


def bootstrap_auth() -> None:
    if settings.auth_enabled:
        ensure_bootstrap_admin()
        return
    c = get_conn()
    row = c.execute("SELECT id FROM users WHERE id = 'local'").fetchone()
    if not row:
        c.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ("local", "local", "local-open-mode", "admin", db_now()),
        )
        c.commit()
