"""SCIM 2.0 Users + Groups (RFC 7644) — enterprise IdP provisioning hook.

Honest status: Users list/create/GET/PATCH(minimal)/DELETE; Groups CRUD (minimal).
Not a full SCIM provider (no Bulk, no filter algebra, no full PatchOp).
Enable with SCIM_ENABLED=true and SCIM_TOKEN.

Auth: Authorization: Bearer <SCIM_TOKEN>  (or Basic with token as password).
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from app.auth import list_users_public, register_user
from app.config import settings
from app.db import get_conn, new_id, now, row_to_dict

router = APIRouter(prefix="/scim/v2", tags=["scim"])

_SCIM_CONTENT = "application/scim+json"


def _scim_enabled() -> bool:
    return bool(getattr(settings, "scim_enabled", False)) and bool(
        (getattr(settings, "scim_token", "") or "").strip()
    )


def _check_auth(authorization: str | None) -> None:
    if not _scim_enabled():
        raise HTTPException(
            status_code=503,
            detail="SCIM disabled — set SCIM_ENABLED=true and SCIM_TOKEN in Settings/.env",
        )
    token = (settings.scim_token or "").strip()
    auth = (authorization or "").strip()
    ok = False
    if auth.lower().startswith("bearer "):
        ok = secrets.compare_digest(auth[7:].strip(), token)
    elif auth.lower().startswith("basic "):
        import base64

        try:
            raw = base64.b64decode(auth[6:].strip()).decode("utf-8", errors="replace")
            _user, _, pwd = raw.partition(":")
            ok = secrets.compare_digest(pwd, token)
        except Exception:
            ok = False
    if not ok:
        raise HTTPException(
            status_code=401,
            detail="Invalid SCIM bearer/basic token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _ensure_groups_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS scim_groups (
            id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL DEFAULT '',
            members_json TEXT NOT NULL DEFAULT '[]',
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scim_groups_name ON scim_groups(display_name);
        """
    )
    c.commit()


def _user_resource(row: dict[str, Any]) -> dict[str, Any]:
    uid = row["id"]
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": uid,
        "userName": row.get("username") or "",
        "active": True,
        "emails": [{"value": row.get("email") or "", "primary": True}] if row.get("email") else [],
        "meta": {
            "resourceType": "User",
            "location": f"/scim/v2/Users/{uid}",
        },
        "roles": [{"value": row.get("role") or "user"}],
    }


def _group_resource(row: dict[str, Any]) -> dict[str, Any]:
    gid = row["id"]
    try:
        members = json.loads(row.get("members_json") or "[]")
    except Exception:
        members = []
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": gid,
        "displayName": row.get("display_name") or "",
        "members": [
            {
                "value": m.get("value") if isinstance(m, dict) else str(m),
                "display": (m.get("display") if isinstance(m, dict) else "") or "",
            }
            for m in members
        ],
        "meta": {
            "resourceType": "Group",
            "location": f"/scim/v2/Groups/{gid}",
            "created": row.get("created_at"),
            "lastModified": row.get("updated_at"),
        },
    }


@router.get("/ServiceProviderConfig")
async def sp_config(authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    return JSONResponse(
        content={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://github.com/nrbns/SecuraIQ-ai",
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": False, "maxResults": 100},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "SCIM_TOKEN as Bearer",
                    "primary": True,
                }
            ],
        },
        media_type=_SCIM_CONTENT,
    )


@router.get("/Users")
async def list_users(
    authorization: str | None = Header(default=None),
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=1, le=200),
):
    _check_auth(authorization)
    users = list_users_public()
    enriched = []
    c = get_conn()
    for u in users:
        row = c.execute("SELECT * FROM users WHERE id = ?", (u["id"],)).fetchone()
        enriched.append(row_to_dict(row) if row else u)
    slice_ = enriched[startIndex - 1 : startIndex - 1 + count]
    resources = [_user_resource(u) for u in slice_]
    return JSONResponse(
        content={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(enriched),
            "startIndex": startIndex,
            "itemsPerPage": len(resources),
            "Resources": resources,
        },
        media_type=_SCIM_CONTENT,
    )


@router.get("/Users/{user_id}")
async def get_user(user_id: str, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    row = get_conn().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return JSONResponse(content=_user_resource(dict(row)), media_type=_SCIM_CONTENT)


@router.post("/Users", status_code=201)
async def create_user(request: Request, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    body = await request.json()
    username = (body.get("userName") or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="userName required")
    temp = secrets.token_urlsafe(18)
    try:
        user = register_user(username, temp, role="user")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    emails = body.get("emails") or []
    email = ""
    if emails and isinstance(emails[0], dict):
        email = (emails[0].get("value") or "").strip()
    if email:
        get_conn().execute("UPDATE users SET email = ? WHERE id = ?", (email[:200], user.id))
        get_conn().commit()
    row = get_conn().execute("SELECT * FROM users WHERE id = ?", (user.id,)).fetchone()
    return JSONResponse(content=_user_resource(dict(row)), status_code=201, media_type=_SCIM_CONTENT)


@router.patch("/Users/{user_id}")
async def patch_user(user_id: str, request: Request, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    row = get_conn().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    body = await request.json()
    c = get_conn()
    ops = body.get("Operations") or []
    if not ops and body.get("userName"):
        ops = [{"op": "replace", "path": "userName", "value": body["userName"]}]
    for op in ops:
        path = (op.get("path") or "").lower()
        value = op.get("value")
        if "username" in path or path == "username":
            c.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (str(value).strip().lower()[:80], user_id),
            )
        elif "emails" in path and isinstance(value, str):
            c.execute("UPDATE users SET email = ? WHERE id = ?", (value[:200], user_id))
        elif "emails" in path and isinstance(value, list) and value:
            email = (value[0].get("value") if isinstance(value[0], dict) else str(value[0]))[:200]
            c.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
        elif path == "active" and value is False:
            c.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (f"disabled_{user_id[:8]}", user_id),
            )
    c.commit()
    row = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return JSONResponse(content=_user_resource(dict(row)), media_type=_SCIM_CONTENT)


@router.delete("/Users/{user_id}", status_code=204)
async def delete_user(user_id: str, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    c = get_conn()
    cur = c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    c.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return Response(status_code=204)


@router.get("/Groups")
async def list_groups(
    authorization: str | None = Header(default=None),
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=1, le=200),
):
    _check_auth(authorization)
    _ensure_groups_schema()
    rows = [
        row_to_dict(r)
        for r in get_conn()
        .execute("SELECT * FROM scim_groups ORDER BY display_name LIMIT 500")
        .fetchall()
    ]
    slice_ = rows[startIndex - 1 : startIndex - 1 + count]
    resources = [_group_resource(r) for r in slice_]
    return JSONResponse(
        content={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(rows),
            "startIndex": startIndex,
            "itemsPerPage": len(resources),
            "Resources": resources,
        },
        media_type=_SCIM_CONTENT,
    )


@router.get("/Groups/{group_id}")
async def get_group(group_id: str, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    _ensure_groups_schema()
    row = get_conn().execute("SELECT * FROM scim_groups WHERE id = ?", (group_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Group not found")
    return JSONResponse(content=_group_resource(row_to_dict(row)), media_type=_SCIM_CONTENT)


@router.post("/Groups", status_code=201)
async def create_group(request: Request, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    _ensure_groups_schema()
    body = await request.json()
    name = (body.get("displayName") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="displayName required")
    members = body.get("members") or []
    gid = new_id()
    t = now()
    get_conn().execute(
        """
        INSERT INTO scim_groups (id, display_name, members_json, meta_json, created_at, updated_at)
        VALUES (?, ?, ?, '{}', ?, ?)
        """,
        (gid, name[:200], json.dumps(members)[:8000], t, t),
    )
    get_conn().commit()
    row = get_conn().execute("SELECT * FROM scim_groups WHERE id = ?", (gid,)).fetchone()
    return JSONResponse(
        content=_group_resource(row_to_dict(row)), status_code=201, media_type=_SCIM_CONTENT
    )


@router.patch("/Groups/{group_id}")
async def patch_group(group_id: str, request: Request, authorization: str | None = Header(default=None)):
    """Minimal Group PATCH: displayName replace; members replace."""
    _check_auth(authorization)
    _ensure_groups_schema()
    row = get_conn().execute("SELECT * FROM scim_groups WHERE id = ?", (group_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Group not found")
    body = await request.json()
    d = row_to_dict(row)
    name = d.get("display_name") or ""
    try:
        members = json.loads(d.get("members_json") or "[]")
    except Exception:
        members = []
    ops = body.get("Operations") or []
    if not ops:
        if body.get("displayName"):
            ops.append({"op": "replace", "path": "displayName", "value": body["displayName"]})
        if "members" in body:
            ops.append({"op": "replace", "path": "members", "value": body["members"]})
    for op in ops:
        path = (op.get("path") or "").lower()
        value = op.get("value")
        if "displayname" in path:
            name = str(value or "")[:200]
        elif "members" in path:
            members = value if isinstance(value, list) else members
    t = now()
    get_conn().execute(
        """
        UPDATE scim_groups SET display_name = ?, members_json = ?, updated_at = ?
        WHERE id = ?
        """,
        (name, json.dumps(members)[:8000], t, group_id),
    )
    get_conn().commit()
    row = get_conn().execute("SELECT * FROM scim_groups WHERE id = ?", (group_id,)).fetchone()
    return JSONResponse(content=_group_resource(row_to_dict(row)), media_type=_SCIM_CONTENT)


@router.delete("/Groups/{group_id}", status_code=204)
async def delete_group(group_id: str, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    _ensure_groups_schema()
    cur = get_conn().execute("DELETE FROM scim_groups WHERE id = ?", (group_id,))
    get_conn().commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Group not found")
    return Response(status_code=204)


@router.get("/status")
async def scim_status():
    """Unauthenticated capability probe for Settings UI."""
    return {
        "enabled": bool(getattr(settings, "scim_enabled", False)),
        "token_set": bool((getattr(settings, "scim_token", "") or "").strip()),
        "ready": _scim_enabled(),
        "base_path": "/scim/v2",
        "supported": [
            "ServiceProviderConfig",
            "Users",
            "Users PATCH (minimal)",
            "Users DELETE",
            "Groups",
            "Groups PATCH (minimal)",
            "Groups DELETE",
        ],
        "not_supported": ["Bulk", "Filter", "full PatchOp algebra"],
        "hint": "Beta — set SCIM_ENABLED + SCIM_TOKEN; point IdP to /scim/v2",
    }
