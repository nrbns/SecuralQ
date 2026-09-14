"""Engagements, chats, messages, memories."""

from __future__ import annotations

import json
from typing import Any

from app.db import audit, get_conn, new_id, now, row_to_dict


ENGAGEMENT_STATUSES = ("draft", "active", "on_hold", "completed", "archived")

# Multi-project lifecycle: what status an engagement may move to next.
# "partial" engagements live in on_hold (paused mid-way) rather than being
# force-closed or force-active.
ENGAGEMENT_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"active", "archived"},
    "active": {"on_hold", "completed", "archived"},
    "on_hold": {"active", "completed", "archived"},
    "completed": {"archived"},
    "archived": set(),
}


def create_engagement(
    user_id: str,
    name: str,
    scope_notes: str = "",
    status: str = "active",
    scope_json: str | list | None = None,
    cmmc_enclave_architecture: str = "",
) -> dict[str, Any]:
    if status not in ENGAGEMENT_STATUSES:
        status = "active"
    from app.commercial_ext import ensure_org_schema
    from app.cmmc_enclave_architecture import normalize_enclave_architecture
    from app.services.tool_policy import scope_to_storage

    ensure_org_schema()
    eid = new_id()
    t = now()
    scope_stored = scope_to_storage(scope_json)
    enclave = normalize_enclave_architecture(cmmc_enclave_architecture)
    c = get_conn()
    c.execute(
        """
        INSERT INTO engagements
        (id, user_id, name, scope_notes, scope_json, status, cmmc_enclave_architecture, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (eid, user_id, (name or "Engagement").strip(), scope_notes or "", scope_stored, status, enclave, t, t),
    )
    c.commit()
    audit("engagement_create", user_id, {"id": eid, "name": name, "status": status, "scope_size": len(json.loads(scope_stored or "[]"))})
    return get_engagement(user_id, eid)  # type: ignore[return-value]


def list_engagements(user_id: str, status: str | None = None) -> list[dict[str, Any]]:
    c = get_conn()
    if status:
        rows = c.execute(
            "SELECT * FROM engagements WHERE user_id = ? AND status = ? ORDER BY updated_at DESC",
            (user_id, status),
        ).fetchall()
    else:
        rows = c.execute(
            "SELECT * FROM engagements WHERE user_id = ? ORDER BY updated_at DESC",
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def transition_engagement_status(user_id: str, engagement_id: str, new_status: str) -> dict[str, Any]:
    """Move an engagement to a new lifecycle stage, enforcing valid transitions
    so a completed/archived engagement can't be silently reopened by accident.
    """
    eng = get_engagement(user_id, engagement_id)
    if not eng:
        raise LookupError("Engagement not found")
    if new_status not in ENGAGEMENT_STATUSES:
        raise ValueError(f"Unknown status '{new_status}'. Must be one of: {', '.join(ENGAGEMENT_STATUSES)}")
    current = eng.get("status") or "active"
    if new_status == current:
        return eng
    allowed = ENGAGEMENT_TRANSITIONS.get(current, set())
    if new_status not in allowed:
        raise ValueError(
            f"Cannot move engagement from '{current}' to '{new_status}'. "
            f"Allowed from '{current}': {sorted(allowed) or 'none (terminal state)'}"
        )
    c = get_conn()
    c.execute(
        "UPDATE engagements SET status = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (new_status, now(), engagement_id, user_id),
    )
    c.commit()
    audit("engagement_status_change", user_id, {"id": engagement_id, "from": current, "to": new_status})
    return get_engagement(user_id, engagement_id)  # type: ignore[return-value]


def get_engagement(user_id: str, engagement_id: str) -> dict[str, Any] | None:
    c = get_conn()
    row = c.execute(
        "SELECT * FROM engagements WHERE id = ? AND user_id = ?",
        (engagement_id, user_id),
    ).fetchone()
    return row_to_dict(row)


def update_engagement(
    user_id: str,
    engagement_id: str,
    name: str | None = None,
    scope_notes: str | None = None,
    scope_json: str | list | None = None,
    cmmc_enclave_architecture: str | None = None,
) -> dict[str, Any] | None:
    from app.commercial_ext import ensure_org_schema

    ensure_org_schema()
    eng = get_engagement(user_id, engagement_id)
    if not eng:
        return None
    from app.cmmc_enclave_architecture import normalize_enclave_architecture
    from app.services.tool_policy import scope_to_storage

    next_scope = eng.get("scope_json") or "[]"
    if scope_json is not None:
        next_scope = scope_to_storage(scope_json)
    next_enclave = eng.get("cmmc_enclave_architecture") or ""
    if cmmc_enclave_architecture is not None:
        next_enclave = normalize_enclave_architecture(cmmc_enclave_architecture)
    c = get_conn()
    c.execute(
        """
        UPDATE engagements
        SET name = ?, scope_notes = ?, scope_json = ?, cmmc_enclave_architecture = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
        """,
        (
            name if name is not None else eng["name"],
            scope_notes if scope_notes is not None else eng["scope_notes"],
            next_scope,
            next_enclave,
            now(),
            engagement_id,
            user_id,
        ),
    )
    c.commit()
    return get_engagement(user_id, engagement_id)


def create_chat(
    user_id: str,
    title: str = "New chat",
    mode: str = "default",
    engagement_id: str | None = None,
) -> dict[str, Any]:
    cid = new_id()
    t = now()
    c = get_conn()
    if engagement_id and not get_engagement(user_id, engagement_id):
        engagement_id = None
    c.execute(
        "INSERT INTO chats (id, engagement_id, user_id, title, mode, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (cid, engagement_id, user_id, (title or "New chat")[:120], mode or "default", t, t),
    )
    c.commit()
    audit("chat_create", user_id, {"id": cid, "engagement_id": engagement_id})
    return get_chat(user_id, cid)  # type: ignore[return-value]


def list_chats(user_id: str, engagement_id: str | None = None) -> list[dict[str, Any]]:
    c = get_conn()
    if engagement_id:
        rows = c.execute(
            "SELECT * FROM chats WHERE user_id = ? AND engagement_id = ? ORDER BY updated_at DESC",
            (user_id, engagement_id),
        ).fetchall()
    else:
        rows = c.execute(
            "SELECT * FROM chats WHERE user_id = ? ORDER BY updated_at DESC LIMIT 100",
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_chat(user_id: str, chat_id: str) -> dict[str, Any] | None:
    c = get_conn()
    row = c.execute(
        "SELECT * FROM chats WHERE id = ? AND user_id = ?",
        (chat_id, user_id),
    ).fetchone()
    return row_to_dict(row)


def append_message(user_id: str, chat_id: str, role: str, content: str) -> dict[str, Any] | None:
    chat = get_chat(user_id, chat_id)
    if not chat:
        return None
    mid = new_id()
    t = now()
    c = get_conn()
    c.execute(
        "INSERT INTO messages (id, chat_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (mid, chat_id, role, content, t),
    )
    title = chat["title"]
    if title in {"New chat", "Untitled"} and role == "user":
        title = (content.strip().split("\n")[0] or title)[:80]
    c.execute(
        "UPDATE chats SET title = ?, updated_at = ? WHERE id = ?",
        (title, t, chat_id),
    )
    if chat.get("engagement_id"):
        c.execute(
            "UPDATE engagements SET updated_at = ? WHERE id = ?",
            (t, chat["engagement_id"]),
        )
    c.commit()
    return {"id": mid, "chat_id": chat_id, "role": role, "content": content, "created_at": t}


def list_messages(user_id: str, chat_id: str, limit: int = 200) -> list[dict[str, Any]]:
    if not get_chat(user_id, chat_id):
        return []
    c = get_conn()
    rows = c.execute(
        "SELECT * FROM messages WHERE chat_id = ? ORDER BY created_at ASC LIMIT ?",
        (chat_id, max(1, min(limit, 500))),
    ).fetchall()
    return [dict(r) for r in rows]


def delete_chat(user_id: str, chat_id: str) -> bool:
    if not get_chat(user_id, chat_id):
        return False
    c = get_conn()
    c.execute("DELETE FROM chats WHERE id = ? AND user_id = ?", (chat_id, user_id))
    c.commit()
    audit("chat_delete", user_id, {"id": chat_id})
    return True


def set_memory(user_id: str, engagement_id: str, key: str, value: str) -> dict[str, Any] | None:
    if not get_engagement(user_id, engagement_id):
        return None
    key = (key or "").strip()[:120]
    if not key:
        return None
    c = get_conn()
    mid = new_id()
    t = now()
    c.execute(
        "INSERT INTO memories (id, engagement_id, key, value, created_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(engagement_id, key) DO UPDATE SET value = excluded.value, created_at = excluded.created_at",
        (mid, engagement_id, key, value, t),
    )
    c.commit()
    audit("memory_set", user_id, {"engagement_id": engagement_id, "key": key})
    return {"engagement_id": engagement_id, "key": key, "value": value}


def list_memories(user_id: str, engagement_id: str) -> list[dict[str, Any]]:
    if not get_engagement(user_id, engagement_id):
        return []
    c = get_conn()
    rows = c.execute(
        "SELECT key, value, created_at FROM memories WHERE engagement_id = ? ORDER BY key",
        (engagement_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def memory_context(user_id: str, engagement_id: str | None) -> str:
    if not engagement_id:
        return ""
    if user_id != "local" and not get_engagement(user_id, engagement_id):
        return ""
    return memory_context_raw(engagement_id)


def memory_context_raw(engagement_id: str) -> str:
    c = get_conn()
    rows = c.execute(
        "SELECT key, value FROM memories WHERE engagement_id = ? ORDER BY key LIMIT 40",
        (engagement_id,),
    ).fetchall()
    if not rows:
        return ""
    lines = ["## Engagement memory"]
    for m in rows:
        lines.append(f"- **{m['key']}**: {m['value']}")
    return "\n".join(lines)


def list_audit(limit: int = 100) -> list[dict[str, Any]]:
    c = get_conn()
    rows = c.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?",
        (max(1, min(limit, 500)),),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["detail"] = json.loads(d.get("detail") or "{}")
        except Exception:
            pass
        out.append(d)
    return out
