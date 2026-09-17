"""Engagement file uploads → local store + optional RAG ingest + chat attachments."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

from app.config import settings
from app.db import audit, get_conn, new_id, now
from app.rag import rag_engine
from app.upload_validation import check_magic_bytes, check_user_quota
from app.workspace import get_engagement

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

# Chat-style uploads: docs, code, configs, images (authorized work only)
_TEXT_EXT = {
    ".md", ".txt", ".pdf", ".json", ".csv", ".log", ".xml", ".html", ".htm",
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".rs", ".rb", ".php", ".cs", ".c", ".cpp", ".h", ".hpp",
    ".kt", ".swift", ".scala", ".sql", ".sh", ".ps1", ".bat", ".cmd",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env.example",
    ".dockerfile", ".makefile", ".gradle", ".properties",
    ".css", ".scss", ".less", ".vue", ".svelte",
    ".ipynb", ".r", ".lua", ".pl", ".pm",
}
_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"}
_ALLOWED_EXT = _TEXT_EXT | _IMAGE_EXT | {".zip"}  # zip stored but not fully extracted in MVP


def uploads_root() -> Path:
    root = Path(settings.data_dir) / "uploads"
    root.mkdir(parents=True, exist_ok=True)
    return root


def save_upload(
    user_id: str,
    filename: str,
    data: bytes,
    engagement_id: str | None = None,
    ingest: bool = True,
) -> dict[str, Any]:
    if engagement_id and not get_engagement(user_id, engagement_id):
        raise ValueError("Engagement not found")
    if len(data) > settings.upload_max_mb * 1024 * 1024:
        raise ValueError(f"File exceeds {settings.upload_max_mb} MB limit")

    raw_name = Path(filename or "upload.bin").name
    safe = _SAFE_NAME.sub("_", raw_name)[:180] or "upload.bin"
    ext = Path(safe).suffix.lower()
    # allow Dockerfile / Makefile without extension
    stem_l = Path(safe).stem.lower()
    if not ext and stem_l in {"dockerfile", "makefile", "gemfile", "procfile"}:
        ext = f".{stem_l}"
        safe = f"{safe}{ext}" if not safe.lower().endswith(ext) else safe

    if ext and ext not in _ALLOWED_EXT:
        raise ValueError(
            f"Unsupported file type `{ext}`. "
            "Upload docs, code, configs, CSV/JSON/XML, PDF, or images."
        )

    # Extension-spoofing / renamed-executable defense (real gap — extension
    # allowlist alone doesn't verify content matches what it claims to be).
    check_magic_bytes(safe, data)

    # Per-user aggregate storage quota (previously only a per-file cap existed).
    existing_total = get_conn().execute(
        "SELECT COALESCE(SUM(size_bytes), 0) AS total FROM files WHERE user_id = ?", (user_id,)
    ).fetchone()["total"]
    check_user_quota(int(existing_total or 0), len(data), settings.upload_quota_mb_per_user)

    fid = new_id()
    dest_dir = uploads_root() / user_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    stored = dest_dir / f"{fid}_{safe}"
    stored.write_bytes(data)

    # #251 — also mirror into object storage when configured (local no-op copy)
    object_meta: dict[str, Any] = {}
    try:
        from app.object_storage import evidence_key, put_bytes

        okey = evidence_key(None, fid, safe)
        object_meta = put_bytes(okey, data, content_type="application/octet-stream")
    except Exception:
        object_meta = {}

    text = extract_text(safe, data)
    kind = "image" if ext in _IMAGE_EXT else "zip" if ext == ".zip" else "document"

    if ingest and text.strip() and kind == "document":
        knowledge = Path(settings.data_dir) / "knowledge" / "uploads"
        knowledge.mkdir(parents=True, exist_ok=True)
        out_md = knowledge / f"{fid}_{Path(safe).stem}.md"
        header = f"# Upload: {safe}\n\nEngagement: `{engagement_id or 'none'}`\n\n"
        out_md.write_text(header + text[:200_000], encoding="utf-8")
        try:
            rag_engine.ingest_directory(force=True)
        except Exception:
            pass

    c = get_conn()
    c.execute(
        "INSERT INTO files (id, engagement_id, user_id, filename, stored_path, size_bytes, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (fid, engagement_id, user_id, safe, str(stored), len(data), now()),
    )
    c.commit()
    audit("file_upload", user_id, {"id": fid, "filename": safe, "bytes": len(data), "kind": kind})
    return {
        "id": fid,
        "filename": safe,
        "size_bytes": len(data),
        "engagement_id": engagement_id,
        "ingested": bool(ingest and text.strip() and kind == "document"),
        "object_storage": object_meta or None,
        "kind": kind,
        "preview": (text[:240] + ("…" if len(text) > 240 else "")) if text else "",
    }


def extract_text(filename: str, data: bytes) -> str:
    ext = Path(filename).suffix.lower()
    if ext in _IMAGE_EXT:
        return ""
    if ext == ".zip":
        return f"[ZIP archive: {filename}, {len(data)} bytes — list/extract in authorized lab if needed]"
    if ext == ".pdf":
        return _pdf_text(data)
    if ext in _TEXT_EXT or not ext:
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.decode("latin-1", errors="replace")
    return ""


def get_file_record(user_id: str, file_id: str) -> dict[str, Any] | None:
    row = get_conn().execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?", (file_id, user_id)
    ).fetchone()
    return dict(row) if row else None


def attachment_context(user_id: str, file_ids: list[str], *, per_file_chars: int = 24_000) -> str:
    """Build system/user context from chat attachments (ChatGPT-style)."""
    if not file_ids:
        return ""
    blocks: list[str] = [
        "## Chat attachments (user uploaded for this message)",
        "Treat attached files as ground truth for this turn. Quote paths/names when referencing them.",
        "",
    ]
    for fid in file_ids[:12]:
        rec = get_file_record(user_id, fid)
        if not rec:
            blocks.append(f"- Missing attachment id `{fid}`")
            continue
        path = Path(rec["stored_path"])
        name = rec["filename"]
        ext = Path(name).suffix.lower()
        size = rec.get("size_bytes") or 0
        if not path.exists():
            blocks.append(f"### {name}\nFile missing on disk.\n")
            continue
        data = path.read_bytes()
        if ext in _IMAGE_EXT:
            # Multimodal backends can use data-URL later; include metadata + tiny SVG text if any
            note = f"Image attachment `{name}` ({size} bytes, {ext}). "
            if ext == ".svg":
                note += "SVG markup:\n```svg\n" + data.decode("utf-8", errors="replace")[:8000] + "\n```"
            else:
                b64 = base64.b64encode(data[: min(len(data), 400_000)]).decode("ascii")
                note += (
                    "Describe/analyze for authorized security review (screenshots, diagrams, UI). "
                    f"Base64 length={len(b64)} (truncated if huge). "
                    "If you cannot view pixels, reason from filename and ask clarifying questions."
                )
            blocks.append(f"### {name}\n{note}\n")
            continue
        text = extract_text(name, data)
        if not text.strip():
            blocks.append(f"### {name}\nBinary/unreadable ({size} bytes).\n")
            continue
        clipped = text[:per_file_chars]
        fence = "text"
        if ext.lstrip("."):
            fence = ext.lstrip(".")
            if fence in {"md", "txt", "log"}:
                fence = "markdown" if fence == "md" else "text"
        blocks.append(f"### {name} ({size} bytes)\n```{fence}\n{clipped}\n```\n")
    return "\n".join(blocks)


def list_files(user_id: str, engagement_id: str | None = None) -> list[dict[str, Any]]:
    c = get_conn()
    if engagement_id:
        rows = c.execute(
            "SELECT id, engagement_id, filename, size_bytes, created_at FROM files "
            "WHERE user_id = ? AND engagement_id = ? ORDER BY created_at DESC",
            (user_id, engagement_id),
        ).fetchall()
    else:
        rows = c.execute(
            "SELECT id, engagement_id, filename, size_bytes, created_at FROM files "
            "WHERE user_id = ? ORDER BY created_at DESC LIMIT 100",
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def _pdf_text(data: bytes) -> str:
    try:
        raw = data.decode("latin-1", errors="ignore")
        chunks = re.findall(r"\((?:\\.|[^\\)]){3,}\)", raw)
        text = " ".join(c.strip("()") for c in chunks[:2000])
        text = re.sub(r"\\n", "\n", text)
        return re.sub(r"\s+", " ", text)[:100_000]
    except Exception:
        return ""
