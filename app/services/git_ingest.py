"""Git repo ingestion for code scanning.

Lets SecuraIQ Code / Semgrep / CodeQL scan a remote repo the user owns or is
authorized to test, without the user having to clone it manually first. This
does the minimum needed to hand a real local folder to the existing scan
pipeline (app.tools.runner.iter_security_tools) — it does not run git through
a shell, does not accept ssh/file URLs, and does not keep the clone around
longer than the scan needs it.
"""

from __future__ import annotations

import asyncio
import shutil
import uuid
from pathlib import Path
from typing import Any

from app.config import settings

_UNSAFE_CHARS = set(" \t\n\r;&|`$()<>\"'\\")


def git_available() -> tuple[bool, str]:
    path = shutil.which("git")
    if not path:
        return False, "git not found on PATH — install Git to clone remote repos for scanning"
    return True, path


def validate_git_url(url: str) -> tuple[bool, str]:
    """Only http(s) URLs are accepted — no ssh/scp syntax, no file:// or local
    paths that could be used to point the 'clone' at something already on
    disk (including SecuraIQ's own data directory)."""
    u = (url or "").strip()
    if not u:
        return False, "git URL required"
    if not (u.startswith("http://") or u.startswith("https://")):
        return False, "only http(s) git URLs are supported (no ssh/file/local paths)"
    if u.startswith("-"):
        return False, "invalid git URL"
    if any(c in _UNSAFE_CHARS for c in u):
        return False, "invalid characters in git URL"
    return True, u


def validate_git_ref(ref: str) -> tuple[bool, str]:
    r = (ref or "").strip()
    if not r:
        return True, ""
    if r.startswith("-") or any(c in _UNSAFE_CHARS for c in r):
        return False, "invalid git ref"
    return True, r


def clone_root() -> Path:
    root = Path(settings.data_dir) / "git_clones"
    root.mkdir(parents=True, exist_ok=True)
    return root


async def clone_repo(url: str, *, ref: str = "", timeout_sec: float = 120.0) -> dict[str, Any]:
    """Shallow-clone (--depth 1) a public/authorized http(s) git repo into a
    fresh scratch directory for scanning. Returns
    {"ok": True, "path": str, "url": str, "ref": str|None} on success, or
    {"ok": False, "error": str} — never raises for expected failure modes
    (missing git, bad URL, clone failure) so callers can stream an honest
    NDJSON event instead of a stack trace.
    """
    ok_g, git_path_or_err = git_available()
    if not ok_g:
        return {"ok": False, "error": git_path_or_err}
    ok_u, u_or_err = validate_git_url(url)
    if not ok_u:
        return {"ok": False, "error": u_or_err}
    ok_r, ref_or_err = validate_git_ref(ref)
    if not ok_r:
        return {"ok": False, "error": ref_or_err}

    dest = clone_root() / uuid.uuid4().hex
    argv = [git_path_or_err, "clone", "--depth", "1", "--single-branch"]
    if ref_or_err:
        argv.extend(["--branch", ref_or_err])
    argv.extend([u_or_err, str(dest)])

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        shutil.rmtree(dest, ignore_errors=True)
        return {"ok": False, "error": f"git clone timed out after {int(timeout_sec)}s"}

    code = int(proc.returncode or 0)
    if code != 0 or not dest.is_dir():
        stderr = (stderr_b or b"").decode("utf-8", errors="replace").strip()[:2000]
        shutil.rmtree(dest, ignore_errors=True)
        return {"ok": False, "error": stderr or f"git clone failed (exit {code})"}

    # Evidence for this scan is the source tree, not the repo's history.
    shutil.rmtree(dest / ".git", ignore_errors=True)
    return {"ok": True, "path": str(dest), "url": u_or_err, "ref": ref_or_err or None}


def cleanup_clone(path: str) -> None:
    """Best-effort removal of a scratch clone once its scan is done. Only
    ever deletes inside our own git_clones scratch root — never trusts the
    caller's path blindly."""
    try:
        p = Path(path).resolve()
        root = clone_root().resolve()
        if p == root or root not in p.parents:
            return
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
    except Exception:
        pass
