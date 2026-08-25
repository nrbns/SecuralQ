"""First-run bootstrap so a clean clone starts without extra steps.

Creates ``.env`` from ``.env.example``, data directories, and picks a usable
model backend when Ollama is not installed. Never wipes existing workspace data.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
from pathlib import Path
from typing import Any


def project_root() -> Path:
    from app.paths import project_root as _root

    return _root()


def ensure_env_file(root: Path | None = None) -> dict[str, Any]:
    from app.paths import project_root as _root
    from app.paths import resource_root

    root = root or _root()
    env = root / ".env"
    example = root / ".env.example"
    if not example.is_file():
        bundled = resource_root() / ".env.example"
        if bundled.is_file():
            example = bundled
    created = False
    if not env.is_file():
        if not example.is_file():
            raise FileNotFoundError("Missing .env.example — clone the full SecuraIQ repo.")
        shutil.copyfile(example, env)
        created = True
    return {"ok": True, "path": str(env), "created": created}


def ollama_listening(host: str = "127.0.0.1", port: int = 11434, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_data_dirs() -> dict[str, str]:
    try:
        from app.archive import ensure_data_layout

        return ensure_data_layout()
    except Exception:
        from app.paths import resolve_path

        data = resolve_path("./data")
        data.mkdir(parents=True, exist_ok=True)
        for sub in ("evidence/scans", "archive/scans", "uploads", "kpi_snaps", "chroma"):
            (data / sub).mkdir(parents=True, exist_ok=True)
        return {"data": str(data)}


def apply_usable_backend(*, first_run: bool = False) -> dict[str, Any]:
    """If Ollama is missing, keep the app usable (scans do not need a model)."""
    from app.config import settings
    from app.env_persist import update_env_value

    current = (settings.model_backend or "ollama").strip().lower()
    if current != "ollama":
        return {"backend": current, "changed": False, "reason": "already_set"}
    if ollama_listening():
        return {"backend": "ollama", "changed": False, "reason": "ollama_up"}

    token = (settings.hf_token or os.environ.get("HF_TOKEN") or "").strip()
    if first_run and token:
        update_env_value("MODEL_BACKEND", "huggingface_api")
        settings.model_backend = "huggingface_api"
        return {
            "backend": "huggingface_api",
            "changed": True,
            "reason": "ollama_missing_hf_token",
        }
    return {
        "backend": "ollama",
        "changed": False,
        "reason": "ollama_missing",
        "hint": "Scans/tools/reports work now. For chat: install Ollama, or set a model backend in Settings.",
    }


def bootstrap(root: Path | None = None) -> dict[str, Any]:
    root = root or project_root()
    os.chdir(root)
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    env = ensure_env_file(root)
    layout = ensure_data_dirs()
    backend = apply_usable_backend(first_run=bool(env.get("created")))
    return {"ok": True, "env": env, "layout": layout, "backend": backend}


def main() -> None:
    result = bootstrap()
    env = result["env"]
    be = result["backend"]
    print(f"Env: {'created ' if env.get('created') else ''}{env.get('path')}")
    print(f"Data: {result['layout'].get('data') or result['layout']}")
    print(f"Backend: {be.get('backend')} ({be.get('reason')})")
    if be.get("hint"):
        print(be["hint"])


if __name__ == "__main__":
    main()
