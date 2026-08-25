"""Start SecuraIQ — portable across Windows / macOS / Linux, cwd, and a frozen EXE."""

from __future__ import annotations

import multiprocessing
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Anchor to install/repo root before importing settings (loads ROOT/.env, data paths).
from app.paths import is_frozen, project_root

ROOT = project_root()
os.chdir(ROOT)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Fresh clone / first EXE run: copy .env.example before Settings() reads it.
try:
    from app.bootstrap import ensure_env_file

    ensure_env_file(ROOT)
except Exception as exc:
    print(f"Env bootstrap skipped: {exc}")

import uvicorn

from app.config import settings


def _print_banner() -> None:
    try:
        from app.platform_info import platform_info

        info = platform_info()
        print(f"SecuraIQ · {info.get('os')} {info.get('os_release')} · Python {info.get('python')}")
        print(f"  Local:  {info.get('local_url')}")
        for url in info.get("lan_urls") or []:
            print(f"  LAN:    {url}")
        print(f"  Data:   {settings.data_dir}")
        print(f"  Mode:   {settings.deployment_mode} · auth={'on' if settings.auth_enabled else 'off'}")
        if is_frozen():
            print(f"  App:    {Path(sys.executable)}")
    except Exception as exc:
        print(f"SecuraIQ starting on {settings.host}:{settings.port} ({exc})")


def _open_browser(url: str, delay: float = 1.4) -> None:
    def _go() -> None:
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_go, daemon=True).start()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    try:
        from app.bootstrap import bootstrap

        boot = bootstrap(ROOT)
        be = boot.get("backend") or {}
        if be.get("hint"):
            print(be["hint"])
    except Exception as exc:
        print(f"Bootstrap: {exc}")
        Path(getattr(settings, "data_dir", ROOT / "data")).mkdir(parents=True, exist_ok=True)

    # Reload only when explicitly requested — never inside a frozen EXE.
    reload_env = os.environ.get("UVICORN_RELOAD", "").strip().lower()
    reload = (not is_frozen()) and reload_env in {"1", "true", "yes"}
    if reload:
        os.environ.setdefault("WATCHFILES_FORCE_POLLING", "true")

    _print_banner()
    open_browser = is_frozen() or os.environ.get("SECURAIQ_OPEN_BROWSER", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    if open_browser:
        host = settings.host if settings.host not in {"0.0.0.0", "::"} else "127.0.0.1"
        _open_browser(f"http://{host}:{int(settings.port)}")

    if is_frozen():
        from app.main import app

        # Lab .env.example defaults to wiping the UI on start. A double-click
        # EXE should keep scans/assets unless the user set the env var.
        if os.environ.get("WORKSPACE_ZERO_START", "").strip() == "":
            try:
                settings.workspace_zero_start = False
            except Exception:
                pass
        uvicorn.run(app, host=settings.host, port=int(settings.port), reload=False)
    else:
        uvicorn.run(
            "app.main:app",
            host=settings.host,
            port=int(settings.port),
            reload=reload,
            reload_dirs=[str(ROOT / "app"), str(ROOT / "static")] if reload else None,
        )
