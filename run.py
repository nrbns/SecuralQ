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


def _apply_lan_mode() -> None:
    """Bind for phones / other PCs. Safe for lab LAN — not a public-internet expose."""
    os.environ["HOST"] = "0.0.0.0"
    os.environ["CORS_ORIGINS"] = "*"
    os.environ["ALLOW_OPEN_LAN"] = "true"
    os.environ["LAN_AUTO_SCAN"] = "false"
    os.environ["WORKSPACE_ZERO_START"] = "false"
    try:
        settings.host = "0.0.0.0"
        settings.cors_origins = "*"
        settings.allow_open_lan = True
        settings.lan_auto_scan = False
        settings.workspace_zero_start = False
    except Exception:
        pass
    try:
        from app.platform_info import clear_platform_cache

        clear_platform_cache()
    except Exception:
        pass
    env_path = ROOT / ".env"
    if env_path.is_file():
        try:
            lines = env_path.read_text(encoding="utf-8").splitlines()
            updates = {
                "HOST": "0.0.0.0",
                "CORS_ORIGINS": "*",
                "ALLOW_OPEN_LAN": "true",
                "LAN_AUTO_SCAN": "false",
                "WORKSPACE_ZERO_START": "false",
            }
            seen: set[str] = set()
            out: list[str] = []
            for line in lines:
                key = line.split("=", 1)[0] if "=" in line and not line.lstrip().startswith("#") else ""
                if key in updates:
                    out.append(f"{key}={updates[key]}")
                    seen.add(key)
                else:
                    out.append(line)
            for key, val in updates.items():
                if key not in seen:
                    out.append(f"{key}={val}")
            env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
        except Exception:
            pass


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if any(a in {"--lan", "-Lan", "-lan"} for a in sys.argv[1:]):
        _apply_lan_mode()
        print("LAN mode: other devices use the printed LAN URL — never localhost on the other device.")
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
