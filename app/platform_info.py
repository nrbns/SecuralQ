"""Cross-platform helpers and capability reporting."""

from __future__ import annotations

import platform
import socket
from pathlib import Path
from typing import Any

from app.config import settings

# VirtualBox host-only, Hyper-V ICS, VMware/Parallels NAT — not the Wi-Fi LAN
_VIRTUAL_PREFIXES = (
    "192.168.56.",
    "192.168.57.",
    "192.168.58.",
    "192.168.59.",
    "192.168.137.",
    "192.168.64.",
    "198.18.",
)


def rank_lan_ips(ips: list[str], *, preferred: str = "") -> list[str]:
    """Prefer the default-route NIC over VirtualBox/VMware host-only adapters."""
    seen: list[str] = []
    for raw in ips:
        ip = (raw or "").strip()
        if not ip or ip.startswith("127.") or ip in seen:
            continue
        seen.append(ip)

    def _key(ip: str) -> tuple[int, str]:
        if preferred and ip == preferred:
            return (0, ip)
        if ip.startswith("169.254."):
            return (8, ip)
        if any(ip.startswith(p) for p in _VIRTUAL_PREFIXES):
            return (5, ip)
        return (1, ip)

    return sorted(seen, key=_key)


def _default_route_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return ""


def _lan_ips() -> list[str]:
    ips: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    preferred = _default_route_ip()
    if preferred:
        ips.append(preferred)
    return rank_lan_ips(ips, preferred=preferred)[:5]


def _module_available(name: str) -> bool:
    """Cheap presence check — never import heavy packages (unsloth/torch hang the event loop)."""
    try:
        import importlib.util

        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def normalize_path(value: str) -> str:
    """Normalize user paths for Windows/Linux/macOS."""
    p = Path(value).expanduser()
    try:
        return str(p.resolve()) if p.exists() else str(p)
    except OSError:
        return str(p)


_PLATFORM_CACHE: dict[str, Any] | None = None
_PLATFORM_CACHE_TS = 0.0


def platform_info() -> dict[str, Any]:
    global _PLATFORM_CACHE, _PLATFORM_CACHE_TS
    import time

    now = time.monotonic()
    if _PLATFORM_CACHE is not None and (now - _PLATFORM_CACHE_TS) < 30:
        return _PLATFORM_CACHE

    system = platform.system()
    ips = _lan_ips()
    port = settings.port
    payload = {
        "os": system,
        "os_release": platform.release(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "host": settings.host,
        "port": port,
        "lan_urls": [f"http://{ip}:{port}" for ip in ips],
        "local_url": f"http://127.0.0.1:{port}",
        "lan_mode": (settings.host or "").strip() in {"0.0.0.0", "::", "[::]"},
        "share_url": ([f"http://{ip}:{port}" for ip in ips] or [f"http://127.0.0.1:{port}"])[0],
        "lan_auto_scan": bool(getattr(settings, "lan_auto_scan", False)),
        "workspace_zero_start": bool(getattr(settings, "workspace_zero_start", False)),
        "client_note": (
            "Open this UI from any browser on Windows, Linux, macOS, Android, or iOS. "
            "On phones/tablets use a LAN URL below (same Wi‑Fi). "
            "Model backends (Ollama/Hermes/Unsloth) run on the host machine — set their URLs in Settings if needed."
        ),
        "backends": {
            "ollama": {"ui": True, "server_side": True, "notes": "Works on Windows/Linux/macOS/Android (Termux) hosts"},
            "openai_compat": {"ui": True, "server_side": True, "notes": "LM Studio or any OpenAI-compatible endpoint"},
            "hermes": {
                "ui": True,
                "server_side": True,
                "notes": "Nous Hermes Agent API — sessions, tools, memory (Win/Linux/macOS host)",
            },
            "unsloth": {
                "ui": True,
                "server_side": True,
                "installed": _module_available("unsloth"),
                "notes": "GPU host recommended; not for on-device phone training",
            },
            "huggingface": {
                "ui": True,
                "server_side": True,
                "installed": _module_available("transformers"),
                "notes": "Local Transformers on host",
            },
        },
        "mobile_clients": ["Android browser", "iOS Safari", "PWA / Add to Home Screen"],
    }
    _PLATFORM_CACHE = payload
    _PLATFORM_CACHE_TS = now
    return payload
