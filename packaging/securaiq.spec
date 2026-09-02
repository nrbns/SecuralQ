# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for SecuraIQ — onedir build, one spec for all three OSes.

PyInstaller does not cross-compile: run this spec ON the OS you want a
binary for. It produces dist/SecuraIQ/SecuraIQ.exe on Windows (via
scripts/build_exe.ps1 or build_exe.cmd) and dist/SecuraIQ/SecuraIQ
(no extension) on Linux/macOS (via scripts/build_exe.sh or build_exe.sh).
Nothing in this spec is Windows-specific — same datas/hiddenimports/excludes
on every platform.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_dynamic_libs, collect_submodules

ROOT = Path(SPECPATH).resolve().parent

datas = [
    (str(ROOT / "static"), "static"),
    (str(ROOT / ".env.example"), "."),
    (str(ROOT / "data" / "knowledge"), "data/knowledge"),
    (str(ROOT / "data" / "frameworks"), "data/frameworks"),
    # Only these four — not the whole scripts/ dir, which also holds dev-only
    # tooling (backups, migrations, use_*.ps1 config helpers) that has no
    # business shipping inside the exe. These four are served at runtime by
    # app/agents_api.py's /api/agents/install-script[/{platform}] routes
    # (the native-agent "install as a persistent service" download), so
    # without them that feature 404s in a packaged build even though it
    # works fine running from source.
    (str(ROOT / "scripts" / "securaiq_agent.py"), "scripts"),
    (str(ROOT / "scripts" / "install_agent_linux.sh"), "scripts"),
    (str(ROOT / "scripts" / "install_agent_macos.sh"), "scripts"),
    (str(ROOT / "scripts" / "install_agent_windows.ps1"), "scripts"),
]
binaries = []
hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "app.main",
    "app.jobs",
    "app.bootstrap",
    "app.lan_sync",
    "app.lan_inventory",
    "multipart",
    "email.mime.text",
    "anyio._backends._asyncio",
    "pydantic_settings",
    "chromadb",
    "sentence_transformers",
    "unicodedata",
    "encodings.idna",
    "idna",
    "httpx",
    "httpcore",
    "h11",
    "certifi",
    "sniffio",
    "anyio",
    "chromadb.api.rust",
    "chromadb.telemetry.product.posthog",
]

for pkg in (
    "chromadb.api",
    "chromadb.db",
    "chromadb.segment",
    "chromadb.telemetry",
    "chromadb.utils",
    "chromadb.migrations",
):
    try:
        hiddenimports += collect_submodules(pkg)
    except Exception:
        pass

# Fast API stack only — do not collect_all torch/chromadb (walks for many minutes).
for pkg in ("uvicorn", "fastapi", "starlette", "httpx", "httpcore"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        try:
            hiddenimports += collect_submodules(pkg)
        except Exception:
            pass

try:
    datas += collect_data_files("chromadb")
except Exception:
    pass
try:
    datas += collect_data_files("sentence_transformers")
except Exception:
    pass

try:
    binaries += collect_dynamic_libs("torch")
except Exception:
    pass

a = Analysis(
    [str(ROOT / "run.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(ROOT / "packaging" / "pyi_rth_securaiq.py")],
    excludes=[
        "pytest",
        "IPython",
        "jupyter",
        "notebook",
        "tkinter",
        "matplotlib",
        "prefect",
        "unsloth",
        "alembic",
        "psycopg",
        "tensorboard",
        "cv2",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SecuraIQ",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SecuraIQ",
)
