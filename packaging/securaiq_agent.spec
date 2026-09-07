# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the SecuraIQ native agent — standalone binary.

Stdlib-only agent (scripts/securaiq_agent.py). No torch/chromadb. Build via:

    python scripts/build_agent_packages.py --platform windows
"""

from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent
AGENT = ROOT / "scripts" / "securaiq_agent.py"

a = Analysis(
    [str(AGENT)],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "torch",
        "chromadb",
        "sentence_transformers",
        "uvicorn",
        "fastapi",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SecuraIQ-Agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
