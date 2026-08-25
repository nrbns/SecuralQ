# Runtime hook — cwd is the folder containing SecuraIQ.exe (writable data/.env).
import os
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    os.chdir(str(Path(sys.executable).resolve().parent))
    os.environ.setdefault("UVICORN_RELOAD", "0")
    os.environ.setdefault("SECURAIQ_OPEN_BROWSER", "1")
    os.environ.setdefault("WORKSPACE_ZERO_START", "false")
