"""Optional Prefect orchestration for SecuraIQ background jobs.

Local-first default remains the in-process asyncio worker in ``app.jobs``.
When Prefect is installed, ``engine=prefect`` runs the job flow in a
**subprocess** (so an ephemeral Prefect API cannot stall uvicorn). Set
``PREFECT_API_URL`` to point at a dedicated server (compose profile
``prefect``) instead of the temporary local API.

Install::

    pip install "prefect>=3.0,<4"

Enable auto-routing (engine=auto picks Prefect)::

    PREFECT_ENABLED=true
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any


def prefect_installed() -> bool:
    try:
        import prefect  # noqa: F401

        return True
    except Exception:
        return False


def prefect_version() -> str:
    try:
        import prefect

        return getattr(prefect, "__version__", "unknown")
    except Exception:
        return ""


def prefect_status() -> dict[str, Any]:
    from app.config import settings

    installed = prefect_installed()
    enabled = bool(getattr(settings, "prefect_enabled", False))
    api_url = (getattr(settings, "prefect_api_url", "") or "").strip() or (
        os.environ.get("PREFECT_API_URL") or ""
    ).strip()
    # "ready" means auto engine may choose Prefect; jobs can still force engine=prefect when installed.
    ready = installed and enabled
    return {
        "installed": installed,
        "enabled": enabled,
        "ready": ready,
        "version": prefect_version() if installed else "",
        "api_url": api_url or ("ephemeral-subprocess" if installed else ""),
        "default_engine": "prefect" if ready else "local",
        "hint": (
            "Prefect ready — engine=auto uses Prefect flows (subprocess)"
            if ready
            else (
                "pip install 'prefect>=3.0,<4' then set PREFECT_ENABLED=true"
                if not installed
                else "Prefect installed — set PREFECT_ENABLED=true for auto, or pick engine=prefect on a job"
            )
        ),
    }


def _parse_flow_stdout(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        return {}
    # Prefers a trailing RESULT_JSON: line; else last JSON object in output.
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("RESULT_JSON:"):
            return json.loads(line[len("RESULT_JSON:") :].strip())
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    raise RuntimeError(f"Prefect flow produced no JSON result: {text[-500:]}")


async def run_kind_via_prefect(kind: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute a registered job kind inside a Prefect flow (isolated subprocess)."""
    if not prefect_installed():
        raise RuntimeError("Prefect is not installed. pip install 'prefect>=3.0,<4'")

    from app.config import settings
    from app.paths import project_root

    api_url = (getattr(settings, "prefect_api_url", "") or "").strip()
    root = project_root()
    env = os.environ.copy()
    if api_url:
        env["PREFECT_API_URL"] = api_url
    # Avoid nested uvicorn conflict noise from Prefect telemetry where possible
    env.setdefault("PREFECT_LOGGING_TO_API_ENABLED", "false")

    cmd = [
        sys.executable,
        "-m",
        "app.prefect_flows",
        "--run",
        kind,
        json.dumps(payload or {}, ensure_ascii=False),
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        cwd=str(root),
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=420)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError("Prefect job timed out after 420s") from None

    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(
            f"Prefect flow failed (exit {proc.returncode}): {(stderr or stdout)[-2500:]}"
        )
    result = _parse_flow_stdout(stdout)
    if not isinstance(result, dict):
        result = {"result": result}
    result.setdefault("engine", "prefect")
    result.setdefault("kind", kind)
    if stderr.strip():
        result.setdefault("prefect_log_tail", stderr.strip()[-800:])
    return result
