"""Stream scanner/tool subprocess output instead of waiting on communicate().

HTTP handlers must not call this. Scan/tool workers already own the process.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

LineCallback = Callable[[str, str], Any]


async def stream_subprocess(
    argv: list[str],
    *,
    timeout: float,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
    on_line: LineCallback | None = None,
    input_bytes: bytes | None = None,
    max_capture: int = 256_000,
) -> tuple[int, str, str]:
    """Run argv, read stdout/stderr line-by-line, optionally persist + notify.

    Returns (exit_code, stdout_tail, stderr_tail). Never buffers an unbounded
    communicate() blob into RAM.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if input_bytes is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_size = 0
    stderr_size = 0
    stdout_fp = stdout_path.open("wb") if stdout_path else None
    stderr_fp = stderr_path.open("wb") if stderr_path else None

    async def _pump(stream: asyncio.StreamReader, dest: list[bytes], fp, which: str) -> None:
        nonlocal stdout_size, stderr_size
        while True:
            line = await stream.readline()
            if not line:
                break
            if fp is not None:
                fp.write(line)
            size = stdout_size if which == "stdout" else stderr_size
            if size < max_capture:
                dest.append(line)
                if which == "stdout":
                    stdout_size += len(line)
                else:
                    stderr_size += len(line)
            if on_line:
                text = line.decode("utf-8", errors="replace")
                maybe = on_line(which, text)
                if asyncio.iscoroutine(maybe):
                    await maybe

    try:
        if input_bytes is not None and proc.stdin is not None:
            proc.stdin.write(input_bytes)
            try:
                await proc.stdin.drain()
            except Exception:
                pass
            proc.stdin.close()
        await asyncio.wait_for(
            asyncio.gather(
                _pump(proc.stdout, stdout_chunks, stdout_fp, "stdout") if proc.stdout else asyncio.sleep(0),
                _pump(proc.stderr, stderr_chunks, stderr_fp, "stderr") if proc.stderr else asyncio.sleep(0),
            ),
            timeout=timeout,
        )
        code = await asyncio.wait_for(proc.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except Exception:
            pass
        return -1, b"".join(stdout_chunks).decode("utf-8", errors="replace"), "timed out"
    finally:
        if stdout_fp is not None:
            try:
                stdout_fp.close()
            except Exception:
                pass
        if stderr_fp is not None:
            try:
                stderr_fp.close()
            except Exception:
                pass

    return (
        int(code or 0),
        b"".join(stdout_chunks).decode("utf-8", errors="replace"),
        b"".join(stderr_chunks).decode("utf-8", errors="replace"),
    )


def publish_scan_progress(ctx: Any, **fields: Any) -> None:
    scan_id = getattr(ctx, "scan_id", None) or (ctx.get("scan_id") if isinstance(ctx, dict) else None)
    if not scan_id:
        return
    try:
        from app.realtime_bus import publish

        publish(type="scan", id=scan_id, status="running", **fields)
    except Exception:
        pass
