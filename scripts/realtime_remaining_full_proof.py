"""Full remaining-ops simulation: failover → reclaim → SSE resume → signing gate.

Runs without Docker. Marks every row ``simulated: true`` unless a live Redis
URL is provided. Never invents commercial HA or EV Authenticode claims.

Usage:
  python scripts/realtime_remaining_full_proof.py
  python scripts/realtime_remaining_full_proof.py --with-redis redis://127.0.0.1:6379/0
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

LOG = _ROOT / "data" / "ops" / "remaining_full_proofs.jsonl"
DISCLAIMER = (
    "lab remaining-ops proof — simulated unless --with-redis; "
    "not commercial HA / EV Authenticode certification"
)


def _append_log(row: dict[str, Any]) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")


def step_sentinel_failover_simulated() -> dict[str, Any]:
    """Measure reconnect path + XAUTOCLAIM reclaim + SSE resume (mocked Redis)."""
    from app.realtime.once_only import prove_consumer_failover_once_only
    from app.realtime_bus import (
        bind_loop,
        clear_replay_buffer_for_tests,
        publish,
        replay_since,
        subscribe,
        unsubscribe,
    )

    t0 = time.perf_counter()
    # --- reconnect helper timing ---
    from app.redis_client import reconnect_after_failover, reset_clients_for_tests

    reset_clients_for_tests()
    t_re = time.perf_counter()
    reconnect_after_failover()
    reconnect_ms = round((time.perf_counter() - t_re) * 1000, 1)

    # --- once-only reclaim (consumer A dies → B XAUTOCLAIM) ---
    from app import event_idempotency, event_processor
    from app.db import reset_conn_for_tests
    from app.tenancy import ensure_tenant_schema
    from tests._http_test_utils import configure_isolated_settings

    class _MP:
        def setattr(self, target, name=None, value=None, raising=True):
            if isinstance(target, str) and value is None and name is not None:
                import importlib

                mod_name, _, attr = target.rpartition(".")
                obj = importlib.import_module(mod_name)
                setattr(obj, attr, name)
                return
            setattr(target, name, value)

    td = Path(tempfile.mkdtemp())
    configure_isolated_settings(_MP(), td)
    reset_conn_for_tests()
    ensure_tenant_schema()
    event_idempotency.clear_processed_for_tests()
    event_idempotency.ensure_processed_events_schema()

    side: list[str] = []

    def _h(e: dict) -> None:
        side.append(str(e.get("event_id")))

    event_processor.HANDLERS["vuln"] = _h
    event = {"type": "vuln", "event_id": "fail-reclaim-1", "user_id": "u"}
    client = AsyncMock()
    client.xautoclaim = AsyncMock(
        return_value=("0-0", [("1-0", {"payload": json.dumps(event)})])
    )
    client.xpending_range = AsyncMock(return_value=[{"times_delivered": 1}])
    client.xack = AsyncMock()
    client.xadd = AsyncMock()

    async def _reclaim() -> Any:
        return await prove_consumer_failover_once_only(
            reclaim_pending=event_processor._reclaim_pending,
            process_event=event_processor.process_event,
            client=client,
            stream="securaiq:events",
            event=event,
            side_effects=side,
        )

    reclaim = asyncio.run(_reclaim())
    reclaim_ms = round((time.perf_counter() - t0) * 1000, 1)

    # --- SSE disconnect → Last-Event-ID resume ---
    clear_replay_buffer_for_tests()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    bind_loop(loop)
    q = subscribe(maxsize=100)
    try:
        publish(type="control.failed", event_id="sse-pre", user_id="u", _from_processor=True)
        # Simulate disconnect: unsubscribe, then reconnect with last id
        unsubscribe(q)
        publish(type="control.passed", event_id="sse-while-down", user_id="u", _from_processor=True)
        missed = replay_since("sse-pre", limit=20)
        ids = [str(e.get("event_id") or "") for e in missed]
        sse_ok = "sse-while-down" in ids and "sse-pre" not in ids
    finally:
        try:
            unsubscribe(q)
        except Exception:
            pass
        loop.close()
        reset_conn_for_tests()

    ok = bool(reclaim.ok) and sse_ok and len(side) == 1
    return {
        "name": "sentinel_failover_chain_simulated",
        "ok": ok,
        "simulated": True,
        "reconnect_ms": reconnect_ms,
        "reclaim_ok": reclaim.ok,
        "reclaim_side_effects": len(side),
        "sse_resume_ok": sse_ok,
        "sse_caught_up": ids,
        "elapsed_ms": reclaim_ms,
        "disclaimer": DISCLAIMER,
    }


def step_multiworker_soak() -> dict[str, Any]:
    from app.realtime.ops_proofs import run_inprocess_soak

    out = run_inprocess_soak(subscribers=4, events=25)
    return {
        "name": "multiworker_sse_soak",
        "ok": bool(out.get("ok")),
        "simulated": True,
        "detail": out,
        "disclaimer": out.get("disclaimer") or DISCLAIMER,
    }


def step_lab_authenticode() -> dict[str, Any]:
    """Generate lab self-signed code-signing cert and verify pipeline exists.

    Does NOT produce EV/Trusted Authenticode. Sets up lab cert under tools/lab-certs
    and documents how CI would call sign_windows.ps1.
    """
    cert_dir = _ROOT / "tools" / "lab-certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cer = cert_dir / "securaiq-lab-codesign.cer"
    pfx = cert_dir / "securaiq-lab-codesign.pfx"
    readme = cert_dir / "README.md"
    readme.write_text(
        "# Lab code-signing material (NOT for commercial release)\n\n"
        "Self-signed / lab-only. Commercial Windows release requires an EV "
        "Authenticode certificate from a public CA (`SIGN_WINDOWS=1` + "
        "`CODE_SIGN_THUMBPRINT` or PFX in CI secrets).\n\n"
        "Generate / refresh:\n"
        "  python scripts/realtime_remaining_full_proof.py\n"
        "Sign (when SIGN_WINDOWS=1 and PFX set):\n"
        "  .\\scripts\\packaging\\sign_windows.ps1 -ArtifactDir dist\\agent-packages\n",
        encoding="utf-8",
    )

    created = False
    err = None
    try:
        # PowerShell New-SelfSignedCertificate (Windows)
        ps = f"""
$ErrorActionPreference = 'Stop'
$dir = '{cert_dir}'
$pfx = Join-Path $dir 'securaiq-lab-codesign.pfx'
$cer = Join-Path $dir 'securaiq-lab-codesign.cer'
$pwd = ConvertTo-SecureString -String 'securaiq-lab-only' -Force -AsPlainText
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=SecuraIQ Lab CodeSign' `
  -CertStoreLocation 'Cert:\\CurrentUser\\My' -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(2)
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pwd | Out-Null
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
# Remove from store to avoid polluting user certs (keep files)
Remove-Item -Path ('Cert:\\CurrentUser\\My\\' + $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
Write-Output $cert.Thumbprint
"""
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(_ROOT),
        )
        if proc.returncode == 0 and pfx.is_file() and cer.is_file():
            created = True
            thumb = (proc.stdout or "").strip().splitlines()[-1] if proc.stdout else ""
        else:
            err = (proc.stderr or proc.stdout or "cert_create_failed")[:400]
            thumb = ""
    except Exception as exc:
        err = str(exc)[:400]
        thumb = ""

    from app.realtime.ops_proofs import verify_signing_scaffolds

    scaffolds = verify_signing_scaffolds()
    ok = bool(scaffolds.get("ok")) and (created or pfx.is_file())
    return {
        "name": "lab_authenticode_pipeline",
        "ok": ok,
        "simulated": True,
        "lab_cert_created": created or pfx.is_file(),
        "pfx": str(pfx.relative_to(_ROOT)) if pfx.is_file() else None,
        "cer": str(cer.relative_to(_ROOT)) if cer.is_file() else None,
        "thumbprint": thumb or None,
        "scaffolds_ok": scaffolds.get("ok"),
        "error": err,
        "disclaimer": (
            "Lab self-signed code-signing cert only — NOT EV Authenticode / not trusted by Windows SmartScreen"
        ),
    }


def step_live_redis_optional(url: str) -> dict[str, Any]:
    """If REDIS_URL provided, ping + XADD/XLEN smoke (still not Sentinel HA)."""
    os.environ["REDIS_URL"] = url
    try:
        from app.config import settings

        settings.redis_url = url
    except Exception:
        pass
    try:
        from app.redis_client import get_sync_redis, reconnect_after_failover, reset_clients_for_tests

        reset_clients_for_tests()
        reconnect_after_failover()
        client = get_sync_redis(decode_responses=True, cached=False)
        if client is None:
            return {"name": "live_redis_smoke", "ok": False, "error": "client_unavailable", "simulated": False}
        try:
            t0 = time.perf_counter()
            pong = client.ping()
            stream = "securaiq:events:labproof"
            sid = client.xadd(stream, {"payload": json.dumps({"event_id": "live-1", "type": "agent"})})
            length = client.xlen(stream)
            client.xtrim(stream, maxlen=10, approximate=True)
            ms = round((time.perf_counter() - t0) * 1000, 1)
            return {
                "name": "live_redis_smoke",
                "ok": bool(pong) and bool(sid),
                "simulated": False,
                "ping": bool(pong),
                "xadd_id": sid,
                "stream_length": length,
                "elapsed_ms": ms,
                "disclaimer": "single Redis URL smoke — not Sentinel failover certification",
            }
        finally:
            try:
                client.close()
            except Exception:
                pass
    except Exception as exc:
        return {"name": "live_redis_smoke", "ok": False, "error": str(exc)[:300], "simulated": False}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--with-redis", default="", help="Optional redis:// URL for live smoke")
    args = ap.parse_args()

    steps = [
        step_sentinel_failover_simulated(),
        step_multiworker_soak(),
        step_lab_authenticode(),
    ]
    if (args.with_redis or "").strip():
        steps.append(step_live_redis_optional(args.with_redis.strip()))

    overall = all(bool(s.get("ok")) for s in steps)
    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "ok": overall,
        "passed": sum(1 for s in steps if s.get("ok")),
        "total": len(steps),
        "steps": steps,
        "disclaimer": DISCLAIMER,
    }
    _append_log(row)
    print("=== SECURAIQ REMAINING FULL PROOF ===")
    for s in steps:
        print(f"  [{'PASS' if s.get('ok') else 'FAIL'}] {s.get('name')}: {json.dumps({k:v for k,v in s.items() if k not in ('detail','sse_caught_up')}, default=str)[:160]}")
    print(json.dumps({k: v for k, v in row.items() if k != "steps"}, indent=2))
    print("RESULT:", "REMAINING COMPLETE (lab/sim)" if overall else "INCOMPLETE")
    if overall:
        print(
            "\nOps host still required for commercial claims:\n"
            "  docker compose --profile redis-ha up -d\n"
            "  python scripts/sentinel_failover_measure.py --inject-stop --record\n"
            "  SIGN_WINDOWS=1 + EV cert -> scripts/packaging/sign_windows.ps1\n"
            "  Or: powershell scripts/ops_host_complete_remaining.ps1"
        )
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
