#!/usr/bin/env python3
"""Verify connector status endpoints — safe against unconfigured vendors.

Usage:
  python scripts/connector_verify.py
  python scripts/connector_verify.py --base http://127.0.0.1:8080 --sync
  python scripts/connector_verify.py --matrix
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

ENDPOINTS = [
    ("GET", "/api/integrations/catalog"),
    ("GET", "/api/wazuh/status"),
    ("GET", "/api/openaudit/status"),
    ("GET", "/api/xdr/status"),
    ("GET", "/api/hardeningkitty/status"),
    ("GET", "/api/thehive/status"),
    ("GET", "/api/cloud/status"),
    ("GET", "/api/gap/evidence-queue"),
]

SYNC_ENDPOINTS = [
    "/api/wazuh/sync",
    "/api/openaudit/sync",
    "/api/xdr/sync",
    "/api/thehive/sync",
    "/api/cloud/sync",
]

# Marketing honesty matrix — update after real tenant trials.
VALIDATION_MATRIX = [
    ("GitHub webhooks", "built", "verified_when_secret_set"),
    ("Jira", "built", "trial_pending"),
    ("Slack webhook", "built", "trial_pending"),
    ("Wazuh / SecuraIQ SIEM", "built", "trial_pending"),
    ("CrowdStrike", "built", "trial_pending"),
    ("SentinelOne", "built", "trial_pending"),
    ("Sophos", "built", "trial_pending"),
    ("Microsoft Defender", "built", "trial_pending"),
    ("TheHive", "built", "trial_pending"),
    ("AWS Security Hub", "built", "trial_pending"),
    ("Azure Defender", "built", "trial_pending"),
    ("GCP SCC", "built", "trial_pending"),
    ("GitLab webhooks", "built", "trial_pending"),
]


def _req(base: str, method: str, path: str, timeout: float = 20.0) -> tuple[int, Any]:
    url = base.rstrip("/") + path
    r = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {"raw": body[:200]}
            return int(resp.status), data
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {"raw": body[:200]}
        return int(exc.code), data
    except Exception as exc:  # noqa: BLE001
        return 0, {"error": str(exc)}


def _print_matrix() -> None:
    print("Connector validation matrix (do not claim 'supported' until verified):")
    print(f"  {'Integration':<28} {'Code':<8} {'Live tenant'}")
    print(f"  {'-' * 28} {'-' * 8} {'-' * 16}")
    for name, code, live in VALIDATION_MATRIX:
        print(f"  {name:<28} {code:<8} {live}")
    print(
        "\nAfter a successful trial, update docs/connector-validation-matrix.md "
        "and this VALIDATION_MATRIX list."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="SecuraIQ connector verification harness")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--sync", action="store_true", help="Also POST sync for configured connectors")
    parser.add_argument("--matrix", action="store_true", help="Print live-tenant validation matrix and exit")
    args = parser.parse_args()

    if args.matrix:
        _print_matrix()
        return 0

    fails = 0
    print(f"Base: {args.base}")
    for method, path in ENDPOINTS:
        code, data = _req(args.base, method, path)
        ok = 200 <= code < 300
        if not ok or code >= 500:
            fails += 1
        summary = ""
        if isinstance(data, dict):
            if "configured" in data:
                summary = f"configured={data.get('configured')}"
            elif "configured_count" in data:
                summary = f"configured_count={data.get('configured_count')}"
            elif "count" in data and "items" in data:
                summary = f"queue={data.get('count')}"
            elif "vendors" in data:
                summary = f"vendors={len(data.get('vendors') or {})}"
            elif "groups" in data:
                summary = "catalog"
            elif "count" in data:
                summary = f"count={data.get('count')}"
            elif data.get("error"):
                summary = str(data.get("error"))[:80]
        mark = "OK" if ok else "FAIL"
        print(f"  [{mark}] {method} {path} -> {code} {summary}")

    if args.sync:
        print("-- sync (only if configured) --")
        for path in SYNC_ENDPOINTS:
            st_path = path.replace("/sync", "/status")
            _code, st = _req(args.base, "GET", st_path)
            configured = False
            if isinstance(st, dict):
                configured = bool(st.get("configured") or st.get("configured_count"))
            if not configured:
                print(f"  [skip] POST {path} (not configured)")
                continue
            sc, _data = _req(args.base, "POST", path)
            ok = 200 <= sc < 300
            if not ok:
                fails += 1
            print(f"  [{'OK' if ok else 'FAIL'}] POST {path} -> {sc}")

    print()
    _print_matrix()
    print(f"\nResult: {'PASS' if fails == 0 else f'FAIL ({fails})'}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
