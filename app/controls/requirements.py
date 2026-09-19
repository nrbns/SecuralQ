"""First-class Requirement entities derived from framework catalogs.

Hierarchy (honest):

  Framework → Requirement → Control → Test → Evidence → Finding → Rem → Verify

Requirements are **domain/theme groupings** of catalog controls (e.g. CMMC
"Access Control"), not invented normative text. Control titles stay the SoT
from ``data/frameworks/*.json``.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from app.controls.catalog import list_framework_controls, normalize_control_id
from app.controls.test_registry import control_bindings_for_test, tests_for_control
from app.gap_analysis import list_frameworks, load_framework

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    s = _SLUG_RE.sub("-", (text or "").strip().lower()).strip("-")
    return s or "general"


def requirement_id(framework_id: str, domain: str) -> str:
    """Stable id: {framework}:{domain-slug} (short hash suffix if empty)."""
    fid = (framework_id or "").strip().lower() or "unknown"
    dom = (domain or "").strip() or "General"
    slug = _slug(dom)
    if slug == "general" and not (domain or "").strip():
        h = hashlib.sha1(f"{fid}:general".encode()).hexdigest()[:6]
        return f"{fid}:general-{h}"
    return f"{fid}:{slug}"


def list_requirements(
    framework_id: str,
    *,
    user_id: str | None = None,
) -> list[dict[str, Any]]:
    """Group controls by domain into Requirement entities."""
    fw = load_framework(framework_id)
    fid = str(fw.get("id") or framework_id).strip()
    controls = list_framework_controls(fid)
    buckets: dict[str, dict[str, Any]] = {}
    for c in controls:
        domain = (c.domain or "").strip() or "General"
        rid = requirement_id(fid, domain)
        bucket = buckets.get(rid)
        if not bucket:
            bucket = {
                "id": rid,
                "framework_id": fid,
                "framework_name": fw.get("name") or fid,
                "title": domain,
                "description": (
                    f"Requirement theme '{domain}' in {fw.get('name') or fid}: "
                    "groups catalog controls for evidence and live-test rollup. "
                    "Not a legal determination of compliance."
                ),
                "control_ids": [],
                "control_count": 0,
                "live_test_names": [],
                "verifiability": "human",
            }
            buckets[rid] = bucket
        bucket["control_ids"].append(c.id)
        for tname in _mapped_tests(fid, c.id):
            if tname not in bucket["live_test_names"]:
                bucket["live_test_names"].append(tname)

    # Attach last-result rollup when user_id provided
    results_by_ctrl: dict[str, str] = {}
    if user_id:
        try:
            from app.controls.results import list_results_for_framework

            rows = list_results_for_framework(user_id, fid) or []
            # Keep latest status per control_id
            for r in rows:
                cid = str(r.get("control_id") or "").strip()
                if not cid:
                    continue
                results_by_ctrl[cid] = str(r.get("status") or "unknown").lower()
        except Exception:
            results_by_ctrl = {}

    out: list[dict[str, Any]] = []
    for rid, bucket in sorted(buckets.items(), key=lambda kv: kv[1]["title"].lower()):
        bucket["control_count"] = len(bucket["control_ids"])
        bucket["verifiability"] = (
            "machine"
            if bucket["live_test_names"]
            else "human"
        )
        if results_by_ctrl:
            statuses = [results_by_ctrl[cid] for cid in bucket["control_ids"] if cid in results_by_ctrl]
            bucket["results_summary"] = {
                "passing": sum(1 for s in statuses if s == "pass"),
                "failing": sum(1 for s in statuses if s == "fail"),
                "unknown": sum(1 for s in statuses if s not in ("pass", "fail")),
                "with_results": len(statuses),
            }
        else:
            bucket["results_summary"] = None
        out.append(bucket)
    return out


def _mapped_tests(framework_id: str, control_id: str) -> list[str]:
    try:
        return list(tests_for_control(framework_id, control_id) or [])
    except Exception:
        return []


def get_requirement(
    framework_id: str,
    requirement_id_str: str,
    *,
    user_id: str | None = None,
) -> dict[str, Any] | None:
    rid = (requirement_id_str or "").strip()
    for row in list_requirements(framework_id, user_id=user_id):
        if row["id"] == rid:
            # Expand controls with live-test bindings
            controls_out = []
            for cid in row["control_ids"]:
                tests = _mapped_tests(framework_id, cid)
                controls_out.append(
                    {
                        "id": cid,
                        "live_tests": tests,
                        "bindings": [
                            b
                            for t in tests
                            for b in control_bindings_for_test(t)
                            if b.get("framework_id") == framework_id
                            and normalize_control_id(framework_id, b.get("control_id") or "")
                            == normalize_control_id(framework_id, cid)
                        ],
                    }
                )
            row = dict(row)
            row["controls"] = controls_out
            row["chain"] = [
                "framework",
                "requirement",
                "control",
                "test",
                "evidence",
                "finding",
                "remediation",
                "verification",
            ]
            return row
    return None


def requirements_index(*, user_id: str | None = None) -> dict[str, Any]:
    """All frameworks with requirement counts (catalog index)."""
    frameworks = []
    for meta in list_frameworks():
        fid = str(meta.get("id") or "")
        if not fid:
            continue
        try:
            reqs = list_requirements(fid, user_id=user_id)
        except Exception:
            reqs = []
        frameworks.append(
            {
                "framework_id": fid,
                "name": meta.get("name") or fid,
                "requirement_count": len(reqs),
                "control_count": sum(r.get("control_count") or 0 for r in reqs),
                "machine_verifiable_requirements": sum(
                    1 for r in reqs if r.get("verifiability") == "machine"
                ),
            }
        )
    return {
        "ok": True,
        "frameworks": frameworks,
        "note": (
            "Requirements are domain groupings of catalog controls — "
            "not a legal compliance determination."
        ),
    }
