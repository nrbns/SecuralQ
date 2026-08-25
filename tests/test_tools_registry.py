"""Regression guard for the exact bug class found and fixed earlier this
session: a tool registered in TOOL_CATALOG with no matching dispatch branch
in the runner always fails at execution time, even when it's genuinely
available (HardeningKitty had `binaries=()` and no dispatch case, so it fell
through to the generic external-binary path and permanently reported "not
installed").

This test doesn't execute any tool (no subprocess, no network) — it
statically confirms every *builtin* tool id has a real `tid == "<id>"`
dispatch branch in app/tools/runner.py, and every *external* tool has at
least one PATH binary name registered (an external tool with an empty
`binaries` tuple can never be found by `resolve_binary`/`is_available`,
which is precisely the historical bug).
"""

from __future__ import annotations

import re
from pathlib import Path

from app.tools.registry import TOOL_CATALOG

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNER_SRC = (REPO_ROOT / "app" / "tools" / "runner.py").read_text(encoding="utf-8")

_DISPATCH_ID_RE = re.compile(r'tid == "([a-z0-9_]+)"')
_DISPATCH_IN_RE = re.compile(r"tid in \{([^}]+)\}")
DISPATCHED_IDS = set(_DISPATCH_ID_RE.findall(RUNNER_SRC))
for _m in _DISPATCH_IN_RE.finditer(RUNNER_SRC):
    DISPATCHED_IDS.update(re.findall(r'"([a-z0-9_]+)"', _m.group(1)))


def test_every_builtin_tool_has_a_dispatch_branch():
    builtins = [tid for tid, spec in TOOL_CATALOG.items() if spec.kind == "builtin"]
    assert builtins, "TOOL_CATALOG has no builtin tools — did the catalog import fail silently?"
    missing = [tid for tid in builtins if tid not in DISPATCHED_IDS]
    assert not missing, (
        f"builtin tool(s) with no runner.py dispatch branch (will always report "
        f"'unknown tool' or fall through to the PATH-binary check and fail): {missing}"
    )


def test_every_external_tool_declares_a_binary_or_has_a_dedicated_dispatch():
    # A tool marked kind="external" with no PATH binaries is only safe if it
    # has its own `tid == "<id>"` branch in runner.py that intercepts it
    # *before* the generic external-PATH fallback (see hardeningkitty: it has
    # no PATH binary by design — it runs via a PowerShell module — and would
    # always report "not installed" if it fell through to the generic path).
    bad = [
        tid
        for tid, spec in TOOL_CATALOG.items()
        if spec.kind == "external" and not spec.binaries and tid not in DISPATCHED_IDS
    ]
    assert not bad, (
        f"external tool(s) with no PATH binaries and no dedicated dispatch branch — "
        f"resolve_binary() can never find these, so they'll always report 'not "
        f"installed on PATH' regardless of real install status: {bad}"
    )


def test_hardeningkitty_has_its_dedicated_branch():
    # The specific regression this whole test file exists to catch.
    assert "hardeningkitty" in DISPATCHED_IDS


def test_no_duplicate_tool_ids_across_registry():
    # TOOL_CATALOG is a dict so Python itself prevents literal duplicate keys,
    # but confirm the `.id` field on every ToolSpec matches its dict key —
    # a copy-paste of an existing ToolSpec with a new dict key but stale
    # internal id would silently misreport itself everywhere id is read from spec.id.
    mismatched = [key for key, spec in TOOL_CATALOG.items() if spec.id != key]
    assert not mismatched, f"ToolSpec.id != registry key for: {mismatched}"


def test_heavy_tools_are_not_needs_target_false_with_binaries_missing():
    # Sanity check on the ToolSpec data itself, not the runner: a tool that
    # doesn't need a target should be reachable without target-resolution
    # (informational/awareness tools) — just confirm the flag is a real bool,
    # guards against a stray string like "True" from a copy-paste.
    for tid, spec in TOOL_CATALOG.items():
        assert isinstance(spec.needs_target, bool), f"{tid}.needs_target is not a bool: {spec.needs_target!r}"
        assert isinstance(spec.heavy, bool), f"{tid}.heavy is not a bool: {spec.heavy!r}"


def test_tools_split_securaiq_vs_third_party():
    from app.tools.registry import ENGINE_TOOLS, PT_PACK_TOOLS, list_tools_status

    if hasattr(list_tools_status, "_cache"):
        list_tools_status._cache = None
    for tid, spec in TOOL_CATALOG.items():
        assert spec.origin in {"securaiq", "third_party"}, f"{tid} bad origin={spec.origin!r}"
        if spec.kind == "external":
            assert spec.origin == "third_party", f"external {tid} must be third_party"
    status = list_tools_status()
    assert status["securaiq_count"] > 0
    assert status["third_party_count"] > 0
    assert all(t.get("origin") in {"securaiq", "third_party"} for t in status["tools"])
    assert TOOL_CATALOG["ports"].origin == "securaiq"
    assert TOOL_CATALOG["nmap"].origin == "third_party"
    assert TOOL_CATALOG["defender_hunt"].origin == "third_party"
    assert TOOL_CATALOG["cve_lookup"].origin == "third_party"
    assert TOOL_CATALOG["netvuln_scan"].origin == "securaiq"
    assert TOOL_CATALOG["openvas"].origin == "securaiq"
    assert TOOL_CATALOG["openvas"].kind == "builtin"
    assert TOOL_CATALOG["zap"].origin == "securaiq"
    assert TOOL_CATALOG["zap"].kind == "builtin"
    assert TOOL_CATALOG["zap"].name == "SecuraIQ Web Scanner"
    assert "zap" in DISPATCHED_IDS
    assert TOOL_CATALOG["securaiq"].kind == "builtin"
    assert TOOL_CATALOG["securaiq"].origin == "securaiq"
    assert TOOL_CATALOG["securaiq_code"].origin == "securaiq"
    assert TOOL_CATALOG["securaiq_code"].kind == "builtin"
    assert "combo_assessment" in PT_PACK_TOOLS
    assert ENGINE_TOOLS["securaiq"] == "securaiq"
    assert set(ENGINE_TOOLS) >= {"securaiq", "nmap", "nuclei", "zap"}
    assert status.get("engine_tools", {}).get("securaiq") == "securaiq"


def test_extract_targets_ignores_scan_code_phrase():
    # Regression: "scan code <path>" must not treat the word "code" as a hostname
    # (that caused code_scan / securaiq_code to fail with getaddrinfo).
    from app.net_assess import extract_targets

    assert "code" not in {t.lower() for t in extract_targets("scan code C:\\lab\\app", None)}
    assert "code" not in {t.lower() for t in extract_targets("scan code /home/lab/app", None)}
    assert extract_targets("scan 10.10.10.5", None) == ["10.10.10.5"]
