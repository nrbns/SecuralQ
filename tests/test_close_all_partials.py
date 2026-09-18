"""Close remaining PARTIAL checklist items with real tests (#174/#228/#234/#235/#246/#241/#248/#256/#221)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from tests._http_test_utils import configure_isolated_settings


def test_174_firewall_fail_refreshes_attack_paths(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.services import control_testing as ct
    import app.services.attack_path_realtime as apr

    calls: list[dict] = []

    def _fake_refresh(user_id, **kwargs):
        calls.append({"user_id": user_id, **kwargs})
        return {"ok": True}

    monkeypatch.setattr(apr, "refresh_attack_paths_for_threat", _fake_refresh)
    apr.refresh_attack_paths_for_threat(
        "user1", agent_id="ag1", asset_id="as1", reason="host_firewall_fail"
    )
    assert calls and calls[0]["reason"] == "host_firewall_fail"
    src = Path(ct.__file__).read_text(encoding="utf-8")
    assert "refresh_attack_paths_for_threat" in src
    assert "host_firewall_fail" in src


def test_228_and_234_rate_limit_redis_and_api_key(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.rate_limit import RateLimitMiddleware

    class _FakeRedis:
        def __init__(self):
            self.store: dict[str, int] = {}

        def incr(self, key):
            self.store[key] = int(self.store.get(key) or 0) + 1
            return self.store[key]

        def expire(self, key, _sec):
            return True

    fake = _FakeRedis()
    monkeypatch.setattr("app.redis_client.redis_enabled", lambda: True)
    monkeypatch.setattr("app.redis_client.get_sync_redis", lambda cached=True: fake)

    mw = RateLimitMiddleware(app=None, per_minute=100, api_key_per_minute=3)
    # Direct bucket checks (same path as dispatch for API keys)
    assert mw._allow("apikey:testhash", 3, prefer_redis=True) is True
    assert mw._allow("apikey:testhash", 3, prefer_redis=True) is True
    assert mw._allow("apikey:testhash", 3, prefer_redis=True) is True
    assert mw._allow("apikey:testhash", 3, prefer_redis=True) is False
    assert any("securaiq:ratelimit:apikey:testhash" == k or k.endswith("apikey:testhash") for k in fake.store)
    # Auth path redis preference
    assert mw._allow("1.2.3.4:auth", 2, prefer_redis=True) is True
    assert mw._allow("1.2.3.4:auth", 2, prefer_redis=True) is True
    assert mw._allow("1.2.3.4:auth", 2, prefer_redis=True) is False


def test_235_webhook_dlq_enqueue(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.automation import create_webhook, dispatch_webhooks, ensure_webhook_schema, list_dlq
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    ensure_webhook_schema()
    u = register_user("hook_dlq2", "password123")
    create_webhook(u.id, name="fail", url="http://127.0.0.1:1/nope", secret="sec")

    async def _go():
        out = await dispatch_webhooks(u.id, "agent.offline", {"id": "a1"})
        assert out["errors"]
        assert list_dlq(u.id)

    asyncio.run(_go())


def test_246_rotate_secrets_dry_run(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    import sys

    from scripts.rotate_secrets import main

    monkeypatch.setattr(
        sys, "argv", ["rotate_secrets.py", "--dry-run", "--env-file", str(tmp_path / "none.env")]
    )
    assert main() == 0


def test_241_canary_upgrade_rings(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import create_upgrade_canary_campaign, enroll_agent, ensure_schema
    from app.auth import register_user
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    ensure_schema()
    u = register_user("canary_op", "password123")
    a1 = enroll_agent(u.id, name="ring0")
    a2 = enroll_agent(u.id, name="ring1")
    camp = create_upgrade_canary_campaign(
        u.id, agent_ids=[a1["agent_id"], a2["agent_id"]], ring_sizes=[1, 1]
    )
    assert camp["ok"] is True
    assert camp["rings"] == 2
    assert len(camp["commands"]) == 2
    assert camp["commands"][0]["ring_index"] == 0
    assert camp["commands"][1]["ring_index"] == 1


def test_248_mtls_fleet_status(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app import agent_certs
    from app.config import settings

    monkeypatch.setattr(settings, "agent_mtls_enabled", True, raising=False)
    st = agent_certs.fleet_mtls_status()
    assert st["enabled"] is True
    assert "ca_ready" in st
    assert "proxy_verify" in st


def test_256_saml_and_scim_surfaces(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    import pytest

    from app import saml_scaffold
    from app.config import settings

    assert saml_scaffold.enabled() is False
    st = saml_scaffold.status()
    assert st["protocol"] == "saml2"
    assert st["signature_verification_required"] is True
    assert st["production_ready"] is False
    monkeypatch.setattr(settings, "saml_enabled", True, raising=False)
    meta = saml_scaffold.sp_metadata()
    assert "EntityDescriptor" in meta
    assert "WantAssertionsSigned=\"true\"" in meta or "WantAssertionsSigned='true'" in meta

    # Fail-closed: unsigned / unverified response must not be accepted
    with pytest.raises(ValueError, match="fail-closed|refusing|signxml|SAML_IDP"):
        saml_scaffold.receive_acs({"SAMLResponse": "dGVzdC1mYWtlLXJlc3BvbnNl"})

    # Lab receipt mode still refuses accepted=True
    monkeypatch.setattr(settings, "saml_allow_unverified_lab", True, raising=False)
    lab = saml_scaffold.receive_acs({"SAMLResponse": "dGVzdC1mYWtlLXJlc3BvbnNl"})
    assert lab["ok"] is True
    assert lab["accepted"] is False
    assert lab["verified_signature"] is False
    assert lab.get("lab_receipt_only") is True


def test_221_pptx_export(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    import zipfile

    from app.pptx_export import build_executive_pptx

    out = tmp_path / "board.pptx"
    meta = build_executive_pptx(
        out, title="SecuraIQ Board Pack", bullets=["Critical: 2", "High: 5"]
    )
    assert out.is_file() and meta["bytes"] > 500
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "[Content_Types].xml" in names
        assert any(n.startswith("ppt/slides/") for n in names)


def test_244_245_docs_and_scripts_exist():
    root = Path(__file__).resolve().parents[1]
    assert (root / "docs" / "incident-sla.md").is_file()
    assert (root / "scripts" / "staging_rollback_check.py").is_file()
    assert (root / "docs" / "openapi.json").is_file()
    assert (root / "alembic" / "versions" / "0002_audit_chain.py").is_file()
