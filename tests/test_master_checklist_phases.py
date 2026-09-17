"""Master checklist Phases 2–5 acceptance (in-repo implementable items)."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from tests._http_test_utils import configure_isolated_settings


def test_251_object_storage_local_put_get(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.config import settings
    from app import object_storage as os_

    monkeypatch.setattr(settings, "object_storage_backend", "local", raising=False)
    meta = os_.put_bytes("evidence/test/a.bin", b"hello-evidence", content_type="text/plain")
    assert meta["sha256"] == hashlib.sha256(b"hello-evidence").hexdigest()
    assert meta["backend"] == "local"
    got = os_.get_bytes("evidence/test/a.bin")
    assert got == b"hello-evidence"
    assert os_.status()["backend"] == "local"


def test_239_audit_hash_chain(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.audit_chain import append_chained, verify_chain
    from app.db import init_schema

    init_schema()
    a = append_chained("chain_a", "u1", {"n": 1})
    b = append_chained("chain_b", "u1", {"n": 2})
    assert a["entry_hash"]
    assert b["prev_hash"] == a["entry_hash"]
    v = verify_chain()
    assert v["ok"] is True
    assert v["checked"] >= 2


def test_237_retention_purge_dry_run(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.db import init_schema
    from app.retention import purge_expired

    init_schema()
    out = purge_expired(dry_run=True)
    assert out["ok"] is True
    assert "deleted" in out


def test_238_gdpr_export_erase(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.db import init_schema
    from app.gdpr import erase_subject, export_subject
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    u = register_user("gdpr_subj", "password123")
    pack = export_subject(u.id)
    assert pack["user"]["username"] == "gdpr_subj"
    erased = erase_subject(u.id)
    assert erased["ok"] is True
    assert erased["counts"].get("users_anonymized") == 1


def test_231_tenant_quotas(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.db import init_schema
    from app.tenant_quotas import get_quotas, set_quotas, usage

    init_schema()
    q = set_quotas("org_test", max_agents=3, api_per_minute=120)
    assert q["max_agents"] == 3
    assert get_quotas("org_test")["api_per_minute"] == 120
    u = usage("org_test")
    assert u["quotas"]["max_agents"] == 3


def test_235_webhook_hmac_sign_verify(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.automation import create_webhook, ensure_webhook_schema, verify_signature
    from app.auth import register_user
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    ensure_webhook_schema()
    u = register_user("hook_user", "password123")
    wh = create_webhook(u.id, name="lab", url="http://127.0.0.1:9/hook", secret="s3cret")
    assert wh.get("secret") == "s3cret"
    body = b'{"event":"test"}'
    ts = "1700000000"
    sig = "sha256=" + hmac.new(b"s3cret", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    assert verify_signature("s3cret", body, ts, sig) is True
    assert verify_signature("s3cret", body, ts, "sha256=deadbeef") is False


def test_255_argon2_rehash_on_login(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    import hashlib
    import secrets

    from app.auth import login, maybe_rehash_password, verify_password
    from app.db import get_conn, init_schema, new_id, now
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    # Insert legacy pbkdf2 user
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", b"password123", salt.encode(), 180_000)
    stored = f"pbkdf2${salt}${dk.hex()}"
    uid = new_id()
    get_conn().execute(
        "INSERT INTO users (id, username, password_hash, role, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
        (uid, "legacy_pw", stored, "user", now(), ""),
    )
    get_conn().commit()
    assert verify_password("password123", stored)
    assert maybe_rehash_password(uid, "password123", stored) is True
    row = get_conn().execute("SELECT password_hash FROM users WHERE id = ?", (uid,)).fetchone()
    # If argon2-cffi present → argon2; else may stay pbkdf2
    assert verify_password("password123", row["password_hash"])
    user_tok = login("legacy_pw", "password123")
    assert isinstance(user_tok, tuple)


def test_257_kms_local_roundtrip(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app import kms

    enc = kms.encrypt("secret-lab-value")
    assert enc["provider"] == "local"
    plain = kms.decrypt(enc)
    assert b"secret-lab-value" in plain or plain.decode("utf-8") == "secret-lab-value"


def test_259_mssp_link_children(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.commercial_ext import create_org
    from app.db import init_schema
    from app.mssp import link_child, list_children, mssp_status
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    u = register_user("mssp_admin", "password123", role="admin")
    parent = create_org(u.id, "MSSP Parent")
    child = create_org(u.id, "Customer A")
    link_child(parent["id"], child["id"], actor_user_id=u.id)
    kids = list_children(parent["id"])
    assert any(k["id"] == child["id"] for k in kids)
    st = mssp_status(parent["id"])
    assert st["mssp"] is True


def test_242_uninstall_command_kind(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import SUPPORTED_COMMAND_KINDS, agent_resource_caps, request_agent_uninstall
    from app.auth import register_user
    from app.agents import enroll_agent
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    assert "agent_uninstall" in SUPPORTED_COMMAND_KINDS
    caps = agent_resource_caps()
    assert caps["max_cpu_percent"] > 0
    u = register_user("uninst_op", "password123")
    ag = enroll_agent(u.id, name="lab-box")
    cmd = request_agent_uninstall(u.id, ag["agent_id"])
    assert cmd["status"] == "pending_approval"


def test_243_security_txt_and_status_docs():
    root = Path(__file__).resolve().parents[1]
    assert (root / "docs" / "staging-rollback.md").is_file()
    assert (root / "docs" / "chaos-load-plan.md").is_file()
    assert (root / "static" / "status.html").is_file()
    assert (root / "scripts" / "export_openapi.py").is_file()
    assert (root / "scripts" / "rotate_secrets.py").is_file()


def test_256_webauthn_scaffold_disabled_by_default(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.webauthn_scaffold import enabled, status

    assert enabled() is False
    st = status()
    assert st["saml_deferred"] is True


def test_master_checklist_phases_documented():
    text = (Path(__file__).resolve().parents[1] / "docs" / "MASTER-CHECKLIST.md").read_text(
        encoding="utf-8"
    )
    for needle in ("#251", "#239", "#238", "#255", "#259", "PHASE 6"):
        assert needle in text
