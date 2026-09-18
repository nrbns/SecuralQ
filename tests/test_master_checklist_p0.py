"""Master checklist Phase 0–1 acceptance tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests._http_test_utils import configure_isolated_settings


def test_226_production_refuses_auth_disabled(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import assert_safe_deployment_auth
    from app.config import settings

    monkeypatch.setattr(settings, "deployment_mode", "production", raising=False)
    monkeypatch.setattr(settings, "auth_enabled", False, raising=False)
    monkeypatch.setattr(settings, "require_postgres_in_production", False, raising=False)
    with pytest.raises(RuntimeError, match="AUTH_ENABLED"):
        assert_safe_deployment_auth()


def test_228_login_lockout_uses_redis_when_available(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app import login_attempts as la

    class _FakeRedis:
        def __init__(self):
            self.store: dict[str, int] = {}

        def incr(self, key):
            self.store[key] = int(self.store.get(key) or 0) + 1
            return self.store[key]

        def expire(self, key, _sec):
            return True

        def get(self, key):
            return self.store.get(key)

        def delete(self, key):
            self.store.pop(key, None)

    fake = _FakeRedis()
    monkeypatch.setattr("app.redis_client.redis_enabled", lambda: True)
    monkeypatch.setattr("app.redis_client.get_sync_redis", lambda cached=True: fake)
    monkeypatch.setattr(la, "_max_failures", lambda: 3)
    monkeypatch.setattr(la, "_window_sec", lambda: 900.0)

    user = "lockout_redis_user"
    for _ in range(3):
        la.record_login_attempt(user, ip="1.2.3.4", success=False)
    locked, detail = la.is_locked(user)
    assert locked is True
    assert detail.get("distributed") is True
    assert fake.store  # redis mirrored


def test_229_backup_restore_drill():
    from scripts.backup_restore_drill import run_drill

    result = run_drill(keep=False)
    assert result["ok"] is True, result


def test_227_sqlite_export_roundtrip(tmp_path):
    import sqlite3

    from scripts.sqlite_to_postgres_export import export_json, export_sql

    db = tmp_path / "t.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT)")
    conn.execute("INSERT INTO users VALUES ('u1', 'alice')")
    conn.commit()
    conn.close()

    sql_out = tmp_path / "out.sql"
    info = export_sql(db, sql_out)
    assert info["ok"] is True
    text = sql_out.read_text(encoding="utf-8")
    assert "INSERT INTO" in text
    assert "alice" in text

    jdir = tmp_path / "json"
    jinfo = export_json(db, jdir)
    assert jinfo["ok"] is True
    assert (jdir / "users.json").is_file()


def test_master_checklist_doc_exists():
    root = Path(__file__).resolve().parents[1]
    p = root / "docs" / "MASTER-CHECKLIST.md"
    assert p.is_file()
    text = p.read_text(encoding="utf-8")
    assert "#226" in text
    assert "#224" in text
    assert ("Phase 0" in text) or ("PHASE 0" in text)
