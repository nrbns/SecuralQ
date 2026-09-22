"""Local FS WORM + remaining ops proofs."""

from __future__ import annotations

import hashlib


def test_local_fs_worm_readonly(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURAIQ_DATA_DIR", str(tmp_path))
    from app.config import settings

    settings.data_dir = str(tmp_path)
    from app.evidence_spine.worm import apply_local_fs_worm, worm_backend_status

    payload = b"worm-unit-test"
    digest = hashlib.sha256(payload).hexdigest()
    out = apply_local_fs_worm(digest, content=payload)
    assert out["readonly"] is True
    assert digest in out["path"]
    # Second call must not crash on readonly meta rewrite
    out2 = apply_local_fs_worm(digest, content=payload)
    assert out2["readonly"] is True
    st = worm_backend_status()
    assert st["backend"] == "local_fs"
    assert st["object_lock_enabled"] is False
    assert int(st["local_fs_marker_count"]) >= 1


def test_record_worm_lock_local_fs(tmp_path, monkeypatch):
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

    configure_isolated_settings(_MP(), tmp_path)
    from app.db import reset_conn_for_tests
    from app.evidence_spine.worm import record_worm_lock
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    try:
        payload = b"record-worm"
        digest = hashlib.sha256(payload).hexdigest()
        row = record_worm_lock("u1", content_hash=digest, content=payload)
        assert row["status"] in {"local_fs_immutable", "local_marker"}
        assert row.get("local_fs", {}).get("readonly") is True
    finally:
        reset_conn_for_tests()
