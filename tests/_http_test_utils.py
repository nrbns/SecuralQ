"""Shared helper for HTTP-layer (TestClient) tests that need real
AUTH_ENABLED + an isolated DATA_DIR.

`app.config.settings` is a module-level singleton that every other module
imports by reference (`from app.config import settings`) at its own
first-import time. Some existing test files (test_dashboard.py,
test_builtin_scanner.py) get a fresh Settings by reloading `app.config` —
that replaces `app.config.settings` with a *new* object, but any module
that already imported the old one (e.g. app.commercial_api, whose
`require_user` reads `settings.auth_enabled`) keeps pointing at the stale
instance. Across a whole-suite run this means more than one distinct
Settings object can be alive at once, each referenced by a different
subset of already-imported modules, so patching only `app.config.settings`
is not guaranteed to reach the one a given route handler actually reads.

`configure_isolated_settings` sweeps every module already in sys.modules
for a `settings` attribute and patches each live Settings instance found,
so the effective config is consistent regardless of import/reload order
elsewhere in the suite. Modules imported for the first time *after* this
call still pick up the change, because they bind to `app.config`'s current
(already-patched) singleton at their own import time.
"""

from __future__ import annotations

import sys


def configure_isolated_settings(monkeypatch, data_dir, *, auth_enabled: bool = True):
    import app.config as config_mod
    import app.db as db_mod

    # Duck-type rather than `isinstance(s, Settings)`: a module reloaded via
    # importlib.reload() (test_dashboard.py, test_builtin_scanner.py both do
    # this) re-executes `class Settings(BaseSettings): ...`, producing a
    # *new* class object with the same name. An old Settings instance built
    # from the pre-reload class fails `isinstance(old, NewSettings)` even
    # though it's exactly the stale singleton we need to catch and patch.
    #
    # After a reload, modules that did `from app.config import settings` still
    # hold the *pre-reload* object. Rebind every such attribute to the live
    # app.config.settings singleton so later monkeypatches on that object
    # reach production_profile / agent_certs / login_attempts / etc.
    canonical = config_mod.settings
    _required_attrs = ("auth_enabled", "data_dir", "database_url")
    for mod in list(sys.modules.values()):
        s = getattr(mod, "settings", None)
        if s is None or not all(hasattr(s, a) for a in _required_attrs):
            continue
        if s is not canonical:
            monkeypatch.setattr(mod, "settings", canonical, raising=False)

    monkeypatch.setattr(canonical, "data_dir", str(data_dir), raising=False)
    monkeypatch.setattr(canonical, "workspace_zero_start", False, raising=False)
    monkeypatch.setattr(canonical, "auth_enabled", auth_enabled, raising=False)
    monkeypatch.setattr(canonical, "deployment_mode", "lab", raising=False)
    monkeypatch.setattr(canonical, "database_url", "", raising=False)
    # Lab defaults — prevent production/mTLS flags leaking across reload-heavy tests.
    for _flag in (
        "agent_mtls_enabled",
        "agent_mtls_proxy_verify",
        "agent_mtls_require_fingerprint_match",
        "agent_require_command_signature",
        "agent_require_replay_protection",
        "commercial_profile_enforce",
        "license_enforcement_enabled",
        "billing_enforcement_enabled",
        "quota_enforcement_enabled",
    ):
        monkeypatch.setattr(canonical, _flag, False, raising=False)
    db_mod.reset_conn_for_tests()
    return db_mod
