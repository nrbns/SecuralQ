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
    import app.db as db_mod

    # Duck-type rather than `isinstance(s, Settings)`: a module reloaded via
    # importlib.reload() (test_dashboard.py, test_builtin_scanner.py both do
    # this) re-executes `class Settings(BaseSettings): ...`, producing a
    # *new* class object with the same name. An old Settings instance built
    # from the pre-reload class fails `isinstance(old, NewSettings)` even
    # though it's exactly the stale singleton we need to catch and patch.
    _required_attrs = ("auth_enabled", "data_dir", "database_url")
    seen: set[int] = set()
    for mod in list(sys.modules.values()):
        s = getattr(mod, "settings", None)
        if (
            s is not None
            and all(hasattr(s, a) for a in _required_attrs)
            and id(s) not in seen
        ):
            seen.add(id(s))
            monkeypatch.setattr(s, "data_dir", str(data_dir), raising=False)
            monkeypatch.setattr(s, "workspace_zero_start", False, raising=False)
            monkeypatch.setattr(s, "auth_enabled", auth_enabled, raising=False)
            monkeypatch.setattr(s, "deployment_mode", "lab", raising=False)
            monkeypatch.setattr(s, "database_url", "", raising=False)
    db_mod.reset_conn_for_tests()
    return db_mod
