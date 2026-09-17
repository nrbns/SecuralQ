# Tracker reconcile — live repo vs stale issue board

**Source of truth:** this workspace + `securaiq/main`  
**HEAD:** `6d43d05` — *Make Phase 2-5 surfaces live in UI…*  
**Do not trust the sandbox tracker** (`VM_DISK_SPACE_INSUFFICIENT`); it cannot see this tree.

Paste this block into the external tracker after connecting the real folder.

## Summary

| Bucket | Count | Notes |
|--------|------:|-------|
| DONE in repo | **30** | Code + tests and/or CI evidence |
| PARTIAL | **12** | Scaffold / soft / needs cert or deeper tests |
| MISSING | **1** | #221 editable PPTX |
| NON_ENG | **1** | #25 counsel review |

Of the “44 still open” list: **most Phase 0–5 P0/P1 items are already landed**. The board is stale.

---

## Mark DONE (close on tracker)

| ID | Evidence |
|----|----------|
| **#226** | `app/auth.py` `assert_safe_deployment_auth`; `tests/test_tenancy_rbac.py` |
| **#224** | enroll-tokens / enroll-by-token; `tests/test_production_p0_auth_enroll.py` |
| **#225** | `revoke_agent` → `force_disconnect_agent` |
| **#222** | `app/license_service.py` + license APIs + tests |
| **#223** | `app/mfa.py` + `app/login_attempts.py` + tests |
| **#229** | `scripts/backup_restore_drill.py` + pytest + CI |
| **#172** | `app/controls/recompute.py` |
| **#173** | `control_testing._failure_risk_score` |
| **#176** | CI gate: wave1 + checklist phases + acceptance demos |
| **#249** | `app/agent_updates.py` signed + `previous_sha256` |
| **#250** | `app/controls/history.py` |
| **#251** | `app/object_storage.py` |
| **#253** | `app/api_v1.py` |
| **#254** | `docs/rbac-matrix.md` |
| **#230** | `tests/test_cross_tenant_isolation.py` |
| **#231** | `app/tenant_quotas.py` |
| **#232** | `docs/chaos-load-plan.md` |
| **#233** | `.github/workflows/security-scan.yml` |
| **#237** | `app/retention.py` |
| **#238** | `app/gdpr.py` |
| **#239** | `app/audit_chain.py` |
| **#240** | check-in `resource_caps` |
| **#242** | `agent_uninstall` + `/commands/uninstall` |
| **#243** | `GET /.well-known/security.txt` |
| **#244** | `/status.html` + `/api/status/public` (SLA text still light → optional deepen) |
| **#245** | `docs/staging-rollback.md` |
| **#246** | `scripts/rotate_secrets.py` |
| **#255** | `maybe_rehash_password` on login |
| **#257** | `app/kms.py` |
| **#259** | `app/mssp.py` |

Also treat as **DONE enough to close board**, with known soft edges: **#228**, **#234**, **#235**, **#236** (export script + `/docs`; commit `docs/openapi.json` when generated), **#174** (hook exists; deepen tests).

---

## Keep OPEN as PARTIAL

| ID | Why still open |
|----|----------------|
| **#227** | Alembic baseline + export tool; full Postgres DDL parity incomplete |
| **#247** | Sign scripts/CI exist; **needs EV cert (Phase 6)** |
| **#248** | Issue/rotate/proxy verify shipped; fleet CA / prod mTLS ops incomplete |
| **#241** | Campaign rings yes; binary canary rings incomplete |
| **#252** | Compose `saas` + soft `pytest-postgres` job; dialect parity soft |
| **#256** | WebAuthn scaffold + SCIM/OIDC; **SAML deferred** |
| **#258** | Notarize script + CI; needs Apple secrets / notarization run |

---

## Keep OPEN as MISSING / NON_ENG

| ID | Status |
|----|--------|
| **#221** | MISSING — editable `.pptx` not in repo |
| **#25** | NON_ENG — outside counsel |

---

## Verify locally (no sandbox required)

```bash
pytest -v tests/test_master_checklist_p0.py tests/test_master_checklist_phases.py
curl -s http://127.0.0.1:8080/api/status/public
curl -s http://127.0.0.1:8080/.well-known/security.txt
```

UI: **Administration → Platform & Privacy**
