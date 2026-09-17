# SecuraIQ Master Checklist — work order + verified status

Consolidates `SECURAIQ-PRODUCTION-BUILD.md`, conversation gaps, and Phase A–B shipping.
**Cursor executes top → bottom. Claude verifies against this file.**

Status legend: ✅ done in repo · 🟡 partial · ❌ missing · 🔒 Phase 6 (non-engineering)

Last verified against `securaiq/main` (static audit + tests). Re-check after each push.

---

## PHASE 0 — Do first

| ID | Item | Status | Evidence |
|----|------|--------|----------|
| **#226** | `AUTH_ENABLED=false` / local-admin bypass hard-disabled in production | ✅ | `assert_safe_deployment_auth()` in `app/auth.py`; called from `app/main.py` lifespan; tests in `tests/test_tenancy_rbac.py` |

---

## PHASE 1 — P0 (paying customer / real machine)

| ID | Item | Status | Evidence / gap |
|----|------|--------|----------------|
| **#224** | Enrollment token flow | ✅ | `POST /api/agents/enroll-tokens`, `/enroll-by-token`; packaging installers; `tests/test_production_p0_auth_enroll.py` |
| **#225** | Revoke terminates live connections | ✅ | `revoke_agent()` → `force_disconnect_agent()`; cert revoke |
| **#222** | License/entitlement + Ed25519 + grace + APIs | ✅ | `app/license_service.py`, `GET /api/licenses/current`, `/api/entitlements/check` |
| **#223** | MFA recovery + `login_attempts` lockout | ✅ | `app/mfa.py`, `app/login_attempts.py` |
| **#228** | Login/MFA rate limit on Redis | 🟡→✅ | Middleware Redis for `/api/auth/*`; login lockout + MFA counters also Redis-backed when `REDIS_URL` set (DB remains SoT/audit) |
| **#227** | Alembic + SQLite→Postgres export | 🟡 | Alembic baseline exists; **export tool:** `scripts/sqlite_to_postgres_export.py` (full DDL migration chain still incremental) |
| **#229** | Backup-restore drill (executed) | 🟡→✅ | Scripts exist; **automated drill:** `scripts/backup_restore_drill.py` + pytest |

---

## PHASE 2 — Realtime control engine

| ID | Item | Status |
|----|------|--------|
| **#172** | Affected-controls-only recompute | ✅ `app/controls/recompute.py` |
| **#173** | Risk-weight failed controls | ✅ `control_testing._failure_risk_score` |
| **#174** | Correlate with attack-path graph | ✅ RT-09 / `attack_graph` |
| **#176** | Full suite + live verification | 🟡 Gate tests exist; expand as engine grows |

---

## PHASE 3 — P1 commercial credibility

| ID | Item | Status |
|----|------|--------|
| **#247** | MSI + Authenticode / deb+rpm signing | 🟡 Scaffolds + CI secrets-gated (needs EV cert — Phase 6) |
| **#248** | Agent mTLS | 🟡 Server issue/rotate/proxy verify shipped; fleet CA ops |
| **#249** | Signed rollback-capable agent update | ✅ Base mechanism |
| **#241** | Staged/canary rollout | 🟡 Campaign rings exist; deepen as needed |
| **#250** | `control_results` history | ✅ |
| **#251** | Object storage for evidence | ❌ |
| **#252** | CI Postgres matrix + Compose SaaS default | 🟡 Partial |
| **#253** | `/api/v1` versioning | ✅ |
| **#254** | `rbac-matrix.md` client role | ✅ Documented in `docs/rbac-matrix.md` |
| **#236** | Real OpenAPI from routes | 🟡 FastAPI `/docs`; export artifact optional |

---

## PHASE 4 — Reliability / tenant / lifecycle

| ID | Status notes |
|----|--------------|
| **#230** Cross-tenant isolation tests | ✅ `tests/test_cross_tenant_isolation.py` |
| **#231–246** Quotas, chaos plan, SCA, retention, GDPR export, hash-chain audit, uninstall, PSIRT, status page, staging, secrets rotation | 🟡/# ❌ Mix — prioritize after Phase 1 close |

---

## PHASE 5 — P2

| ID | Status |
|----|--------|
| **#255** Argon2id opportunistic rehash | 🟡 Argon2 on hash; rehash-on-login polish |
| **#256** WebAuthn → SAML → SCIM | 🟡 Partial modules |
| **#257** KMS/HSM | ❌ |
| **#258** macOS notarization | 🟡 Scaffold + secrets |
| **#259** MSSP multi-org | ❌ |

---

## PHASE 6 — Outside engineering (parallel)

🔒 Legal (MSA/DPA/BAA), SOC 2, ISO 27001, FedRAMP, third-party pentest, EV code-signing cert purchase, target vertical decision, vertical depth, localization.

---

## How to run verification

```bash
# Phase 0–1 gates
pytest -v tests/test_tenancy_rbac.py tests/test_production_p0_auth_enroll.py \
  tests/test_mfa_and_license_billing.py tests/test_master_checklist_p0.py

python scripts/backup_restore_drill.py
python scripts/sqlite_to_postgres_export.py --help
```

Work order for Cursor: close any 🟡 in Phase 0–1 first, then Phase 2 #176, then Phase 3 #251/#252/#254.
