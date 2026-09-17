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
| **#228** | Login/MFA rate limit on Redis | ✅ | Middleware Redis for `/api/auth/*`; login lockout + MFA counters Redis-backed when `REDIS_URL` set |
| **#227** | Alembic + SQLite→Postgres export | 🟡 | Alembic baseline; `scripts/sqlite_to_postgres_export.py` |
| **#229** | Backup-restore drill (executed) | ✅ | `scripts/backup_restore_drill.py` + pytest |

---

## PHASE 2 — Realtime control engine

| ID | Item | Status |
|----|------|--------|
| **#172** | Affected-controls-only recompute | ✅ `app/controls/recompute.py` |
| **#173** | Risk-weight failed controls | ✅ `control_testing._failure_risk_score` |
| **#174** | Correlate with attack-path graph | ✅ RT-09 / `attack_graph` |
| **#176** | Full suite + live verification | ✅ Gate includes wave1 + master checklist phases + acceptance demos |

---

## PHASE 3 — P1 commercial credibility

| ID | Item | Status |
|----|------|--------|
| **#247** | MSI + Authenticode / deb+rpm signing | 🟡 Scaffolds + CI secrets-gated (**needs EV cert — Phase 6**) |
| **#248** | Agent mTLS | 🟡 Server issue/rotate/proxy verify shipped; fleet CA ops |
| **#249** | Signed rollback-capable agent update | ✅ Base mechanism |
| **#241** | Staged/canary rollout | 🟡 Campaign rings; see `docs/staging-rollback.md` |
| **#250** | `control_results` history | ✅ |
| **#251** | Object storage for evidence | ✅ `app/object_storage.py` (local default; S3/MinIO/R2 via boto3) |
| **#252** | CI Postgres matrix + Compose SaaS | 🟡 Compose `saas` profile + CI `pytest-postgres` job (soft until dialect parity) |
| **#253** | `/api/v1` versioning | ✅ |
| **#254** | `rbac-matrix.md` client role | ✅ `docs/rbac-matrix.md` |
| **#236** | Real OpenAPI from routes | ✅ FastAPI `/docs` + `scripts/export_openapi.py` → `docs/openapi.json` |

---

## PHASE 4 — Reliability / tenant / lifecycle

| ID | Item | Status |
|----|------|--------|
| **#230** | Cross-tenant isolation tests | ✅ |
| **#231** | Per-tenant quotas | ✅ `app/tenant_quotas.py` + `/api/orgs/{id}/quotas` |
| **#232** | Chaos / load plan | ✅ `docs/chaos-load-plan.md` + existing load scripts |
| **#233** | Dependency scanning CI | ✅ `.github/workflows/security-scan.yml` |
| **#234** | API rate limit per key/tenant | ✅ `RateLimitMiddleware` API-key bucket + org quota overlay |
| **#235** | Webhook signing + retry/DLQ | ✅ HMAC `X-SecuraIQ-Signature` + `webhook_dlq` |
| **#237** | Data retention TTL purge | ✅ `app/retention.py` + `/api/admin/retention/purge` |
| **#238** | GDPR export / erasure | ✅ `app/gdpr.py` + `/api/gdpr/export|/erase` |
| **#239** | Tamper-evident audit hash chain | ✅ `app/audit_chain.py`; `audit()` chains by default |
| **#240** | Agent resource caps | ✅ Advertised on check-in `resource_caps` |
| **#242** | Agent uninstall flow | ✅ `agent_uninstall` command + `/commands/uninstall` |
| **#243** | security.txt + PSIRT | ✅ `GET /.well-known/security.txt` |
| **#244** | Status page | ✅ `/status.html` + `/api/status/public` |
| **#245** | Staging + rollback | ✅ `docs/staging-rollback.md` |
| **#246** | Secrets rotation | ✅ `scripts/rotate_secrets.py` |

---

## PHASE 5 — P2

| ID | Item | Status |
|----|------|--------|
| **#255** | Argon2id opportunistic rehash | ✅ `maybe_rehash_password` on login |
| **#256** | WebAuthn → SAML → SCIM | 🟡 WebAuthn scaffold + SCIM/OIDC exist; SAML still deferred |
| **#257** | KMS/HSM | ✅ `app/kms.py` local Fernet + optional AWS KMS |
| **#258** | macOS notarization | 🟡 Scaffold + secrets |
| **#259** | MSSP multi-org | ✅ `app/mssp.py` parent/child links + API |

---

## PHASE 6 — Outside engineering (parallel)

🔒 Legal (MSA/DPA/BAA), SOC 2, ISO 27001, FedRAMP, third-party pentest, EV code-signing cert purchase, target vertical decision, vertical depth, localization.

Engineering cannot close these in-repo. Track externally.

---

## How to run verification

```bash
# Phase 0–5 gates
pytest -v tests/test_tenancy_rbac.py tests/test_production_p0_auth_enroll.py \
  tests/test_mfa_and_license_billing.py tests/test_master_checklist_p0.py \
  tests/test_master_checklist_phases.py

python scripts/backup_restore_drill.py
python scripts/export_openapi.py
python scripts/rotate_secrets.py --dry-run
```

Work order remaining: deepen #248/#252 dialect parity; buy EV cert (#247/#258 Phase 6); SAML if a customer requires it.
