# SecuraIQ Production Build Specification

**Purpose.** Single actionable spec for turning SecuraIQ into a commercial SaaS control plane customers can sign up for, pay for, and connect real Windows/Linux/macOS machines to. It consolidates ~34 docs under `docs/`, corrects assumptions that don't match code, and turns gaps into schemas, endpoints, and a P0→P1→P2 checklist.

**Related:** [production-readiness.md](./production-readiness.md) · [securaiq-architecture.md](./securaiq-architecture.md) · [postgres-migration.md](./postgres-migration.md) · [realtime-v1.md](./realtime-v1.md) · [realtime-controls-evidence-spec.md](./realtime-controls-evidence-spec.md) · [SECURAIQ-REALTIME-PRODUCTION.md](./SECURAIQ-REALTIME-PRODUCTION.md) · [rbac-matrix.md](./rbac-matrix.md) · [agent-protocol-v1.md](./agent-protocol-v1.md)

**Rule:** Do **not** rebuild anything Section 0 marks as already real.

---

## 0. Do-not-rebuild list — what's already real

| Area | Already real (verified in code) |
|------|----------------------------------|
| MFA TOTP | RFC 6238 in `app/mfa.py`, `mfa_enabled`/`mfa_secret`, `mfa_pending` step-up |
| MFA recovery codes | **Shipped** — `mfa_recovery_codes` (hashed), confirm issues 10 codes, login/verify accept recovery; regenerate via `/api/auth/mfa/recovery/regenerate` |
| MFA mandatory | `MFA_REQUIRED` (all users) + `MFA_REQUIRED_FOR_ADMIN`; `require_user` blocks until enrolled |
| Password security | PBKDF2-HMAC-SHA256 (180k) + **Argon2id when `argon2-cffi` installed** (`app/auth.py`). Opportunistic rehash on login = P2 polish |
| Sessions / password reset | Real tables; hashed tokens; email when SMTP set |
| RBAC / tenancy | `app/rbac.py` + `tenant_visibility_sql()` on high-value tables |
| Agent bearer/HMAC/replay + opt Ed25519 | Real in `app/agent_auth.py` / `app/agent_security.py`. **mTLS stub:** `AGENT_MTLS_ENABLED` issues lab self-signed client certs on enroll (`app/agent_certs.py`) — reverse-proxy client auth is still an ops step |
| Realtime bus | Streams + DLQ + XAUTOCLAIM + metrics. **Gap:** event-scoped control recompute |
| Evidence freshness | TTL + freshness + confirm. Deduped by fingerprint (not broken — see §8) |
| Secrets at rest | Fernet envelope (`app/secrets_crypto.py`). **Gap:** KMS/HSM |
| Postgres guardrail | Production refuses SQLite unless override. **Gap:** Alembic + export tool + CI matrix |
| Billing | Stripe checkout + Customer Portal + webhook → license; downloads catalog; inert without keys |
| License service | **Shipped** — Ed25519-signed `securaiq_licenses`, plans/entitlements, soft enroll quota, Stripe → `issue_license`, online validate + restricted mode, agent `POST /api/agents/license/validate` + local activation cache (state only) |

**Still genuinely missing (build these):** event-driven control recompute, `control_results` history, object storage artifacts, Alembic + SQLite→Postgres export. **Signing/notarization** require your org secrets in CI (scaffolds ship; certs do not).

**Shipped packaging / updates / versioning / mTLS edge:**
- WiX MSI / deb / rpm wrappers under `scripts/packaging/` (tooling-gated)
- CI secrets-gated Authenticode (`sign_windows.ps1`), dpkg-sig (`sign_deb.sh`), rpm (`sign_rpm.sh`), Apple notarization (`notarize_macos.sh`) in `.github/workflows/agent-packages.yml`
- Signed update metadata + script **and** frozen-binary self-upgrade (`.bak` / staged MSI|DEB when `SECURAIQ_ALLOW_PACKAGE_INSTALL=1`)
- `/api/v1/*` → `/api/*` alias middleware (`app/api_v1.py`)
- Proxy mTLS examples: `deploy/nginx-mtls.conf.example`, `deploy/Caddyfile.mtls` + `AGENT_MTLS_PROXY_VERIFY`
- Commercial activation: validate APIs + Deploy UI + enroll tokens + 30-day trial

---

## 1. Architecture — confirmed, not changed

```text
CDN/TLS → FastAPI (app/main.py)
            ├── PostgreSQL (SoT in SaaS)
            ├── Redis Streams (+ DLQ)
            └── Object storage (artifact gap)
Web Dashboard · Agent Gateway · AI SecOps
Agents: Windows / Linux / macOS (PyInstaller + optional MSI/deb/rpm scaffolds; Authenticode/notarization = CI)
```

No second server. Logical split of API/worker/gateway later is scaling, not a P0 rewrite.

---

## 2. Auth hardening — remaining gaps

### 2.1 Recovery codes — **done** (see §0)

### 2.2 Persistent login lockout — **P0**

```sql
CREATE TABLE login_attempts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    mfa_stage INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
```

Lock after N failures / rolling window (default 8/15min). Survives restarts. Audit lockout start/clear.

### 2.3 Distributed rate limiting — **P0 when multi-replica**

Move login/MFA limiter onto Redis `INCR`+`EXPIRE`; fall back to in-memory when Redis unset.

### 2.4 Enterprise SSO — after TOTP/lockout; don't market until SAML+SCIM complete

---

## 3. License & entitlement — foundations shipped; finish product surface

See `app/license_service.py`, `/api/licenses/*`. Remaining:

- `GET /api/entitlements/check?feature=`
- `POST /api/admin/licenses/{id}/revoke`
- Check-in grace: expired beyond grace → heartbeat-only (no new commands)
- Optional `entitlements` child table / stripe_subscription_id column

Plans: Community 5 · Professional 100 · Enterprise unlimited soft · MSSP later.

Grace: never brick agents on license lapse; block new enroll in grace; degrade after grace.

---

## 4–6. Agent mTLS / packages / enroll tokens

- **mTLS:** lab cert issuance when `AGENT_MTLS_ENABLED=true`; proxy examples in `deploy/*mtls*`; enforce with `AGENT_MTLS_PROXY_VERIFY=true`
- **MSI/deb/rpm scaffolds + CI signing hooks:** `scripts/packaging/sign_*.ps1|sh`, `notarize_macos.sh` (secrets-gated in `agent-packages.yml`)
- **Signed updates:** script + package publish; frozen binary in-place swap (MSI/DEB need `SECURAIQ_ALLOW_PACKAGE_INSTALL=1`)
- **Enroll tokens:** P0 done — `agent_enroll_tokens` in front of existing `enroll_agent`
- **Revoke:** closes live WSS immediately (P0 done)

---

## 7–11. Realtime controls, evidence history, object storage, Postgres, `/api/v1`

As in the engineering brief: affected-controls-only recompute (P1/#172); `control_results` append-only (P1); S3-compatible artifacts (P1); Alembic+export (P0). **`/api/v1` alias middleware shipped** (rewrites to `/api`; bare `/api` remains canonical for the UI).

---

## 12. RBAC matrix

Document `client` org role. Production must keep `AUTH_ENABLED=true` (already enforced by `DEPLOYMENT_MODE=production`).

---

## 14. Checklist (live status)

**P0**

1. [x] License foundations (sign/quota/grace enroll / Stripe issue / entitlements check / admin revoke)
2. [x] MFA recovery codes + mandatory MFA
3. [x] Persistent `login_attempts` lockout
4. [x] Agent enroll-token flow (`/enroll-tokens`, `/enroll-by-token`)
5. [x] Revoke terminates live WSS (`force_disconnect_agent`)
6. [x] Production refuses `AUTH_ENABLED=false` (guardrail exists — keep asserted in deploy docs)
7. [ ] Alembic + SQLite→Postgres export
8. [x] Redis-backed auth rate limit (falls back to in-memory when Redis unset)

**P1**
- [x] MSI/deb/rpm **scaffolds** (WiX / dpkg-deb / fpm)
- [x] CI secrets-gated Authenticode / dpkg-sig / Apple notarization scaffolds (need org secrets)
- [x] mTLS cert issuance + **proxy verify** (`AGENT_MTLS_PROXY_VERIFY` + nginx/Caddy examples)
- [x] Signed update metadata + script **and** frozen-binary self-upgrade
- [x] `/api/v1` alias middleware
- [ ] Event-driven control recompute, `control_results`, object storage, CI Postgres

**P2** — Argon2 rehash-on-login, WebAuthn/SAML/SCIM, KMS, MSSP

---

## 15. Acceptance test

Windows/Linux package install → inventory → CVE → **affected-only** control recompute → evidence + `control_results` → compliance/risk → SSE live; then approved rem → verify → PASS trail. Must pass on Postgres+Redis with licensed multi-tenant agents — not lab-only.
