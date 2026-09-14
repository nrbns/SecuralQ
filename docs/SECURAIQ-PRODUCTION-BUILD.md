# SecuraIQ — Production SaaS Build Spec

**Status:** Active commercial control-plane roadmap (no rewrite).  
**Principle:** Extend the existing FastAPI + Agent Gateway + Evidence Store + Streams bus.  
**Related:** [production-hardening.md](./production-hardening.md) · [production-readiness.md](./production-readiness.md) · [realtime-v1.md](./realtime-v1.md) · [realtime-controls-evidence-spec.md](./realtime-controls-evidence-spec.md) · [master-build-plan.md](./master-build-plan.md)

---

## Architecture (keep this)

```text
CDN / TLS → FastAPI control plane
              ├── PostgreSQL (SoT in production)
              ├── Redis Streams (realtime; not evidence SoT)
              └── Object storage (artifacts) — planned
Web Dashboard · Agent Gateway (WSS/HTTPS) · AI SecOps
Windows / Linux / macOS agents
```

Do **not** invent a second server. Lab may keep SQLite; commercial SaaS requires Postgres (`DEPLOYMENT_MODE=production`).

---

## Already in repo (honest)

| Area | Status |
|------|--------|
| TOTP MFA enroll/confirm/verify | **Partial→done foundations** (`app/mfa.py`, `/api/auth/mfa/*`); admin MFA optional via `MFA_REQUIRED_FOR_ADMIN` |
| Sessions + password reset paths | **Partial** |
| Stripe billing scaffold + message quotas | **Partial** (`app/billing.py`, soft `BILLING_ENFORCEMENT_ENABLED`) |
| Tenancy / RBAC / org header | **Partial→improved** |
| Agent enroll + revoke + bearer/HMAC + opt-in Ed25519 | **Partial** — mTLS missing |
| Redis Streams + DLQ + XAUTOCLAIM + fan-out | **Near-done (lab)** |
| Evidence Store + TTL/freshness | **Partial→improved** |
| Package install/remove/update events | **Partial→improved** |
| Host control FAIL→rem→verify loops | **Partial→improved** (lab harness) |
| Signed org licenses + agent quotas | **This slice** (`app/license_service.py`) |
| Windows MSI / Authenticode / deb/rpm | **Missing** |
| mTLS / cert rotation / signed agent updates | **Missing / Partial** |
| Full SSO/SCIM | **Partial** (OIDC/SCIM scaffolds; not enterprise-complete) |

---

## P0 before real customers (ordered)

### P0-1 Authentication
- [x] TOTP foundations  
- [ ] MFA mandatory for commercial (`MFA_REQUIRED_FOR_ADMIN` → org-policy / all users)  
- [ ] Hashed recovery codes, MFA rate limits, Argon2id password hash audit  
- [ ] Session revocation UI + audit  

### P0-2 License service ← **current implementation slice**
- [x] Plan catalog with `max_agents` + feature entitlements  
- [x] Org/user signed license payload (Ed25519; private key never in agent)  
- [x] Server-side enrollment quota gate (soft unless `LICENSE_ENFORCEMENT_ENABLED`)  
- [x] Grace policy for expired licenses (block new enroll; do not brick agents)  
- [ ] Stripe webhook → issue/refresh signed license  
- [ ] Downloads portal org-aware packaging  

### P0-3 Multi-tenancy / RBAC
- [x] Org membership + permission helpers  
- [ ] Consistent `require_perm` on every sensitive route  
- [ ] Cross-tenant regression suite expansion  

### P0-4 Realtime
- [x] Streams default, DLQ, reclaim, metrics, Realtime Health  
- [ ] Event-driven control resolver (only affected controls)  
- [ ] Eliminate remaining soft-poll panels  

### P0-5 Agent security
- [x] Enroll / revoke / replay headers / optional Ed25519 seals  
- [ ] mTLS + short-lived certs + rotation  
- [ ] Signed updates + rollback  

### P0-6 Commercial agent packages
- [ ] MSI + Authenticode  
- [ ] deb/rpm + systemd  
- [ ] Org-aware download UI  

### P0-7–10 Controls / Evidence / Compliance / Closed-loop
See [realtime-controls-evidence-spec.md](./realtime-controls-evidence-spec.md) and RT-10/11 acceptance.

---

## License format (v1)

Unsigned logical record (JSON canonical):

```json
{
  "license_id": "lic_…",
  "organization_id": "org_…",
  "plan": "pro",
  "status": "active",
  "max_agents": 100,
  "features": ["agent", "compliance", "remediation", "ai", "realtime"],
  "issued_at": 0,
  "expires_at": 0,
  "grace_days": 14
}
```

Signed blob:

```json
{
  "payload": { … },
  "alg": "ed25519",
  "signature": "<base64url>",
  "kid": "license-v1"
}
```

- **Private key:** `LICENSE_ED25519_PRIVATE_KEY` (or lab-generated ephemeral; never shipped to agents).  
- **Public key:** `LICENSE_ED25519_PUBLIC_KEY` for verify.  
- Enforcement is **server-side** on enroll / feature gates. Agents do not trust local license files as authority.

### Plans (defaults)

| Plan | max_agents | Notes |
|------|------------|--------|
| `free` / Community | 5 | Lab-friendly |
| `pro` / Professional | 100 | Realtime + compliance + rem + AI |
| `team` / Business | 500 | Multi-seat |
| `enterprise` | unlimited (`null`) | Soft ceiling only when enforced |

---

## Commercial enrollment flow (target UX)

```text
Dashboard → Add endpoint → enroll API (quota check)
  → one-time agent token → download package
  → agent check-in / WS → revoke anytime
```

Enrollment tokens that auto-expire after first use remain a follow-on (current API returns long-lived agent key once).

---

## Killer commercial acceptance (do not claim until green)

```text
Install package on owned Windows/Linux lab host
  → software.installed → CVE/control/evidence/risk/compliance
  → SSE dashboard updates without hard refresh
  → approved remediation → verify → evidence PASS
```

Harness today: `scripts/realtime_acceptance_demo.py --local` (synthetic). Owned-host proof is still operator-owned.

---

## Explicit non-claims

- Not CMMC/SPRS certification  
- Not enterprise SSO-complete  
- Not 5k-agent load-proven  
- Not MSI/Authenticode-complete  
- Signed licenses ≠ payment processed until Stripe live  

---

## Implementation map

| Spec piece | Code |
|------------|------|
| License service | `app/license_service.py` |
| License API | `app/license_api.py` → `/api/licenses/*` |
| Enroll gate | `app/agents.py` `enroll_agent` + `agents_api` |
| MFA | `app/mfa.py` |
| Billing soft quotas | `app/billing.py` |
| Evidence SoT | `app/services/evidence.py` |
