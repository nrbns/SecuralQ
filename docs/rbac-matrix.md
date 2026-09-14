# SecuraIQ — RBAC Matrix (beta)

**Roles:** `admin` (global) · `user` (global) · org roles: `admin` · `analyst` · `viewer` · `client`

When `AUTH_ENABLED=false`, all API writes use synthetic user `local` with `admin` role (lab mode).
**Production:** `DEPLOYMENT_MODE=production` refuses to boot with `AUTH_ENABLED=false`.

## Global roles

| Capability | admin | user | local (auth off) |
|------------|:-----:|:----:|:----------------:|
| All workspace CRUD | ✓ | ✓ | ✓ |
| View audit log | ✓ | ✗ | ✓ |
| Export audit CSV | ✓ | ✗ | ✓ |
| Create API keys | ✓ | ✓ | ✗ |
| MFA enroll/disable (self) | ✓ | ✓ | n/a |
| Settings (incl. secrets) | ✓ | ✓ | ✓ |
| Workspace reset | ✓ | ✓ | ✓ |

## Org roles (`/api/orgs/{id}/members`)

Rank in code (`app/rbac.py`): `client(0) < viewer(1) < analyst(2) < admin(3)`.

| Capability | org admin | analyst | viewer | client |
|------------|:---------:|:-------:|:------:|:------:|
| Invite member | ✓ | ✗ | ✗ | ✗ |
| List members | ✓ | ✓ | ✓ | ✗* |
| Evidence / assets / vulns read | ✓ | ✓ | ✓ | ✓ (engagement-scoped typical) |
| Write / triage / tools | ✓ | ✓ | ✗ | ✗ |
| Evidence links | ✓ | ✓ | read | read |

\* `client` is the lowest org rank — typically read-only report/engagement export for an external stakeholder. Exact route coverage still uses `org_min` from `PERMISSIONS`; treat `client` as below `viewer` for any write.

Org checks enforced in `app/commercial_ext.py` and `app/rbac.py` — viewer is read-only for org write actions.

## Permission actions (`app/rbac.py`)

| Action | Global | Org min role |
|--------|--------|--------------|
| asset.read / vuln.read / risk.read | admin, user | viewer |
| asset.write / vuln.write / vuln.triage / tools.run | admin, user | analyst |
| org.manage / audit.read | admin | admin |
| agent.read | admin, user | viewer |
| agent.write / agent.command | admin, user | analyst |
| agent.approve | admin | admin |

Tenant header: `X-SecuraIQ-Org: <org_id>` scopes asset/vuln lists. Core rows stamp `org_id` via `app/tenancy.py`.

## Auth endpoints

| Route | Auth | Notes |
|-------|------|-------|
| `POST /api/auth/login` | Public | Returns `mfa_required` when MFA on; persistent `login_attempts` lockout |
| `POST /api/auth/mfa/verify` | Public | Completes MFA step-up (TOTP or recovery code) |
| `POST /api/auth/mfa/enroll` | User | Returns TOTP secret + otpauth URI |
| `POST /api/auth/mfa/confirm` | User | Enables MFA + issues recovery codes once |
| `POST /api/auth/mfa/recovery/regenerate` | User | New recovery codes (invalidates unused) |
| `GET /api/auth/oidc/login` | Public | Redirect to IdP |
| `GET /api/auth/oidc/callback` | Public | OIDC callback → session |

## Integration webhooks

| Route | Auth | Notes |
|-------|------|-------|
| `POST /api/integrations/github/webhook` | HMAC secret | No session; attributes to first admin |

## Hardening notes

- Enforce `MFA_REQUIRED=true` (all users) or at least `MFA_REQUIRED_FOR_ADMIN=true` on commercial deploys.
- Enable `AUTH_ENABLED=true`; disable open registration (`AUTH_ALLOW_REGISTER=false`) for team use.
- Review write routes periodically — new endpoints must use `require_user` and org checks where applicable.

See [beta-deploy.md](./beta-deploy.md) · [security-baseline.md](./security-baseline.md) · [SECURAIQ-PRODUCTION-BUILD.md](./SECURAIQ-PRODUCTION-BUILD.md)
