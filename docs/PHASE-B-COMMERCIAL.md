# Phase B — Commercial packaging foundations

Finish after Phase A golden loop greens. Do **not** claim Authenticode/notarization
without org signing secrets.

## Checklist

| # | Capability | Status |
|---|------------|--------|
| 1 | Signed license + entitlements + activation/renewal helpers | Done (`app/licensing`) |
| 2 | Activation cache ≠ license truth | Done (`app/activation_cache`) |
| 3 | TOTP MFA + recovery + mandatory policy | Done (`app/mfa`, `auth_commercial.identity_v1_status`) |
| 4 | RBAC permission matrix | Done (`app/rbac.permission_matrix`) |
| 5 | WebAuthn / OIDC / SAML / SCIM | Deferred V2 (modules may exist) |
| 6 | Installer scaffolds MSI/DEB/RPM/DMG | Scaffold only — signing secrets gated |
| 7 | Signed auto-update + rollback | Partial — deepen with secrets |
| 8 | HA/DR runbooks | Done docs (`docs/ops/HA-DR.md`, Sentinel note) |
| 9 | Billing / MSSP | Placeholder / later |

## Tests

```bash
pytest -v tests/test_phase_ab_commercial_foundations.py tests/test_mfa_and_license_billing.py tests/test_cross_tenant_isolation.py
```
