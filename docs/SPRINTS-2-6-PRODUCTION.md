# Sprints 2–6 — foundations shipped on existing stack

**Honesty:** Lab → commercial-ready is incremental. This document tracks what was
**extended** (not rewritten) after Sprint 1’s Phase 1 realtime gate.

## Sprint 2 — Agent security (mTLS device certs)

| Capability | Path | Status |
|------------|------|--------|
| Issue lab client cert on enroll | `app/agent_certs.py` + `AGENT_MTLS_ENABLED` | Done |
| Renew / rotate / revoke | `renew_agent_client_certificate`, `rotate_*`, `revoke_*` | Done |
| Revocation denylist | `securaiq_agent_cert_revocations` + proxy verify | Done |
| Agent revoke ⇒ cert revoke | `revoke_agent()` | Done |
| API | `POST /api/agents/{id}/certificate/{issue,rotate,renew,revoke}` | Done |
| Proxy mTLS | `deploy/nginx-mtls.conf.example`, `AGENT_MTLS_PROXY_VERIFY` | Ops |
| Fleet CA / short-lived ACME | — | Still ops / future |

Production toggles:

```bash
AGENT_MTLS_ENABLED=true
AGENT_MTLS_PROXY_VERIFY=true
AGENT_MTLS_REQUIRE_FINGERPRINT_MATCH=true
AGENT_REQUIRE_COMMAND_SIGNATURE=true
AGENT_REQUIRE_REPLAY_PROTECTION=true
```

## Sprint 3 — Controls + automatic evidence

| Capability | Path | Status |
|------------|------|--------|
| Requirement / Check / Observation / ControlResult | `app/controls/types_extended.py` | Done |
| Auto evidence helper | `app/controls/auto_evidence.py` | Done |
| control.failed → structured evidence | `app/event_processor.py` | Done |
| Remediation verified → evidence | `record_command_verification` | Done |
| Curated live tests (firewall/Defender/SSH) | existing `controls/` + host checks | Partial (curated) |

## Sprint 4 — Remediation lifecycle vocabulary

Dual-written `lifecycle` on the bus (DB `status` unchanged):

`RECOMMENDED → PENDING_APPROVAL → APPROVED → SIGNED → SENT → ACK → EXECUTED → VERIFYING → VERIFIED`

Failure paths: `REJECTED`, `EXPIRED`, `TIMEOUT`, `FAILED`, `ROLLBACK`.

UI: `static/workspace.js` `_agentCommandLifecycle` aligned.

## Sprint 5 — Commercialization (facades + packaging)

| Capability | Path | Status |
|------------|------|--------|
| Signed licenses | `app/license_service.py` (existing) | Done |
| `app/licensing/` facade | subscriptions / activation helpers | Done |
| TOTP MFA | `app/mfa.py` (existing) + `app/auth_commercial/` | Done |
| WebAuthn / OIDC / SAML / SCIM | existing modules | Partial / deferred depth |
| MSI / DEB / RPM / DMG scaffolds | `scripts/packaging/*`, CI | Scaffold |
| `release-manifest.json` + SHA-256 | `scripts/build_agent_packages.py` | Done |
| Authenticode / notarization | CI secrets-gated | Not claimed without secrets |

## Sprint 6 — Production ops

| Capability | Path | Status |
|------------|------|--------|
| Postgres production guard | `require_postgres_in_production` | Done |
| Redis HA lab stub | `docker compose --profile redis-ha` | Lab |
| Phase 1 CI gate | `phase1-realtime-gate` | Done |
| Tenant isolation tests | `tests/test_cross_tenant_isolation.py` etc. | Done |
| Backups / restore / chaos | scripts + docs | Partial — runbook only |
| Load / capacity measurement | `scripts/realtime_load_test.py` | Lab tool — not a published SLO |

## Freeze reminder

Do **not** expand cloud/EDR/AI/frameworks until:

1. `phase1-realtime-gate` green  
2. One owned-host closed loop (`realtime_acceptance_demo.py`)  
3. Production profile flags above for any commercial install  

## Tests

```bash
pytest -v tests/test_sprints_2_6_foundations.py tests/test_realtime_acceptance_local.py
```
