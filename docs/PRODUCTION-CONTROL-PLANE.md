# SecuraIQ — Production control plane (freeze)

**Positioning:** Continuous Security Truth Engine — not another scanner dashboard.

```text
Signal → Truth → Risk → Compliance → Action → Verification → Evidence → New Truth
```

Aligns with NIST CSF 2.0 (Govern → Identify → Protect → Detect → Respond → Recover)
as an **operational loop**, not a checklist score.

Cross-links: [RELEASE-GATES.md](./RELEASE-GATES.md) · [GOLDEN-PATH.md](./GOLDEN-PATH.md) ·
[POSTURE-ENGINE.md](./POSTURE-ENGINE.md) · [USP-CLAIMS.md](./USP-CLAIMS.md) (what you may claim) ·
[WORLD-CLASS-CHECKLIST.md](./WORLD-CLASS-CHECKLIST.md) (master 39-section target + honest status)

## Freeze rule

Do **not** add Release 5 breadth (attack-path depth, digital twin, AI SecOps autonomy,
cloud/K8s/AppSec depth) until Releases 0–1 stay green on **owned-host** + measured
HA/load.

## P0 map (honest)

| Area | Status | Notes |
|------|--------|-------|
| Realtime event fabric | **Lab-production** | Soft BP shed, SSE recovery/gap, correlation_id, MC worker health, chaos CI; not HA exactly-once |
| 30-min Posture Engine | **Shipped** | Layer B reconciliation — never Nmap/Nuclei/ZAP |
| Agent security | **Lab-production** | Allowlist + seals + mTLS APIs; lab flags off by default; `AGENT_LAB_SEALED_MODE` / commercial five-flag profile |
| Evidence Spine | Shipped | Finish; do **not** build a second evidence system |
| Risk recalculation | Shipped | Evidence write → org risk + audit/evidence on delta |
| Remediation → Verify | Shipped | Execute ≠ verified; approve/execute publish evidence |
| Compliance Operations | **Lab-production** | Calendar/tasks/tick + L1–L3 escalation fan-out / SLA breach; not legal determination |
| CMMC | **Lab-production (Tier-1)** | SSP/POA&M/SPRS-prep/audit-pack/management + `/tier1-readiness`; not C3PAO/SPRS submit |
| Tenant isolation | **Lab-production** | Fail-closed product paths + object-store org key guard; cloud object leftovers ops |
| RBAC / MFA / SSO | **Lab-production (facades)** | RBAC+MFA+SCIM Groups + OIDC/SAML readiness; full IdP depth still Partial |
| Audit trail | **Lab-production** | Hash chain + sealed export + verify; SQLite ≠ cloud WORM |
| HA / DR | **Code-unblocked / ops-blocked live** | CI Sentinel self-test + `/ready`; live inject needs Docker |
| Load testing | **Lab-production (HTTP 1000 measured; soft→1000)** | HTTP 1000 @ 99.3% (2026-09-22); soft ≠ market claim |
| Self-security | **Lab-production** | Dogfood report API + Bandit productized; CI Trivy/ZAP remain report-only |
| Asset identity | Shipped | `asset_aliases` — correlation ≠ ownership proof |
| Phase-1 leftovers board | **Shipped** | `GET /api/admin/ops/phase1-remaining` · `scripts/live_lab_verify.py` |
| Owned-host live accept | **Lab (when SECURAIQ_OWNED_HOST=1)** | Live verify GREEN 2026-09-22 on this lab host |

## Sellable acceptance (must work)

The 21-step demo (install agent → … → audit trail) is the commercial gate.
Local CI: `pytest tests/test_realtime_acceptance_local.py` including
`test_realtime_acceptance_requires_command_seals`.

Owned-host OS mutation remains **ops**.

## Latency targets (measure — do not market until measured)

| Stage | Target |
|-------|--------|
| Ingestion | < 1 s |
| Detection | < 5 s |
| Risk update | < 10 s |
| UI SSE | < 15 s |

Record results in [ops/CAPACITY-LAB.md](./ops/CAPACITY-LAB.md) when available.
