# SecuraIQ — Production control plane (freeze)

**Positioning:** Continuous Security Truth Engine — not another scanner dashboard.

```text
Signal → Truth → Risk → Compliance → Action → Verification → Evidence → New Truth
```

Aligns with NIST CSF 2.0 (Govern → Identify → Protect → Detect → Respond → Recover)
as an **operational loop**, not a checklist score.

Cross-links: [RELEASE-GATES.md](./RELEASE-GATES.md) · [GOLDEN-PATH.md](./GOLDEN-PATH.md) ·
[POSTURE-ENGINE.md](./POSTURE-ENGINE.md)

## Freeze rule

Do **not** add Release 5 breadth (attack-path depth, digital twin, AI SecOps autonomy,
cloud/K8s/AppSec depth) until Releases 0–1 stay green on **owned-host** + measured
HA/load.

## P0 map (honest)

| Area | Status | Notes |
|------|--------|-------|
| Realtime event fabric | Partial | Streams, DLQ, Last-Event-ID; not HA exactly-once |
| 30-min Posture Engine | **Shipped** | Layer B reconciliation — never Nmap/Nuclei/ZAP |
| Agent security | Partial | Sealed acceptance with `AGENT_REQUIRE_COMMAND_SIGNATURE`; mTLS lab-off |
| Evidence Spine | Shipped | Finish; do **not** build a second evidence system |
| Risk recalculation | Shipped | Evidence write → org risk |
| Remediation → Verify | Shipped | Execute ≠ verified |
| Compliance Operations | Partial | Calendar/tasks MVP |
| CMMC | Partial | Tier-1; not C3PAO/SPRS submit |
| Tenant isolation | Partial | Broad tests; object-store leftovers |
| RBAC / MFA / SSO | Partial | SSO IdP facades |
| Audit trail | Partial | `audit()` → hash chain; SQLite ≠ WORM |
| HA / DR | Ops-blocked | Live Sentinel inject needs Docker |
| Load testing | Partial | HTTP 100 measured; 500+ unmeasured |
| Self-security | Partial | Tooling exists; dogfood report thin |
| Asset identity | Shipped | `asset_aliases` — correlation ≠ ownership proof |

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
