# SecuraIQ P0 launch backlog (P0-01 → P0-50)

**Identity:** Continuous Security, Risk & Compliance Control Plane  
**Rule:** do not rebuild. Close the golden loop, then reliability, then enterprise proof. Freeze cloud/K8s/AppSec/identity depth until P0-01 stays green.

**Do not market production/enterprise-ready** until the 🔴 blockers below are measured or purchased (see [production-readiness.md](./production-readiness.md), [RELEASE-GATES.md](./RELEASE-GATES.md)).

**Launch demo (exists now):** `POST /api/launch/loop` · `python scripts/launch_loop_demo.py` · `pytest tests/test_launch_loop.py`  
Wraps the existing firewall chain in [PHASE-A-GOLDEN-LOOP.md](./PHASE-A-GOLDEN-LOOP.md). CI is synthetic check-in + lab-simulated execute. Owned-host OS mutation is still **ops**.

Status key: **lab** = in-repo proof · **ops** = needs Docker/certs/live tenant · **open** = engineering remaining · **frozen** = after core launch

---

## P0-01 — Golden closed loop (THE PRODUCT)

| | |
|--|--|
| **Status** | **lab** — firewall FAIL→evidence→risk→POA&M→approve→execute→independent verify→PASS→recalc→SSE |
| **Modify** | `app/launch_loop.py`, `scripts/realtime_acceptance_demo.py`, `app/agents.py`, `app/services/control_testing.py`, `app/controls/auto_evidence.py`, `app/controls/live_compliance.py`, `app/controls/poam.py` |
| **New** | `tests/test_launch_loop.py`, `scripts/launch_loop_demo.py` |
| **API** | `POST /api/launch/loop` |
| **Accept** | Loop `ok` and `verification_status=verified` without treating command `done` as verified. Owned-host: `realtime_acceptance_demo.py --server` + `SECURAIQ_OWNED_HOST`. |

---

## P0-02 — Production agent parity (Win/Linux/macOS)

| | |
|--|--|
| **Status** | **lab** (`app/agent_parity.py` same keys + honest `collected=false`) / **ops** (M1/M2 live) |
| **Modify** | `scripts/securaiq_agent.py`, `securaiq-agent/src/platform/deep/{windows,linux,macos}.rs`, `app/macos_hardening.py` |
| **Accept** | Same check-in schema on all three OS; firewall/FIM/packages/services present or honest `collected=false`. |

---

## P0-03 — Production agent security profile (no accidental lab mode)

| | |
|--|--|
| **Status** | **lab** (`DEPLOYMENT_MODE=production` or `SECURAIQ_COMMERCIAL_PROFILE` refuses boot; `SECURAIQ_ALLOW_LAB_INSECURE` is the escape hatch) |
| **Modify** | `app/config.py`, `app/production_profile.py`, `app/agent_security.py`, `app/agent_certs.py`, `docs/production-hardening.md` |
| **Accept** | `SECURAIQ_COMMERCIAL_PROFILE=true` or production mode refuses start unless mTLS + command seals + replay + expiry are on. |

---

## P0-04 — Realtime reliability (dedupe, order, gap, DLQ, BP, retention)

| | |
|--|--|
| **Status** | **lab** (Streams path when `REDIS_URL`; in-proc otherwise) |
| **Modify** | `app/realtime_bus.py`, `app/event_processor.py`, `app/realtime/` |
| **Accept** | `tests/test_realtime_phase1_proof.py` + `phase1-realtime-gate` stay green. |

---

## P0-05 — Redis Sentinel measured failover

| | |
|--|--|
| **Status** | **lab** (Desktop inject measured) / **ops** (multi-AZ) |
| **Modify** | `scripts/sentinel_failover_measure.py`, `deploy/redis/`, `docs/ops/SENTINEL-FAILOVER-LAB.md` |
| **Accept** | Published failover seconds + no silent event loss. Do not claim commercial HA. |

---

## P0-06 — Tenant isolation proof (attacker-style)

| | |
|--|--|
| **Status** | **lab** (core tables + object-store org keys + RAG + job payload user_id + tenant streams) |
| **Modify** | `app/tenancy.py`, `tests/test_cross_tenant_isolation.py`, `app/object_storage.py`, `app/rag*` |
| **Accept** | Tenant A cannot read Tenant B asset/evidence/agent/scan/risk/SSE/object/AI. |

---

## P0-07 — Automatic evidence on every state change

| | |
|--|--|
| **Status** | **lab** (host FAIL/PASS + remediations + Command Center / drawer evidence) |
| **Modify** | `app/controls/auto_evidence.py`, `app/evidence_spine/ingest.py` |
| **Accept** | Control fail/pass, approve, verify, risk delta each create vault evidence. |

---

## P0-08 — WORM / Object Lock evidence

| | |
|--|--|
| **Status** | **lab** (local FS markers) / **ops** (cloud Object Lock) |
| **Modify** | `app/evidence_spine/worm.py`, `app/object_storage.py` |
| **Accept** | Lab overwrite denied. Cloud Object Lock only when bucket+creds proven. |

---

## P0-09 — Risk recalculation after verify

| | |
|--|--|
| **Status** | **lab** (`risk.changed` + org score on host PASS/FAIL) |
| **Modify** | `app/services/risk_priority.py`, `app/services/risk_narrative.py`, `app/event_processor.py` |
| **Accept** | After verify PASS, org risk score/band updates and is explainable. |

---

## P0-10 — Compliance recalculation after verify

| | |
|--|--|
| **Status** | **lab** (`publish_live_compliance_update`) |
| **Modify** | `app/controls/live_compliance.py`, `app/controls/recompute.py` |
| **Accept** | `live_percent` moves on FAIL→PASS; not a certification score. |

---

## P0-11 — Independent remediation verification

| | |
|--|--|
| **Status** | **lab** (host remediations) |
| **Modify** | `app/agents.py` (`report_command_result`), `app/secops/verification.py` |
| **Accept** | `done` ≠ `verified`. Only next-check-in telemetry may set verified. |

---

## P0-12 — SSO / SCIM / MFA / RBAC

| | |
|--|--|
| **Status** | **lab** (MFA + facades) / **ops** (live IdP) |
| **Modify** | `app/auth.py`, `app/oidc.py`, `app/saml_scaffold.py`, `app/scim*`, `app/rbac.py` |
| **Accept** | Lab MFA + SCIM users/groups. Live OIDC/SAML handshake is ops. |

---

## P0-13 — HA / DR measured

| | |
|--|--|
| **Status** | **lab** (SQLite RTO/RPO via `--record`) / **ops** (Postgres + cluster kill) |
| **Modify** | `scripts/backup_restore_drill.py`, `docs/ops/HA-DR.md`, `GET /api/ops/measured` |
| **Accept** | `python scripts/backup_restore_drill.py --record` publishes rto_ms/rpo_ms. Cluster kill + Postgres restore remain ops. |

---

## P0-14 — Backup / restore drill

| | |
|--|--|
| **Status** | **lab** (SQLite drill) / **ops** (Postgres) |
| **Modify** | `scripts/backup_restore_drill.py` |
| **Accept** | Drill exit 0 on this host; Postgres restore documented separately. |

---

## P0-15 — Load testing ladder

| | |
|--|--|
| **Status** | **lab** (≤1k HTTP measured) / **ops** (5k+) |
| **Modify** | `docs/ops/CAPACITY-LAB.md`, capacity scripts |
| **Accept** | Publish p50/p95/loss per rung. Never market 100k unmeasured. |

---

## P0-16 — Chaos testing

| | |
|--|--|
| **Status** | **lab** (soft chaos) / **ops** (kill@5k) |
| **Modify** | `scripts/realtime_chaos_test.py`, `tests/test_realtime_chaos_local.py` |
| **Accept** | No cross-tenant leak, no silent loss, no false VERIFIED/PASS. |

---

## P0-17 — Signed commercial installers

| | |
|--|--|
| **Status** | **lab** (PFX/sha256) / **ops** (EV + notarize) |
| **Modify** | `scripts/packaging/`, `scripts/sign_windows.ps1`, `scripts/packaging/notarize_macos.sh` |
| **Accept** | Install→enroll→connected in 3 minutes on owned hosts. EV/notarize purchased. |

---

## P0-18 — Dogfood / pentest / Trust Center

| | |
|--|--|
| **Status** | **lab** (`/trust.html`) / **ops** (third-party pentest) |
| **Modify** | `app/trust_center.py`, `static/trust.html`, CI SAST/SCA |
| **Accept** | Trust Center shows real job results. No fake SOC2. |

---

## P0-19 — Commercial onboarding

| | |
|--|--|
| **Status** | **lab** (`/api/onboarding/progress` wizard steps: org→agent→asset→frameworks→risk→pulse) |
| **Modify** | `app/product_close.py`, `static/workspace.js`, `static/index.html` |
| **Accept** | Org → agent → asset → frameworks → baseline → Security Pulse in one flow. |

---

## P0-20 — Production-grade UI (3 modes + Command Center)

| | |
|--|--|
| **Status** | **lab** (Exec / SOC / Compliance mode switch + Command Center pulse / what-changed / top decisions) |
| **Modify** | `static/index.html`, `static/app.js`, `static/workspace.js`, `static/style.css` |
| **Accept** | Exec / SOC / Compliance nav; Command Center shows pulse + what-changed + top decisions. |

---

## P0-21 — Kill remaining panel polling

| | |
|--|--|
| **Status** | **lab** (soft-poll only when SSE offline/stalled; Command Center / software already gated) |
| **Modify** | `static/app.js` (`RealtimeManager`), `static/workspace.js` |
| **Accept** | Soft-poll only when SSE offline/stalled. |

---

## P0-22 — 30-minute posture reconcile (no Nmap/ZAP)

| | |
|--|--|
| **Status** | **lab** (Layer B exists) |
| **Modify** | `app/posture/`, `app/jobs.py` |
| **Accept** | 30-min job reconciles assets/controls/freshness/risk/compliance/tasks. Deep scanners stay scheduled separately. |

---

## P0-23 — Asset Security Identity Card

| | |
|--|--|
| **Status** | **lab** (`GET /api/assets/{id}/identity-card` + identity card on asset detail) |
| **Modify** | `app/enterprise.py`, `static/workspace.js`, `app/security_graph_depth.py` |
| **API** | `GET /api/assets/{id}/identity-card` (add) |
| **Accept** | One card: online, risk, owner, service, exposure, failed controls, framework %, Fix/Investigate/Simulate. |

---

## P0-24 — Canonical asset identity (no duplicates)

| | |
|--|--|
| **Status** | **lab** |
| **Modify** | `app/asset_identity.py`, `docs/ASSET-IDENTITY.md` |
| **Accept** | IP + hostname + agent + MAC + cloud id resolve to one asset; conflicts recorded. |

---

## P0-25 — Vulnerability “why should I care / what if I fix”

| | |
|--|--|
| **Status** | **lab** (`GET /api/risk/finding/{id}/why` + Decision Drawer) |
| **Modify** | `app/services/risk_narrative.py`, `app/services/risk_priority.py`, `static/workspace.js` |
| **Accept** | Finding shows exposure, service, path, KEV, compensating controls + simulator delta. |

---

## P0-26 — Factor risk + fix simulation

| | |
|--|--|
| **Status** | **lab** (simulator API + finding why / drawer contributions) |
| **Modify** | `app/services/risk.py`, `app/services/risk_priority.py`, `app/risk_api.py` |
| **Accept** | Risk is a factor list, not a naked 78. Simulate patch → expected risk/paths/gaps. |

---

## P0-27 — Attack paths with evidence + “close this path”

| | |
|--|--|
| **Status** | **lab** (narrow graph) / **frozen** (twin-grade) |
| **Modify** | `app/services/attack_graph.py` |
| **Accept** | Edges CONFIRMED/INFERRED/UNVERIFIED + evidence. Remediation names the edge it breaks. No invented edges. |

---

## P0-28 — Evidence Spine finish (lineage, package, compare, legal hold)

| | |
|--|--|
| **Status** | **lab** (vault/freshness/recon + legal hold + export package + hash compare) |
| **Modify** | `app/evidence_spine/*` |
| **Accept** | Every Command Center claim has “show evidence”. Do not build a second evidence system. |

---

## P0-29 — Compliance as operations (not a score)

| | |
|--|--|
| **Status** | **lab** (ops module + requirements API) |
| **Modify** | `app/compliance_ops/*`, `app/controls/requirements.py` |
| **Accept** | States: READY / NEEDS ACTION / MISSING EVIDENCE / STALE / FAILED / HUMAN REVIEW / EXCEPTION. |

---

## P0-30 — CMMC assessment-readiness (not a label)

| | |
|--|--|
| **Status** | **lab** (Tier-1) / **honesty** (not C3PAO / not verbatim L3) |
| **Modify** | `app/cmmc/*`, `docs/CMMC-ASSESSMENT.md` |
| **Accept** | Level→domain→requirement→objective→examine/interview/test→POA&M→SSP pack. Never claim C3PAO. |

---

## P0-31 — Compliance Operations product surfaces

| | |
|--|--|
| **Status** | **lab** (calendar/tasks/escalation + missing-evidence gate) |
| **Modify** | `app/compliance_ops/api.py`, `static/workspace.js` |
| **Accept** | Calendar, my tasks, queue, approvals, escalations, automation. Missing evidence blocks the task. |

---

## P0-32 — Remediation Center workflow + campaigns

| | |
|--|--|
| **Status** | **lab** (lifecycle + rings + rollback + Command Center / SOC surfaces) |
| **Modify** | `app/agents.py`, `app/services/remediation.py`, `static/workspace.js` |
| **Accept** | RECOMMENDED→…→VERIFIED plus FAILED/TIMEOUT/REJECTED/EXPIRED/ROLLED BACK. Rings 5→100%. |

---

## P0-33 — Decision Drawer (signature UI)

| | |
|--|--|
| **Status** | **lab** (`GET /api/decisions/drawer` + slide-over on risk/finding/asset) |
| **Modify** | `static/app.js`, `static/workspace.js`, `static/style.css` |
| **API** | Reuse `decision_drawer` from `POST /api/launch/loop` + risk why-increased |
| **Accept** | Click risk/finding/control → WHAT/WHY/EVIDENCE/IMPACT/ACTION/VERIFY + Simulate/Approve. |

---

## P0-34 — Global “What changed?”

| | |
|--|--|
| **Status** | **lab** (`GET /api/command-center/pulse` + Command Center strip) |
| **Modify** | `app/host_change.py`, `app/services/executive_dashboard.py`, `static/app.js` |
| **API** | `GET /api/exposure/changes` + pulse feed |
| **Accept** | Every major mode shows since-last-refresh deltas. |

---

## P0-35 — One scan experience (hide engine names)

| | |
|--|--|
| **Status** | **lab** (product intents; engines stay behind Advanced) |
| **Modify** | `app/scans_api.py`, `static/index.html`, `app/scanners/product_facades.py` |
| **Accept** | Quick/Full/EASM/Internal/Web/API/Cloud/Endpoint/Compliance. Engines normalize to asset/finding/evidence. |

---

## P0-36 — Contextual AI (never “Fixed” without verify)

| | |
|--|--|
| **Status** | **lab** (grounded analyst + AI SecOps missions nav; autonomy frozen) |
| **Modify** | `app/secops/`, `static/workspace.js` |
| **Accept** | Asset/vuln/compliance/incident/remediation/risk/path actions. Output observation→verify. Freeze autonomy. |

---

## P0-37 — Business service graph

| | |
|--|--|
| **Status** | **lab** (`GET /api/services/graph`) / **frozen** (twin) |
| **Modify** | `app/service_impact.py`, `app/enterprise.py` |
| **Accept** | Service→app→asset→data; “which services does this vuln affect?” |

---

## P0-38 — Incident timeline

| | |
|--|--|
| **Status** | **lab** (`GET /api/incidents/{id}/timeline` + SOC Timeline) |
| **Modify** | `app/thehive_api.py`, `static/workspace.js` |
| **Accept** | Clickable events with source + evidence. Isolation remains allowlisted/approved. |

---

## P0-39 — EDR strategy (normalize, don’t clone CrowdStrike)

| | |
|--|--|
| **Status** | **lab** (connectors) / **frozen** (native EDR) |
| **Modify** | `app/connectors/*`, `app/xdr.py` |
| **Accept** | Defender/CS/S1/Wazuh ingest into asset/threat/evidence/risk/incident. |

---

## P0-40 — Worker / API / DB restart recovery

| | |
|--|--|
| **Status** | **lab** (`GET /api/ops/restart-recovery` + measured in-process reclaim) / **ops** (kill@5k) |
| **Modify** | `app/jobs.py`, `app/restart_recovery.py`, `scripts/restart_reclaim_drill.py` |
| **Accept** | `python scripts/restart_reclaim_drill.py --record` publishes reclaim_ms. Process-kill @5k HTTP remains ops. |

---

## P0-41 — Tenant-isolated streams

| | |
|--|--|
| **Status** | **lab** (SSE filter + tenant-suffixed stream dual-write) / **ops** (exclusive Redis ACLs) |
| **Modify** | `app/realtime_bus.py` |
| **Accept** | Tenant B cannot subscribe to Tenant A event ids. |

---

## P0-42 — Signed evidence + custody + retention + legal hold

| | |
|--|--|
| **Status** | **lab** (legal hold + `GET /api/evidence-spine/export-package`) |
| **Modify** | `app/evidence_spine/vault.py`, `app/audit_chain.py`, `app/retention.py` |
| **Accept** | Hold blocks purge. Export package includes hash chain. |

---

## P0-43 — Launch navigation IA

| | |
|--|--|
| **Status** | **lab** (Command Center / Security / Assets / Risk / Compliance / CompOps / Remediation / AI / Admin + Exec/SOC/Compliance modes) |
| **Modify** | `static/index.html` sidebar |
| **Accept** | Command Center / Security / Assets / Risk / Compliance / CompOps / Remediation / AI / Integrations / Admin. |

---

## P0-44 — UX law: WHAT → WHY → EVIDENCE → IMPACT → ACTION → VERIFY

| | |
|--|--|
| **Status** | **lab** (Decision Drawer + narrative blocks on Command Center / assets / findings / SOC) |
| **Modify** | `static/workspace.js` (`renderNarrativeBlock`) |
| **Accept** | FAIL is never a bare table cell. |

---

## P0-45 — Why? on every number

| | |
|--|--|
| **Status** | **lab** (`/api/risk/why-increased` + `/api/compliance/why`) |
| **Modify** | `app/services/risk_narrative.py`, `app/controls/live_compliance.py` |
| **Accept** | Risk 82 and CMMC 72% both expand to contributions / PASS-FAIL-STALE counts. |

---

## P0-46 — macOS M1/M2 live lab

| | |
|--|--|
| **Status** | **ops** (friend hardware) |
| **Modify** | none until live run; log in `docs/ops/` |
| **Accept** | Install, enroll, FDA, sleep/wake, offline buffer, upgrade/rollback on M1; load on M2 Pro. |

---

## P0-47 — Packaging commercial feel

| | |
|--|--|
| **Status** | **lab** (exe/deb/rpm/tar/dmg scripts) / **ops** (signed stores) |
| **Modify** | `scripts/build_agent_packages.py`, `scripts/packaging/` |
| **Accept** | MSI/EXE/DEB/RPM/PKG/DMG catalog from `/api/agents/packages`. |

---

## P0-48 — Digital twin (do not start now)

| | |
|--|--|
| **Status** | **frozen** — risk sim ≠ twin |
| **Modify** | none until P0-01..P0-16 stay green |
| **Accept** | “What if I patch WEB-01?” is a later moat, not a launch claim. |

---

## P0-49 — After-core domain expansion (cloud/IdP/K8s/AppSec)

| | |
|--|--|
| **Status** | **frozen** |
| **Modify** | `app/cloud_posture.py`, identity connectors — later |
| **Accept** | Only after owned-host loop + measured HA/load. |

---

## P0-50 — File-by-file execution cadence

| | |
|--|--|
| **Status** | **lab** — `GET /api/launch/plan` + [LAUNCH-PLAN.md](./LAUNCH-PLAN.md) |
| **Modify** | `docs/MASTER-EXECUTION-PLAN.md`, `docs/GOLDEN-PATH.md` |
| **Accept** | Next implementers pick **one** open P0 (prefer 03, 20, 21, 23, 33) and land tests before the next. |

---

## Immediate sequence (do not skip)

```text
P0-01..P0-45 lab-unblocked closed (GET /api/launch/plan open_count=0)
  → keep P0-01 green
  → P0-05/P0-13/P0-15/P0-46 measured ops
```

🔴 Launch blockers that stay **ops** even when code is ready: EV/notarize, cloud Object Lock, live IdP, C3PAO, 5k–100k HTTP, third-party pentest.
