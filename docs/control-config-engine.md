# Control & Configuration Engine

**LIVE** control path — not static checkboxes:

```text
SEE → TEST → DETECT → EVIDENCE → RISK → REMEDIATE → VERIFY
```

Sprint 1 foundation package: `app/controls/`. Wired at `/api/controls`.

**Priority:** close the **firewall E2E acceptance loop** (agent check-in →
`host_firewall` FAIL → evidence + rem + `control.failed` / thin risk /
`risk.changed` → **approved** `enable_firewall` → next check-in PASS).

Local harness: `python scripts/realtime_acceptance_demo.py --local`
(steps 1–10; step 6 is request→approve→lab-sim agent result before synthetic PASS).

Related: [master-build-plan.md](./master-build-plan.md) (Phase 13) ·
[compliance-platform.md](./compliance-platform.md) ·
[realtime-v1.md](./realtime-v1.md)

---

## Honesty caveats (read first)

- This engine produces **operating-effectiveness signals** from SecuraIQ telemetry and curated live tests.
- Do **not** claim: CMMC certification, SPRS submission, FIPS validation, PreVeil / GCC High integration, C3PAO assessment, or Maryland (or any) funding eligibility.
- Framework PDFs / official catalogs are the **workflow source of control text only** — SecuraIQ reuses `data/frameworks/*.json` and does not invent practice wording.
- Live tests exist **only** via the explicit registry in `app/controls/test_registry.py` (derived map in `control_testing._CONTROL_TEST_MAP` — same philosophy as canonical controls: no fuzzy AI mappings).
- Task **#144** (Frameworks table Live Test UI column) remains **frozen** — this package does not change that UI.
- **No auto-execute** of firewall/defender/SSH remediations without operator approval.

---

## Architecture (Sprint 1)

```text
data/frameworks/{cmmc_l2,nist_800_171,...}.json
        │
        ▼
app/controls/catalog.py     ← list/get/normalize; Control Center summary
        │
        ├── schema.py         Framework / Control / ControlTest / TestResult / verifiability
        ├── results.py        optional SQLite last-result store
        ├── test_registry.py  curated live-test definitions + control bindings (SoT)
        ├── test_engine.py    thin wrapper → control_testing + events + persist
        └── controls_api.py   FastAPI /api/controls/*
                │
                ▼
app/services/control_testing.py   runs registry tests (host_*, vuln, patch, …)
                │
                ▼
realtime_bus.publish  control.test.completed | control.passed | control.failed |
                      control.unknown  (+ dual-write type=compliance for UI)
```

### Control Test Registry

`app/controls/test_registry.py` is the **single source of truth**. Each entry:

| Field | Role |
|-------|------|
| `test_name` | Stable id (`host_firewall`, …) |
| `data_sources` | Telemetry / store inputs |
| `expected_state` | Hints only (not certification criteria) |
| `frequency` | `checkin` / `daily` / `on_change` / `on_demand` |
| `verifiability` | `machine` / `partial` / … |
| `control_bindings` | Explicit `(framework_id, control_id)` pairs only |
| `remediation_hint` | Recommend-only text |

`control_testing._CONTROL_TEST_MAP` is **derived** via `build_control_test_map()` — do not add fuzzy mappings.

### Verifiability enum

| Value | Meaning |
|-------|---------|
| `machine` | Curated live test(s) driven by telemetry |
| `partial` | Live test exists but is soft/incomplete (e.g. asset inventory alone) |
| `human` | No live test — human evidence / gap assessment |
| `unknown` | Cannot classify |

### API (`/api/controls`)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/summary?framework_id=cmmc_l2` | Counts: total, passing/failing/unknown/na, evidence coverage & open gaps best-effort, `last_test` |
| GET | `/catalog/{framework_id}` | Normalized catalog |
| GET | `/catalog/{framework_id}/{control_id}` | Control + last live results + why-failing |
| POST | `/test/{framework_id}/{control_id}` | Run live tests now |
| GET | `/verifiability/{framework_id}` | Per-control verifiability map |

Summary counts use stored results when present; otherwise **honest zeros** (never invent pass rates).

---

## Firewall E2E loop (acceptance priority)

```text
agent check-in (firewall_status.enabled=false)
        → evaluate_agent_host_controls
        → evidence (observed) + compliance + control.failed
        → thin type=risk + compute_org_risk_score → risk.changed
        → POA&M stub + remediation.recommended (auto_execute=false)
        → (optional) attack_path refresh when asset_id known
        → operator: POST .../commands/enable-firewall → approve → agent enable
        → next check-in enabled=true → control.passed + rem closed
```

### Agent command `enable_firewall`

| Piece | Behavior |
|-------|----------|
| Allowlist | `SUPPORTED_COMMAND_KINDS` includes `enable_firewall` |
| Gate | Always `pending_approval` → `approve_command` → `queued` (never auto on FAIL) |
| Helper | `request_enable_firewall_command` / `POST /api/agents/{id}/commands/enable-firewall` |
| Windows | Fixed argv: `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True` |
| Linux | `ufw --force enable`; else honest error (+ `firewall-cmd --state` note) |
| Safety | No `shell=True` with interpolated untrusted strings |

Host FAIL still **recommend-only** by default (open rem + `remediation.recommended`); the operator creates/approves the command.

---

## Sprint roadmap (1–7)

| Sprint | Focus | Status |
|--------|--------|--------|
| **1** | Foundation: `app/controls/`, catalog, results, `/api/controls`, CMMC/800-171 host maps, events | **Done** (foundations) |
| **2** | Configuration observe/drift (`app/configuration/`), Control Center UI, check-in hook | **Done** (foundations) |
| **3** | CMMC/800-171 deeper test coverage + why-failing UX | **Partial foundations** (why/deviations on GET catalog control; host maps from Sprint 1) |
| **4** | Realtime score + POA&M auto-open from FAIL | **Partial foundations** (`app/controls/poam.py` opens/closes `gap_remediations` on host FAIL/PASS; not a formal POA&M package) |
| **5** | Remediate → Approve → Agent → Verify → PASS (extend RT-11; no default auto-fix) | **Partial foundations** (`enable_firewall` + rem recommend; verify on check-in PASS; no auto-execute) |
| **6** | Live SSP / exceptions / audit packages | Planned |
| **7** | CUI enclave / boundary / SPA classification | Planned |

**Frozen until later:** full Windows/Linux/macOS config tree, IdP MFA live test, auto-remediation of dangerous actions, vendor claims from external PDFs. Task **#144** frozen.

---

## Explicit host-control mappings (Sprint 1)

Registry bindings (exact catalog IDs):

| Test | NIST 800-171 | CMMC L2 |
|------|--------------|---------|
| `host_firewall` | `3.13.1`, `3.4.7` | `SC.L2-3.13.1`, `CM.L2-3.4.2` |
| `host_defender` | `3.14.2` | `SI.L2-3.14.2` |
| `host_ssh_root` | `3.1.5` | `AC.L2-3.1.5` |
| `host_disk_encryption` | `3.13.16` | `SC.L2-3.13.16` |

Baseline setting → control IDs (seeded `CMMC Windows Workstation`):

| Setting | Expected | Controls |
|---------|----------|----------|
| `firewall.enabled` | `true` | `SC.L2-3.13.1` / `3.13.1` |
| `defender.enabled` | `true` (windows) | `SI.L2-3.14.2` / `3.14.2` |
| `disk_encryption.enabled` | `true` when collected | `SC.L2-3.13.16` / `3.13.16` (live `host_disk_encryption`; UNKNOWN if not collected) |
| `ssh.permit_root_login` | `false` (linux) | `AC.L2-3.1.5` / `3.1.5` |

Existing CIS / CSF / ISO / 800-53 host mappings unchanged. Never invent BitLocker PASS without telemetry.

**Phase 6 risk wedge:** live host PASS/FAIL from online agent `last_payload` feeds
`app.services.risk_priority` compensating_controls (and a small exposure bump on
`host_firewall` FAIL). Priority reasons explain offsets/elevations; UNKNOWN does
not invent PASS. Attack-path ranking inherits the same scored findings.

---

## Sprint 2 — Configuration + Control Center

| Piece | Role |
|-------|------|
| `app/configuration/baselines.py` | Seeded `CMMC Windows Workstation` baseline (firewall / Defender / disk encryption / SSH root) |
| `app/configuration/observe.py` | Extract + persist `securaiq_config_observations` |
| `app/configuration/drift.py` | Baseline diff + `configuration.drift_detected` publish |
| `app/configuration/configuration_api.py` | `/api/configuration/baselines\|drift\|observations` |
| Check-in hook | `agents.checkin` records observations then runs host control tests |
| UI | Compliance → **Control Center** (`data-workspace="control_center"`) |

### Configuration API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/baselines` | Seeded baselines |
| GET | `/drift` | Current baseline failures from latest observations |
| GET | `/observations` | Observation history |

## Event types

Registered in `app/event_schema.py`:

- `control.test.completed` / `control.passed` / `control.failed` / `control.unknown`
- `configuration` / `configuration.observed` / `configuration.changed` / `configuration.drift_detected`
- `remediation.recommended`

Control runs dual-write flat `type=compliance`; host path dual-writes `control.failed` / `control.passed`; drift dual-writes `configuration` + `compliance` for SSE.

### Event processor hooks

`configuration.drift_detected` and `control.failed` → derived/observed evidence + thin `type=risk` + `_maybe_publish_org_risk` (`risk.changed` with `previous_score` / `score_delta` when known). Idempotent via the processor ledger.

---

## Sprint 3–5 foundations (honest / partial)

Not full CMMC assessment tooling. No certification claims. No default auto-fix of dangerous actions.

| Area | What landed |
|------|-------------|
| **Why failing (Sprint 3)** | `GET /api/controls/catalog/{framework}/{control_id}` returns top-level `why` / `why_failing` / `deviations` plus per-result copies from last stored live tests |
| **POA&M auto-open (Sprint 4)** | `app/controls/poam.py` inserts/updates open rows in `gap_remediations` on host FAIL; marks done on PASS. Wired from `evaluate_agent_host_controls` and `control.failed` publish path. Never breaks check-in |
| **Remediate recommend (Sprint 5)** | Firewall FAIL publishes `remediation.recommended` with `auto_execute=false`. Optional approved `enable_firewall` command; next check-in verifies PASS |
