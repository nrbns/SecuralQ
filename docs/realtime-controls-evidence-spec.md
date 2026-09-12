# SecuraIQ — Real-Time Controls & Evidence Engine (Engineering Spec v1)

**Status:** Active build phase after Phase 1 realtime durability.  
**Source:** Product engineering specification (Realtime Controls & Evidence).  
**Related:** [control-config-engine.md](./control-config-engine.md) · [realtime-v1.md](./realtime-v1.md) · [master-build-plan.md](./master-build-plan.md) · [compliance-platform.md](./compliance-platform.md)

---

## Architectural decision (non-negotiable)

```text
Live structured Evidence Store  =  source of truth
PDF / DOCX / Markdown reports   =  outputs / exports only
```

Do **not** treat report files as compliance truth. Do **not** expand framework catalogs
until this control → evidence → verify loop is reliable on owned lab endpoints.

Task **#144** (Frameworks Live Test UI) remains **frozen**.

---

## Core realtime loop

```text
Windows / Linux host
        ↓
Package / config / security change
        ↓
SecuraIQ Agent (check-in / WS)
        ↓
Realtime event (normalize → Redis Streams when configured)
        ↓
Control check (curated registry only)
        ↓
Evidence created / updated (securaiq_evidence)
        ↓
Compliance signal + Risk signal
        ↓
Dashboard SSE (RealtimeManager)
```

### Remediation loop

```text
CONTROL FAIL → Evidence → Risk → Approval → Signed command
    → Agent fix → Independent verification → New evidence
    → CONTROL PASS → Compliance / Risk updated
```

Harness: `python scripts/realtime_acceptance_demo.py --local`

---

## What already exists in this repo

| Spec area | Repo reality |
|-----------|----------------|
| Controls registry | `app/controls/test_registry.py` + `app/services/control_testing.py` |
| Host firewall / Defender / SSH / disk | Live tests + POA&M + rem verify on check-in |
| Evidence Store | `app/services/evidence.py` → `securaiq_evidence` (`record_evidence`) |
| Realtime bus | Streams + DLQ + XAUTOCLAIM + fan-out + Realtime Health UI |
| Package inventory | Agent check-in → `ingest_agent_packages` (upsert; **diffs shipped in this phase**) |
| Reports | PDF/DOCX via `/api/reports/*` — **export only** |
| Soft-poll skip | Mission Control skips interval refresh while SSE connected |

---

## This phase Definition of Done (engineering)

1. **Evidence freshness** — `expires_at` on `securaiq_evidence`; observed host-control (and package) evidence carries TTL; readers expose `freshness_status` (`fresh` \| `stale` \| `expired`).
2. **Package change events** — `software.installed` / `software.removed` / `software.updated` published on check-in diffs; observed evidence recorded; registry lists the event types.
3. **Reports stay outputs** — no new path that ingests PDF/DOCX as authoritative control evidence.
4. **Honesty** — not a certification; curated live tests only; no auto-execute remediations without approval.
5. **Acceptance** — existing RT-10/11 local harness still green; unit tests for TTL + package diffs.

### Explicitly later (not this slice)

- Full 14-test suite automation against owned Windows+Linux fleets  
- Per-tenant sequence authority  
- Measured Redis Sentinel failover / 5k agents  
- mTLS agent identity  
- More compliance frameworks / unfreezing #144  

---

## Evidence Store contract (extended)

Existing fields plus:

| Field | Role |
|-------|------|
| `expires_at` | Optional unix ts; null = no automatic expiry |
| `freshness_status` | Derived on read: `fresh` / `stale` / `expired` |

Default TTL for **observed** host-control / package evidence: `EVIDENCE_OBSERVED_TTL_SEC` (default **172800** = 48h). Re-observation renews `last_seen` and `expires_at`.

---

## Event types (package)

| Event | When |
|-------|------|
| `software.installed` | Package appears vs previous check-in set |
| `software.removed` | Package missing vs previous check-in set |
| `software.updated` | Same name, version changed |
| `software.inventory.updated` | Coarse inventory snapshot (existing) |

---

## Repo map (recommended / actual)

```text
app/services/evidence.py          Evidence Store SoT
app/services/control_testing.py   Host control tests + evidence
app/controls/                     Registry, API, POA&M
app/software/sources/securaiq_agent.py   Package ingest + diffs
app/realtime_bus.py / event_processor.py Bus + hooks
docs/realtime-controls-evidence-spec.md  This file
```

---

## Operator notes

- Lab without Redis: in-process bus; evidence TTL still applies in SQLite.  
- Redis: Streams durability + DLQ admin ops under `/api/admin/realtime/dlq`.  
- Drop the ChatGPT sandbox DOCX into `docs/specs/` if you want the full prose archived; this markdown is the **repo SoT** for implementation.
