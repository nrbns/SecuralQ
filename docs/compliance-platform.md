# SecuraIQ Compliance / GRC platform

**Positioning:** Wazuh (and similar) tell you *what happened*. SecuraIQ tells you *what matters*, *what to do*, executes an **approved** fix where wired, **verifies**, and turns the result into **security evidence** that helps assess control requirements.

This is **not** a certification product. Scores and audit packs support assessment and evidence collection — they do **not** mean “ISO compliant,” “SOC 2 certified,” or “PCI validated.”

## Information architecture (target hierarchy)

```
FRAMEWORK → REQUIREMENT → CONTROL → CONTROL TEST → EVIDENCE → FINDING → REMEDIATION → VERIFICATION
```

| Layer | Intent | Today (honest) |
|-------|--------|----------------|
| **Framework** | Catalog (NIST CSF 2.0, CIS, ISO 27001, …) | `data/frameworks/*.json` + Frameworks UI |
| **Requirement** | Normative “shall” / TSC / Annex A theme | Often folded into control rows (domain + title); not a first-class entity yet |
| **Control** | Testable statement in catalog | Gap assessment `results[]` |
| **Control test** | Operating-effectiveness check | **Live tests** (Task #144): curated map in `app/services/control_testing.py` — additive to pasted-evidence scoring |
| **Evidence** | Artifacts linked to controls | Evidence locker, `evidence_links`, evidence queue, audit ZIP |
| **Finding** | Gap / fail / partial from score or live test | Assessment status + live test status (shown separately) |
| **Remediation** | Owned task to close the gap | `gap_remediations` from assessments |
| **Verification** | Re-test / re-score after fix | Re-run gap / live tests; attestation workflows still thin |

**Exceptions** sit beside the chain: bounded, owned, expiring risk acceptance (`securaiq_exceptions`) — never a silent “gap fixed.”

## Product surfaces (nav)

Under **Compliance & Governance**:

1. **Compliance Center** — rollup of assessed frameworks only; top gaps; exceptions & evidence expiry signals  
2. **Frameworks & control testing** — per-framework cards → Open controls (status, evidence, **Live test** column, remediations)  
3. **Gap analysis** — paste policies/notes → heuristic score + roadmap  
4. **Exceptions** — request / approve / revoke with hard expiry  
5. **Audit Center** — evidence supplied vs missing; export audit packs  
6. **Evidence** (Security Ops group) — locker / uploads used by the chain above  

## Honest language (required)

Use:

- “Security evidence supporting … controls”  
- “Helps assess … requirements”  
- “Heuristic / keyword score — not an auditor attestation”  
- “Live test from product telemetry — not certification”

Avoid:

- “You are ISO/SOC/PCI compliant”  
- “Certified” / “guaranteed compliance”  
- Counting never-assessed frameworks as 0% in the overall rollup  

API methodology fields (`SCORING_METHODOLOGY`, Compliance Center `methodology`) are the source of truth for scoring claims.

## Framework roadmap (phased — do not claim full depth)

| Phase | Frameworks | Status |
|-------|------------|--------|
| **1 (shipped catalogs)** | NIST CSF 2.0, CIS Controls v8.1, ISO/IEC 27001:2022 Annex A, SOC 2 TSC, PCI DSS v4.0.1 | Catalog + gap + selective live tests |
| **Also in tree** | NIST 800-53 / 800-171, CMMC L2, HIPAA, GDPR, NIS2, ISO 27701, OWASP ASVS / Top 10 | Catalogs present; depth and live-test coverage vary |
| **Later** | First-class Requirement entities, fuller attestation, more live tests, control→finding→verify closed loop | Sprint B/C+ |

Catalog inventory: `data/knowledge/compliance_frameworks.md`.

## How scoring and live tests relate

- **Gap analysis** answers: “Does pasted evidence *describe* this control?” (heuristic).  
- **Live tests** answer: “Does SecuraIQ telemetry suggest the control is *operating*?” (explicit map only).  
- They are **never silently blended**; UI shows both so disagreements stay visible.

## Sprint focus

- **Sprint B (shipped track):** deepen existing pages — honest copy, control→test→evidence→gap visibility, top-gap CTAs, exceptions.
- **Continuous control loop (this slice):** curated live tests → risk-ranked fail queue → **Fix with SecuraIQ** remediations → derived evidence on explicit re-run.
  - `GET /api/compliance/live-failures`
  - `POST /api/compliance/run-live-tests` (records derived evidence)
  - `POST /api/compliance/live-failures/fix`
  - Compliance Center **Continuous compliance** panel (not blended into heuristic %)
- **Sprint C+:** first-class Requirement entities, cross-framework canonical map in UI, verification workflow, more live-test mappings, digital twin / simulate-before-patch — **not** 27 empty domain menus.

## What we are *not* doing yet

Do not treat catalog presence as “supported depth.” Do not claim India regulatory / legal compliance from technical control tests alone. Do not convert inferred attack-path edges into verified facts.