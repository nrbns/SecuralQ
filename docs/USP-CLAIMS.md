# SecuraIQ — USP claims map (code-backed)

**Purpose.** Positioning guardrail: what you may claim in demos / decks vs what is
partial vs aspirational. Verified against the repo (not marketing copy).

**Product line:** Continuous Security Truth Engine — not another scanner dashboard.

```text
Signal → Truth → Risk → Compliance → Action → Verification → Evidence → New Truth
```

Cross-links: [PRODUCTION-CONTROL-PLANE.md](./PRODUCTION-CONTROL-PLANE.md) ·
[POSTURE-ENGINE.md](./POSTURE-ENGINE.md) · [commercial-roadmap.md](./commercial-roadmap.md)

---

## Verdict

The core USP framing is **unusually well-grounded** — not generic fluff. The
operating loop and freshness/posture engine are built and tested. Do **not**
extend claims to live vendor ingest (Wiz/Tenable/…) or full graph depth until
those ship.

---

## Claim now (Real — verified in code)

| USP / claim | Evidence in repo | Demo language (safe) |
|-------------|------------------|----------------------|
| **#4 — 30-min Posture Reconciliation** | `app/posture/refresh_policy.py` + Layer B orchestrator; cadences include 30m; **excludes** Nmap/Nuclei/ZAP | “Freshness-driven posture cycle — not a deep scan farm.” |
| **Evidence freshness / STALE** | `app/evidence_spine/freshness.py` + control state PASS→STALE | “PASS, observed N minutes ago — valid until … / STALE.” |
| **Explainable factor risk** | `app/services/risk_priority.py` (exposure, KEV, quick-win) + `explain_risk_score` | “Why fix first: exposure · KEV · criticality — not a bare CVSS.” |
| **#8 — Compliance Operations control room** | `app/compliance_ops/` calendar/tasks/tick + L1–L3 escalation | “Task board, overdue/escalated, evidence gates — not a legal cert.” |
| **#2 — Find → Fix → Verify** | Patch/verify, `control_results`, acceptance golden loop | “Execute ≠ verified; verification closes the loop.” |
| **#3 — Security → Compliance auto-map** | Canonical controls / cross-framework engine | “One observation supports sibling framework controls.” |
| **XDR / cloud posture connectors** | `app/connectors/`: wazuh, crowdstrike, sentinelone, sophos, defender, aws_security_hub, azure_defender_cloud, gcp_scc (+ azure_sentinel, webhooks, …) | “Connect these sources today.” Name only what is in `app/connectors/`. |

---

## Claim carefully (Partial — concept exists, depth limited)

| USP / claim | What is real | What not to say |
|-------------|--------------|-----------------|
| **#6 — One security graph** | Attack graph + asset dependency / correlation exist | Full user/permission/container/cloud/data depth as if complete |
| **#7 — AI explains “why did risk increase”** | `risk.changed` carries `previous_score` / `score_delta` + factor `explain_risk_score` (deterministic math narrative). Investigation paths can surface explanations | “Our LLM narrates every risk spike” as a baked product feature — generative narrative is **not** a dedicated demo gate yet |
| **SBOM** | Wired via scanner adapters / software inventory | Branded standalone “SecuraIQ SBOM Engine” |

---

## Do not claim yet (Aspirational)

| Claim | Honesty |
|-------|---------|
| Live ingest from **Tenable, Qualys, Nessus, Rapid7, Wiz, Splunk, Elastic** as first-class connectors | **No** matching modules under `app/connectors/`. Generic CSV/XML import and outbound SIEM/HEC ≠ live vendor pull. If asked “can you pull my Wiz data?” → **not today**. |
| Distinct branded **Secret / API / Config Scanner** products | Coverage is folded into other tools/adapters — not standalone named offerings |

---

## Connector inventory (claim only these)

Present under `app/connectors/` (2026-09-22):

- **XDR / endpoint:** `wazuh`, `crowdstrike`, `sentinelone`, `sophos`, `defender`
- **Cloud posture:** `aws_security_hub`, `azure_defender_cloud`, `gcp_scc`
- **Also present:** `azure_sentinel`, `github_webhook`, `gitlab_webhook`, `openaudit`, `servicenow`, `slack`, `teams`, `thehive`, `sonarqube`

Not connectors: Tenable, Qualys, Nessus, Rapid7, Wiz, Splunk ingest, Elastic ingest.

---

## Positioning rules

1. Lead with the **closed loop** + **30-min posture** + **evidence freshness** — those are distinctive and real.
2. Name **only** shipped connectors in customer conversations.
3. Graph / AI risk narrative / SBOM → “available / deepening,” never “complete.”
4. Release 5 breadth (twin, cloud depth, AI autonomy) stays **frozen** until owned-host + measured HA/load — see control plane freeze.

*Last verified against codebase: 2026-09-22.*
