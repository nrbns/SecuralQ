# SecuraIQ — USP claims map (code-backed)

**Purpose.** Positioning guardrail: what you may claim in demos / decks vs what is
partial vs aspirational. Verified against the repo (not marketing copy).

**Product line:** Continuous Security Truth Engine — not another scanner dashboard.

```text
Signal → Truth → Risk → Compliance → Action → Verification → Evidence → New Truth
```

Cross-links: [PRODUCTION-CONTROL-PLANE.md](./PRODUCTION-CONTROL-PLANE.md) ·
[POSTURE-ENGINE.md](./POSTURE-ENGINE.md) · [commercial-roadmap.md](./commercial-roadmap.md)

**Lab surfaces:** `GET /api/usp/status` · `/api/usp/graph/depth` · `/api/usp/risk/why-increased` ·
`/api/usp/sbom/*` · `/api/usp/vendors*` · `/api/usp/scanners*`

---

## Verdict

The core USP framing is **code-backed**. Former Partial/Aspirational rows below are
now **lab-production** with honest leftovers (full twin, live vendor API without
creds, Syft binary, etc.).

---

## Claim now (Real / lab-production)

| USP / claim | Evidence | Demo language (safe) |
|-------------|----------|----------------------|
| **#4 — 30-min Posture** | `app/posture/refresh_policy.py` | Freshness cycle — not deep scan farm |
| **Evidence freshness / STALE** | `evidence_spine/freshness.py` | PASS observed N ago / STALE |
| **Factor risk** | `risk_priority.py` | Why fix first: exposure · KEV · quick-win |
| **#8 Compliance Ops** | `compliance_ops/` | Board + L1–L3 escalation |
| **#2 Find→Fix→Verify** | patch/verify + acceptance | Execute ≠ verified |
| **#3 Security→Compliance map** | canonical controls | One observation → sibling frameworks |
| **XDR / cloud connectors** | `app/connectors/*` | Name only shipped connectors |
| **#6 One security graph** | attack graph + knowledge graph + **identity depth** (`security_graph_depth.py`) | Lab-production graph with user/permission/container/cloud/data scaffolds — **not** full twin |
| **#7 Why risk increased** | `risk_narrative.explain_risk_increase` + `/api/risk/why-increased` | Deterministic narrative from deltas + drivers; LLM polish optional |
| **SecuraIQ SBOM** | `app/sbom.py` + `/api/usp/sbom/export` | Branded CycloneDX export over inventory — not Syft |
| **Vendor export ingest** | `connectors/vendor_ingest.py` (Tenable/Qualys/Nessus/Rapid7/Wiz/Splunk/Elastic) | Export ingest ready; live API when env creds set |
| **Secret / API / Config Scanner** | `scanners/product_facades.py` | Branded facades over Gitleaks / Web-ZAP / Checkov |

---

## Claim carefully (leftovers)

| Topic | Honesty |
|-------|---------|
| Full security twin | User/container/cloud/data nodes are scaffolds — not complete IAM/K8s/cloud topology |
| Live Wiz/Tenable API pull | Requires operator credentials; until set, `configured=false` |
| LLM risk storytelling | Product gate is deterministic; generative polish is optional hook |
| Syft filesystem SBOM | Inventory-derived CycloneDX only |

---

## Connector inventory

**Endpoint / XDR / cloud (existing):** wazuh, crowdstrike, sentinelone, sophos, defender,
aws_security_hub, azure_defender_cloud, gcp_scc, azure_sentinel, …

**Vendor export ingest (lab-production):** tenable, qualys, nessus, rapid7, wiz, splunk, elastic
via `POST /api/usp/vendors/{vendor}/ingest`.

---

## Positioning rules

1. Lead with closed loop + 30-min posture + evidence freshness + factor risk.
2. Graph / SBOM / branded scanners / vendor ingest — claim **lab-production**, not complete twin or live-only.
3. Release 5 breadth (digital twin depth, AI autonomy) stays frozen until owned-host + measured HA/load.

*Last verified: 2026-09-22.*
