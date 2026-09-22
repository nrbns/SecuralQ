# Continuous Posture Engine

**Not “auto-scan every 30 minutes.”** Platform reconciliation + evidence-backed
state, while realtime events update immediately and deep scanners stay on their
own schedules.

Cross-links: [EVIDENCE-SPINE.md](./EVIDENCE-SPINE.md) · [RELEASE-GATES.md](./RELEASE-GATES.md)

## Honesty

| Claim | Reality |
|-------|---------|
| Full Nmap/Nuclei/ZAP every 30m | **No** — explicitly excluded |
| Realtime latency = 30m | **No** — events update immediately; 30m is reconciliation |
| Multi-AZ HA workers | **No** — in-process job worker |
| 100K proven | **No** — jitter/locking designed for scale; capacity still gated |

## Three layers

```text
A — Realtime (seconds/minutes): agent telemetry, firewall, Defender, FIM, threats
B — Posture refresh (default 30m ± jitter): assets, controls, evidence, vulns, risk, compliance
C — Deep scans (independent): Nmap, Nuclei, ZAP, DAST, cloud deep — rate-limited
```

## APIs (`/api/posture`)

| Endpoint | Purpose |
|----------|---------|
| `GET /dashboard` | Last/next refresh, scores, asset health, attention |
| `POST /refresh` | Refresh Now (org lock + idempotency) |
| `GET /runs` · `GET /runs/{id}` | Refresh run history / detail |
| `GET /history` | Posture snapshot trajectory |
| `GET /what-changed` | Delta since previous snapshot |
| `GET /policies` | Freshness-driven policies + layer map |
| `GET/POST /settings` | Interval (15m–24h) + jitter |
| `POST /baseline` · `GET /drift` | Baseline snapshot + drift detection |
| `GET /health` | Mission Control posture engine health |

## Job

`posture_refresh` registered in `app/jobs.py`, scheduled ~every
`SECURAIQ_POSTURE_REFRESH_SEC` (default 1800) with jitter
`SECURAIQ_POSTURE_JITTER_SEC` (default 60).

SSE: `posture.refresh.started` · `posture.refresh.completed`

## Integrates (does not replace)

- `control_stale_tick` / Evidence Spine freshness
- `exception_expiry_tick` · `vault_expiry_tick` · compliance ops tick
- `_maybe_publish_org_risk` on evidence writes (already realtime)
- Mission Control component `posture_engine`
