# SecuraIQ launch plan (single board)

**API:** `GET /api/launch/plan` · **All phases:** `GET /api/launch/complete` · **Measured ops:** `GET /api/ops/measured`  
**File-by-file P0s:** [P0-LAUNCH-BACKLOG.md](./P0-LAUNCH-BACKLOG.md)  
**Golden loop:** [GOLDEN-PATH.md](./GOLDEN-PATH.md) · [MASTER-EXECUTION-PLAN.md](./MASTER-EXECUTION-PLAN.md)  
**Phases:** [master-build-plan.md](./master-build-plan.md) · [WORLD-CLASS-CHECKLIST.md](./WORLD-CLASS-CHECKLIST.md)

## What “complete” means

| Label | Meaning |
|-------|---------|
| **lab** | In-repo proof exists (module + test or file). |
| **ops** | Code/scripts exist; needs hardware, certs, Docker, or a live tenant. |
| **frozen** | Intentionally not started (twin, cloud/IdP/K8s depth). |

Engineering is complete when `open_count = 0` on `/api/launch/plan`.  
That is **not** public enterprise-ready.

## Do not market as done

EV / Apple notarize · cloud Object Lock · live IdP · C3PAO · 5k–100k HTTP · macOS M1/M2 live · digital twin · third-party pentest.

## Prove

```text
python scripts/complete_launch_all.py
```

That one command proves launch P0-01..50 + world-class 1–5 + master-build 1–46 + every in-repo checklist.

Low-storage cloud package (AI in Docker): [ops/CLOUD-DOCKER.md](./ops/CLOUD-DOCKER.md) · `docker compose -f docker-compose.cloud.yml up -d`

Commercial gap (honest): [COMMERCIAL-GAP.md](./COMMERCIAL-GAP.md)
