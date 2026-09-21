# Asset Identity / Entity Resolution

**Purpose:** collapse multi-source sightings of the same machine into one canonical asset.

```text
AWS instance i-123
      \
Agent AG-892 ----→ Canonical Asset
      /
EDR ABC123
      /
IP 10.0.0.21
```

Without this index, scans/agents/EDR create **duplicate assets** and incorrect risk at scale.

## Model

| Table | Role |
|-------|------|
| `asset_aliases` | `(user_id, kind, value) → asset_id` unique |
| `asset_identity_conflicts` | Same alias claimed by two assets — recorded, never stolen |

Supported kinds: `hostname`, `ip`, `mac`, `securaiq_agent_id`, `siem_agent_id`, `aws_instance_id`, `azure_vm_id`, `gcp_instance_id`, `edr_id`, `openaudit_id`, `vm_id`, `cloud_resource_id`.

## Behavior

1. `ensure_asset_for_target` resolves aliases **before** the linear notes scan
2. On match/create, registers all recognizable identifiers from notes
3. Agent check-in registers `securaiq_agent_id` + host/ip
4. Alias collision → conflict row (no silent rebind)

## API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/assets/resolve` | Identifiers → canonical asset |
| GET | `/api/assets/{id}/aliases` | List aliases |
| POST | `/api/assets/{id}/aliases` | Register alias |
| GET | `/api/assets/identity-conflicts` | Conflict log |

## Tests

```bash
pytest -v tests/test_asset_identity.py tests/test_asset_correlation.py
```

## Honesty

This is identifier correlation, not ownership proof or CMDB completeness.
Human review of `identity-conflicts` is required when sources disagree.
