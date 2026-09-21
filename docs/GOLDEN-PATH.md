# Golden path (frozen) — do not rebuild

SecuraIQ already has Evidence Spine, Compliance Ops, remediation campaigns, and realtime.
**Do not create a competing architecture.** Make every module participate in this loop:

```text
SERVER CHANGE
    ↓
AGENT → AUTHENTICATED GATEWAY → REDIS STREAM
    ↓
OBSERVATION → EVIDENCE → CONTROL TEST → PASS/FAIL
    ↓
RISK / COMPLIANCE → FINDING → REMEDIATION → APPROVAL
    ↓
SIGNED COMMAND → AGENT EXECUTION
    ↓
INDEPENDENT VERIFICATION  ← never “fixed” from execute alone
    ↓
NEW EVIDENCE → RISK + COMPLIANCE RECALC → SSE → UI
```

## Hard rule

| Event | Allowed status |
|-------|----------------|
| Command sent / `done` | `verification_status=pending` |
| Independent host/inventory verify PASS | `verified` |
| Linked remediation plan | `executing` → `verified` only when **all** done campaign commands are `verified` |

## Related docs

- [MASTER-EXECUTION-PLAN.md](./MASTER-EXECUTION-PLAN.md)
- [RELEASE-GATES.md](./RELEASE-GATES.md) — prove closes; Release 0→4 before breadth
- [CMMC-ASSESSMENT.md](./CMMC-ASSESSMENT.md) — objectives / methods / POA&M / SPRS prep
- [EVIDENCE-SPINE.md](./EVIDENCE-SPINE.md)
- [COMPLIANCE-OPERATIONS.md](./COMPLIANCE-OPERATIONS.md)
- [ASSET-IDENTITY.md](./ASSET-IDENTITY.md)

## Domain freeze

Cloud / K8s / Identity / AppSec / SBOM depth stay frozen until this loop stays green on owned-host + measured HA/load.
