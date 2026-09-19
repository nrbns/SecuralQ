# Compliance Operations

**Know what must be done, when it must be done, who must do it, whether it was completed, and escalate if it wasn't.**

## Product split

| Surface | Answers |
|---------|---------|
| **Compliance** (Frameworks / Evidence / DPDP) | Are we compliant and **why**? |
| **Compliance Operations** (Calendar / My Work) | What must people **do**, and **when**? |

Honesty: this module manages **work**. It is **not** a legal determination of compliance or a certification.

## Model

```text
Framework → Requirement → Control → ComplianceTask
  → Owner → Due → Reminder → Evidence → Review → Approval → Complete
```

Overdue path: Reminder → Overdue → Manager escalate → (optional) risk signal.

Task kinds:

- **automated** — live control rollup (e.g. `host_firewall`, `host_disk_encryption`)
- **assisted** — SecuraIQ + human evidence
- **manual** — governance (access review, training, management review)

## API

Prefix: `/api/compliance-ops`

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/summary` | Management rollup + departments |
| GET | `/my-work` | Overdue / due today / week / upcoming |
| GET | `/calendar?year=&month=` | Month view |
| GET/POST | `/tasks` | List / create |
| POST | `/tasks/{id}/evidence` | Attach evidence note |
| POST | `/tasks/{id}/complete` | Complete (blocked if evidence required missing) |
| POST | `/tasks/{id}/escalate` | Manual escalate |
| GET/POST | `/schedules` | Recurring schedules |
| POST | `/seed` | Seed default Compliance Year schedules |
| POST | `/materialize` | Create tasks from due schedules |
| POST | `/tick` | Reminders + overdue + auto-escalate |

## Automation

Background job `compliance_ops_tick` (every ~5 min via `app/jobs.py`):

1. Materialize schedules within horizon  
2. Remind at ~7d / ~3d / due day  
3. Overdue notify  
4. Escalate L1 at ~2d overdue, L2 at ~7d (notifies manager/reviewer; may open soft risk)

Realtime events (SSE):

`compliance.task.created|updated|due_soon|due|overdue|completed|escalated|evidence_attached`

## UI

Nav: **Compliance Ops → Calendar / Tasks · My Work · Management**

Seed year → materialize → work the queue. Evidence is required before complete when `evidence_required` is set.

## Out of scope for this MVP (next slices)

- Full holiday calendars / regional working days  
- Multi-step approval graphs  
- Slack / Teams connectors (email + in-app first)  
- SMS / WhatsApp  
- Full board / Gantt timeline views  

## Tests

```bash
pytest -v tests/test_compliance_ops.py
```
