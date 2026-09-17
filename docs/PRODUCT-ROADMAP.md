# SecuraIQ commercial product roadmap (no rebuild)

Source: product architecture review against github.com/nrbns/SecuralQ.
**Principle:** finish the closed loop in the UI — do not start a second app.

## Priority (current)

1. **UI shell + commercial nav** (this sprint) ✅ in progress
2. **Command Center** as security OS home (posture · attention · timeline)
3. **One RealtimeManager** already exists — extend subscriptions, kill page-local polling
4. **WHAT → WHY → EVIDENCE → IMPACT → ACTION → VERIFY** on every object
5. Closed-loop remediation visibility + campaigns
6. Evidence / continuous compliance depth
7. Risk center + attack paths
8. AI Missions (not chat-only)
9. Commercial admin (license, deploy agent, system health)
10. Integrations / cloud / identity / AppSec (P2 — after core loop)

## Golden loop (must stay visible)

```text
Agent → Inventory → Telemetry → Detection → Finding → Risk → Control →
Evidence → Remediation → Approval → Signed command → Execute → Verify →
Evidence → Risk → UI via SSE
```

## Out of scope for immediate work

- Rebuilding realtime bus
- Replacing Rust agent
- Cloud/K8s modules before endpoint loop is demo-solid
