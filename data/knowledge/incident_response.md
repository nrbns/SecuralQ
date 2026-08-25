# Incident Response Workflow

## Phase 1 — Preparation
- IR plan, contact tree, escalation matrix
- Forensic toolkit ready (KAPE, Velociraptor, Magnet AXIOM)
- Jump bag: write-blocker, USB with trusted tools
- Tabletop exercises quarterly

## Phase 2 — Identification
```bash
# Quick triage commands (authorized IR only)
# Windows
whoami /all
netstat -ano
tasklist /v
wmic process get name,processid,commandline

# Linux
ps auxf
ss -tulpn
last -20
find /tmp -mtime -1 -type f
```

**Indicators to collect:**
- Suspicious processes, parent-child anomalies
- New scheduled tasks / services
- Unusual outbound connections
- New local admin accounts
- AV/EDR alerts

## Phase 3 — Containment
| Type | Action |
|------|--------|
| Network | VLAN isolation, EDR network contain |
| Account | Disable AD account, revoke sessions, reset password |
| Host | Snapshot VM, pull from network (not shutdown if memory needed) |

**Document every action with timestamp.**

## Phase 4 — Eradication
- Remove malware artifacts (verify with second tool)
- Close initial access vector (patch, disable feature)
- Reset compromised credentials company-wide if domain admin hit
- Reimage if rootkit suspected

## Phase 5 — Recovery
- Restore from known-good backup (verify backup wasn't compromised)
- Staged return to production with enhanced monitoring
- Password resets, certificate rotation if needed

## Phase 6 — Lessons learned
- IR timeline (detection → containment → recovery)
- Mean time to detect / respond
- Control failures
- Detection rule updates

## Communication template
```
Subject: [SEV-?] Security Incident — <brief title>
Status: Investigating / Contained / Resolved
Impact: <systems/data affected>
Actions taken: <bullets>
Next update: <time>
```

## Legal / compliance
- Preserve evidence before remediation when possible
- Involve legal for breach notification thresholds
- Chain of custody for forensic images
