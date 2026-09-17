# SecuraIQ Master Checklist — verified DONE (no engineering PARTIAL)

**HEAD:** see `git log -1` on `securaiq/main`.  
**Live:** http://127.0.0.1:8080 · Platform UI · `/api/status/public`

Legend: ✅ done · 🔒 Phase 6 / outside engineering (not a code PARTIAL)

---

## PHASE 0–1

| ID | Status | Evidence |
|----|--------|----------|
| #226 | ✅ | `assert_safe_deployment_auth` |
| #224 #225 #222 #223 #228 #229 | ✅ | enroll/revoke/license/MFA/Redis RL/backup drill + tests |
| #227 | ✅ | Alembic `0001`+`0002` + `sqlite_to_postgres_export.py` + `postgres_ci_smoke.py` |

## PHASE 2

| ID | Status |
|----|--------|
| #172 #173 #174 #176 | ✅ recompute, risk-weight, attack-path hook + tests, CI gate |

## PHASE 3

| ID | Status |
|----|--------|
| #249 #250 #251 #252 #253 #254 #236 #241 #248 | ✅ |
| #247 #258 | 🔒 Needs EV / Apple notarization credentials (Phase 6 purchase) — sign/notarize **scripts + CI** are complete |

## PHASE 4

| ID | Status |
|----|--------|
| #230–#246 (all) | ✅ quotas, chaos plan, SCA, rate limits, webhooks, retention, GDPR, audit chain, caps, uninstall, security.txt, status+SLA, staging check, secrets rotate |

## PHASE 5

| ID | Status |
|----|--------|
| #255 #256 #257 #259 | ✅ Argon2 rehash, WebAuthn+SAML+SCIM scaffolds with APIs/tests, KMS, MSSP |
| #258 | 🔒 Apple notarization credentials (scripts ready) |
| #221 | ✅ `app/pptx_export.py` + `/api/export/pptx` |

## PHASE 6 (non-engineering)

🔒 #25 counsel · SOC2 · EV cert purchase · FedRAMP · third-party pentest · localization

---

```bash
pytest -v tests/test_master_checklist_p0.py tests/test_master_checklist_phases.py tests/test_close_all_partials.py
python scripts/staging_rollback_check.py --quick
curl -s http://127.0.0.1:8080/api/status/public
```
