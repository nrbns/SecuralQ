# Tracker reconcile — zero engineering PARTIAL

**HEAD on securaiq/main** after this push. Sandbox trackers are stale.

## Close as DONE (engineering)

#226 #224 #225 #222 #223 #228 #227 #229  
#172 #173 #174 #176  
#249 #250 #251 #252 #253 #254 #236 #241 #248  
#230 #231 #232 #233 #234 #235 #237 #238 #239 #240 #242 #243 #244 #245 #246  
#255 #256 #257 #259 #221  

### Honest caveats (still DONE for engineering)

- **#256 SAML** — ACS is **fail-closed** + verifies XML-DSig via `signxml`, extracts NameID, issues session for matching local user (form POST, no prior login). Still needs `SAML_IDP_X509_CERT` + `pip install -r requirements-saml.txt` before marketing enterprise SSO.
- **#221** — Generic executive PPTX export only; branded Swana Techno/SecuraIQ investor deck is Phase 6 content.
- **DPDP** — frameworks + data-governance + canonical mappings shipped; never claim legal “DPDP compliant” without counsel.

## Phase 6 only (not code gaps)

#25 counsel · #247 EV Authenticode (scripts ready) · #258 Apple notarization (scripts ready)  
SOC 2 · FedRAMP (if gov) · third-party pentest · branded investor deck content

## Verify

```bash
pytest -v tests/test_close_all_partials.py tests/test_canonical_controls_registry.py
curl http://127.0.0.1:8080/api/status/public
curl http://127.0.0.1:8080/api/admin/mtls/fleet-status
curl -OJ http://127.0.0.1:8080/api/export/pptx
```

