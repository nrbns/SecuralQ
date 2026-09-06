# SecuraIQ compliance frameworks (current editions)

Catalogs live in `data/frameworks/*.json` and power `GET /api/frameworks`, gap analysis, remediations, and audit packs.

**Honest use:** catalogs and scores produce **security evidence that helps assess** control requirements. They do **not** certify ISO / SOC 2 / PCI compliance. See `docs/compliance-platform.md` for the product IA (framework → control → test → evidence → finding → remediation → verification).

| ID | Standard | Notes |
|----|----------|-------|
| iso27001 | ISO/IEC 27001:2022 Annex A | Full 93 controls |
| iso27701 | ISO/IEC 27701:2025 PIMS | Standalone privacy MS |
| nist_csf | NIST CSF 2.0 | Govern–Recover outcomes |
| nist_800_53 | NIST SP 800-53 Rev. 5 | Priority AC–SR controls |
| nist_800_171 | NIST SP 800-171 | CUI protection |
| cmmc_l2 | CMMC 2.0 Level 2 | DFARS / CUI, all 110 NIST SP 800-171 Rev 2 practices (see `resources` below) |
| cis_controls | CIS Controls v8.1 | IG1 essentials |
| soc2 | SOC 2 TSC | 2017 TSC / 2022 points of focus |
| pci_dss | PCI DSS v4.0.1 | Priority requirements |
| hipaa | HIPAA Security Rule | 45 CFR Part 164 |
| gdpr | GDPR | Core articles |
| nis2 | NIS2 Directive | Art. 20–23 themes |
| owasp_asvs | OWASP ASVS 5.0 | Chapter requirements |
| owasp_top10 | OWASP Top 10:2025 | Risk categories |

## CMMC current status (cmmc_l2)

Per the official DoD CIO CMMC pages (https://dodcio.defense.gov/CMMC/About/ and
.../Resources-Documentation/, fetched 2026):

- **July 13, 2026:** the Department of War suspended CMMC Phase II (previously
  due Nov 10, 2026) and stood up a CMMC reform task force aligned to the
  Secretary's Acquisition Transformation System directives. Phase I
  self-assessment requirements remain in force during the review.
- **Level 1 (Basic safeguarding of FCI):** 15 requirements from FAR clause
  52.204-21. Annual self-assessment + annual affirmation, entered into SPRS.
  POA&Ms are not permitted.
- **Level 2 (Broad protection of CUI):** 110 requirements from NIST SP 800-171
  Rev 2 (required by DFARS 252.204-7012). Currently a self-assessment every 3
  years + annual affirmation into SPRS; third-party (C3PAO) certification
  assessments are paused pending the reform review. POA&M closeout must be
  self-assessed and closed within 180 days.
- This app's `cmmc_l2` catalog now covers **all 110 NIST SP 800-171 Rev 2
  practices** across all 14 families (previously a 24-practice priority
  subset). Each control carries the official DoD SPRS point weight (5, 3, 1,
  or 0 for the SSP requirement, which has no point value) and a `cmmc_level1`
  flag marking the 17 practices also required at Level 1. Weights are sourced
  from the DoD NIST SP 800-171 Assessment Methodology (32 CFR 170) and total
  313 points across the 110 controls, matching the official scale (start at
  110, subtract each unimplemented control's weight; MFA (3.5.3) and FIPS
  crypto (3.13.11) have partial-credit exceptions the app does not model). See
  the official Level 2 Scoping/Assessment Guides (linked in the framework's
  `resources` field, also surfaced in the Frameworks page UI) for the DoD's
  own assessment procedures.
- **PreVeil** (preveil.com) is a commercial vendor selling encrypted
  email/file-sharing plus prefilled CMMC compliance documentation. It is
  listed only as an external reference in `cmmc_l2.json`'s `resources` field
  -- SecuraIQ has no API integration, data exchange, or partnership with this
  or any other named vendor.

## Workflow

1. Collect evidence (policies, configs, tickets, screenshots) in Evidence.
2. Run gap analysis (`POST /api/gap/run`) with framework_id + evidence text and/or file_ids.
3. Review Frameworks → Open controls (status, owner, evidence, **Live test**, risk).
4. Close remediations and link evidence; export Markdown assessment or audit ZIP.
5. Optionally request a bounded **Exception** when risk is accepted with owner + expiry.

Scoring is keyword/evidence heuristic with optional manual status overrides — attach formal artifacts before audit assertion. Live tests (Task #144) are a separate telemetry signal and are not blended into the %.
