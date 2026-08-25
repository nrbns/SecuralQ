# OWASP Top 10:2025 — Summary for RAG

Official list: https://owasp.org/Top10/2025/

## A01:2025 Broken Access Control
Test horizontal/vertical privilege escalation, IDOR/BOLA, forced browsing, and missing function-level access control.
Mitigation: deny by default, server-side checks, rate limiting, log access control failures.

## A02:2025 Security Misconfiguration
Default credentials, verbose errors, open cloud storage, missing security headers, unnecessary features.
Mitigation: hardened baselines, automated config scanning, minimal attack surface.

## A03:2025 Software Supply Chain Failures
Compromised dependencies, poisoned packages, weak CI/CD provenance, missing SBOM.
Mitigation: dependency pinning/signing, SCA, SBOM, verified builds, vendor risk review.

## A04:2025 Cryptographic Failures
Weak TLS, hardcoded keys, plaintext storage of passwords/PII, weak hashing or cipher suites.
Mitigation: TLS 1.2+, bcrypt/argon2, envelope encryption, key rotation, FIPS-validated crypto where required.

## A05:2025 Injection
SQLi, NoSQLi, OS command injection, LDAP/template injection. Prefer parameterized queries and allowlists.
Mitigation: prepared statements, input validation, least privilege DB accounts, output encoding.

## A06:2025 Insecure Design
Threat modeling gaps, missing security requirements, business-logic abuse (coupon races, workflow bypass).
Mitigation: secure design reviews, abuse-case modeling, security requirements in SDLC.

## A07:2025 Authentication Failures
Weak passwords, missing MFA, session fixation, credential stuffing, insecure recovery.
Mitigation: MFA/passkeys, secure session management, breach-resistant password policies.

## A08:2025 Software or Data Integrity Failures
Unsigned updates, insecure CI/CD, insecure deserialization, integrity bypass.
Mitigation: code signing, pipeline integrity checks, SBOM attestation, safe deserialization.

## A09:2025 Security Logging and Alerting Failures
Missing audit logs, no alerting on brute force or privilege changes, unmonitored high-risk actions.
Mitigation: centralized logging, SIEM/detection rules, alert triage, IR playbooks.

## A10:2025 Mishandling of Exceptional Conditions
Fail-open error paths, improper exception handling, logic flaws under abnormal conditions.
Mitigation: fail closed, consistent error handling, chaos/resilience testing, safe defaults.
