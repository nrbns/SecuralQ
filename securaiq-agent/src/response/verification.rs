//! Host remediation verification is **server-side** (SecOps Phase 9–10 thin path).
//!
//! After an approved `enable_firewall` / `enable_defender`, the control plane
//! re-evaluates agent check-in telemetry via
//! `app.secops.verification.verify_host_remediation` — observed PASS/FAIL only.
//!
//! This module intentionally has no local rollback / canary engine yet.
//! Do not invent success here.

/// Placeholder for future local post-action probes (lab). Prefer server verify.
pub fn local_verify_not_implemented() -> &'static str {
    "server-side verify_host_remediation — no local canary/rollback yet"
}
