//! Rollback / canary percentage campaigns are **not implemented** on the endpoint.
//!
//! Approved remediations are allowlisted fixed-argv actions only. Recovery is
//! operator-driven (disable firewall manually, re-image lab VM, etc.).
//! Claiming automated rollback here would be dishonest.

pub fn rollback_not_implemented() -> &'static str {
    "no automated rollback — operator / lab recovery only"
}
