//! Local enrollment identity. Private material never leaves the endpoint.
//!
//! Bearer token `agent_id.agent_key` + optional HMAC / Ed25519 command seals.
//! Device client certificates for proxy mTLS: see `crypto::certificates`
//! (`agent.crt` / `agent.key` or SECURAIQ_CLIENT_CERT / SECURAIQ_CLIENT_KEY).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Endpoint identity: enrollment token is `agent_id.agent_key` (admin enrolls once).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub agent_key: String,
    pub token: String,
}

impl AgentIdentity {
    pub fn from_token(token: &str) -> Option<Self> {
        let token = token.trim();
        let (aid, key) = token.split_once('.')?;
        if aid.is_empty() || key.is_empty() {
            return None;
        }
        Some(Self {
            agent_id: aid.to_string(),
            agent_key: key.to_string(),
            token: token.to_string(),
        })
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = identity_path(&self.agent_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let has_cert = crate::crypto::certificates::has_client_certificate();
        let body = serde_json::json!({
            "agent_id": self.agent_id,
            "has_key": true,
            "has_certificate": has_cert,
        });
        fs::write(path, serde_json::to_vec_pretty(&body).unwrap_or_default())
    }

    /// Load identity metadata if present (token still from env / --token).
    pub fn load_optional() -> Option<Self> {
        None
    }
}

fn identity_path(agent_id: &str) -> PathBuf {
    let root = crate::crypto::certificates::agent_data_dir();
    root.join(format!("identity_{}.json", &agent_id[..agent_id.len().min(12)]))
}
