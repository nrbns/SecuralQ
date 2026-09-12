//! Local enrollment identity. Private material never leaves the endpoint.
//!
//! Commercial Alpha: bearer token `agent_id.agent_key` + optional HMAC / Ed25519
//! *command* seals (server keys). Device Ed25519 identity keypairs and mTLS
//! certificates are Phase 3 (RT-16) — see `docs/agent-protocol-v1.md`.

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
        let body = serde_json::json!({
            "agent_id": self.agent_id,
            "has_key": true,
            // Token file separate preferred; store id only in identity.json for discovery.
            // Future RT-16 fields: public_key, certificate_pem, certificate_expiry, status.
        });
        fs::write(path, serde_json::to_vec_pretty(&body).unwrap_or_default())
    }

    /// Placeholder until local device-key persistence lands (RT-16).
    pub fn load_optional() -> Option<Self> {
        None
    }
}

fn identity_path(agent_id: &str) -> PathBuf {
    let root = std::env::var("SECURAIQ_AGENT_DATA_DIR")
        .or_else(|_| std::env::var("SECURAIQ_DATA_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".securaiq")
                .join("agent")
        });
    root.join(format!("identity_{}.json", &agent_id[..agent_id.len().min(12)]))
}
