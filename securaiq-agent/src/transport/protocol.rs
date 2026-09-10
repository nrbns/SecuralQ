//! Wire shapes aligned with Agent Protocol v1 / existing FastAPI agents API.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 1;
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSeal {
    pub command_id: Uuid,
    pub kind: String,
    pub agent_id: String,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub signature: Option<String>,
}
