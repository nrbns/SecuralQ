//! Allowlisted command handling — ACK + honest result until remediations land in Rust.

use crate::transport::https::HttpsClient;
use serde_json::{json, Value};

pub async fn handle_commands(client: &HttpsClient, commands: Vec<Value>) {
    for cmd in commands {
        let Some(cid) = cmd.get("id").and_then(|v| v.as_str()).map(str::to_string) else {
            continue;
        };
        let kind = cmd
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        tracing::info!(command_id = %cid, kind, "received allowlisted command");
        if let Err(e) = client.ack_command(&cid).await {
            tracing::warn!(error = %e, %cid, "ack failed");
        }
        // Phase 1: do not execute remediations yet — report clearly so dashboard is honest.
        let result = json!({
            "ok": false,
            "error": format!(
                "Rust agent {ver} received '{kind}' but execution is not implemented yet; use Python bridge for allowlisted remediations",
                ver = env!("CARGO_PKG_VERSION"),
                kind = kind
            ),
            "kind": kind,
        });
        if let Err(e) = client.command_result(&cid, "error", &result).await {
            tracing::warn!(error = %e, %cid, "result report failed");
        }
    }
}
