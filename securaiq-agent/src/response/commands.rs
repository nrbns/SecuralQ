//! Allowlisted command handling — seal verify → fixed-argv execute → result.

use crate::crypto::command_signatures_ok;
use crate::response::remediation::execute_kind;
use crate::transport::https::HttpsClient;
use serde_json::{json, Value};

pub async fn handle_commands(client: &HttpsClient, commands: Vec<Value>) {
    let agent_id = client
        .token()
        .split_once('.')
        .map(|(a, _)| a.to_string())
        .unwrap_or_default();

    for cmd in commands {
        let Some(cid) = cmd.get("id").and_then(|v| v.as_str()).map(str::to_string) else {
            continue;
        };
        let kind = cmd
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        tracing::info!(command_id = %cid, kind = %kind, "received allowlisted command");

        if let Err(e) = client.ack_command(&cid).await {
            tracing::warn!(error = %e, %cid, "ack failed");
        }

        if let Err(reason) = command_signatures_ok(&cmd, &agent_id) {
            tracing::warn!(%cid, %reason, "refusing command");
            let result = json!({
                "ok": false,
                "error": format!("signature verification failed: {reason}"),
            });
            let _ = client.command_result(&cid, "error", &result).await;
            continue;
        }

        let result = match kind.as_str() {
            "enable_firewall" | "enable_defender" => execute_kind(&kind),
            "patch_package" | "agent_upgrade" => json!({
                "ok": false,
                "error": format!("kind '{kind}' not yet implemented in Rust agent — use Python bridge"),
                "kind": kind,
            }),
            other => json!({
                "ok": false,
                "error": format!("Unknown command kind '{other}'"),
                "kind": other,
            }),
        };

        let ok = result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        let status = if ok { "done" } else { "error" };
        if let Err(e) = client.command_result(&cid, status, &result).await {
            tracing::warn!(error = %e, %cid, "result report failed");
        } else {
            tracing::info!(%cid, status, "command result reported");
        }
    }
}
