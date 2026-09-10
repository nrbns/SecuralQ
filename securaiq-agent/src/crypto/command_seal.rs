//! Command seal verification — matches `app.agent_security` / Python bridge.

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::env;

type HmacSha256 = Hmac<Sha256>;

fn signing_secret() -> Vec<u8> {
    let raw = env::var("SECURAIQ_AGENT_SIGNING_KEY")
        .unwrap_or_else(|_| "securaiq-dev-agent-signing-key-change-me".into());
    Sha256::digest(raw.as_bytes()).to_vec()
}

fn sort_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), sort_value(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

pub fn canonical_command_bytes(cmd: &Value, agent_id: &str) -> Vec<u8> {
    let mut body = Map::new();
    body.insert(
        "command_id".into(),
        json!(cmd.get("id").and_then(|v| v.as_str()).unwrap_or("")),
    );
    body.insert("agent_id".into(), json!(agent_id));
    body.insert(
        "kind".into(),
        json!(cmd.get("kind").and_then(|v| v.as_str()).unwrap_or("")),
    );
    let payload = cmd
        .get("payload")
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    body.insert("payload".into(), sort_value(&payload));
    body.insert(
        "nonce".into(),
        json!(cmd.get("nonce").and_then(|v| v.as_str()).unwrap_or("")),
    );
    body.insert(
        "event_id".into(),
        json!(cmd.get("event_id").and_then(|v| v.as_str()).unwrap_or("")),
    );
    if let Some(v) = cmd.get("issued_at") {
        if let Some(f) = v.as_f64().or_else(|| v.as_i64().map(|i| i as f64)) {
            body.insert("issued_at".into(), json!(f));
        }
    }
    if let Some(v) = cmd.get("expires_at") {
        if let Some(f) = v.as_f64().or_else(|| v.as_i64().map(|i| i as f64)) {
            body.insert("expires_at".into(), json!(f));
        }
    }
    let sorted = sort_value(&Value::Object(body));
    serde_json::to_vec(&sorted).unwrap_or_default()
}

pub fn verify_command_hmac(cmd: &Value, agent_id: &str) -> bool {
    let sig = cmd
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if sig.is_empty() {
        return false;
    }
    let msg = canonical_command_bytes(cmd, agent_id);
    let mut mac = HmacSha256::new_from_slice(&signing_secret()).expect("hmac key");
    mac.update(&msg);
    let expected = hex::encode(mac.finalize().into_bytes());
    constant_time_eq(expected.as_bytes(), sig.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Lab-friendly by default; mandatory when env or command require_verify.
pub fn command_signatures_ok(cmd: &Value, agent_id: &str) -> Result<(), String> {
    let env_require = matches!(
        env::var("SECURAIQ_REQUIRE_COMMAND_VERIFY")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    );
    let cmd_require = cmd
        .get("require_verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let require = env_require || cmd_require;

    if let Some(exp) = cmd
        .get("expires_at")
        .and_then(|v| v.as_f64().or_else(|| v.as_i64().map(|i| i as f64)))
    {
        let now = chrono::Utc::now().timestamp() as f64;
        if now > exp + 30.0 {
            return Err("seal expired".into());
        }
    }

    let hmac_sig = cmd
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let ed_sig = cmd
        .get("signature_ed25519")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();

    if require && hmac_sig.is_empty() && ed_sig.is_empty() {
        return Err("missing signature (require_verify)".into());
    }

    if !hmac_sig.is_empty() {
        // Prefer verifying when a signature is present.
        if !verify_command_hmac(cmd, agent_id) {
            // Lab: if signing key mismatch and not required, allow with warning path.
            if require {
                return Err("HMAC signature verification failed".into());
            }
            // Still refuse bad HMAC when present — a wrong seal should not execute.
            return Err("HMAC signature verification failed".into());
        }
    }

    if !ed_sig.is_empty() {
        // Ed25519 verify deferred (needs cryptography crate); refuse if required.
        if require {
            return Err("Ed25519 seal present but Rust agent Ed25519 verify not enabled yet".into());
        }
    }

    Ok(())
}
