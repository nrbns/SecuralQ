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

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    use base64::{
        engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
        Engine,
    };
    let t = text.trim();
    URL_SAFE_NO_PAD
        .decode(t)
        .or_else(|_| URL_SAFE.decode(t))
        .ok()
}

fn ed25519_public_material(cmd: &Value) -> String {
    cmd.get("signing_public_key")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| env::var("SECURAIQ_AGENT_ED25519_PUBLIC_KEY").ok())
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn verify_command_ed25519(cmd: &Value, agent_id: &str) -> Result<(), String> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pub_mat = ed25519_public_material(cmd);
    if pub_mat.is_empty() {
        return Err(
            "Ed25519 seal present but no signing_public_key / SECURAIQ_AGENT_ED25519_PUBLIC_KEY"
                .into(),
        );
    }
    let sig_b64 = cmd
        .get("signature_ed25519")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let sig_bytes =
        b64url_decode(sig_b64).ok_or_else(|| "invalid signature_ed25519 encoding".to_string())?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|_| "invalid Ed25519 signature length")?;

    let verifying = if pub_mat.contains("BEGIN") {
        VerifyingKey::from_public_key_pem(&pub_mat)
            .map_err(|e| format!("invalid Ed25519 public PEM: {e}"))?
    } else {
        let raw =
            b64url_decode(&pub_mat).ok_or_else(|| "invalid Ed25519 public key encoding".to_string())?;
        if raw.len() != 32 {
            return Err("Ed25519 public key must be 32 raw bytes (base64url)".into());
        }
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "bad key length")?;
        VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid Ed25519 public key: {e}"))?
    };

    let msg = canonical_command_bytes(cmd, agent_id);
    verifying
        .verify(&msg, &sig)
        .map_err(|_| "Ed25519 signature verification failed".to_string())
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

    if !hmac_sig.is_empty() && !verify_command_hmac(cmd, agent_id) {
        return Err("HMAC signature verification failed".into());
    }

    if !ed_sig.is_empty() {
        match verify_command_ed25519(cmd, agent_id) {
            Ok(()) => {}
            Err(e) if require => return Err(e),
            Err(e) => {
                // Soft mode: still refuse a present-but-invalid Ed seal.
                if e.contains("verification failed") || e.contains("invalid Ed25519 signature") {
                    return Err(e);
                }
                // Missing key material in soft mode — allow without Ed check.
            }
        }
    }

    Ok(())
}
