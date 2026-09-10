//! Request HMAC — matches `app.agent_auth.sign_payload`.
//!
//! ``X-SecuraIQ-Sig`` = HMAC-SHA256(agent_key, ``ts.nonce.sha256(body)``)

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn sign_payload(agent_key: &str, ts: &str, nonce: &str, body: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(body));
    let msg = format!("{ts}.{nonce}.{digest}");
    let mut mac =
        HmacSha256::new_from_slice(agent_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn new_nonce_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn unix_ts() -> String {
    chrono::Utc::now().timestamp().to_string()
}

/// Headers for authenticated agent HTTPS calls.
pub fn replay_headers(agent_key: &str, body: &[u8]) -> Vec<(String, String)> {
    let ts = unix_ts();
    let nonce = new_nonce_hex(16);
    let sig = sign_payload(agent_key, &ts, &nonce, body);
    vec![
        ("X-SecuraIQ-Ts".into(), ts),
        ("X-SecuraIQ-Nonce".into(), nonce),
        ("X-SecuraIQ-Sig".into(), sig),
    ]
}
