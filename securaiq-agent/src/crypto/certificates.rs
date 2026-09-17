//! Device client certificates for proxy mTLS (RT-16).
//!
//! Present `agent.crt` + `agent.key` (or SECURAIQ_CLIENT_CERT / SECURAIQ_CLIENT_KEY)
//! when talking HTTPS to a terminating proxy. Private key never leaves the endpoint.

use std::fs;
use std::path::PathBuf;

/// Resolve optional client certificate + key paths.
pub fn client_cert_paths() -> Option<(PathBuf, PathBuf)> {
    let cert_env = std::env::var("SECURAIQ_CLIENT_CERT").unwrap_or_default();
    let key_env = std::env::var("SECURAIQ_CLIENT_KEY").unwrap_or_default();
    if !cert_env.is_empty() && !key_env.is_empty() {
        let c = PathBuf::from(cert_env);
        let k = PathBuf::from(key_env);
        if c.is_file() && k.is_file() {
            return Some((c, k));
        }
    }
    let home = agent_data_dir();
    for (cname, kname) in [("agent.crt", "agent.key"), ("client.crt", "client.key")] {
        let c = home.join(cname);
        let k = home.join(kname);
        if c.is_file() && k.is_file() {
            return Some((c, k));
        }
    }
    None
}

pub fn agent_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("SECURAIQ_AGENT_DATA_DIR").or_else(|_| std::env::var("SECURAIQ_DATA_DIR"))
    {
        return PathBuf::from(p);
    }
    // Prefer directory next to cwd / binary-friendly home
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".securaiq")
        .join("agent")
}

/// Write issued PEMs once (from enroll / rotate). Returns (cert_path, key_path).
pub fn install_client_certificate(cert_pem: &str, key_pem: &str) -> std::io::Result<(PathBuf, PathBuf)> {
    let home = agent_data_dir();
    fs::create_dir_all(&home)?;
    let cert_path = home.join("agent.crt");
    let key_path = home.join("agent.key");
    fs::write(&cert_path, format!("{}\n", cert_pem.trim()))?;
    fs::write(&key_path, format!("{}\n", key_pem.trim()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }
    Ok((cert_path, key_path))
}

/// Combined PEM (cert + key) for `reqwest::Identity::from_pem`.
pub fn identity_pem_bytes() -> Option<Vec<u8>> {
    let (cert, key) = client_cert_paths()?;
    let mut out = fs::read(&cert).ok()?;
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let key_bytes = fs::read(&key).ok()?;
    out.extend_from_slice(&key_bytes);
    Some(out)
}

pub fn has_client_certificate() -> bool {
    client_cert_paths().is_some()
}

/// Persist certificate metadata beside identity (no private key in JSON).
pub fn save_cert_metadata(agent_id: &str, fingerprint: &str, expires_at: Option<f64>) -> std::io::Result<()> {
    let home = agent_data_dir();
    fs::create_dir_all(&home)?;
    let path = home.join(format!("cert_meta_{}.json", &agent_id[..agent_id.len().min(12)]));
    let body = serde_json::json!({
        "agent_id": agent_id,
        "fingerprint": fingerprint,
        "expires_at": expires_at,
        "has_certificate": true,
    });
    fs::write(path, serde_json::to_vec_pretty(&body).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn install_and_resolve() {
        let dir = env::temp_dir().join(format!("securaiq-cert-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        env::set_var("SECURAIQ_AGENT_DATA_DIR", &dir);
        let cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        let key = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----";
        let (c, k) = install_client_certificate(cert, key).unwrap();
        assert!(c.is_file());
        assert!(k.is_file());
        assert!(has_client_certificate());
        let pem = identity_pem_bytes().unwrap();
        assert!(pem.windows(11).any(|w| w == b"CERTIFICATE"));
        let _ = fs::remove_dir_all(&dir);
        env::remove_var("SECURAIQ_AGENT_DATA_DIR");
    }
}
