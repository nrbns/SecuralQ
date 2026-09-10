//! Deep inventory + host security status — shapes match Python `securaiq_agent.py`.

use serde_json::{json, Value};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[derive(Debug, Clone)]
pub struct DeepSnapshot {
    pub hostname: String,
    pub ip: String,
    pub os: String,
    pub os_version: String,
    pub listening_ports: Vec<u16>,
    pub processes: Vec<Value>,
    pub packages: Vec<Value>,
    pub services: Value,
    pub local_users: Value,
    pub local_groups: Value,
    pub hardware: Value,
    pub network: Value,
    pub startup_apps: Value,
    pub firewall_status: Value,
    pub disk_encryption_status: Value,
    pub defender_status: Value,
    pub ssh_config: Value,
}

pub fn collect_deep() -> DeepSnapshot {
    #[cfg(target_os = "windows")]
    {
        windows::collect()
    }
    #[cfg(target_os = "linux")]
    {
        linux::collect()
    }
    #[cfg(target_os = "macos")]
    {
        macos::collect()
    }
}

pub fn primary_ip() -> String {
    use std::net::UdpSocket;
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    String::new()
}

pub fn hostname_string() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".into())
}

pub fn not_collected(reason: &str) -> Value {
    json!({ "collected": false, "reason": reason })
}

pub fn not_collected_items(reason: &str) -> Value {
    json!({ "collected": false, "reason": reason, "items": [] })
}
