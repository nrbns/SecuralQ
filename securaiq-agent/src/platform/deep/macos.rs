//! macOS deep inventory (launchctl, FileVault, Application Firewall).

use super::{hostname_string, not_collected_items, primary_ip, DeepSnapshot};
use crate::platform::cmd::run_cmd;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

pub fn collect() -> DeepSnapshot {
    DeepSnapshot {
        hostname: hostname_string(),
        ip: primary_ip(),
        os: "macOS".into(),
        os_version: macos_version(),
        listening_ports: listening_ports(),
        processes: processes(40),
        packages: packages(200),
        services: services(),
        local_users: local_users(),
        local_groups: local_groups(),
        hardware: hardware(),
        network: network(),
        startup_apps: startup_apps(),
        firewall_status: firewall_status(),
        disk_encryption_status: disk_encryption(),
        defender_status: json!({
            "collected": false,
            "reason": "Not applicable on macOS",
            "enabled": null
        }),
        ssh_config: ssh_config(),
    }
}

fn macos_version() -> String {
    run_cmd("sw_vers", &["-productVersion"], 5)
        .map(|s| format!("macOS {}", s.trim()))
        .unwrap_or_else(|| "macOS".into())
}

fn listening_ports() -> Vec<u16> {
    let mut ports = std::collections::BTreeSet::new();
    if let Some(out) = run_cmd("netstat", &["-an"], 8) {
        for line in out.lines() {
            if !line.contains("LISTEN") {
                continue;
            }
            for token in line.split_whitespace() {
                if let Some(idx) = token.rfind('.') {
                    if let Ok(p) = token[idx + 1..].parse::<u16>() {
                        if p > 0 {
                            ports.insert(p);
                        }
                    }
                }
            }
        }
    }
    ports.into_iter().collect()
}

fn processes(limit: usize) -> Vec<Value> {
    let Some(out) = run_cmd("ps", &["-eo", "pid,user,comm"], 8) else {
        return vec![];
    };
    let mut rows = Vec::new();
    for line in out.lines().skip(1) {
        let bits: Vec<&str> = line.split_whitespace().collect();
        if bits.len() < 3 {
            continue;
        }
        let pid: Option<u32> = bits[0].parse().ok();
        rows.push(json!({ "pid": pid, "user": bits[1], "name": bits[2] }));
        if rows.len() >= limit {
            break;
        }
    }
    rows
}

fn packages(limit: usize) -> Vec<Value> {
    // Prefer brew list when present.
    if let Some(out) = run_cmd("brew", &["list", "--versions"], 20) {
        let mut rows = Vec::new();
        for line in out.lines() {
            let bits: Vec<&str> = line.split_whitespace().collect();
            if bits.len() >= 2 {
                rows.push(json!({ "name": bits[0], "version": bits[1] }));
            }
            if rows.len() >= limit {
                break;
            }
        }
        return rows;
    }
    vec![]
}

fn services() -> Value {
    let Some(out) = run_cmd("launchctl", &["list"], 15) else {
        return not_collected_items("launchctl unavailable or failed");
    };
    let items: Vec<Value> = out
        .lines()
        .skip(1)
        .filter_map(|line| {
            let bits: Vec<&str> = line.split('\t').collect();
            if bits.len() == 3 {
                Some(json!({ "name": bits[2], "pid": bits[0] }))
            } else {
                None
            }
        })
        .take(200)
        .collect();
    json!({ "collected": true, "reason": "", "items": items })
}

fn local_users() -> Value {
    let Ok(text) = fs::read_to_string("/etc/passwd") else {
        return not_collected_items("Could not read /etc/passwd");
    };
    let mut items = Vec::new();
    for line in text.lines() {
        let bits: Vec<&str> = line.split(':').collect();
        if bits.len() < 7 {
            continue;
        }
        let uid: u32 = match bits[2].parse() {
            Ok(u) => u,
            Err(_) => continue,
        };
        if uid < 500 && uid != 0 {
            continue;
        }
        let shell = bits[6];
        let login_shell = !matches!(
            shell,
            "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false" | ""
        );
        items.push(json!({ "name": bits[0], "uid": uid, "login_shell": login_shell }));
    }
    json!({ "collected": true, "reason": "", "items": items })
}

fn local_groups() -> Value {
    let Ok(text) = fs::read_to_string("/etc/group") else {
        return not_collected_items("Could not read /etc/group");
    };
    let mut items = Vec::new();
    for line in text.lines() {
        let bits: Vec<&str> = line.split(':').collect();
        if bits.len() < 4 {
            continue;
        }
        let gid: i64 = match bits[2].parse() {
            Ok(g) => g,
            Err(_) => continue,
        };
        let members: Vec<&str> = bits[3].split(',').filter(|m| !m.is_empty()).take(20).collect();
        items.push(json!({ "name": bits[0], "gid": gid, "members": members }));
        if items.len() >= 80 {
            break;
        }
    }
    json!({ "collected": true, "reason": "", "items": items })
}

fn hardware() -> Value {
    let model = run_cmd("sysctl", &["-n", "hw.model"], 5)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let mem_bytes = run_cmd("sysctl", &["-n", "hw.memsize"], 5)
        .and_then(|s| s.trim().parse::<u64>().ok());
    json!({
        "collected": true,
        "reason": "",
        "arch": std::env::consts::ARCH,
        "processor": "",
        "cpu_count": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "memory_mb": mem_bytes.map(|b| b / (1024 * 1024)),
        "disk_root_gb": null,
        "manufacturer": "Apple",
        "model": model,
    })
}

fn network() -> Value {
    let Some(out) = run_cmd("ifconfig", &["-a"], 8) else {
        return json!({
            "collected": false,
            "reason": "ifconfig unavailable or failed",
            "interfaces": []
        });
    };
    let mut interfaces = Vec::new();
    let mut current: Option<String> = None;
    let mut ipv4 = Vec::new();
    for line in out.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            if let Some(name) = current.take() {
                interfaces.push(json!({ "name": name, "ipv4": ipv4, "mac": "" }));
                ipv4 = Vec::new();
            }
            current = Some(line.split(':').next().unwrap_or("").to_string());
        } else if line.trim_start().starts_with("inet ") {
            if let Some(addr) = line.split_whitespace().nth(1) {
                ipv4.push(addr.to_string());
            }
        }
    }
    if let Some(name) = current {
        interfaces.push(json!({ "name": name, "ipv4": ipv4, "mac": "" }));
    }
    json!({ "collected": true, "reason": "", "interfaces": interfaces })
}

fn startup_apps() -> Value {
    let dirs = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        &format!(
            "{}/Library/LaunchAgents",
            dirs::home_dir()
                .unwrap_or_default()
                .to_string_lossy()
        ),
    ];
    let mut items = Vec::new();
    let mut found = false;
    for d in dirs {
        let path = Path::new(d);
        if !path.is_dir() {
            continue;
        }
        found = true;
        if let Ok(entries) = fs::read_dir(path) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".plist") {
                    items.push(json!({ "name": name, "location": d }));
                }
            }
        }
    }
    if !found {
        return not_collected_items("No LaunchAgents/LaunchDaemons directories found");
    }
    json!({ "collected": true, "reason": "", "items": items })
}

fn firewall_status() -> Value {
    let Some(out) = run_cmd(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
        8,
    ) else {
        return json!({
            "collected": false,
            "reason": "socketfilterfw unavailable or failed",
            "enabled": null
        });
    };
    json!({
        "collected": true,
        "reason": "",
        "backend": "pf/ALF",
        "enabled": out.to_lowercase().contains("enabled")
    })
}

fn disk_encryption() -> Value {
    let Some(out) = run_cmd("fdesetup", &["status"], 8) else {
        return json!({
            "collected": false,
            "reason": "fdesetup unavailable or failed",
            "encrypted": null
        });
    };
    json!({
        "collected": true,
        "reason": "",
        "backend": "FileVault",
        "encrypted": out.to_lowercase().contains("filevault is on")
    })
}

fn ssh_config() -> Value {
    let path = Path::new("/etc/ssh/sshd_config");
    let Ok(text) = fs::read_to_string(path) else {
        return json!({
            "collected": false,
            "reason": "Could not read /etc/ssh/sshd_config (may need TCC/permissions)",
            "settings": {}
        });
    };
    let mut settings = serde_json::Map::new();
    for key in ["PermitRootLogin", "PasswordAuthentication", "PubkeyAuthentication"] {
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            if parts.next() == Some(key) {
                if let Some(val) = parts.next() {
                    settings.insert(key.to_string(), json!(val));
                }
            }
        }
    }
    json!({ "collected": true, "reason": "", "settings": settings })
}
