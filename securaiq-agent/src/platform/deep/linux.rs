//! Linux deep inventory (/proc, systemd, package managers).

use super::{hostname_string, not_collected_items, primary_ip, DeepSnapshot};
use crate::platform::cmd::{parse_json_rows, run_cmd};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

pub fn collect() -> DeepSnapshot {
    DeepSnapshot {
        hostname: hostname_string(),
        ip: primary_ip(),
        os: "Linux".into(),
        os_version: linux_version(),
        listening_ports: listening_ports(),
        processes: processes(40),
        packages: packages(500),
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
            "reason": "Not applicable on linux",
            "enabled": null
        }),
        ssh_config: ssh_config(),
    }
}

fn linux_version() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| {
                    l.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .chars()
                        .take(120)
                        .collect()
                })
        })
        .unwrap_or_else(|| {
            fs::read_to_string("/proc/version")
                .map(|s| s.chars().take(120).collect())
                .unwrap_or_else(|_| "Linux".into())
        })
}

fn listening_ports() -> Vec<u16> {
    let mut ports = std::collections::BTreeSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 || parts[3] != "0A" {
                continue;
            }
            if let Some(hex_port) = parts[1].split(':').next_back() {
                if let Ok(p) = u16::from_str_radix(hex_port, 16) {
                    if p > 0 {
                        ports.insert(p);
                    }
                }
            }
        }
    }
    if ports.is_empty() {
        if let Some(out) = run_cmd("ss", &["-tln"], 5) {
            for token in out.split_whitespace() {
                if let Some(idx) = token.rfind(':') {
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
    if let Some(out) = run_cmd("ps", &["-eo", "pid,user,comm", "--no-headers"], 8) {
        let mut rows = Vec::new();
        for line in out.lines() {
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
        return rows;
    }
    vec![]
}

fn packages(limit: usize) -> Vec<Value> {
    if let Some(out) = run_cmd(
        "dpkg-query",
        &["-W", "-f=${Package}\\t${Version}\\n"],
        15,
    ) {
        return parse_pkg_lines(&out, limit);
    }
    if let Some(out) = run_cmd("rpm", &["-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"], 15)
    {
        return parse_pkg_lines(&out, limit);
    }
    vec![]
}

fn parse_pkg_lines(out: &str, limit: usize) -> Vec<Value> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let bits: Vec<&str> = line.split('\t').collect();
        if bits.len() == 2 {
            rows.push(json!({ "name": bits[0], "version": bits[1] }));
        }
        if rows.len() >= limit {
            break;
        }
    }
    rows
}

fn services() -> Value {
    let Some(out) = run_cmd(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ],
        15,
    ) else {
        return not_collected_items("systemctl unavailable or failed (non-systemd host?)");
    };
    let items: Vec<Value> = out
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().next()?;
            Some(json!({ "name": name, "status": "running" }))
        })
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
        if uid < 1000 && uid != 0 {
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
    let mut memory_mb = None;
    if let Ok(mem) = fs::read_to_string("/proc/meminfo") {
        for line in mem.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                if let Some(kb) = rest.split_whitespace().next().and_then(|s| s.parse::<u64>().ok())
                {
                    memory_mb = Some(kb / 1024);
                }
                break;
            }
        }
    }
    let manufacturer = fs::read_to_string("/sys/class/dmi/id/sys_vendor")
        .map(|s| s.trim().chars().take(80).collect::<String>())
        .unwrap_or_default();
    let model = fs::read_to_string("/sys/class/dmi/id/product_name")
        .map(|s| s.trim().chars().take(80).collect::<String>())
        .unwrap_or_default();
    let disk_root_gb = fs::metadata("/")
        .ok()
        .and_then(|_| None::<f64>); // filled via df below
    let disk_root_gb = run_cmd("df", &["-BG", "--output=size", "/"], 5)
        .and_then(|o| {
            o.lines()
                .nth(1)?
                .trim()
                .trim_end_matches('G')
                .parse()
                .ok()
        })
        .or(disk_root_gb);

    json!({
        "collected": true,
        "reason": "",
        "arch": std::env::consts::ARCH,
        "processor": "",
        "cpu_count": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "memory_mb": memory_mb,
        "disk_root_gb": disk_root_gb,
        "manufacturer": manufacturer,
        "model": model,
    })
}

fn network() -> Value {
    if let Some(raw) = run_cmd("ip", &["-j", "addr"], 8) {
        if let Some(rows) = parse_json_rows(&raw) {
            let interfaces: Vec<Value> = rows
                .iter()
                .map(|r| {
                    let name = r.get("ifname").and_then(|v| v.as_str()).unwrap_or("");
                    let addrs: Vec<String> = r
                        .get("addr_info")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter(|a| a.get("family").and_then(|f| f.as_str()) == Some("inet"))
                                .filter_map(|a| a.get("local").and_then(|l| l.as_str()).map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    json!({ "name": name, "ipv4": addrs, "mac": r.get("address") })
                })
                .collect();
            return json!({ "collected": true, "reason": "", "interfaces": interfaces });
        }
    }
    let base = Path::new("/sys/class/net");
    if !base.is_dir() {
        return json!({
            "collected": false,
            "reason": "/sys/class/net not available",
            "interfaces": []
        });
    }
    let mut interfaces = Vec::new();
    if let Ok(entries) = fs::read_dir(base) {
        for e in entries.flatten().take(40) {
            let name = e.file_name().to_string_lossy().into_owned();
            let mac = fs::read_to_string(e.path().join("address"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            interfaces.push(json!({ "name": name, "ipv4": [], "mac": mac }));
        }
    }
    json!({ "collected": true, "reason": "sysfs partial (ip -j unavailable)", "interfaces": interfaces })
}

fn startup_apps() -> Value {
    let Some(out) = run_cmd(
        "systemctl",
        &[
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ],
        15,
    ) else {
        return not_collected_items("systemctl unavailable or failed");
    };
    let items: Vec<Value> = out
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().next()?;
            Some(json!({ "name": name }))
        })
        .collect();
    json!({ "collected": true, "reason": "", "items": items })
}

fn firewall_status() -> Value {
    if let Some(out) = run_cmd("ufw", &["status"], 8) {
        let enabled = out.trim().to_lowercase().starts_with("status: active");
        return json!({
            "collected": true,
            "reason": "",
            "backend": "ufw",
            "enabled": enabled
        });
    }
    if let Some(out) = run_cmd("firewall-cmd", &["--state"], 8) {
        return json!({
            "collected": true,
            "reason": "",
            "backend": "firewalld",
            "enabled": out.trim().eq_ignore_ascii_case("running")
        });
    }
    json!({
        "collected": false,
        "reason": "No supported firewall tool found (tried ufw, firewalld)",
        "enabled": null
    })
}

fn disk_encryption() -> Value {
    let Some(out) = run_cmd("lsblk", &["-o", "NAME,FSTYPE", "-n"], 8) else {
        return json!({
            "collected": false,
            "reason": "lsblk unavailable or failed",
            "encrypted": null
        });
    };
    let encrypted = out.to_lowercase().contains("crypto_luks");
    json!({
        "collected": true,
        "reason": "",
        "backend": "LUKS",
        "encrypted": encrypted
    })
}

fn ssh_config() -> Value {
    let path = Path::new("/etc/ssh/sshd_config");
    let Ok(text) = fs::read_to_string(path) else {
        return json!({
            "collected": false,
            "reason": "Could not read /etc/ssh/sshd_config",
            "settings": {}
        });
    };
    let mut settings = serde_json::Map::new();
    for key in [
        "PermitRootLogin",
        "PasswordAuthentication",
        "PubkeyAuthentication",
        "Port",
    ] {
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
