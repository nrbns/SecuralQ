//! Windows deep inventory via PowerShell / CIM (same signals as Python bridge).

use super::{hostname_string, not_collected_items, primary_ip, DeepSnapshot};
use crate::platform::cmd::{parse_json_rows, run_cmd, run_powershell};
use serde_json::{json, Value};
use std::path::Path;

pub fn collect() -> DeepSnapshot {
    DeepSnapshot {
        hostname: hostname_string(),
        ip: primary_ip(),
        os: "Windows".into(),
        os_version: windows_version(),
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
        defender_status: defender_status(),
        ssh_config: json!({
            "collected": false,
            "reason": "SSH config not applicable as primary Windows signal",
            "settings": {}
        }),
    }
}

fn windows_version() -> String {
    run_powershell(
        "(Get-CimInstance Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance Win32_OperatingSystem).Version",
        12,
    )
    .map(|s| s.trim().chars().take(120).collect())
    .unwrap_or_else(|| {
        std::env::var("OS").unwrap_or_else(|_| format!("Windows {}", std::env::consts::ARCH))
    })
}

fn listening_ports() -> Vec<u16> {
    let out = match run_cmd("netstat", &["-an"], 8) {
        Some(o) => o,
        None => return vec![],
    };
    let mut ports = std::collections::BTreeSet::new();
    for line in out.lines() {
        let lower = line.to_lowercase();
        if !lower.contains("listen") {
            continue;
        }
        // TCP    0.0.0.0:8080    ... LISTENING
        for token in line.split_whitespace() {
            if let Some(idx) = token.rfind(':') {
                if let Ok(p) = token[idx + 1..].parse::<u16>() {
                    if p > 0 {
                        ports.insert(p);
                    }
                }
            }
        }
        if ports.len() >= 200 {
            break;
        }
    }
    ports.into_iter().collect()
}

fn processes(limit: usize) -> Vec<Value> {
    let out = match run_cmd("tasklist", &["/FO", "CSV", "/NH"], 10) {
        Some(o) => o,
        None => return vec![],
    };
    let mut rows = Vec::new();
    for line in out.lines() {
        // "name.exe","1234","Session","1","12,345 K"
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0].trim().trim_matches('"');
        let pid_s = parts[1].trim().trim_matches('"');
        let pid: Option<u32> = pid_s.parse().ok();
        if name.is_empty() {
            continue;
        }
        rows.push(json!({ "pid": pid, "name": name, "user": "" }));
        if rows.len() >= limit {
            break;
        }
    }
    rows
}

fn packages(limit: usize) -> Vec<Value> {
    let raw = run_powershell(
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* , \
         HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* \
         -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion | ConvertTo-Json -Compress",
        25,
    );
    let Some(raw) = raw else {
        return vec![];
    };
    let Some(rows) = parse_json_rows(&raw) else {
        return vec![];
    };
    let mut out = Vec::new();
    for r in rows {
        let name = r
            .get("DisplayName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if name.is_empty() {
            continue;
        }
        let ver = r
            .get("DisplayVersion")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        out.push(json!({ "name": name, "version": ver }));
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn services() -> Value {
    let raw = run_powershell(
        "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 200 Name,Status | ConvertTo-Json -Compress",
        20,
    );
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return not_collected_items("Get-Service unavailable or failed");
    };
    let Some(rows) = parse_json_rows(&raw) else {
        return not_collected_items("Could not parse Get-Service output");
    };
    let items: Vec<Value> = rows
        .iter()
        .filter_map(|r| {
            let name = r.get("Name")?.as_str()?;
            Some(json!({ "name": name, "status": "running" }))
        })
        .collect();
    json!({ "collected": true, "reason": "", "items": items })
}

fn local_users() -> Value {
    let raw = run_powershell(
        "Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json -Compress",
        15,
    );
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return not_collected_items(
            "Get-LocalUser unavailable or failed (needs the LocalAccounts module)",
        );
    };
    let Some(rows) = parse_json_rows(&raw) else {
        return not_collected_items("Could not parse Get-LocalUser output");
    };
    let items: Vec<Value> = rows
        .iter()
        .filter_map(|r| {
            let name = r.get("Name")?.as_str()?;
            Some(json!({
                "name": name,
                "enabled": r.get("Enabled").and_then(|v| v.as_bool()).unwrap_or(false),
            }))
        })
        .collect();
    json!({ "collected": true, "reason": "", "items": items })
}

fn local_groups() -> Value {
    let raw = run_powershell(
        "Get-LocalGroup | Select-Object -First 40 Name | ForEach-Object { \
         $m = @(); try { $m = @(Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue | \
         Select-Object -First 15 -ExpandProperty Name) } catch {}; \
         [pscustomobject]@{ name = $_.Name; members = $m } } | ConvertTo-Json -Compress",
        25,
    );
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return not_collected_items(
            "Get-LocalGroup unavailable or failed (needs LocalAccounts module / elevation)",
        );
    };
    let Some(rows) = parse_json_rows(&raw) else {
        return not_collected_items("Could not parse Get-LocalGroup output");
    };
    let mut items = Vec::new();
    for r in rows {
        let name = r
            .get("name")
            .or_else(|| r.get("Name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let members = r
            .get("members")
            .or_else(|| r.get("Members"))
            .cloned()
            .unwrap_or(json!([]));
        items.push(json!({ "name": name, "members": members }));
    }
    json!({ "collected": true, "reason": "", "items": items })
}

fn hardware() -> Value {
    let mut out = json!({
        "collected": true,
        "reason": "",
        "arch": std::env::consts::ARCH,
        "processor": "",
        "cpu_count": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "memory_mb": null,
        "disk_root_gb": disk_root_gb(),
        "manufacturer": "",
        "model": "",
    });
    if let Some(raw) = run_powershell(
        "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory,NumberOfLogicalProcessors | ConvertTo-Json -Compress",
        15,
    ) {
        if let Ok(data) = serde_json::from_str::<Value>(raw.trim()) {
            if let Some(m) = data.get("Manufacturer").and_then(|v| v.as_str()) {
                out["manufacturer"] = json!(m.chars().take(80).collect::<String>());
            }
            if let Some(m) = data.get("Model").and_then(|v| v.as_str()) {
                out["model"] = json!(m.chars().take(80).collect::<String>());
            }
            if let Some(mem) = data.get("TotalPhysicalMemory").and_then(|v| v.as_u64()) {
                out["memory_mb"] = json!(mem / (1024 * 1024));
            }
            if let Some(cpus) = data
                .get("NumberOfLogicalProcessors")
                .and_then(|v| v.as_u64())
            {
                out["cpu_count"] = json!(cpus);
            }
        }
    }
    out
}

fn disk_root_gb() -> Option<f64> {
    // Current drive root via PowerShell for accuracy.
    run_powershell(
        "[math]::Round((Get-PSDrive -Name (Get-Location).Drive.Name).Used/1GB + (Get-PSDrive -Name (Get-Location).Drive.Name).Free/1GB, 1)",
        8,
    )
    .and_then(|s| s.trim().parse().ok())
    .or_else(|| {
        // Fallback: C:\
        if Path::new("C:\\").exists() {
            run_powershell(
                "[math]::Round(((Get-Volume -DriveLetter C).Size)/1GB, 1)",
                8,
            )
            .and_then(|s| s.trim().parse().ok())
        } else {
            None
        }
    })
}

fn network() -> Value {
    let raw = run_powershell(
        "Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | Select-Object -First 20 \
         InterfaceAlias,@{N='IPv4';E={$_.IPv4Address.IPAddress}},\
         @{N='Mac';E={(Get-NetAdapter -Name $_.InterfaceAlias -ErrorAction SilentlyContinue).MacAddress}} \
         | ConvertTo-Json -Compress",
        20,
    );
    if let Some(raw) = raw.filter(|s| !s.trim().is_empty()) {
        if let Some(rows) = parse_json_rows(&raw) {
            let interfaces: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "name": r.get("InterfaceAlias").and_then(|v| v.as_str()).unwrap_or(""),
                        "ipv4": r.get("IPv4").cloned().unwrap_or(json!([])),
                        "mac": r.get("Mac").and_then(|v| v.as_str()).unwrap_or(""),
                    })
                })
                .collect();
            if !interfaces.is_empty() {
                return json!({ "collected": true, "reason": "", "interfaces": interfaces });
            }
        }
    }
    // Fallback: IPv4 addresses only (no elevation / NetIPConfiguration quirks).
    let raw = run_powershell(
        "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | \
         Where-Object { $_.IPAddress -notlike '127.*' } | Select-Object -First 20 \
         InterfaceAlias,IPAddress | ConvertTo-Json -Compress",
        15,
    );
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return json!({
            "collected": false,
            "reason": "Get-NetIPConfiguration / Get-NetIPAddress unavailable or failed",
            "interfaces": []
        });
    };
    let Some(rows) = parse_json_rows(&raw) else {
        return json!({
            "collected": false,
            "reason": "Could not parse network configuration",
            "interfaces": []
        });
    };
    let interfaces: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "name": r.get("InterfaceAlias").and_then(|v| v.as_str()).unwrap_or(""),
                "ipv4": r.get("IPAddress").cloned().unwrap_or(json!([])),
                "mac": "",
            })
        })
        .collect();
    json!({
        "collected": true,
        "reason": "fallback Get-NetIPAddress",
        "interfaces": interfaces
    })
}

fn startup_apps() -> Value {
    let raw = run_powershell(
        "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | ConvertTo-Json -Compress",
        20,
    );
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return not_collected_items("Get-CimInstance Win32_StartupCommand unavailable or failed");
    };
    let Some(rows) = parse_json_rows(&raw) else {
        return not_collected_items("Could not parse Win32_StartupCommand output");
    };
    let items: Vec<Value> = rows
        .iter()
        .filter_map(|r| {
            let name = r.get("Name")?.as_str()?;
            Some(json!({
                "name": name,
                "command": r.get("Command"),
                "location": r.get("Location"),
            }))
        })
        .collect();
    json!({ "collected": true, "reason": "", "items": items })
}

fn firewall_status() -> Value {
    let raw = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress",
        15,
    );
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return json!({
            "collected": false,
            "reason": "Get-NetFirewallProfile unavailable or failed",
            "enabled": null
        });
    };
    let Some(rows) = parse_json_rows(&raw) else {
        return json!({
            "collected": false,
            "reason": "Could not parse Get-NetFirewallProfile output",
            "enabled": null
        });
    };
    let mut profiles = serde_json::Map::new();
    let mut any = false;
    for r in rows {
        if let Some(name) = r.get("Name").and_then(|v| v.as_str()) {
            let en = r.get("Enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            any |= en;
            profiles.insert(name.to_string(), json!(en));
        }
    }
    json!({
        "collected": true,
        "reason": "",
        "backend": "Windows Firewall",
        "enabled": any,
        "profiles": profiles
    })
}

fn disk_encryption() -> Value {
    let raw = run_powershell(
        "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus | ConvertTo-Json -Compress",
        15,
    );
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return json!({
            "collected": false,
            "reason": "Get-BitLockerVolume unavailable or failed (BitLocker module not present, or needs elevation)",
            "encrypted": null
        });
    };
    let Some(rows) = parse_json_rows(&raw) else {
        return json!({
            "collected": false,
            "reason": "Could not parse Get-BitLockerVolume output",
            "encrypted": null
        });
    };
    let mut volumes = serde_json::Map::new();
    let mut any_on = false;
    for r in rows {
        if let Some(mp) = r.get("MountPoint").and_then(|v| v.as_str()) {
            let status = r
                .get("VolumeStatus")
                .map(|v| v.to_string())
                .unwrap_or_default();
            if status.to_lowercase().contains("fullyencrypted") {
                any_on = true;
            }
            volumes.insert(mp.to_string(), json!(status.trim_matches('"')));
        }
    }
    json!({
        "collected": true,
        "reason": "",
        "backend": "BitLocker",
        "encrypted": any_on,
        "volumes": volumes
    })
}

fn defender_status() -> Value {
    let raw = run_powershell(
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress",
        15,
    );
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return json!({
            "collected": false,
            "reason": "Get-MpComputerStatus unavailable or failed (Defender module not present, or a 3rd-party AV has taken over)",
            "enabled": null
        });
    };
    let Ok(data) = serde_json::from_str::<Value>(raw.trim()) else {
        return json!({
            "collected": false,
            "reason": "Could not parse Get-MpComputerStatus output",
            "enabled": null
        });
    };
    let rt = data
        .get("RealTimeProtectionEnabled")
        .and_then(|v| v.as_bool());
    json!({
        "collected": true,
        "reason": "",
        "antivirus_enabled": data.get("AntivirusEnabled").and_then(|v| v.as_bool()),
        "realtime_protection_enabled": rt,
        "signature_age_days": data.get("AntivirusSignatureAge"),
        "enabled": rt,
    })
}
