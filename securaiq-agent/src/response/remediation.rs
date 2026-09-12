//! Allowlisted host remediations — fixed argv only, never free-form shell.

use serde_json::{json, Value};

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

pub fn execute_enable_firewall() -> Value {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::cmd::run_powershell;
        let ps = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; \
                  Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress";
        match run_powershell(ps, 30) {
            Some(out) => json!({
                "ok": true,
                "backend": "Windows Firewall",
                "note": "Enabled Domain,Public,Private profiles",
                "output": clip(&out, 2000),
            }),
            None => json!({
                "ok": false,
                "error": "Set-NetFirewallProfile failed or unavailable (elevation may be required)",
                "backend": "Windows Firewall",
            }),
        }
    }
    #[cfg(target_os = "linux")]
    {
        use crate::platform::cmd::run_cmd;
        if let Some(out) = run_cmd("ufw", &["--force", "enable"], 30) {
            return json!({
                "ok": true,
                "backend": "ufw",
                "note": "ufw --force enable succeeded",
                "output": clip(&out, 2000),
            });
        }
        if let Some(state) = run_cmd("firewall-cmd", &["--state"], 8) {
            return json!({
                "ok": false,
                "error": format!(
                    "ufw enable failed; firewalld is present (state={:?}) but auto-enable via firewall-cmd is not performed — enable manually or install ufw",
                    state.trim()
                ),
                "backend": "firewalld",
                "firewall_state": state.trim(),
            });
        }
        json!({
            "ok": false,
            "error": "Could not enable firewall: ufw enable failed and firewall-cmd unavailable",
            "backend": null,
        })
    }
    #[cfg(target_os = "macos")]
    {
        json!({
            "ok": false,
            "error": "enable_firewall is not automated on macOS — enable Application Firewall manually",
            "backend": "pf/ALF",
        })
    }
}

pub fn execute_enable_defender() -> Value {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::cmd::run_powershell;
        let ps = "Set-MpPreference -DisableRealtimeMonitoring $false; \
                  Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress";
        match run_powershell(ps, 30) {
            Some(out) => json!({
                "ok": true,
                "backend": "Microsoft Defender",
                "note": "Set-MpPreference -DisableRealtimeMonitoring $false applied",
                "output": clip(&out, 2000),
            }),
            None => json!({
                "ok": false,
                "error": "Set-MpPreference failed or unavailable (Defender module / elevation / third-party AV)",
                "backend": "Microsoft Defender",
            }),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        json!({
            "ok": false,
            "error": format!(
                "enable_defender is not supported on {} — Microsoft Defender realtime preference is Windows-only",
                std::env::consts::OS
            ),
            "backend": null,
        })
    }
}

pub fn execute_disable_ssh_root() -> Value {
    #[cfg(target_os = "windows")]
    {
        json!({
            "ok": false,
            "error": "disable_ssh_root is not automated on Windows — configure OpenSSH PermitRootLogin manually if used",
            "backend": null,
        })
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::fs;
        use std::path::Path;
        use crate::platform::cmd::run_cmd;

        let candidates: &[&str] = if cfg!(target_os = "macos") {
            &["/etc/ssh/sshd_config", "/private/etc/ssh/sshd_config"]
        } else {
            &["/etc/ssh/sshd_config"]
        };
        let path = candidates
            .iter()
            .find(|p| Path::new(p).is_file())
            .copied()
            .unwrap_or(candidates[0]);
        let raw = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                return json!({
                    "ok": false,
                    "error": format!("Cannot read {path}: {e} (root/elevation may be required)"),
                    "backend": "sshd_config",
                    "path": path,
                });
            }
        };
        let mut found = false;
        let mut out_lines: Vec<String> = Vec::new();
        for line in raw.lines() {
            let stripped = line.trim_start();
            if stripped.starts_with('#')
                || !stripped.to_ascii_lowercase().starts_with("permitrootlogin")
            {
                out_lines.push(line.to_string());
                continue;
            }
            out_lines.push("PermitRootLogin no".to_string());
            found = true;
        }
        if !found {
            out_lines.push("PermitRootLogin no".to_string());
        }
        let body = out_lines.join("\n") + "\n";
        if let Err(e) = fs::write(path, body) {
            return json!({
                "ok": false,
                "error": format!("Cannot write {path}: {e} (root/elevation may be required)"),
                "backend": "sshd_config",
                "path": path,
            });
        }
        let mut reload_note = "config written; sshd reload not confirmed".to_string();
        let reloads: &[(&str, &[&str])] = &[
            ("systemctl", &["reload", "sshd"]),
            ("systemctl", &["reload", "ssh"]),
            ("service", &["sshd", "reload"]),
            ("service", &["ssh", "reload"]),
        ];
        for (bin, args) in reloads {
            if let Some(out) = run_cmd(bin, args, 15) {
                reload_note = format!("{bin} {} succeeded ({})", args.join(" "), clip(&out, 120));
                break;
            }
        }
        json!({
            "ok": true,
            "backend": "sshd_config",
            "path": path,
            "note": format!("PermitRootLogin no applied; {reload_note}"),
            "output": clip(&reload_note, 2000),
        })
    }
}

pub fn execute_kind(kind: &str) -> Value {
    match kind {
        "enable_firewall" => execute_enable_firewall(),
        "enable_defender" => execute_enable_defender(),
        "disable_ssh_root" => execute_disable_ssh_root(),
        other => json!({
            "ok": false,
            "error": format!("Unsupported or not-yet-implemented allowlisted kind '{other}' in Rust agent"),
            "kind": other,
        }),
    }
}
