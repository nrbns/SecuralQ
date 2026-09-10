//! Bounded recent security log samples for check-in (not a full SIEM shipper).

use serde_json::{json, Value};

pub fn collect_security_logs() -> Value {
    #[cfg(target_os = "windows")]
    {
        windows_security_log()
    }
    #[cfg(target_os = "linux")]
    {
        linux_auth_logs()
    }
    #[cfg(target_os = "macos")]
    {
        macos_logs()
    }
}

#[cfg(target_os = "windows")]
fn windows_security_log() -> Value {
    // Newest 20 Security events — fixed argv, no payload interpolation.
    let ps = "Get-WinEvent -LogName Security -MaxEvents 20 -ErrorAction SilentlyContinue | \
              Select-Object TimeCreated,Id,LevelDisplayName,ProviderName | ConvertTo-Json -Compress";
    let Some(raw) = crate::platform::cmd::run_powershell(ps, 25) else {
        return json!({
            "collected": false,
            "reason": "Get-WinEvent Security unavailable (permissions or log missing)",
            "backend": "Windows Security",
            "items": []
        });
    };
    let rows = crate::platform::cmd::parse_json_rows(&raw).unwrap_or_default();
    json!({
        "collected": true,
        "reason": "",
        "backend": "Windows Security",
        "items": rows
    })
}

#[cfg(target_os = "linux")]
fn linux_auth_logs() -> Value {
    use crate::platform::cmd::run_cmd;
    // Prefer journalctl; fall back to auth.log / secure tail.
    if let Some(out) = run_cmd(
        "journalctl",
        &["-n", "30", "-o", "short-iso", "--no-pager", "-u", "sshd", "-u", "sudo"],
        10,
    ) {
        let items: Vec<Value> = out
            .lines()
            .take(30)
            .map(|l| json!({ "line": l.chars().take(240).collect::<String>() }))
            .collect();
        return json!({
            "collected": true,
            "reason": "",
            "backend": "journalctl",
            "items": items
        });
    }
    for path in ["/var/log/auth.log", "/var/log/secure"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let items: Vec<Value> = text
                .lines()
                .rev()
                .take(30)
                .map(|l| json!({ "line": l.chars().take(240).collect::<String>() }))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            return json!({
                "collected": true,
                "reason": "",
                "backend": path,
                "items": items
            });
        }
    }
    json!({
        "collected": false,
        "reason": "journalctl and auth.log/secure unavailable",
        "backend": null,
        "items": []
    })
}

#[cfg(target_os = "macos")]
fn macos_logs() -> Value {
    use crate::platform::cmd::run_cmd;
    if let Some(out) = run_cmd(
        "log",
        &[
            "show",
            "--predicate",
            "eventMessage CONTAINS \"authentication\" OR process == \"sshd\"",
            "--last",
            "15m",
            "--style",
            "compact",
        ],
        15,
    ) {
        let items: Vec<Value> = out
            .lines()
            .take(30)
            .map(|l| json!({ "line": l.chars().take(240).collect::<String>() }))
            .collect();
        return json!({
            "collected": !items.is_empty(),
            "reason": if items.is_empty() { "No recent auth-related log lines" } else { "" },
            "backend": "log show",
            "items": items
        });
    }
    json!({
        "collected": false,
        "reason": "log show unavailable or permission denied (TCC/privacy)",
        "backend": "log show",
        "items": []
    })
}
