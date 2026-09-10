//! Shared subprocess helper for inventory / host-status collectors.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

pub fn run_cmd(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    match child.wait_timeout(Duration::from_secs(timeout_secs)).ok()? {
        Some(status) if status.success() => {
            let mut out = String::new();
            let _ = stdout.read_to_string(&mut out);
            Some(out)
        }
        Some(_) => None,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

pub fn run_powershell(script: &str, timeout_secs: u64) -> Option<String> {
    run_cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
        timeout_secs,
    )
}

pub fn parse_json_rows(raw: &str) -> Option<Vec<serde_json::Value>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    Some(match v {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    })
}
