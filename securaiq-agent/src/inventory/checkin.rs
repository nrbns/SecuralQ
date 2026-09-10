use crate::platform::deep::collect_deep;
use crate::transport::protocol::AGENT_VERSION;
use serde_json::{json, Value};

/// Build a check-in JSON body matching `CheckinPayload` on the server.
pub fn collect_checkin_payload() -> Value {
    let deep = collect_deep();
    json!({
        "hostname": deep.hostname,
        "ip": deep.ip,
        "os": deep.os,
        "os_version": deep.os_version,
        "agent_version": AGENT_VERSION,
        "listening_ports": deep.listening_ports,
        "processes": deep.processes,
        "packages": deep.packages,
        "file_integrity": Value::Array(vec![]),
        "uptime_sec": Value::Null,
        "services": deep.services,
        "local_users": deep.local_users,
        "local_groups": deep.local_groups,
        "hardware": deep.hardware,
        "network": deep.network,
        "firewall_status": deep.firewall_status,
        "disk_encryption_status": deep.disk_encryption_status,
        "defender_status": deep.defender_status,
        "startup_apps": deep.startup_apps,
        "ssh_config": deep.ssh_config,
    })
}
