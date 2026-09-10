use crate::inventory::{
    InventoryCollector, NetworkInfo, SoftwareItem, SystemInfo, SystemInventory,
};
use crate::platform::native_inventory;
use crate::transport::protocol::AGENT_VERSION;
use serde_json::{json, Value};

/// Build a check-in JSON body matching `CheckinPayload` on the server.
pub fn collect_checkin_payload() -> Value {
    let inv = native_inventory();
    let snap = inv.collect_all();
    let system = &snap.system;
    let ip = primary_ip().unwrap_or_default();

    json!({
        "hostname": system.hostname,
        "ip": ip,
        "os": system.os_name,
        "os_version": system.os_version,
        "agent_version": AGENT_VERSION,
        "listening_ports": Value::Array(vec![]),
        "processes": Value::Array(vec![]),
        "packages": software_as_packages(&snap.software),
        "file_integrity": Value::Array(vec![]),
        "uptime_sec": Value::Null,
        "services": json!({ "collected": false, "reason": "Phase 2 inventory", "items": [] }),
        "local_users": json!({ "collected": false, "reason": "Phase 2 inventory", "items": [] }),
        "local_groups": json!({ "collected": false, "reason": "Phase 2 inventory", "items": [] }),
        "hardware": json!({
            "collected": snap.hardware.collected,
            "reason": snap.hardware.reason,
            "cpu": snap.hardware.cpu,
            "ram_mb": snap.hardware.ram_mb,
        }),
        "network": network_json(&snap.network),
        "firewall_status": json!({ "collected": false, "reason": "Phase 3 / v0.2", "enabled": null }),
        "disk_encryption_status": json!({ "collected": false, "reason": "Phase 3 / v0.2", "encrypted": null }),
        "defender_status": json!({ "collected": false, "reason": "Phase 3 / v0.2", "enabled": null }),
        "startup_apps": json!({ "collected": false, "reason": "Phase 2", "items": [] }),
        "ssh_config": json!({ "collected": false, "reason": "Phase 2", "settings": {} }),
    })
}

fn software_as_packages(items: &[SoftwareItem]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "version": s.version,
                })
            })
            .collect(),
    )
}

fn network_json(n: &NetworkInfo) -> Value {
    json!({
        "collected": n.collected,
        "reason": n.reason,
        "interfaces": n.interfaces,
    })
}

fn primary_ip() -> Option<String> {
    // Best-effort: UDP connect trick without sending.
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip().to_string())
}

/// Re-export for callers that want SystemInfo only.
pub fn local_system() -> SystemInfo {
    native_inventory().operating_system()
}
