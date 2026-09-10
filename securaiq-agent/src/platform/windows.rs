use crate::inventory::{
    GroupInfo, HardwareInfo, NetworkInfo, ProcessInfo, ServiceInfo, SoftwareItem, SystemInfo,
    SystemInventory, UserInfo,
};
use crate::platform::deep::{hostname_string, primary_ip};

/// Trait adapter — rich check-in uses `platform::deep::collect_deep()`.
pub struct WindowsInventory;

impl WindowsInventory {
    pub fn new() -> Self {
        Self
    }
}

impl SystemInventory for WindowsInventory {
    fn operating_system(&self) -> SystemInfo {
        let _ = primary_ip();
        SystemInfo {
            hostname: hostname_string(),
            os_name: "Windows".into(),
            os_version: std::env::var("OS").unwrap_or_else(|_| "Windows".into()),
            arch: std::env::consts::ARCH.into(),
            collected: true,
            reason: None,
        }
    }

    fn hardware(&self) -> HardwareInfo {
        HardwareInfo {
            collected: true,
            reason: Some("Use deep::collect_deep for full hardware slice".into()),
            ..Default::default()
        }
    }

    fn software(&self) -> Vec<SoftwareItem> {
        vec![]
    }

    fn users(&self) -> Vec<UserInfo> {
        vec![]
    }

    fn groups(&self) -> Vec<GroupInfo> {
        vec![]
    }

    fn processes(&self) -> Vec<ProcessInfo> {
        vec![]
    }

    fn services(&self) -> Vec<ServiceInfo> {
        vec![]
    }

    fn network(&self) -> NetworkInfo {
        NetworkInfo {
            collected: true,
            reason: Some("Use deep::collect_deep for interfaces".into()),
            ..Default::default()
        }
    }
}
