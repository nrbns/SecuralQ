use crate::inventory::{
    GroupInfo, HardwareInfo, NetworkInfo, ProcessInfo, ServiceInfo, SoftwareItem, SystemInfo,
    SystemInventory, UserInfo,
};

pub struct MacOsInventory;

impl MacOsInventory {
    pub fn new() -> Self {
        Self
    }
}

impl SystemInventory for MacOsInventory {
    fn operating_system(&self) -> SystemInfo {
        SystemInfo {
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".into()),
            os_name: "macOS".into(),
            os_version: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.into(),
            collected: true,
            reason: None,
        }
    }

    fn hardware(&self) -> HardwareInfo {
        HardwareInfo {
            collected: false,
            reason: Some("Phase 2: IOKit / sysctl (TCC-aware)".into()),
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
            collected: false,
            reason: Some("Phase 2: macOS network APIs".into()),
            ..Default::default()
        }
    }
}
