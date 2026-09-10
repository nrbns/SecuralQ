use crate::inventory::{
    GroupInfo, HardwareInfo, NetworkInfo, ProcessInfo, ServiceInfo, SoftwareItem, SystemInfo,
    SystemInventory, UserInfo,
};

pub struct WindowsInventory;

impl WindowsInventory {
    pub fn new() -> Self {
        Self
    }
}

impl SystemInventory for WindowsInventory {
    fn operating_system(&self) -> SystemInfo {
        SystemInfo {
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".into()),
            os_name: "Windows".into(),
            os_version: std::env::var("OS")
                .unwrap_or_else(|_| format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)),
            arch: std::env::consts::ARCH.into(),
            collected: true,
            reason: None,
        }
    }

    fn hardware(&self) -> HardwareInfo {
        HardwareInfo {
            collected: false,
            reason: Some("Phase 2: WMI / WinAPI hardware".into()),
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
            reason: Some("Phase 2: WinAPI network".into()),
            ..Default::default()
        }
    }
}
