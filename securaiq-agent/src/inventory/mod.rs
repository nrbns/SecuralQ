pub mod checkin;
pub mod groups;
pub mod hardware;
pub mod network;
pub mod processes;
pub mod services;
pub mod software;
pub mod system;
pub mod users;

pub use checkin::collect_checkin_payload;

use serde::{Deserialize, Serialize};

/// Shared inventory interface — one product, three OS implementations.
pub trait SystemInventory {
    fn operating_system(&self) -> SystemInfo;
    fn hardware(&self) -> HardwareInfo;
    fn software(&self) -> Vec<SoftwareItem>;
    fn users(&self) -> Vec<UserInfo>;
    fn groups(&self) -> Vec<GroupInfo>;
    fn processes(&self) -> Vec<ProcessInfo>;
    fn services(&self) -> Vec<ServiceInfo>;
    fn network(&self) -> NetworkInfo;
}

pub trait InventoryCollector {
    fn collect_all(&self) -> InventorySnapshot;
}

impl<T: SystemInventory> InventoryCollector for T {
    fn collect_all(&self) -> InventorySnapshot {
        InventorySnapshot {
            system: self.operating_system(),
            hardware: self.hardware(),
            software: self.software(),
            users: self.users(),
            groups: self.groups(),
            processes: self.processes(),
            services: self.services(),
            network: self.network(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventorySnapshot {
    pub system: SystemInfo,
    pub hardware: HardwareInfo,
    pub software: Vec<SoftwareItem>,
    pub users: Vec<UserInfo>,
    pub groups: Vec<GroupInfo>,
    pub processes: Vec<ProcessInfo>,
    pub services: Vec<ServiceInfo>,
    pub network: NetworkInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub arch: String,
    pub collected: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HardwareInfo {
    pub cpu: Option<String>,
    pub ram_mb: Option<u64>,
    pub collected: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareItem {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: String,
    pub uid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub gid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkInfo {
    pub interfaces: Vec<String>,
    pub collected: bool,
    pub reason: Option<String>,
}
