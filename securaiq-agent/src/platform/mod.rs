#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use crate::inventory::SystemInventory;

/// Construct the OS-native inventory adapter for this build target.
pub fn native_inventory() -> impl SystemInventory {
    #[cfg(target_os = "windows")]
    {
        windows::WindowsInventory::new()
    }
    #[cfg(target_os = "linux")]
    {
        linux::LinuxInventory::new()
    }
    #[cfg(target_os = "macos")]
    {
        macos::MacOsInventory::new()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        compile_error!("SecuraIQ agent supports Windows, Linux, and macOS only");
    }
}
