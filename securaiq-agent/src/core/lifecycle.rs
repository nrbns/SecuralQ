//! Process lifecycle hooks (service install is OS packaging — later).

pub fn graceful_shutdown_requested() -> bool {
    false
}
