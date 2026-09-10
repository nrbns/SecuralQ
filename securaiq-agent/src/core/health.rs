use crate::storage::queue::OfflineQueue;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct HealthSnapshot {
    pub observed_at: DateTime<Utc>,
    pub queue_depth: usize,
    pub ok: bool,
}

impl HealthSnapshot {
    pub fn now(queue: &OfflineQueue) -> Self {
        Self {
            observed_at: Utc::now(),
            queue_depth: queue.len(),
            ok: true,
        }
    }
}
