use crate::core::config::AgentConfig;
use tokio::time::{sleep, Duration};

pub struct Scheduler {
    heartbeat_secs: u64,
}

impl Scheduler {
    pub fn from_config(config: &AgentConfig) -> Self {
        Self {
            heartbeat_secs: config.interval_secs,
        }
    }

    pub async fn tick_once(&self) {
        sleep(Duration::from_secs(self.heartbeat_secs.min(5))).await;
    }

    pub async fn tick_for(&self, d: Duration) {
        let _ = self.heartbeat_secs;
        sleep(d).await;
    }
}
