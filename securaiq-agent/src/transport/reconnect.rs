use std::time::Duration;

#[derive(Debug)]
pub struct Backoff {
    failures: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { failures: 0 }
    }
}

impl Backoff {
    pub fn reset(&mut self) {
        self.failures = 0;
    }

    pub fn failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
    }

    pub fn delay(&self) -> Duration {
        let secs = (1u64 << self.failures.min(6)).min(60);
        Duration::from_secs(secs)
    }
}
