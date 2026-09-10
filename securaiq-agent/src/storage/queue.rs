//! Bounded offline telemetry queue — same schema as Python / `agent_offline_buffer`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_EVENTS: usize = 5000;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const SNAPSHOT_SOFT_BYTES: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferedEvent {
    pub sequence: u64,
    pub event_type: String,
    pub payload: Value,
    pub enqueued_at: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistFile {
    agent_id: String,
    next_seq: u64,
    last_acked_seq: u64,
    events: Vec<BufferedEvent>,
    updated_at: f64,
}

#[derive(Debug)]
pub struct OfflineQueue {
    agent_id: String,
    path: PathBuf,
    next_seq: u64,
    last_acked: u64,
    events: Vec<BufferedEvent>,
}

impl OfflineQueue {
    pub fn open(agent_id: &str) -> Self {
        let path = default_path(agent_id);
        let mut q = Self {
            agent_id: agent_id.to_string(),
            path,
            next_seq: 1,
            last_acked: 0,
            events: Vec::new(),
        };
        q.load();
        q
    }

    pub fn open_default() -> Self {
        Self::open("unknown")
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&mut self) {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return;
        };
        let Ok(raw) = serde_json::from_str::<PersistFile>(&text) else {
            return;
        };
        self.next_seq = raw.next_seq.max(1);
        self.last_acked = raw.last_acked_seq;
        self.events = raw.events;
        self.trim();
    }

    fn persist(&self) {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut events = self.events.clone();
        let mut payload = PersistFile {
            agent_id: self.agent_id.clone(),
            next_seq: self.next_seq,
            last_acked_seq: self.last_acked,
            events: events.clone(),
            updated_at: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
        };
        let mut text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
        while text.len() > MAX_BYTES && events.len() > 1 {
            events.remove(0);
            payload.events = events.clone();
            text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
        }
        let tmp = self.path.with_extension("json.tmp");
        if fs::write(&tmp, &text).is_ok() {
            let _ = fs::rename(&tmp, &self.path);
        }
    }

    fn trim(&mut self) {
        if self.events.len() > MAX_EVENTS {
            let overflow = self.events.len() - MAX_EVENTS;
            self.events.drain(0..overflow);
        }
    }

    pub fn enqueue(&mut self, event_type: &str, payload: Value) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.events.push(BufferedEvent {
            sequence: seq,
            event_type: event_type.to_string(),
            payload,
            enqueued_at: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
        });
        self.trim();
        self.persist();
        seq
    }

    pub fn ack(&mut self, sequences: &[u64]) -> usize {
        if sequences.is_empty() {
            return 0;
        }
        let set: std::collections::HashSet<u64> = sequences.iter().copied().collect();
        let before = self.events.len();
        self.events
            .retain(|e| !set.contains(&e.sequence));
        let removed = before - self.events.len();
        if let Some(high) = sequences.iter().max() {
            if *high > self.last_acked {
                self.last_acked = *high;
            }
        }
        self.persist();
        removed
    }

    pub fn ack_through(&mut self, sequence: u64) -> usize {
        let before = self.events.len();
        self.events.retain(|e| e.sequence > sequence);
        let removed = before - self.events.len();
        if sequence > self.last_acked {
            self.last_acked = sequence;
        }
        self.persist();
        removed
    }

    pub fn build_checkin_extension(&self) -> Value {
        let batch: Vec<Value> = self
            .events
            .iter()
            .take(100)
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect();
        let sequence = if self.next_seq > 1 {
            self.next_seq - 1
        } else {
            0
        };
        json!({
            "sequence": sequence,
            "buffered_events": batch,
            "request_missing_from": self.last_acked + 1,
        })
    }

    pub fn apply_server_ack(&mut self, response: &Value) -> usize {
        let mut removed = 0;
        if let Some(acked) = response
            .get("acked_sequences")
            .or_else(|| response.get("ack_sequences"))
            .and_then(|v| v.as_array())
        {
            let seqs: Vec<u64> = acked.iter().filter_map(|v| v.as_u64()).collect();
            removed += self.ack(&seqs);
        }
        if let Some(through) = response.get("last_acked_seq").and_then(|v| v.as_u64()) {
            removed += self.ack_through(through);
        }
        removed
    }
}

pub fn compact_snapshot(snapshot: &Value) -> Value {
    let raw = serde_json::to_vec(snapshot).unwrap_or_default();
    if raw.len() <= SNAPSHOT_SOFT_BYTES {
        return snapshot.clone();
    }
    let mut compact = json!({
        "hostname": snapshot.get("hostname"),
        "os": snapshot.get("os"),
        "os_version": snapshot.get("os_version"),
        "ip": snapshot.get("ip"),
        "agent_version": snapshot.get("agent_version"),
        "timestamp": chrono::Utc::now().timestamp(),
        "truncated": true,
    });
    for key in ["firewall_status", "defender_status", "ssh_config", "packages"] {
        if let Some(v) = snapshot.get(key) {
            compact[key] = v.clone();
        }
    }
    compact
}

fn default_path(agent_id: &str) -> PathBuf {
    let root = std::env::var("SECURAIQ_AGENT_DATA_DIR")
        .or_else(|_| std::env::var("SECURAIQ_DATA_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".securaiq")
                .join("agent")
        });
    let suffix = if agent_id.is_empty() || agent_id == "unknown" {
        String::new()
    } else {
        format!("_{}", &agent_id[..agent_id.len().min(12)])
    };
    root.join(format!("offline_telemetry{suffix}.json"))
}
