use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub server_url: String,
    pub token: String,
    pub interval_secs: u64,
    pub use_gateway: bool,
    pub use_websocket: bool,
    pub use_offline_buffer: bool,
    pub once: bool,
    pub insecure: bool,
    pub data_dir: Option<PathBuf>,
    pub protocol_version: u32,
}

impl AgentConfig {
    pub fn from_env_or_default() -> Self {
        Self {
            server_url: env::var("SECURAIQ_SERVER")
                .or_else(|_| env::var("SECURAIQ_SERVER_URL"))
                .unwrap_or_else(|_| "http://127.0.0.1:8080".into()),
            token: env::var("SECURAIQ_TOKEN").unwrap_or_default(),
            interval_secs: env::var("SECURAIQ_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
            use_gateway: true,
            use_websocket: true,
            use_offline_buffer: true,
            once: false,
            insecure: false,
            data_dir: env::var("SECURAIQ_AGENT_DATA_DIR").ok().map(PathBuf::from),
            protocol_version: 1,
        }
    }
}
