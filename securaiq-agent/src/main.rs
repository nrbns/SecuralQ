use clap::Parser;
use securaiq_agent::core::agent::Agent;
use securaiq_agent::core::config::AgentConfig;
use securaiq_agent::core::identity::AgentIdentity;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "securaiq-agent",
    version,
    about = "SecuraIQ cross-platform endpoint agent (Rust)"
)]
struct Cli {
    /// SecuraIQ server base URL
    #[arg(long, env = "SECURAIQ_SERVER", default_value = "http://127.0.0.1:8080")]
    server: String,

    /// Enrollment token: agent_id.agent_key (shown once at admin enroll)
    #[arg(long, env = "SECURAIQ_TOKEN")]
    token: Option<String>,

    /// Path to a file containing only the token
    #[arg(long)]
    token_file: Option<String>,

    /// Seconds between check-ins
    #[arg(long, default_value_t = 60)]
    interval: u64,

    /// Single check-in then exit (lab / CI)
    #[arg(long)]
    once: bool,

    /// Allow self-signed / invalid TLS (lab only)
    #[arg(long, env = "SECURAIQ_INSECURE")]
    insecure: bool,

    /// Accepted for install.ps1 parity with the Python Sentinel loop.
    /// Rust ships FIM/security_logs on check-in — this interval is ignored.
    #[arg(long, default_value_t = 10)]
    sentinel_interval: u64,

    /// Disable Agent Gateway long-poll
    #[arg(long)]
    no_gateway: bool,

    /// Skip WebSocket; use HTTP check-in + long-poll
    #[arg(long)]
    no_websocket: bool,

    /// Disable offline telemetry buffer
    #[arg(long)]
    no_offline_buffer: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    let token = resolve_token(&cli)?;
    let identity = AgentIdentity::from_token(&token).ok_or_else(|| {
        "Invalid token — expected agent_id.agent_key from admin enroll (POST /api/agents/enroll)"
    })?;

    let config = AgentConfig {
        server_url: cli.server,
        token: token.clone(),
        interval_secs: cli.interval,
        use_gateway: !cli.no_gateway,
        use_websocket: !cli.no_websocket,
        use_offline_buffer: !cli.no_offline_buffer,
        once: cli.once,
        insecure: cli.insecure,
        data_dir: None,
        protocol_version: 1,
    };

    if cli.sentinel_interval > 0 {
        tracing::info!(
            sentinel_interval = cli.sentinel_interval,
            "sentinel-interval accepted for installer parity; FIM/logs ship on check-in (not a separate Sentinel loop)"
        );
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        agent_id = %identity.agent_id,
        server = %config.server_url,
        once = config.once,
        "SecuraIQ agent starting"
    );

    let mut agent = Agent::new(config, identity);
    agent.run().await?;
    Ok(())
}

fn resolve_token(cli: &Cli) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = &cli.token_file {
        let t = std::fs::read_to_string(path)?;
        return Ok(t.trim().to_string());
    }
    if let Some(t) = &cli.token {
        if !t.trim().is_empty() {
            return Ok(t.trim().to_string());
        }
    }
    Err("Provide --token / SECURAIQ_TOKEN or --token-file (from admin enroll)".into())
}
