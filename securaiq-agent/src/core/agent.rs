use crate::core::config::AgentConfig;
use crate::core::health::HealthSnapshot;
use crate::core::identity::AgentIdentity;
use crate::core::scheduler::Scheduler;
use crate::inventory::collect_checkin_payload;
use crate::response::commands::handle_commands;
use crate::storage::queue::{compact_snapshot, OfflineQueue};
use crate::transport::https::HttpsClient;
use crate::transport::reconnect::Backoff;
use crate::transport::websocket::run_websocket_session;
use serde_json::Value;
use tokio::time::{sleep, Duration};

/// Long-running agent lifecycle (token auth → check-in → gateway → reconnect).
pub struct Agent {
    config: AgentConfig,
    identity: AgentIdentity,
    queue: OfflineQueue,
    scheduler: Scheduler,
    backoff: Backoff,
}

impl Agent {
    pub fn new(config: AgentConfig, identity: AgentIdentity) -> Self {
        let scheduler = Scheduler::from_config(&config);
        let queue = if config.use_offline_buffer {
            OfflineQueue::open(&identity.agent_id)
        } else {
            OfflineQueue::open_default()
        };
        Self {
            config,
            identity,
            queue,
            scheduler,
            backoff: Backoff::default(),
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.identity.save();
        let client = HttpsClient::new(
            &self.config.server_url,
            &self.identity.token,
            &self.identity.agent_key,
            env!("CARGO_PKG_VERSION"),
            self.config.insecure,
        );

        if let Err(e) = client.probe_health().await {
            tracing::warn!(error = %e, "Server /health unreachable at start");
        } else {
            tracing::info!(server = %self.config.server_url, "Server /health OK");
        }

        if self.queue.len() > 0 {
            tracing::info!(
                pending = self.queue.len(),
                path = %self.queue.path().display(),
                "offline buffer loaded"
            );
        }

        loop {
            match self.checkin_once(&client).await {
                Ok(resp) => {
                    self.backoff.reset();
                    let drained = self.queue.apply_server_ack(&resp);
                    if drained > 0 {
                        tracing::info!(drained, pending = self.queue.len(), "offline drained");
                    }
                    if let Some(cmds) = resp.get("commands").and_then(|v| v.as_array()) {
                        if !cmds.is_empty() {
                            handle_commands(&client, cmds.clone()).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "check-in failed");
                    self.backoff.failure();
                    if self.config.use_offline_buffer {
                        let snap = collect_checkin_payload();
                        let compact = compact_snapshot(&snap);
                        let seq = self.queue.enqueue("telemetry", compact);
                        tracing::warn!(seq, pending = self.queue.len(), "buffered telemetry");
                    }
                }
            }

            if self.config.once {
                break;
            }

            // Prefer WebSocket; fall back to HTTP long-poll gateway between check-ins.
            if self.config.use_websocket {
                let mut payload = collect_checkin_payload();
                if self.config.use_offline_buffer {
                    merge_obj(&mut payload, self.queue.build_checkin_extension());
                }
                let connected = run_websocket_session(&client, &payload, &mut self.queue)
                    .await
                    .unwrap_or(false);

                if connected {
                    // Session ended — loop to HTTP check-in + reconnect.
                    continue;
                }
                tracing::info!("websocket unavailable — HTTP check-in + long-poll fallback");
            }

            if self.config.use_gateway {
                let wait = self.config.interval_secs.min(25) as f64;
                match client.gateway_wait(wait, 5).await {
                    Ok(gw) => {
                        if let Some(cmds) = gw.get("commands").and_then(|v| v.as_array()) {
                            if !cmds.is_empty() {
                                handle_commands(&client, cmds.clone()).await;
                            }
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "gateway wait failed"),
                }
            } else {
                let delay = self
                    .backoff
                    .delay()
                    .max(Duration::from_secs(self.config.interval_secs));
                self.scheduler.tick_for(delay).await;
            }

            // Extra spacing if gateway returned immediately
            sleep(Duration::from_secs(2)).await;
        }

        let health = HealthSnapshot::now(&self.queue);
        tracing::info!(queue_depth = health.queue_depth, "agent exiting");
        Ok(())
    }

    async fn checkin_once(
        &mut self,
        client: &HttpsClient,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let mut payload = collect_checkin_payload();
        if self.config.use_offline_buffer {
            merge_obj(&mut payload, self.queue.build_checkin_extension());
        }
        tracing::info!(
            hostname = %payload.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
            os = %payload.get("os").and_then(|v| v.as_str()).unwrap_or(""),
            "check-in"
        );
        let resp = client.checkin(&payload).await?;
        tracing::info!(
            asset_id = %resp.get("asset_id").and_then(|v| v.as_str()).unwrap_or(""),
            "check-in ok"
        );
        Ok(resp)
    }

    pub fn config(&self) -> &AgentConfig {
        &self.config
    }
}

fn merge_obj(into: &mut Value, extra: Value) {
    if let (Some(a), Some(b)) = (into.as_object_mut(), extra.as_object()) {
        for (k, v) in b {
            a.insert(k.clone(), v.clone());
        }
    }
}
