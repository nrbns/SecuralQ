use crate::crypto::signatures::replay_headers;
use reqwest::Client;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server error {status}: {body}")]
    Status { status: u16, body: String },
    #[error("{0}")]
    Msg(String),
}

pub struct HttpsClient {
    base: String,
    client: Client,
    token: String,
    agent_key: String,
    agent_version: String,
}

impl HttpsClient {
    pub fn new(
        server_url: &str,
        token: &str,
        agent_key: &str,
        agent_version: &str,
        insecure: bool,
    ) -> Self {
        let mut builder = Client::builder().timeout(std::time::Duration::from_secs(45));
        if insecure {
            // Lab / self-signed only — never default in production packaging docs.
            builder = builder.danger_accept_invalid_certs(true);
        }
        Self {
            base: server_url.trim_end_matches('/').to_string(),
            client: builder.build().expect("reqwest client"),
            token: token.to_string(),
            agent_key: agent_key.to_string(),
            agent_version: agent_version.to_string(),
        }
    }

    async fn post_json(&self, path: &str, body: &Value) -> Result<Value, TransportError> {
        let url = format!("{}{}", self.base, path);
        let bytes = serde_json::to_vec(body).map_err(|e| TransportError::Msg(e.to_string()))?;
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.token))
            .header(
                "User-Agent",
                format!("SecuraIQ-Agent/{}", self.agent_version),
            )
            .body(bytes.clone());
        for (k, v) in replay_headers(&self.agent_key, &bytes) {
            req = req.header(k, v);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(TransportError::Status {
                status,
                body: text.chars().take(500).collect(),
            });
        }
        if text.trim().is_empty() {
            return Ok(Value::Object(Default::default()));
        }
        serde_json::from_str(&text).map_err(|e| TransportError::Msg(e.to_string()))
    }

    pub async fn probe_health(&self) -> Result<(), TransportError> {
        let url = format!("{}/api/health", self.base);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(TransportError::Status {
                status: resp.status().as_u16(),
                body: "unhealthy".into(),
            });
        }
        Ok(())
    }

    pub async fn checkin(&self, payload: &Value) -> Result<Value, TransportError> {
        self.post_json("/api/agents/checkin", payload).await
    }

    pub async fn gateway_wait(
        &self,
        timeout_sec: f64,
        limit: u32,
    ) -> Result<Value, TransportError> {
        let body = serde_json::json!({ "timeout_sec": timeout_sec, "limit": limit });
        self.post_json("/api/agents/gateway/wait", &body).await
    }

    pub async fn ack_command(&self, command_id: &str) -> Result<Value, TransportError> {
        self.post_json(
            &format!("/api/agents/commands/{command_id}/ack"),
            &serde_json::json!({}),
        )
        .await
    }

    pub async fn command_result(
        &self,
        command_id: &str,
        status: &str,
        result: &Value,
    ) -> Result<Value, TransportError> {
        self.post_json(
            &format!("/api/agents/commands/{command_id}/result"),
            &serde_json::json!({ "status": status, "result": result }),
        )
        .await
    }

    pub fn ws_url(&self) -> String {
        let base = &self.base;
        if let Some(rest) = base.strip_prefix("https://") {
            format!("wss://{rest}/api/agents/ws")
        } else if let Some(rest) = base.strip_prefix("http://") {
            format!("ws://{rest}/api/agents/ws")
        } else {
            format!("ws://{base}/api/agents/ws")
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn agent_key(&self) -> &str {
        &self.agent_key
    }
}
