//! WebSocket Agent Gateway client — hello / checkin / heartbeat / commands.

use crate::crypto::signatures::{new_nonce_hex, unix_ts};
use crate::response::commands::handle_commands;
use crate::storage::queue::OfflineQueue;
use crate::transport::https::HttpsClient;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::time::{timeout, Duration};
use tokio_tungstenite::{connect_async, tungstenite::http::Request, tungstenite::Message};

/// Run one WebSocket session. Returns Ok(true) if connected and ran; Ok(false) if handshake failed.
pub async fn run_websocket_session(
    client: &HttpsClient,
    checkin_payload: &Value,
    queue: &mut OfflineQueue,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let url = client.ws_url();
    let req = Request::builder()
        .uri(&url)
        .header("Authorization", format!("Bearer {}", client.token()))
        .header(
            "User-Agent",
            format!("SecuraIQ-Agent/{}", env!("CARGO_PKG_VERSION")),
        )
        .header("Host", host_from_url(&url)?)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .body(())?;

    let (ws, _) = match connect_async(req).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(error = %e, "websocket connect failed");
            return Ok(false);
        }
    };
    let (mut write, mut read) = ws.split();

    let hello = json!({
        "type": "hello",
        "token": client.token(),
        "ts": unix_ts(),
        "nonce": new_nonce_hex(8),
    });
    write.send(Message::Text(hello.to_string())).await?;

    let welcome = match timeout(Duration::from_secs(15), read.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str::<Value>(&t)?,
        _ => {
            tracing::warn!("websocket welcome missing");
            return Ok(false);
        }
    };
    if welcome.get("type").and_then(|v| v.as_str()) != Some("welcome") {
        tracing::warn!(?welcome, "websocket hello rejected");
        return Ok(false);
    }
    let hb = welcome
        .get("heartbeat_sec")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    tracing::info!(heartbeat_sec = hb, "websocket connected");

    write
        .send(Message::Text(
            json!({ "type": "checkin", "payload": checkin_payload }).to_string(),
        ))
        .await?;

    let mut last_hb = std::time::Instant::now();
    loop {
        let wait = Duration::from_secs(hb.max(5)).saturating_sub(last_hb.elapsed());
        let wait = if wait.is_zero() {
            Duration::from_secs(1)
        } else {
            wait
        };
        match timeout(wait, read.next()).await {
            Err(_) => {
                write
                    .send(Message::Text(
                        json!({ "type": "heartbeat", "ts": chrono::Utc::now().timestamp() })
                            .to_string(),
                    ))
                    .await?;
                last_hb = std::time::Instant::now();
            }
            Ok(None) => break,
            Ok(Some(Err(e))) => {
                tracing::warn!(error = %e, "websocket read error");
                break;
            }
            Ok(Some(Ok(Message::Text(t)))) => {
                let msg: Value = serde_json::from_str(&t).unwrap_or(json!({}));
                match msg.get("type").and_then(|v| v.as_str()) {
                    Some("commands") => {
                        let cmds = msg
                            .get("commands")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        for c in &cmds {
                            if let Some(cid) = c.get("id").and_then(|v| v.as_str()) {
                                let _ = write
                                    .send(Message::Text(
                                        json!({ "type": "ack", "command_id": cid }).to_string(),
                                    ))
                                    .await;
                            }
                        }
                        if !cmds.is_empty() {
                            handle_commands(client, cmds).await;
                        }
                    }
                    Some("pong") => {
                        last_hb = std::time::Instant::now();
                    }
                    Some("checkin_ok") => {
                        let drained = queue.apply_server_ack(&msg);
                        if drained > 0 {
                            tracing::info!(drained, pending = queue.len(), "offline buffer drained");
                        }
                        tracing::info!(
                            asset_id = %msg.get("asset_id").and_then(|v| v.as_str()).unwrap_or(""),
                            "ws check-in ok"
                        );
                    }
                    Some("ping") => {
                        write
                            .send(Message::Text(json!({ "type": "pong" }).to_string()))
                            .await?;
                    }
                    _ => {}
                }
            }
            Ok(Some(Ok(Message::Ping(p)))) => {
                write.send(Message::Pong(p)).await?;
            }
            Ok(Some(Ok(Message::Close(_)))) => break,
            Ok(Some(Ok(_))) => {}
        }
    }
    Ok(true)
}

fn host_from_url(url: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let u = url::Url::parse(url)?;
    let host = u.host_str().ok_or("missing host")?;
    Ok(match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}
