use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use axum::{
    extract::{ws::WebSocketUpgrade, State},
    response::IntoResponse,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    sync::mpsc,
    time::{interval, Instant, MissedTickBehavior},
};
use tracing::warn;
use ws_net_common::{decode_data_frame_owned, decode_message, encode_message, Message, Mode};

use crate::{
    app::AppState,
    http_proxy::{format_error_chain, handle_http_request},
    tcp::{handle_tcp_stream, TcpStreams},
};

const ACCESS_PING_INTERVAL: Duration = Duration::from_secs(20);
const ACCESS_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(75);

pub(crate) type Outbound = mpsc::Sender<axum::extract::ws::Message>;

pub(crate) async fn ws_entry(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: axum::extract::ws::WebSocket, state: AppState) {
    if let Err(err) = handle_socket_result(socket, state).await {
        warn!(error = %err, "websocket session ended");
    }
}

async fn handle_socket_result(socket: axum::extract::ws::WebSocket, state: AppState) -> Result<()> {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    let Some(Ok(axum::extract::ws::Message::Text(first))) = ws_receiver.next().await else {
        return Err(anyhow!("expected register message"));
    };

    match decode_message(&first)? {
        Message::RegisterAccess { token } if token == state.config.auth.access_token => {}
        Message::RegisterAccess { .. } => {
            ws_sender
                .send(axum::extract::ws::Message::Text(encode_message(
                    &Message::Error {
                        stream_id: None,
                        code: "UNAUTHORIZED".to_string(),
                        message: "invalid access token".to_string(),
                    },
                )?))
                .await?;
            return Ok(());
        }
        _ => return Err(anyhow!("first message must be RegisterAccess")),
    }

    let (outbound, mut outbound_rx) = mpsc::channel::<axum::extract::ws::Message>(1024);
    outbound
        .send(axum::extract::ws::Message::Text(encode_message(
            &Message::RegisterOk,
        )?))
        .await?;

    let writer = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            if ws_sender.send(message).await.is_err() {
                break;
            }
        }
    });

    let streams: TcpStreams = Arc::new(DashMap::new());
    let mut heartbeat = interval(ACCESS_PING_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_received = Instant::now();

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if last_received.elapsed() > ACCESS_READ_IDLE_TIMEOUT {
                    return Err(anyhow!("access websocket read idle timeout"));
                }

                outbound
                    .send(axum::extract::ws::Message::Ping(Vec::new()))
                    .await?;
            }
            frame = ws_receiver.next() => {
                let Some(frame) = frame else {
                    break;
                };

                last_received = Instant::now();
                match frame? {
                    axum::extract::ws::Message::Text(text) => {
                        handle_text_message(&state, &outbound, &streams, &text).await?;
                    }
                    axum::extract::ws::Message::Binary(bytes) => {
                        if let Some((stream_id, payload)) = decode_data_frame_owned(bytes) {
                            if let Some(tx) =
                                streams.get(&stream_id).map(|entry| entry.value().clone())
                            {
                                if tx.try_send(payload).is_err() {
                                    streams.remove(&stream_id);
                                    let _ = send_text(
                                        &outbound,
                                        &Message::Close {
                                            stream_id,
                                            reason: "target_backpressure".to_string(),
                                        },
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    axum::extract::ws::Message::Ping(payload) => {
                        outbound
                            .send(axum::extract::ws::Message::Pong(payload))
                            .await?;
                    }
                    axum::extract::ws::Message::Pong(_) => {}
                    axum::extract::ws::Message::Close(_) => break,
                }
            }
            else => break,
        }
    }

    writer.abort();
    Ok(())
}

async fn handle_text_message(
    state: &AppState,
    outbound: &Outbound,
    streams: &TcpStreams,
    text: &str,
) -> Result<()> {
    match decode_message(text)? {
        Message::Open {
            stream_id,
            target,
            config,
        } => {
            if config.mode != Mode::Tcp {
                send_error(
                    outbound,
                    Some(stream_id),
                    "MODE_NOT_SUPPORTED",
                    "target is not tcp",
                )
                .await?;
                return Ok(());
            }
            tokio::spawn(handle_tcp_stream(
                stream_id,
                target,
                config,
                outbound.clone(),
                streams.clone(),
            ));
        }
        Message::HttpRequest {
            stream_id,
            target: _,
            config,
            request,
        } => {
            if config.mode != Mode::Http {
                send_error(
                    outbound,
                    Some(stream_id),
                    "MODE_NOT_SUPPORTED",
                    "target is not http",
                )
                .await?;
                return Ok(());
            }
            let state = state.clone();
            let outbound = outbound.clone();
            tokio::spawn(async move {
                match handle_http_request(&state, &config, &request).await {
                    Ok(response) => {
                        let _ = send_text(
                            &outbound,
                            &Message::HttpResponse {
                                stream_id,
                                response,
                            },
                        )
                        .await;
                    }
                    Err(err) => {
                        let _ = send_error(
                            &outbound,
                            Some(stream_id),
                            "HTTP_TARGET_ERROR",
                            &format_error_chain(&err),
                        )
                        .await;
                    }
                }
            });
        }
        Message::Close { stream_id, .. } => {
            streams.remove(&stream_id);
        }
        Message::Ping => {
            send_text(outbound, &Message::Pong).await?;
        }
        other => warn!(?other, "unexpected gateway message"),
    }
    Ok(())
}

pub(crate) async fn send_text(outbound: &Outbound, message: &Message) -> Result<()> {
    outbound
        .send(axum::extract::ws::Message::Text(encode_message(message)?))
        .await?;
    Ok(())
}

pub(crate) async fn send_error(
    outbound: &Outbound,
    stream_id: Option<u64>,
    code: &str,
    message: &str,
) -> Result<()> {
    send_text(
        outbound,
        &Message::Error {
            stream_id,
            code: code.to_string(),
            message: message.to_string(),
        },
    )
    .await
}
