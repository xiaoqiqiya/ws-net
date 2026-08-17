use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use axum::{
    extract::{ws::WebSocketUpgrade, State},
    response::IntoResponse,
};
use dashmap::DashMap;
use futures_util::{future::FutureExt, SinkExt, StreamExt};
use tokio::{
    sync::mpsc,
    time::{interval, Instant, MissedTickBehavior},
};
use tracing::warn;
use ws_net_common::{
    decode_data_frame_owned, decode_message, encode_data_frame, encode_message,
    try_merge_data_frames, HttpRequestHead, HttpResponsePayload, Message, Mode,
    DATA_FRAME_HEADER_LEN,
};

use crate::{
    app::AppState,
    http_proxy::{format_error_chain, handle_http_request},
    tcp::{handle_tcp_stream, TcpStreams},
};

const ACCESS_PING_INTERVAL: Duration = Duration::from_secs(20);
const ACCESS_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
const WS_WRITE_BATCH_MAX_MESSAGES: usize = 64;
const WS_WRITE_BATCH_MAX_BYTES: usize = 256 * 1024;
const WS_DATA_FRAME_MAX_PAYLOAD: usize = 64 * 1024;
const WS_SLOW_FLUSH: Duration = Duration::from_millis(50);

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
        let mut pending = None;

        loop {
            let first = match pending.take() {
                Some(message) => message,
                None => {
                    let Some(message) = outbound_rx.recv().await else {
                        break;
                    };
                    message
                }
            };
            let first_is_binary = matches!(&first, axum::extract::ws::Message::Binary(_));
            let mut batch = Vec::with_capacity(WS_WRITE_BATCH_MAX_MESSAGES);
            let mut batch_bytes = ws_message_size(&first);
            batch.push(first);

            if first_is_binary {
                tokio::task::yield_now().await;
                while batch.len() < WS_WRITE_BATCH_MAX_MESSAGES {
                    let next = match outbound_rx.try_recv() {
                        Ok(message) => message,
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    };
                    match push_ws_message(&mut batch, &mut batch_bytes, next) {
                        Ok(stop_batch) => {
                            if stop_batch {
                                break;
                            }
                        }
                        Err(deferred) => {
                            pending = Some(deferred);
                            break;
                        }
                    }
                }
            }

            let message_count = batch.len();
            let flush_started = Instant::now();
            let mut write_failed = false;
            for message in batch {
                if ws_sender.feed(message).await.is_err() {
                    write_failed = true;
                    break;
                }
            }
            if write_failed || ws_sender.flush().await.is_err() {
                break;
            }

            let flush_elapsed = flush_started.elapsed();
            if flush_elapsed >= WS_SLOW_FLUSH {
                warn!(
                    message_count,
                    batch_bytes,
                    flush_ms = flush_elapsed.as_millis(),
                    "slow gateway websocket batch flush"
                );
            }
        }
    });

    let streams: TcpStreams = Arc::new(DashMap::new());
    let http_bodies: Arc<DashMap<u64, mpsc::Sender<Result<bytes::Bytes, std::io::Error>>>> =
        Arc::new(DashMap::new());
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
                        handle_text_message(&state, &outbound, &streams, &http_bodies, &text).await?;
                    }
                    axum::extract::ws::Message::Binary(bytes) => {
                        let frame_len = bytes.len();
                        if let Some((stream_id, payload)) = decode_data_frame_owned(bytes) {
                            if let Some(tx) = http_bodies.get(&stream_id).map(|entry| entry.value().clone()) {
                                if tx.send(Ok(bytes::Bytes::from(payload.into_vec()))).await.is_err() {
                                    http_bodies.remove(&stream_id);
                                    let _ = send_error(&outbound, Some(stream_id), "HTTP_BODY_BACKPRESSURE", "request body channel is full").await;
                                }
                                continue;
                            }

                            if let Some(tx) =
                                streams.get(&stream_id).map(|entry| entry.value().clone())
                            {
                                if tx.send(payload).await.is_err() {
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
                            } else {
                                warn!(stream_id, "received binary frame for unknown stream");
                            }
                        } else {
                            warn!(len = frame_len, "received invalid binary frame from access");
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

fn try_merge_ws_binary(
    current: &mut axum::extract::ws::Message,
    next: &axum::extract::ws::Message,
) -> bool {
    match (current, next) {
        (axum::extract::ws::Message::Binary(current), axum::extract::ws::Message::Binary(next)) => {
            try_merge_data_frames(current, next, WS_DATA_FRAME_MAX_PAYLOAD)
        }
        _ => false,
    }
}

fn ws_message_size(message: &axum::extract::ws::Message) -> usize {
    match message {
        axum::extract::ws::Message::Text(text) => text.len(),
        axum::extract::ws::Message::Binary(bytes)
        | axum::extract::ws::Message::Ping(bytes)
        | axum::extract::ws::Message::Pong(bytes) => bytes.len(),
        axum::extract::ws::Message::Close(_) => 0,
    }
}

fn push_ws_message(
    batch: &mut Vec<axum::extract::ws::Message>,
    batch_bytes: &mut usize,
    next: axum::extract::ws::Message,
) -> std::result::Result<bool, axum::extract::ws::Message> {
    let next_bytes = ws_message_size(&next);
    if batch
        .last_mut()
        .is_some_and(|current| try_merge_ws_binary(current, &next))
    {
        *batch_bytes += next_bytes.saturating_sub(DATA_FRAME_HEADER_LEN);
        return Ok(false);
    }

    if batch_bytes.saturating_add(next_bytes) > WS_WRITE_BATCH_MAX_BYTES {
        return Err(next);
    }

    let stop_batch = !matches!(&next, axum::extract::ws::Message::Binary(_));
    *batch_bytes += next_bytes;
    batch.push(next);
    Ok(stop_batch)
}

async fn handle_text_message(
    state: &AppState,
    outbound: &Outbound,
    streams: &TcpStreams,
    http_bodies: &Arc<DashMap<u64, mpsc::Sender<Result<bytes::Bytes, std::io::Error>>>>,
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
                let request_head = HttpRequestHead {
                    method: request.method,
                    path_and_query: request.path_and_query,
                    headers: request.headers,
                };
                let (body_tx, body_rx) = mpsc::channel(1);
                let _ = body_tx.send(Ok(bytes::Bytes::from(request.body))).await;
                drop(body_tx);

                let response_head = Arc::new(tokio::sync::Mutex::new(None));
                let response_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
                let result = handle_http_request(
                    &state,
                    &config,
                    request_head,
                    body_rx,
                    {
                        let response_head = response_head.clone();
                        move |response| {
                            let response_head = response_head.clone();
                            async move {
                                *response_head.lock().await = Some(response);
                                Ok(())
                            }
                            .boxed()
                        }
                    },
                    {
                        let response_body = response_body.clone();
                        move |chunk| {
                            let response_body = response_body.clone();
                            async move {
                                response_body.lock().await.extend_from_slice(&chunk);
                                Ok(())
                            }
                            .boxed()
                        }
                    },
                )
                .await;

                match result {
                    Ok(()) => {
                        let Some(head) = response_head.lock().await.take() else {
                            let _ = send_error(
                                &outbound,
                                Some(stream_id),
                                "HTTP_TARGET_ERROR",
                                "target response head missing",
                            )
                            .await;
                            return;
                        };
                        let response = HttpResponsePayload {
                            status: head.status,
                            headers: head.headers,
                            body: response_body.lock().await.clone(),
                        };
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
        Message::HttpRequestStart {
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

            let (body_tx, body_rx) = mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(64);
            http_bodies.insert(stream_id, body_tx);
            let state = state.clone();
            let outbound = outbound.clone();
            let http_bodies = http_bodies.clone();
            tokio::spawn(async move {
                let result = handle_http_request(
                    &state,
                    &config,
                    request,
                    body_rx,
                    {
                        let outbound = outbound.clone();
                        move |response| {
                            let outbound = outbound.clone();
                            async move {
                                send_text(
                                    &outbound,
                                    &Message::HttpResponseStart {
                                        stream_id,
                                        response,
                                    },
                                )
                                .await
                            }
                            .boxed()
                        }
                    },
                    {
                        let outbound = outbound.clone();
                        move |chunk| {
                            let outbound = outbound.clone();
                            async move {
                                outbound
                                    .send(axum::extract::ws::Message::Binary(encode_data_frame(
                                        stream_id, &chunk,
                                    )))
                                    .await?;
                                Ok(())
                            }
                            .boxed()
                        }
                    },
                )
                .await;
                http_bodies.remove(&stream_id);
                match result {
                    Ok(()) => {
                        let _ = send_text(&outbound, &Message::HttpResponseEnd { stream_id }).await;
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
        Message::HttpRequestEnd { stream_id } => {
            http_bodies.remove(&stream_id);
        }
        Message::Close { stream_id, .. } => {
            streams.remove(&stream_id);
            http_bodies.remove(&stream_id);
        }
        Message::TcpEof { stream_id } => {
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

#[cfg(test)]
mod tests {
    use axum::extract::ws::Message as WsMessage;
    use ws_net_common::{decode_data_frame, encode_data_frame};

    use super::{push_ws_message, ws_message_size, WS_WRITE_BATCH_MAX_BYTES};

    #[test]
    fn writer_batch_merges_same_stream_and_preserves_payload_order() {
        let first = WsMessage::Binary(encode_data_frame(11, b"abc"));
        let mut bytes = ws_message_size(&first);
        let mut batch = vec![first];

        assert_eq!(
            push_ws_message(
                &mut batch,
                &mut bytes,
                WsMessage::Binary(encode_data_frame(11, b"def")),
            ),
            Ok(false)
        );
        assert_eq!(batch.len(), 1);
        let WsMessage::Binary(frame) = &batch[0] else {
            panic!("expected binary frame");
        };
        assert_eq!(decode_data_frame(frame), Some((11, b"abcdef".to_vec())));
    }

    #[test]
    fn writer_batch_keeps_different_streams_separate_and_ordered() {
        let first = WsMessage::Binary(encode_data_frame(11, b"first"));
        let mut bytes = ws_message_size(&first);
        let mut batch = vec![first];

        assert_eq!(
            push_ws_message(
                &mut batch,
                &mut bytes,
                WsMessage::Binary(encode_data_frame(12, b"second")),
            ),
            Ok(false)
        );
        assert_eq!(batch.len(), 2);
        let ids = batch
            .iter()
            .map(|message| match message {
                WsMessage::Binary(frame) => decode_data_frame(frame).unwrap().0,
                _ => panic!("expected binary frame"),
            })
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![11, 12]);
    }

    #[test]
    fn writer_batch_flushes_after_a_control_message() {
        let first = WsMessage::Binary(encode_data_frame(11, b"payload"));
        let mut bytes = ws_message_size(&first);
        let mut batch = vec![first];

        assert_eq!(
            push_ws_message(&mut batch, &mut bytes, WsMessage::Ping(vec![1, 2, 3])),
            Ok(true)
        );
        assert!(matches!(batch[1], WsMessage::Ping(_)));
    }

    #[test]
    fn writer_batch_defers_a_message_that_would_exceed_the_batch_limit() {
        let first = WsMessage::Binary(vec![0; WS_WRITE_BATCH_MAX_BYTES]);
        let mut bytes = ws_message_size(&first);
        let mut batch = vec![first];
        let next = WsMessage::Binary(encode_data_frame(12, b"next"));

        let deferred = push_ws_message(&mut batch, &mut bytes, next).unwrap_err();
        assert_eq!(batch.len(), 1);
        assert!(matches!(deferred, WsMessage::Binary(_)));
    }
}
