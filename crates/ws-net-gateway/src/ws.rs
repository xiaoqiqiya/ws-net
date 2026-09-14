use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Result};
use axum::{
    extract::{ws::WebSocketUpgrade, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use dashmap::DashMap;
use futures_util::{future::FutureExt, SinkExt, StreamExt};
use tokio::{
    sync::mpsc,
    task::AbortHandle,
    time::{interval, timeout, Instant, MissedTickBehavior},
};
use tracing::warn;
use ws_net_common::{
    decode_data_frame_owned, decode_message, encode_data_frame, encode_message, random_id,
    try_merge_data_frames, valid_id, GatewayError, HttpRequestHead, HttpResponsePayload, Message,
    Mode, TunnelCipher, TunnelFrameKind, CLIENT_NONCE_HEADER, CREDENTIAL_HEADER,
    DATA_FRAME_HEADER_LEN, MAX_ENCRYPTED_TUNNEL_FRAME_SIZE, PROTOCOL_HEADER, SERVER_NONCE_HEADER,
};

use crate::{
    app::{AppState, SessionLease},
    http_proxy::{format_error_chain, handle_http_request},
    tcp::{handle_tcp_stream, StreamCancellation, StreamCancels, TcpStreams},
};

const ACCESS_PING_INTERVAL: Duration = Duration::from_secs(20);
const ACCESS_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
const WS_WRITE_BATCH_MAX_MESSAGES: usize = 64;
const WS_WRITE_BATCH_MAX_BYTES: usize = 256 * 1024;
const WS_DATA_FRAME_MAX_PAYLOAD: usize = 64 * 1024;
const WS_SLOW_FLUSH: Duration = Duration::from_millis(50);

pub(crate) type Outbound = mpsc::Sender<axum::extract::ws::Message>;
type HttpBodies = Arc<DashMap<u64, mpsc::Sender<Result<bytes::Bytes, std::io::Error>>>>;

struct SessionCleanup {
    writer_abort: AbortHandle,
    streams: TcpStreams,
    stream_cancels: StreamCancels,
    http_bodies: HttpBodies,
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        self.writer_abort.abort();
        let canceled_streams = self.stream_cancels.len();
        for cancellation in self.stream_cancels.iter() {
            cancellation.value().cancel();
        }
        self.stream_cancels.clear();
        self.streams.clear();
        self.http_bodies.clear();
        if canceled_streams > 0 {
            warn!(
                canceled_streams,
                "gateway websocket session ended; canceled remaining tcp streams"
            );
        }
    }
}

pub(crate) async fn ws_entry(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let bootstrap = if let Some(version) = headers.get(PROTOCOL_HEADER) {
        if version != "3" {
            return (
                StatusCode::BAD_REQUEST,
                Json(GatewayError::new("PROTOCOL_ERROR", "不支持的隧道协议版本")),
            )
                .into_response();
        }
        let id = headers
            .get(CREDENTIAL_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let client_nonce = headers
            .get(CLIENT_NONCE_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !valid_id(id) || !valid_id(client_nonce) {
            return (StatusCode::UNAUTHORIZED, Json(GatewayError::unauthorized())).into_response();
        }
        let token = match state.token(id) {
            Ok(token) => token,
            Err(_) => {
                return (StatusCode::UNAUTHORIZED, Json(GatewayError::unauthorized()))
                    .into_response()
            }
        };
        let server_nonce = match random_id() {
            Ok(nonce) => nonce,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let cipher = match TunnelCipher::from_connection_key(&token, client_nonce, &server_nonce) {
            Ok(cipher) => cipher,
            Err(_) => {
                return (StatusCode::UNAUTHORIZED, Json(GatewayError::unauthorized()))
                    .into_response()
            }
        };
        Some((token, cipher, server_nonce))
    } else {
        None
    };
    let server_nonce = bootstrap.as_ref().map(|(_, _, nonce)| nonce.clone());
    let mut response = ws
        .max_message_size(MAX_ENCRYPTED_TUNNEL_FRAME_SIZE)
        .max_frame_size(MAX_ENCRYPTED_TUNNEL_FRAME_SIZE)
        .on_upgrade(move |socket| handle_socket(socket, state, bootstrap))
        .into_response();
    if let Some(nonce) = server_nonce {
        response.headers_mut().insert(
            SERVER_NONCE_HEADER,
            HeaderValue::from_str(&nonce).expect("hex header"),
        );
    }
    response
}

async fn handle_socket(
    socket: axum::extract::ws::WebSocket,
    state: AppState,
    bootstrap: Option<(String, TunnelCipher, String)>,
) {
    if let Err(err) = handle_socket_result(socket, state, bootstrap).await {
        warn!(error = %err, "网关隧道会话结束");
    }
}

async fn handle_socket_result(
    socket: axum::extract::ws::WebSocket,
    state: AppState,
    bootstrap: Option<(String, TunnelCipher, String)>,
) -> Result<()> {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    let v3 = bootstrap.is_some();
    let (token, bootstrap_cipher) = match bootstrap {
        Some((token, cipher, _)) => (token, cipher),
        None => {
            let token = state.config().auth.access_token;
            let cipher = TunnelCipher::from_shared_key(&token)?;
            (token, cipher)
        }
    };
    let Some(Ok(first)) = timeout(Duration::from_secs(10), ws_receiver.next()).await? else {
        return Err(anyhow!("expected encrypted register message"));
    };

    let (instance, client_public_key) = match decode_access_message(&bootstrap_cipher, first) {
        Ok(Message::RegisterAccessV3 {
            instance_id,
            client_public_key,
        }) if v3 => (instance_id, client_public_key),
        Ok(Message::RegisterAccess {
            token: submitted,
            client_public_key,
        }) if !v3 && submitted == token => (random_id()?, client_public_key),
        _ => {
            ws_sender
                .send(encrypt_gateway_message(
                    &bootstrap_cipher,
                    axum::extract::ws::Message::Text(encode_message(&Message::Error {
                        stream_id: None,
                        code: "UNAUTHORIZED".to_string(),
                        message: GatewayError::unauthorized().message,
                    })?),
                )?)
                .await?;
            return Ok(());
        }
    };
    let ephemeral_key_pair = ws_net_common::EphemeralKeyPair::generate()?;
    let gateway_public_key = ephemeral_key_pair.public_key().to_vec();
    let cipher = Arc::new(ephemeral_key_pair.derive_session_cipher(&client_public_key)?);

    let (lease, user_name) = match state.register(&token, &instance, !v3) {
        Ok(registration) => registration,
        Err(error) => {
            let error = error
                .downcast_ref::<GatewayError>()
                .cloned()
                .unwrap_or_else(GatewayError::unauthorized);
            ws_sender
                .send(encrypt_gateway_message(
                    &bootstrap_cipher,
                    axum::extract::ws::Message::Text(encode_message(&Message::Error {
                        stream_id: None,
                        code: error.code,
                        message: error.message,
                    })?),
                )?)
                .await?;
            return Ok(());
        }
    };

    let (outbound, mut outbound_rx) = mpsc::channel::<axum::extract::ws::Message>(1024);
    lease
        .run(async {
            ws_sender
                .send(encrypt_gateway_message(
                    &bootstrap_cipher,
                    axum::extract::ws::Message::Text(encode_message(&if v3 {
                        Message::RegisterOkV3 {
                            gateway_public_key,
                            user_name,
                        }
                    } else {
                        Message::RegisterOk { gateway_public_key }
                    })?),
                )?)
                .await
                .map_err(anyhow::Error::from)
        })
        .await?;

    let writer_cipher = cipher.clone();
    let writer_lease = lease.clone();
    let mut writer = tokio::spawn(async move {
        let mut pending = None;

        loop {
            let first = match pending.take() {
                Some(message) => message,
                None => {
                    let message = tokio::select! {
                        biased;
                        error = writer_lease.cancelled() => {
                            let _ = timeout(Duration::from_secs(1), async {
                                if let Ok(message) = encode_message(&Message::Error { stream_id: None, code: error.code, message: error.message }) {
                                    if let Ok(frame) = encrypt_gateway_message(&writer_cipher, axum::extract::ws::Message::Text(message)) {
                                        let _ = ws_sender.send(frame).await;
                                    }
                                }
                                let _ = ws_sender.close().await;
                            }).await;
                            break;
                        }
                        message = outbound_rx.recv() => message,
                    };
                    let Some(message) = message else {
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
            let write_result = writer_lease
                .run(async {
                    for message in batch {
                        ws_sender
                            .feed(encrypt_gateway_message(&writer_cipher, message)?)
                            .await?;
                    }
                    ws_sender.flush().await?;
                    Ok(())
                })
                .await;
            if write_result.is_err() {
                if let Err(error) = writer_lease.check() {
                    if let Some(error) = error.downcast_ref::<GatewayError>() {
                        let error = error.clone();
                        let _ = timeout(Duration::from_secs(1), async {
                            let frame = encrypt_gateway_message(
                                &writer_cipher,
                                axum::extract::ws::Message::Text(encode_message(
                                    &Message::Error {
                                        stream_id: None,
                                        code: error.code,
                                        message: error.message,
                                    },
                                )?),
                            )?;
                            ws_sender.send(frame).await?;
                            ws_sender.close().await?;
                            Ok::<_, anyhow::Error>(())
                        })
                        .await;
                    }
                }
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
    let stream_cancels: StreamCancels = Arc::new(DashMap::new());
    let http_bodies: HttpBodies = Arc::new(DashMap::new());
    let _session_cleanup = SessionCleanup {
        writer_abort: writer.abort_handle(),
        streams: streams.clone(),
        stream_cancels: stream_cancels.clone(),
        http_bodies: http_bodies.clone(),
    };
    let mut heartbeat = interval(ACCESS_PING_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_received = Instant::now();

    loop {
        tokio::select! {
            biased;
            _ = lease.cancelled() => {
                for cancellation in stream_cancels.iter() { cancellation.value().cancel(); }
                streams.clear(); http_bodies.clear();
                let _ = timeout(Duration::from_secs(2), &mut writer).await;
                return Ok(());
            }
            _ = &mut writer => return Err(anyhow!("网关隧道写任务已结束")),
            _ = heartbeat.tick() => {
                if last_received.elapsed() > ACCESS_READ_IDLE_TIMEOUT {
                    return Err(anyhow!("access websocket read idle timeout"));
                }

                send_text(&outbound, &Message::Ping).await?;
            }
            frame = ws_receiver.next() => {
                let Some(frame) = frame else {
                    break;
                };
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(err) => {
                        warn!(error = %err, "gateway websocket read failed; ending session");
                        break;
                    }
                };

                last_received = Instant::now();
                let result = lease.run(async {
                match frame {
                    axum::extract::ws::Message::Binary(bytes) => {
                        let (kind, bytes) = cipher.decrypt_from_access(bytes)?;
                        if kind == TunnelFrameKind::Text {
                            let text = std::str::from_utf8(&bytes)?;
                            handle_text_message(
                                &state,
                                &lease,
                                &outbound,
                                &streams,
                                &stream_cancels,
                                &http_bodies,
                                text,
                            ).await?;
                            return Ok(true);
                        }
                        let frame_len = bytes.len();
                        if let Some((stream_id, payload)) = decode_data_frame_owned(bytes) {
                            if let Some(tx) = http_bodies.get(&stream_id).map(|entry| entry.value().clone()) {
                                if tx.send(Ok(bytes::Bytes::from(payload.into_vec()))).await.is_err() {
                                    http_bodies.remove(&stream_id);
                                    let _ = send_error(&outbound, Some(stream_id), "HTTP_BODY_BACKPRESSURE", "请求体接收通道已关闭").await;
                                }
                                return Ok(true);
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
                    axum::extract::ws::Message::Text(_) => {
                        return Err(anyhow!("received unencrypted websocket text message"));
                    }
                    axum::extract::ws::Message::Ping(_) | axum::extract::ws::Message::Pong(_) => {
                        return Err(anyhow!("received unencrypted websocket control frame"));
                    }
                    axum::extract::ws::Message::Close(_) => return Ok(false),
                }
                Ok(true)
                }).await;
                match result {
                    Ok(false) => break,
                    Ok(true) => {},
                    Err(_) if lease.check().is_err() => continue,
                    Err(error) => return Err(error),
                }
            }
            else => break,
        }
    }

    Ok(())
}

fn encrypt_gateway_message(
    cipher: &TunnelCipher,
    message: axum::extract::ws::Message,
) -> Result<axum::extract::ws::Message> {
    match message {
        axum::extract::ws::Message::Text(text) => Ok(axum::extract::ws::Message::Binary(
            cipher.encrypt_from_gateway(TunnelFrameKind::Text, text.as_bytes())?,
        )),
        axum::extract::ws::Message::Binary(bytes) => Ok(axum::extract::ws::Message::Binary(
            cipher.encrypt_from_gateway(TunnelFrameKind::Binary, &bytes)?,
        )),
        axum::extract::ws::Message::Close(None) => Ok(axum::extract::ws::Message::Close(None)),
        axum::extract::ws::Message::Close(Some(_)) => {
            bail!("refusing to send a plaintext websocket close reason")
        }
        other => Err(anyhow!(
            "refusing to send unencrypted websocket control message: {other:?}"
        )),
    }
}

fn decode_access_message(
    cipher: &TunnelCipher,
    message: axum::extract::ws::Message,
) -> Result<Message> {
    let axum::extract::ws::Message::Binary(bytes) = message else {
        return Err(anyhow!("expected encrypted websocket binary message"));
    };
    let (kind, bytes) = cipher.decrypt_from_access(bytes)?;
    if kind != TunnelFrameKind::Text {
        return Err(anyhow!("expected encrypted websocket text message"));
    }
    Ok(decode_message(std::str::from_utf8(&bytes)?)?)
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
    lease: &Arc<SessionLease>,
    outbound: &Outbound,
    streams: &TcpStreams,
    stream_cancels: &StreamCancels,
    http_bodies: &HttpBodies,
    text: &str,
) -> Result<()> {
    lease.check()?;
    let message = decode_message(text)?;
    let address = match &message {
        Message::Open { config, .. }
        | Message::HttpRequest { config, .. }
        | Message::HttpRequestStart { config, .. } => {
            match state.authorize_target(lease, config).await {
                Ok(address) => Some(address),
                Err(error) => {
                    let stream_id = match &message {
                        Message::Open { stream_id, .. }
                        | Message::HttpRequest { stream_id, .. }
                        | Message::HttpRequestStart { stream_id, .. } => *stream_id,
                        _ => unreachable!(),
                    };
                    let error = error
                        .downcast_ref::<GatewayError>()
                        .cloned()
                        .unwrap_or_else(|| {
                            GatewayError::new("TARGET_ERROR", format!("目标地址校验失败：{error}"))
                        });
                    send_error(outbound, Some(stream_id), &error.code, &error.message).await?;
                    return Ok(());
                }
            }
        }
        _ => None,
    };
    lease.check()?;
    match message {
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
                    "目标未配置为 TCP 模式",
                )
                .await?;
                return Ok(());
            }
            let cancellation = Arc::new(StreamCancellation::new());
            if let Some(previous) = stream_cancels.insert(stream_id, cancellation.clone()) {
                previous.cancel();
            }
            tokio::spawn(handle_tcp_stream(
                stream_id,
                target,
                address.expect("authorized tcp target"),
                lease.clone(),
                outbound.clone(),
                streams.clone(),
                (stream_cancels.clone(), cancellation),
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
                    "目标未配置为 HTTP 模式",
                )
                .await?;
                return Ok(());
            }
            let state = state.clone();
            let lease = lease.clone();
            let outbound = outbound.clone();
            let cancellation = Arc::new(StreamCancellation::new());
            if let Some(previous) = stream_cancels.insert(stream_id, cancellation.clone()) {
                previous.cancel();
            }
            let stream_cancels = stream_cancels.clone();
            tokio::spawn(async move {
                let work = async {
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
                        address.expect("authorized http target"),
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
                                    "目标未返回有效的 HTTP 响应头",
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
                };
                tokio::select! {
                    biased;
                    _ = lease.cancelled() => {},
                    _ = cancellation.cancelled() => {}
                    _ = work => {}
                }
                stream_cancels
                    .remove_if(&stream_id, |_, current| Arc::ptr_eq(current, &cancellation));
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
                    "目标未配置为 HTTP 模式",
                )
                .await?;
                return Ok(());
            }

            let (body_tx, body_rx) = mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(64);
            http_bodies.insert(stream_id, body_tx);
            let state = state.clone();
            let lease = lease.clone();
            let outbound = outbound.clone();
            let http_bodies = http_bodies.clone();
            let cancellation = Arc::new(StreamCancellation::new());
            if let Some(previous) = stream_cancels.insert(stream_id, cancellation.clone()) {
                previous.cancel();
            }
            let stream_cancels = stream_cancels.clone();
            tokio::spawn(async move {
                let work = async {
                    let result = handle_http_request(
                        &state,
                        &config,
                        address.expect("authorized http target"),
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
                                        .send(axum::extract::ws::Message::Binary(
                                            encode_data_frame(stream_id, &chunk),
                                        ))
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
                            let _ =
                                send_text(&outbound, &Message::HttpResponseEnd { stream_id }).await;
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
                };
                tokio::select! {
                    biased;
                    _ = lease.cancelled() => {},
                    _ = cancellation.cancelled() => {}
                    _ = work => {}
                }
                http_bodies.remove(&stream_id);
                stream_cancels
                    .remove_if(&stream_id, |_, current| Arc::ptr_eq(current, &cancellation));
            });
        }
        Message::HttpRequestEnd { stream_id } => {
            http_bodies.remove(&stream_id);
        }
        Message::Close { stream_id, .. } => {
            if let Some((_, cancellation)) = stream_cancels.remove(&stream_id) {
                cancellation.cancel();
            }
            streams.remove(&stream_id);
            http_bodies.remove(&stream_id);
        }
        Message::TcpEof { stream_id } => {
            streams.remove(&stream_id);
        }
        Message::Ping => {
            send_text(outbound, &Message::Pong).await?;
        }
        Message::Pong => {}
        Message::RegisterAccessV3 { .. }
        | Message::RegisterOkV3 { .. }
        | Message::RegisterAccess { .. }
        | Message::RegisterOk { .. }
        | Message::OpenOk { .. }
        | Message::Error { .. }
        | Message::HttpResponse { .. }
        | Message::HttpResponseStart { .. }
        | Message::HttpResponseEnd { .. } => {
            bail!("unexpected gateway-to-access message from access")
        }
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
