use std::{
    io,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    sync::mpsc,
    time::{interval, sleep, timeout, Instant, MissedTickBehavior},
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message as WsMessage},
};
use tracing::{info, warn};
use ws_net_common::{
    credential_id, decode_data_frame_owned, decode_message, encode_message, random_id,
    try_merge_data_frames, AccessConfig, GatewayError, Message, StreamId, TunnelCipher,
    TunnelFrameKind, CLIENT_NONCE_HEADER, CREDENTIAL_HEADER, DATA_FRAME_HEADER_LEN,
    GATEWAY_CREDENTIAL_HEADER, MAX_ENCRYPTED_TUNNEL_FRAME_SIZE, PROTOCOL_HEADER,
    SERVER_NONCE_HEADER, USER_AUTH_HEADER,
};

use crate::app::{
    AccessIdentity, AccessRuntime, GatewayConnection, GatewayConnectionPool, GatewayConnections,
};

const GATEWAY_PING_INTERVAL: Duration = Duration::from_secs(20);
const GATEWAY_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(10);
const WS_WRITE_BATCH_MAX_MESSAGES: usize = 64;
const WS_WRITE_BATCH_MAX_BYTES: usize = 256 * 1024;
const WS_DATA_FRAME_MAX_PAYLOAD: usize = 64 * 1024;
const WS_SLOW_FLUSH: Duration = Duration::from_millis(50);

pub(crate) async fn connect_all_registered(
    config: &AccessConfig,
    runtime: &Arc<AccessRuntime>,
) -> Result<Arc<GatewayConnections>> {
    let mut pools = Vec::new();
    let pool_size = config.access.gateway_pool_size.max(1);

    // Validate every identity before starting any network task.
    let gateways = config.gateway_configs()?;
    let identities = gateways
        .iter()
        .map(|gateway| {
            runtime.identity(
                &gateway.server_url,
                &gateway.token,
                gateway.user_token.as_deref(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    for (gateway, identity) in gateways.into_iter().zip(identities) {
        let connections = (0..pool_size)
            .map(|_| {
                start_gateway_connection(
                    gateway.server_url.clone(),
                    gateway.token.clone(),
                    gateway.user_token.clone(),
                    identity.clone(),
                    runtime.instance_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        pools.push(GatewayConnectionPool::new(
            gateway.name,
            gateway.server_url,
            connections,
        )?);
    }

    Ok(Arc::new(GatewayConnections::new(pools)?))
}

fn start_gateway_connection(
    server_url: String,
    token: String,
    user_token: Option<String>,
    identity: Arc<AccessIdentity>,
    instance_id: String,
) -> Arc<GatewayConnection> {
    let (outbound, outbound_rx) = mpsc::channel::<WsMessage>(1024);
    let connection = Arc::new(GatewayConnection {
        server_url,
        identity: identity.clone(),
        outbound,
        closed: std::sync::atomic::AtomicBool::new(true),
        stopped: std::sync::atomic::AtomicBool::new(false),
        reconnect_requested: std::sync::atomic::AtomicBool::new(false),
        reconnect_now: tokio::sync::Notify::new(),
        connected: tokio::sync::Notify::new(),
        stream_ids: std::sync::atomic::AtomicU64::new(1),
        tcp_streams: DashMap::new(),
        open_waiters: DashMap::new(),
        http_waiters: DashMap::new(),
        http_head_waiters: DashMap::new(),
        http_body_streams: DashMap::new(),
        unknown_streams: DashMap::new(),
    });

    {
        let mut connections = identity
            .connections
            .lock()
            .expect("identity connections poisoned");
        connections.retain(|connection| connection.strong_count() > 0);
        connections.push(Arc::downgrade(&connection));
    }

    tokio::spawn(run_gateway_connection(
        connection.clone(),
        token,
        user_token,
        instance_id,
        outbound_rx,
    ));

    connection
}

async fn run_gateway_connection(
    connection: Arc<GatewayConnection>,
    token: String,
    user_token: Option<String>,
    instance_id: String,
    mut outbound_rx: mpsc::Receiver<WsMessage>,
) {
    let mut retry_after = Duration::from_secs(1);

    while !connection.stopped.load(Ordering::Acquire) && connection.identity.error().is_none() {
        let result = tokio::select! {
            biased;
            error = connection.identity.cancelled() => Err(error.into()),
            _ = gateway_stopped(&connection) => Ok(()),
            result = run_gateway_session(&connection, &token, user_token.as_deref(), &instance_id, &mut outbound_rx) => result,
        };
        if let Err(error) = &result {
            if let Some(error) = error
                .downcast_ref::<GatewayError>()
                .filter(|error| error.terminal())
            {
                stop_identity(&connection, error.clone());
            }
        }
        let reason = result
            .err()
            .map(|error| error.to_string())
            .unwrap_or_else(|| "网关连接已关闭".into());

        let was_connected = !connection.closed.load(Ordering::Acquire);
        close_gateway_connection(&connection, &reason);
        while outbound_rx.try_recv().is_ok() {}
        if connection.stopped.load(Ordering::Acquire) || connection.identity.error().is_some() {
            break;
        }
        if was_connected {
            retry_after = Duration::from_secs(1);
        }
        if !connection.reconnect_requested.swap(false, Ordering::AcqRel) {
            tokio::select! {
                biased;
                _ = connection.identity.cancelled() => break,
                _ = sleep(retry_after) => {}
                _ = connection.reconnect_now.notified() => {
                    connection.reconnect_requested.store(false, Ordering::Release);
                }
            }
        }
        warn!(server_url = %connection.server_url, reason = %reason, retry_seconds = retry_after.as_secs(), "网关连接中断，将按退避间隔重试");
        retry_after = (retry_after * 2).min(Duration::from_secs(30));
    }

    close_gateway_connection(&connection, "网关连接已停止");
}

fn stop_identity(connection: &GatewayConnection, error: GatewayError) {
    let identity = &connection.identity;
    {
        let mut blocked = identity.blocked.lock().expect("identity lock poisoned");
        if blocked.is_some() {
            return;
        }
        *blocked = Some(error.clone());
    }
    identity.changed.notify_waiters();
    let connections: Vec<_> = identity
        .connections
        .lock()
        .expect("identity connections poisoned")
        .iter()
        .filter_map(|connection| connection.upgrade())
        .collect();
    for connection in connections {
        connection.stopped.store(true, Ordering::Release);
        connection.reconnect_now.notify_waiters();
        connection.connected.notify_waiters();
        close_gateway_connection(&connection, &error.message);
    }
    warn!(server_url = %connection.server_url, code = %error.code, "{}", error.message);
}

async fn run_gateway_session(
    connection: &Arc<GatewayConnection>,
    token: &str,
    user_token: Option<&str>,
    instance_id: &str,
    outbound_rx: &mut mpsc::Receiver<WsMessage>,
) -> Result<()> {
    let server_url = connection.server_url.clone();
    let ws_config = WebSocketConfig {
        max_message_size: Some(MAX_ENCRYPTED_TUNNEL_FRAME_SIZE),
        max_frame_size: Some(MAX_ENCRYPTED_TUNNEL_FRAME_SIZE),
        ..Default::default()
    };
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = server_url.as_str().into_client_request()?;
    let client_nonce = random_id()?;
    request.headers_mut().insert(
        PROTOCOL_HEADER,
        if user_token.is_some() { "4" } else { "3" }.parse()?,
    );
    request.headers_mut().insert(
        CREDENTIAL_HEADER,
        credential_id(user_token.unwrap_or(token)).parse()?,
    );
    request
        .headers_mut()
        .insert(GATEWAY_CREDENTIAL_HEADER, credential_id(token).parse()?);
    request
        .headers_mut()
        .insert(CLIENT_NONCE_HEADER, client_nonce.parse()?);
    info!(server_url = %server_url, "正在连接网关");
    let (ws, response) = match timeout(
        GATEWAY_READY_TIMEOUT,
        connect_async_with_config(request, Some(ws_config), true),
    )
    .await?
    {
        Ok(connected) => connected,
        Err(tokio_tungstenite::tungstenite::Error::Http(response))
            if response.status().as_u16() == 401 =>
        {
            let error = response
                .body()
                .as_ref()
                .and_then(|body| serde_json::from_slice::<GatewayError>(body).ok())
                .filter(|error| error.code == "UNAUTHORIZED")
                .unwrap_or_else(GatewayError::unauthorized);
            return Err(error.into());
        }
        Err(tokio_tungstenite::tungstenite::Error::Http(response))
            if user_token.is_some() && response.status().as_u16() == 400 =>
        {
            return Err(GatewayError::new(
                "UNAUTHORIZED",
                "网关不支持双 Token 鉴权，请升级 gateway；已停止自动重连。",
            )
            .into());
        }
        Err(error) => return Err(error.into()),
    };
    let (mut ws_sender, mut ws_receiver) = ws.split();
    let server_nonce = response
        .headers()
        .get(SERVER_NONCE_HEADER)
        .and_then(|value| value.to_str().ok());
    let v3 = server_nonce.is_some();
    let v4 = response
        .headers()
        .get(PROTOCOL_HEADER)
        .is_some_and(|value| value == "4");
    if user_token.is_some() && !v4 {
        return Err(GatewayError::new(
            "UNAUTHORIZED",
            "网关未确认双 Token 鉴权，拒绝降级连接；已停止自动重连。",
        )
        .into());
    }
    let user_auth = if v4 {
        match response
            .headers()
            .get(USER_AUTH_HEADER)
            .and_then(|value| value.to_str().ok())
        {
            Some("true") => true,
            Some("false") => false,
            _ => {
                return Err(GatewayError::new(
                    "UNAUTHORIZED",
                    "网关未确认用户鉴权状态，已停止自动重连。",
                )
                .into())
            }
        }
    } else {
        false
    };
    if user_auth && user_token.is_none() {
        return Err(GatewayError::unauthorized().into());
    }
    let bootstrap_cipher = if let Some(server_nonce) = server_nonce {
        TunnelCipher::from_tokens(
            token,
            if user_auth { user_token } else { None },
            &client_nonce,
            server_nonce,
        )?
    } else {
        TunnelCipher::from_shared_key(token)?
    };
    let ephemeral_key_pair = ws_net_common::EphemeralKeyPair::generate()?;

    ws_sender
        .send(encrypt_access_message(
            &bootstrap_cipher,
            WsMessage::Text(encode_message(&if v4 {
                Message::RegisterAccessV4 {
                    instance_id: instance_id.to_string(),
                    client_public_key: ephemeral_key_pair.public_key().to_vec(),
                }
            } else if v3 {
                Message::RegisterAccessV3 {
                    instance_id: instance_id.to_string(),
                    client_public_key: ephemeral_key_pair.public_key().to_vec(),
                }
            } else {
                Message::RegisterAccess {
                    token: token.to_string(),
                    client_public_key: ephemeral_key_pair.public_key().to_vec(),
                }
            })?),
        )?)
        .await?;

    let Some(frame) = timeout(GATEWAY_READY_TIMEOUT, ws_receiver.next()).await? else {
        return Err(GatewayError::network("网关在鉴权完成前关闭连接").into());
    };

    let gateway_public_key = match decode_gateway_message(&bootstrap_cipher, frame?)? {
        Message::RegisterOkV4 {
            gateway_public_key,
            user_auth: confirmed,
            ..
        } if v4 && confirmed == user_auth => gateway_public_key,
        Message::RegisterOkV3 {
            gateway_public_key, ..
        } if v3 && !v4 => gateway_public_key,
        Message::RegisterOk { gateway_public_key } if !v3 => gateway_public_key,
        Message::Error { code, message, .. } => {
            return Err(GatewayError::new(&code, message).into())
        }
        _ => return Err(anyhow!("网关注册响应类型不正确")),
    };
    let cipher = Arc::new(ephemeral_key_pair.derive_session_cipher(&gateway_public_key)?);

    {
        let blocked = connection
            .identity
            .blocked
            .lock()
            .expect("identity lock poisoned");
        if let Some(error) = blocked.as_ref() {
            return Err(error.clone().into());
        }
        if connection.stopped.load(Ordering::Acquire) {
            return Err(anyhow!("网关连接已停止"));
        }
        connection.closed.store(false, Ordering::Release);
        connection
            .reconnect_requested
            .store(false, Ordering::Release);
    }
    connection.connected.notify_waiters();
    info!(server_url = %server_url, "网关连接成功，鉴权通过");

    let mut heartbeat = interval(GATEWAY_PING_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_received = Instant::now();

    let writer = async {
        let mut pending = None;

        loop {
            let first = match pending.take() {
                Some(message) => message,
                None => {
                    let Some(message) = outbound_rx.recv().await else {
                        return Err(GatewayError::network("网关发送通道已关闭").into());
                    };
                    message
                }
            };
            let first_is_binary = matches!(&first, WsMessage::Binary(_));
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
            for message in batch {
                ws_sender
                    .feed(encrypt_access_message(&cipher, message)?)
                    .await
                    .context("写入网关隧道失败")?;
            }
            ws_sender.flush().await.context("发送网关隧道数据失败")?;

            let flush_elapsed = flush_started.elapsed();
            if flush_elapsed >= WS_SLOW_FLUSH {
                warn!(
                    server_url = %server_url,
                    message_count,
                    batch_bytes,
                    flush_ms = flush_elapsed.as_millis(),
                    "客户端隧道批量发送耗时较长"
                );
            }
        }
    };
    tokio::pin!(writer);

    loop {
        tokio::select! {
            biased;
            error = connection.identity.cancelled() => return Err(error.into()),
            result = &mut writer => {
                return result;
            }
            _ = connection.reconnect_now.notified() => {
                if connection.stopped.load(Ordering::Acquire) {
                    return Err(GatewayError::network("网关连接已停止").into());
                }

                if connection.reconnect_requested.load(Ordering::Acquire) {
                    return Err(GatewayError::network("已请求重新连接网关").into());
                }
            }
            _ = heartbeat.tick() => {
                if last_received.elapsed() > GATEWAY_READ_IDLE_TIMEOUT {
                    return Err(GatewayError::network("网关隧道接收超时").into());
                }

                send_text(connection, &Message::Ping)
                    .await
                    .context("发送加密心跳失败")?;
            }
            frame = ws_receiver.next() => {
                let Some(frame) = frame else {
                    return Err(GatewayError::network("网关隧道已关闭").into());
                };

                let frame = frame.context("读取网关隧道失败")?;
                last_received = Instant::now();
                handle_gateway_frame(connection, &cipher, frame).await?;
            }
        }
    }
}

fn try_merge_ws_binary(current: &mut WsMessage, next: &WsMessage) -> bool {
    match (current, next) {
        (WsMessage::Binary(current), WsMessage::Binary(next)) => {
            try_merge_data_frames(current, next, WS_DATA_FRAME_MAX_PAYLOAD)
        }
        _ => false,
    }
}

fn ws_message_size(message: &WsMessage) -> usize {
    match message {
        WsMessage::Text(text) => text.len(),
        WsMessage::Binary(bytes) | WsMessage::Ping(bytes) | WsMessage::Pong(bytes) => bytes.len(),
        WsMessage::Close(_) | WsMessage::Frame(_) => 0,
    }
}

fn push_ws_message(
    batch: &mut Vec<WsMessage>,
    batch_bytes: &mut usize,
    next: WsMessage,
) -> std::result::Result<bool, WsMessage> {
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

    let stop_batch = !matches!(&next, WsMessage::Binary(_));
    *batch_bytes += next_bytes;
    batch.push(next);
    Ok(stop_batch)
}

async fn handle_gateway_frame(
    connection: &GatewayConnection,
    cipher: &TunnelCipher,
    frame: WsMessage,
) -> Result<()> {
    match frame {
        WsMessage::Ping(_) | WsMessage::Pong(_) => {
            bail!("收到未加密的隧道控制帧，已拒绝");
        }
        WsMessage::Close(_) => return Err(GatewayError::network("网关隧道已关闭").into()),
        frame => match decrypt_gateway_frame(cipher, frame) {
            Ok((TunnelFrameKind::Text, bytes)) => {
                let text = std::str::from_utf8(&bytes).context("加密消息不是有效 UTF-8 文本")?;
                let message = decode_message(text).context("网关加密消息格式错误")?;
                handle_gateway_message(connection, message).await?;
            }
            Ok((TunnelFrameKind::Binary, bytes)) => {
                let frame_len = bytes.len();
                if let Some((stream_id, payload)) = decode_data_frame_owned(bytes) {
                    if let Some(tx) = connection
                        .http_body_streams
                        .get(&stream_id)
                        .map(|entry| entry.value().clone())
                    {
                        if timeout(
                            GATEWAY_READY_TIMEOUT,
                            tx.send(Ok(Bytes::from(payload.into_vec()))),
                        )
                        .await?
                        .is_err()
                        {
                            connection.http_body_streams.remove(&stream_id);
                            let _ = send_text(
                                connection,
                                &Message::Close {
                                    stream_id,
                                    reason: "local_backpressure".to_string(),
                                },
                            )
                            .await;
                        }
                        return Ok(());
                    }

                    if let Some(tx) = connection
                        .tcp_streams
                        .get(&stream_id)
                        .map(|entry| entry.value().clone())
                    {
                        if timeout(GATEWAY_READY_TIMEOUT, tx.send(payload))
                            .await?
                            .is_err()
                        {
                            connection.tcp_streams.remove(&stream_id);
                            let _ = send_text(
                                connection,
                                &Message::Close {
                                    stream_id,
                                    reason: "local_backpressure".to_string(),
                                },
                            )
                            .await;
                        }
                    } else {
                        if connection.unknown_streams.insert(stream_id, ()).is_none() {
                            warn!(stream_id, "收到未知业务流的数据，已请求远端关闭");
                            let _ = send_text(
                                connection,
                                &Message::Close {
                                    stream_id,
                                    reason: "unknown_stream".to_string(),
                                },
                            )
                            .await;
                        }
                    }
                } else {
                    bail!("收到非法网关数据帧：长度={frame_len}");
                }
            }
            Err(err) => return Err(err).context("网关隧道数据解密失败"),
        },
    }
    Ok(())
}

fn encrypt_access_message(cipher: &TunnelCipher, message: WsMessage) -> Result<WsMessage> {
    match message {
        WsMessage::Text(text) => Ok(WsMessage::Binary(
            cipher.encrypt_from_access(TunnelFrameKind::Text, text.as_bytes())?,
        )),
        WsMessage::Binary(bytes) => Ok(WsMessage::Binary(
            cipher.encrypt_from_access(TunnelFrameKind::Binary, &bytes)?,
        )),
        WsMessage::Close(None) => Ok(WsMessage::Close(None)),
        WsMessage::Close(Some(_)) => {
            bail!("拒绝发送明文隧道关闭原因")
        }
        _ => Err(anyhow!("拒绝发送未加密的隧道控制消息")),
    }
}

fn decrypt_gateway_frame(
    cipher: &TunnelCipher,
    frame: WsMessage,
) -> Result<(TunnelFrameKind, Vec<u8>)> {
    match frame {
        WsMessage::Binary(bytes) => cipher.decrypt_from_gateway(bytes),
        _ => Err(anyhow!("收到不合法的未加密网关消息")),
    }
}

async fn handle_gateway_message(connection: &GatewayConnection, message: Message) -> Result<()> {
    match message {
        Message::OpenOk { stream_id } => {
            if let Some((_, tx)) = connection.open_waiters.remove(&stream_id) {
                let _ = tx.send(Ok(()));
            }
        }
        Message::HttpResponse {
            stream_id,
            response,
        } => {
            if let Some((_, tx)) = connection.http_waiters.remove(&stream_id) {
                let _ = tx.send(Ok(response));
            }
        }
        Message::HttpResponseStart {
            stream_id,
            response,
        } => {
            if let Some((_, tx)) = connection.http_head_waiters.remove(&stream_id) {
                let _ = tx.send(Ok(response));
            }
        }
        Message::HttpResponseEnd { stream_id } => {
            connection.http_body_streams.remove(&stream_id);
        }
        Message::Close { stream_id, .. } => {
            connection.tcp_streams.remove(&stream_id);
            if let Some((_, tx)) = connection.http_head_waiters.remove(&stream_id) {
                let _ = tx.send(Err(GatewayError::network("连接已关闭")));
            }
            if let Some((_, tx)) = connection.http_body_streams.remove(&stream_id) {
                let _ = tx.try_send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "业务连接已关闭",
                )));
            }
            if let Some((_, tx)) = connection.open_waiters.remove(&stream_id) {
                let _ = tx.send(Err(GatewayError::network("连接已关闭")));
            }
            if let Some((_, tx)) = connection.http_waiters.remove(&stream_id) {
                let _ = tx.send(Err(GatewayError::network("连接已关闭")));
            }
        }
        Message::TcpEof { stream_id } => {
            connection.tcp_streams.remove(&stream_id);
        }
        Message::Error {
            stream_id,
            code,
            message,
        } => {
            let error = GatewayError::new(&code, message);
            if error.code == "FORBIDDEN" {
                warn!(server_url = %connection.server_url, stream_id, "{}", error.message);
            }
            if stream_id.is_none() {
                if error.terminal() {
                    stop_identity(connection, error.clone());
                }
                return Err(error.into());
            }
            if let Some(stream_id) = stream_id {
                if let Some((_, tx)) = connection.open_waiters.remove(&stream_id) {
                    let _ = tx.send(Err(error.clone()));
                }
                if let Some((_, tx)) = connection.http_waiters.remove(&stream_id) {
                    let _ = tx.send(Err(error.clone()));
                }
                if let Some((_, tx)) = connection.http_head_waiters.remove(&stream_id) {
                    let _ = tx.send(Err(error.clone()));
                }
                if let Some((_, tx)) = connection.http_body_streams.remove(&stream_id) {
                    let _ = tx.try_send(Err(io::Error::other(error)));
                }
            }
        }
        Message::Ping => {
            send_text(connection, &Message::Pong).await?;
        }
        Message::Pong => {}
        Message::RegisterAccessV4 { .. }
        | Message::RegisterOkV4 { .. }
        | Message::RegisterAccessV3 { .. }
        | Message::RegisterOkV3 { .. }
        | Message::RegisterAccess { .. }
        | Message::RegisterOk { .. }
        | Message::Open { .. }
        | Message::HttpRequest { .. }
        | Message::HttpRequestStart { .. }
        | Message::HttpRequestEnd { .. } => {
            bail!("网关发送了不合法的消息类型")
        }
    }
    Ok(())
}

pub(crate) async fn send_text(connection: &GatewayConnection, message: &Message) -> Result<()> {
    ensure_gateway_open(connection)?;
    if let Err(err) = connection
        .outbound
        .send(WsMessage::Text(encode_message(message)?))
        .await
    {
        close_gateway_connection(connection, "网关发送通道已关闭");
        return Err(err.into());
    }
    Ok(())
}

pub(crate) async fn send_binary(connection: &GatewayConnection, frame: Vec<u8>) -> Result<()> {
    ensure_gateway_open(connection)?;
    if let Err(err) = connection.outbound.send(WsMessage::Binary(frame)).await {
        close_gateway_connection(connection, "网关发送通道已关闭");
        return Err(err.into());
    }
    Ok(())
}

fn ensure_gateway_open(connection: &GatewayConnection) -> Result<()> {
    if let Some(error) = connection.identity.error() {
        return Err(error.into());
    }
    if connection.closed.load(Ordering::Acquire) || connection.outbound.is_closed() {
        return Err(GatewayError::network("网关连接已断开").into());
    }

    Ok(())
}

pub(crate) async fn ensure_gateway_ready(connection: &GatewayConnection) -> Result<()> {
    if let Some(error) = connection.identity.error() {
        return Err(error.into());
    }
    if ensure_gateway_open(connection).is_ok() {
        return Ok(());
    }

    request_gateway_reconnect(connection);

    let wait_connected = async {
        loop {
            if connection.identity.error().is_some() {
                return;
            }
            let notified = connection.connected.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if ensure_gateway_open(connection).is_ok() {
                return;
            }
            notified.await;
        }
    };

    match timeout(GATEWAY_READY_TIMEOUT, wait_connected).await {
        Ok(()) => ensure_gateway_open(connection),
        Err(_) => Err(connection
            .identity
            .error()
            .unwrap_or_else(|| GatewayError::network("等待网关连接超时"))
            .into()),
    }
}

pub(crate) async fn stop_gateway_connections(connections: &GatewayConnections, reason: &str) {
    for pool in &connections.pools {
        for connection in &pool.connections {
            connection.stopped.store(true, Ordering::Release);
            connection.reconnect_now.notify_waiters();
            let _ = connection.outbound.try_send(WsMessage::Close(None));
            close_gateway_connection(connection, reason);
        }
    }
}

pub(crate) fn is_gateway_disconnected_error(err: &anyhow::Error) -> bool {
    if let Some(error) = err.downcast_ref::<GatewayError>() {
        return matches!(error.code.as_str(), "GATEWAY_DISCONNECTED" | "AUTH_CHANGED");
    }
    false
}

fn request_gateway_reconnect(connection: &GatewayConnection) {
    if !connection.stopped.load(Ordering::Acquire) && connection.identity.error().is_none() {
        connection
            .reconnect_requested
            .store(true, Ordering::Release);
        connection.reconnect_now.notify_one();
    }
}

fn close_gateway_connection(connection: &GatewayConnection, reason: &str) {
    if connection.closed.swap(true, Ordering::AcqRel) {
        return;
    }
    connection.connected.notify_waiters();

    connection.tcp_streams.clear();
    connection.unknown_streams.clear();

    let open_waiters = connection
        .open_waiters
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for stream_id in open_waiters {
        if let Some((_, tx)) = connection.open_waiters.remove(&stream_id) {
            let _ = tx.send(Err(connection
                .identity
                .error()
                .unwrap_or_else(|| GatewayError::network(reason))));
        }
    }

    let http_waiters = connection
        .http_waiters
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for stream_id in http_waiters {
        if let Some((_, tx)) = connection.http_waiters.remove(&stream_id) {
            let _ = tx.send(Err(connection
                .identity
                .error()
                .unwrap_or_else(|| GatewayError::network(reason))));
        }
    }

    let http_head_waiters = connection
        .http_head_waiters
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for stream_id in http_head_waiters {
        if let Some((_, tx)) = connection.http_head_waiters.remove(&stream_id) {
            let _ = tx.send(Err(connection
                .identity
                .error()
                .unwrap_or_else(|| GatewayError::network(reason))));
        }
    }

    let http_body_streams = connection
        .http_body_streams
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for stream_id in http_body_streams {
        if let Some((_, tx)) = connection.http_body_streams.remove(&stream_id) {
            let _ = tx.try_send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                reason.to_string(),
            )));
        }
    }

    if connection.identity.error().is_none() {
        warn!(server_url = %connection.server_url, reason = %reason, "网关连接已关闭");
    }
}

fn decode_gateway_message(cipher: &TunnelCipher, message: WsMessage) -> Result<Message> {
    let (kind, bytes) = decrypt_gateway_frame(cipher, message)?;
    if kind != TunnelFrameKind::Text {
        return Err(anyhow!("预期收到加密的网关文本消息"));
    }
    Ok(decode_message(std::str::from_utf8(&bytes)?)?)
}

pub(crate) fn next_stream_id(connection: &GatewayConnection) -> StreamId {
    connection.stream_ids.fetch_add(1, Ordering::Relaxed)
}

pub(crate) async fn gateway_closed(connection: &GatewayConnection) -> GatewayError {
    loop {
        let notified = connection.connected.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(error) = connection.identity.error() {
            return error;
        }
        if connection.closed.load(Ordering::Acquire) || connection.stopped.load(Ordering::Acquire) {
            return GatewayError::network("网关会话已结束，当前业务连接已关闭");
        }
        notified.await;
    }
}

async fn gateway_stopped(connection: &GatewayConnection) {
    loop {
        let notified = connection.reconnect_now.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if connection.stopped.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

#[cfg(test)]
mod tests {
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use ws_net_common::{decode_data_frame, encode_data_frame};

    use super::{push_ws_message, ws_message_size};

    #[tokio::test]
    async fn blocked_identity_survives_pool_reload_and_is_gateway_scoped() {
        use crate::app::AccessRuntime;
        use ws_net_common::GatewayError;
        let runtime = AccessRuntime::new().unwrap();
        let a = runtime
            .identity("ws://a.example/tunnel", "gateway-a", Some("same-user"))
            .unwrap();
        let b = runtime
            .identity("ws://b.example/tunnel", "gateway-b", Some("same-user"))
            .unwrap();
        *a.blocked.lock().unwrap() = Some(GatewayError::replaced());
        a.changed.notify_waiters();
        assert_eq!(a.cancelled().await.code, "SESSION_REPLACED");
        let reloaded = runtime
            .identity("ws://a.example/tunnel", "gateway-a", Some("same-user"))
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&a, &reloaded));
        assert!(reloaded.error().is_some());
        assert!(b.error().is_none());
        assert!(runtime
            .identity("ws://a.example/tunnel", "gateway-a", Some("new-user"))
            .unwrap()
            .error()
            .is_none());
        assert!(runtime
            .identity("ws://a.example/tunnel", "new-gateway", Some("same-user"))
            .unwrap()
            .error()
            .is_none());
    }

    #[test]
    fn writer_batch_merges_same_stream_payloads() {
        let first = WsMessage::Binary(encode_data_frame(21, b"left"));
        let mut bytes = ws_message_size(&first);
        let mut batch = vec![first];

        assert!(matches!(
            push_ws_message(
                &mut batch,
                &mut bytes,
                WsMessage::Binary(encode_data_frame(21, b"right")),
            ),
            Ok(false)
        ));
        assert_eq!(batch.len(), 1);
        let WsMessage::Binary(frame) = &batch[0] else {
            panic!("expected binary frame");
        };
        assert_eq!(decode_data_frame(frame), Some((21, b"leftright".to_vec())));
    }

    #[tokio::test]
    async fn invalid_later_gateway_does_not_start_earlier_pool() {
        use crate::app::AccessRuntime;
        use ws_net_common::{AccessConfig, AccessGatewayConfig, AccessSection};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = AccessConfig {
            access: AccessSection {
                token: None,
                server_url: None,
                server_urls: vec![],
                gateway_pool_size: 1,
            },
            gateways: [
                (
                    "first",
                    format!("ws://{}/tunnel", listener.local_addr().unwrap()),
                ),
                ("invalid", "not-a-url".into()),
            ]
            .into_iter()
            .map(|(name, server_url)| AccessGatewayConfig {
                name: name.into(),
                server_url,
                token: "user".into(),
                user_token: None,
            })
            .collect(),
            listeners: vec![],
        };
        assert!(
            super::connect_all_registered(&config, &AccessRuntime::new().unwrap())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn writer_batch_does_not_merge_different_streams() {
        let first = WsMessage::Binary(encode_data_frame(21, b"left"));
        let mut bytes = ws_message_size(&first);
        let mut batch = vec![first];

        assert!(matches!(
            push_ws_message(
                &mut batch,
                &mut bytes,
                WsMessage::Binary(encode_data_frame(22, b"right")),
            ),
            Ok(false)
        ));
        assert_eq!(batch.len(), 2);
    }
}
