use std::{
    io,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    sync::mpsc,
    time::{interval, sleep, timeout, Instant, MissedTickBehavior},
};
use tokio_tungstenite::{connect_async_with_config, tungstenite::Message as WsMessage};
use tracing::{info, warn};
use ws_net_common::{
    decode_data_frame_owned, decode_message, encode_message, try_merge_data_frames, AccessConfig,
    Message, StreamId, TunnelCipher, TunnelFrameKind, DATA_FRAME_HEADER_LEN,
};

use crate::app::{GatewayConnection, GatewayConnectionPool, GatewayConnections};

const GATEWAY_PING_INTERVAL: Duration = Duration::from_secs(20);
const GATEWAY_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(10);
const WS_WRITE_BATCH_MAX_MESSAGES: usize = 64;
const WS_WRITE_BATCH_MAX_BYTES: usize = 256 * 1024;
const WS_DATA_FRAME_MAX_PAYLOAD: usize = 64 * 1024;
const WS_SLOW_FLUSH: Duration = Duration::from_millis(50);

pub(crate) async fn connect_all_registered(
    config: &AccessConfig,
) -> Result<Arc<GatewayConnections>> {
    let mut pools = Vec::new();
    let pool_size = config.access.gateway_pool_size.max(1);

    for gateway in config.gateway_configs()? {
        let connections = (0..pool_size)
            .map(|_| start_gateway_connection(gateway.server_url.clone(), gateway.token.clone()))
            .collect::<Vec<_>>();
        pools.push(GatewayConnectionPool::new(
            gateway.name,
            gateway.server_url,
            connections,
        )?);
    }

    Ok(Arc::new(GatewayConnections::new(pools)?))
}

fn start_gateway_connection(server_url: String, token: String) -> Arc<GatewayConnection> {
    let (outbound, outbound_rx) = mpsc::channel::<WsMessage>(1024);
    let connection = Arc::new(GatewayConnection {
        server_url,
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
    });

    tokio::spawn(run_gateway_connection(
        connection.clone(),
        token,
        outbound_rx,
    ));

    connection
}

async fn run_gateway_connection(
    connection: Arc<GatewayConnection>,
    token: String,
    mut outbound_rx: mpsc::Receiver<WsMessage>,
) {
    let mut retry_after = Duration::from_secs(1);

    while !connection.stopped.load(Ordering::Acquire) {
        match run_gateway_session(&connection, &token, &mut outbound_rx).await {
            Ok(()) => warn!(server_url = %connection.server_url, "gateway websocket session ended"),
            Err(err) => {
                warn!(server_url = %connection.server_url, error = %err, "gateway reconnect failed")
            }
        }

        let was_connected = !connection.closed.load(Ordering::Acquire);
        close_gateway_connection(&connection, "gateway disconnected");
        while outbound_rx.try_recv().is_ok() {}
        if was_connected {
            retry_after = Duration::from_secs(1);
        }
        if !connection.reconnect_requested.swap(false, Ordering::AcqRel) {
            tokio::select! {
                _ = sleep(retry_after) => {}
                _ = connection.reconnect_now.notified() => {
                    connection.reconnect_requested.store(false, Ordering::Release);
                }
            }
        }
        retry_after = (retry_after * 2).min(Duration::from_secs(30));
    }

    close_gateway_connection(&connection, "gateway connection stopped");
}

async fn run_gateway_session(
    connection: &Arc<GatewayConnection>,
    token: &str,
    outbound_rx: &mut mpsc::Receiver<WsMessage>,
) -> Result<()> {
    let server_url = connection.server_url.clone();
    let (ws, _) = connect_async_with_config(server_url.as_str(), None, true).await?;
    let (mut ws_sender, mut ws_receiver) = ws.split();
    let bootstrap_cipher = TunnelCipher::from_shared_key(token)?;
    let ephemeral_key_pair = ws_net_common::EphemeralKeyPair::generate()?;

    ws_sender
        .send(encrypt_access_message(
            &bootstrap_cipher,
            WsMessage::Text(encode_message(&Message::RegisterAccess {
                token: token.to_string(),
                client_public_key: ephemeral_key_pair.public_key().to_vec(),
            })?),
        )?)
        .await?;

    let Some(frame) = ws_receiver.next().await else {
        return Err(anyhow!("gateway closed before RegisterOk"));
    };

    let gateway_public_key = match decode_gateway_message(&bootstrap_cipher, frame?)? {
        Message::RegisterOk { gateway_public_key } => gateway_public_key,
        Message::Error { code, message, .. } => {
            return Err(anyhow!("gateway error {code}: {message}"))
        }
        other => return Err(anyhow!("unexpected register response: {other:?}")),
    };
    let cipher = Arc::new(ephemeral_key_pair.derive_session_cipher(&gateway_public_key)?);

    connection.closed.store(false, Ordering::Release);
    connection.connected.notify_waiters();
    info!(server_url = %server_url, "gateway connected");

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
                        return Err(anyhow!("gateway outbound channel closed"));
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
                    .context("gateway websocket feed failed")?;
            }
            ws_sender
                .flush()
                .await
                .context("gateway websocket flush failed")?;

            let flush_elapsed = flush_started.elapsed();
            if flush_elapsed >= WS_SLOW_FLUSH {
                warn!(
                    server_url = %server_url,
                    message_count,
                    batch_bytes,
                    flush_ms = flush_elapsed.as_millis(),
                    "slow access websocket batch flush"
                );
            }
        }
    };
    tokio::pin!(writer);

    loop {
        tokio::select! {
            result = &mut writer => {
                return result;
            }
            _ = connection.reconnect_now.notified() => {
                if connection.stopped.load(Ordering::Acquire) {
                    return Err(anyhow!("gateway connection stopped"));
                }

                if connection.reconnect_requested.load(Ordering::Acquire) {
                    return Err(anyhow!("gateway reconnect requested"));
                }
            }
            _ = heartbeat.tick() => {
                if last_received.elapsed() > GATEWAY_READ_IDLE_TIMEOUT {
                    return Err(anyhow!("gateway websocket read idle timeout"));
                }

                send_text(connection, &Message::Ping)
                    .await
                    .context("gateway encrypted heartbeat failed")?;
            }
            frame = ws_receiver.next() => {
                let Some(frame) = frame else {
                    return Err(anyhow!("gateway websocket closed"));
                };

                let frame = frame.context("gateway websocket read failed")?;
                last_received = Instant::now();
                handle_gateway_frame(connection, &cipher, frame).await;
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
) {
    match frame {
        WsMessage::Ping(_) | WsMessage::Pong(_) => {
            close_gateway_connection(connection, "received unencrypted websocket control frame");
        }
        WsMessage::Close(_) => close_gateway_connection(connection, "gateway websocket closed"),
        frame => match decrypt_gateway_frame(cipher, frame) {
            Ok((TunnelFrameKind::Text, bytes)) => match std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| decode_message(text).ok())
            {
                Some(message) => handle_gateway_message(connection, message).await,
                None => warn!("failed to decode encrypted gateway text message"),
            },
            Ok((TunnelFrameKind::Binary, bytes)) => {
                let frame_len = bytes.len();
                if let Some((stream_id, payload)) = decode_data_frame_owned(bytes) {
                    if let Some(tx) = connection
                        .http_body_streams
                        .get(&stream_id)
                        .map(|entry| entry.value().clone())
                    {
                        if tx.send(Ok(Bytes::from(payload.into_vec()))).await.is_err() {
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
                        return;
                    }

                    if let Some(tx) = connection
                        .tcp_streams
                        .get(&stream_id)
                        .map(|entry| entry.value().clone())
                    {
                        if tx.send(payload).await.is_err() {
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
                        warn!(stream_id, "received binary frame for unknown stream");
                    }
                } else {
                    warn!(
                        len = frame_len,
                        "received invalid binary frame from gateway"
                    );
                }
            }
            Err(err) => warn!(error = %err, "failed to decrypt gateway websocket frame"),
        },
    }
}

fn encrypt_access_message(cipher: &TunnelCipher, message: WsMessage) -> Result<WsMessage> {
    match message {
        WsMessage::Text(text) => Ok(WsMessage::Binary(
            cipher.encrypt_from_access(TunnelFrameKind::Text, text.as_bytes())?,
        )),
        WsMessage::Binary(bytes) => Ok(WsMessage::Binary(
            cipher.encrypt_from_access(TunnelFrameKind::Binary, &bytes)?,
        )),
        control => Ok(control),
    }
}

fn decrypt_gateway_frame(
    cipher: &TunnelCipher,
    frame: WsMessage,
) -> Result<(TunnelFrameKind, Vec<u8>)> {
    match frame {
        WsMessage::Binary(bytes) => cipher.decrypt_from_gateway(&bytes),
        other => Err(anyhow!(
            "unexpected unencrypted gateway websocket message: {other:?}"
        )),
    }
}

async fn handle_gateway_message(connection: &GatewayConnection, message: Message) {
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
                let _ = tx.send(Err("stream closed".to_string()));
            }
            if let Some((_, tx)) = connection.http_body_streams.remove(&stream_id) {
                let _ = tx
                    .send(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "stream closed",
                    )))
                    .await;
            }
            if let Some((_, tx)) = connection.open_waiters.remove(&stream_id) {
                let _ = tx.send(Err("stream closed".to_string()));
            }
            if let Some((_, tx)) = connection.http_waiters.remove(&stream_id) {
                let _ = tx.send(Err("stream closed".to_string()));
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
            let error = format!("{code}: {message}");
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
                    let _ = tx.send(Err(io::Error::other(error))).await;
                }
            } else {
                warn!(error = %error, "gateway error");
            }
        }
        Message::Ping => {
            let _ = send_text(connection, &Message::Pong).await;
        }
        Message::Pong => {}
        other => warn!(?other, "unexpected gateway message"),
    }
}

pub(crate) async fn send_text(connection: &GatewayConnection, message: &Message) -> Result<()> {
    ensure_gateway_open(connection)?;
    if let Err(err) = connection
        .outbound
        .send(WsMessage::Text(encode_message(message)?))
        .await
    {
        close_gateway_connection(connection, "gateway outbound channel closed");
        return Err(err.into());
    }
    Ok(())
}

pub(crate) async fn send_binary(connection: &GatewayConnection, frame: Vec<u8>) -> Result<()> {
    ensure_gateway_open(connection)?;
    if let Err(err) = connection.outbound.send(WsMessage::Binary(frame)).await {
        close_gateway_connection(connection, "gateway outbound channel closed");
        return Err(err.into());
    }
    Ok(())
}

fn ensure_gateway_open(connection: &GatewayConnection) -> Result<()> {
    if connection.closed.load(Ordering::Acquire) || connection.outbound.is_closed() {
        return Err(anyhow!("gateway disconnected"));
    }

    Ok(())
}

pub(crate) async fn ensure_gateway_ready(connection: &GatewayConnection) -> Result<()> {
    if ensure_gateway_open(connection).is_ok() {
        return Ok(());
    }

    request_gateway_reconnect(connection);

    let wait_connected = async {
        loop {
            if ensure_gateway_open(connection).is_ok() {
                return;
            }
            connection.connected.notified().await;
        }
    };

    match timeout(GATEWAY_READY_TIMEOUT, wait_connected).await {
        Ok(()) => ensure_gateway_open(connection),
        Err(_) => Err(anyhow!("gateway disconnected")),
    }
}

pub(crate) async fn stop_gateway_connections(connections: &GatewayConnections, reason: &str) {
    for pool in &connections.pools {
        for connection in &pool.connections {
            connection.stopped.store(true, Ordering::Release);
            connection.reconnect_now.notify_waiters();
            let _ = connection.outbound.send(WsMessage::Close(None)).await;
            close_gateway_connection(connection, reason);
        }
    }
}

pub(crate) fn is_gateway_disconnected_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.to_string().as_str(),
            "gateway disconnected"
                | "gateway websocket closed"
                | "gateway websocket write failed"
                | "gateway error gateway websocket closed"
                | "gateway error gateway websocket write failed"
        )
    })
}

fn request_gateway_reconnect(connection: &GatewayConnection) {
    if !connection.stopped.load(Ordering::Acquire) {
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

    request_gateway_reconnect(connection);

    connection.tcp_streams.clear();

    let open_waiters = connection
        .open_waiters
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for stream_id in open_waiters {
        if let Some((_, tx)) = connection.open_waiters.remove(&stream_id) {
            let _ = tx.send(Err(reason.to_string()));
        }
    }

    let http_waiters = connection
        .http_waiters
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for stream_id in http_waiters {
        if let Some((_, tx)) = connection.http_waiters.remove(&stream_id) {
            let _ = tx.send(Err(reason.to_string()));
        }
    }

    let http_head_waiters = connection
        .http_head_waiters
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for stream_id in http_head_waiters {
        if let Some((_, tx)) = connection.http_head_waiters.remove(&stream_id) {
            let _ = tx.send(Err(reason.to_string()));
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

    warn!(server_url = %connection.server_url, reason = %reason, "gateway connection closed");
}

fn decode_gateway_message(cipher: &TunnelCipher, message: WsMessage) -> Result<Message> {
    let (kind, bytes) = decrypt_gateway_frame(cipher, message)?;
    if kind != TunnelFrameKind::Text {
        return Err(anyhow!("expected encrypted gateway text message"));
    }
    Ok(decode_message(std::str::from_utf8(&bytes)?)?)
}

pub(crate) fn next_stream_id(connection: &GatewayConnection) -> StreamId {
    connection.stream_ids.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use ws_net_common::{decode_data_frame, encode_data_frame};

    use super::{push_ws_message, ws_message_size};

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
