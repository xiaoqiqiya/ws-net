use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    sync::mpsc,
    time::{interval, sleep, timeout, Instant, MissedTickBehavior},
};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{info, warn};
use ws_net_common::{
    decode_data_frame_owned, decode_message, encode_message, AccessConfig, Message, StreamId,
};

use crate::app::{GatewayConnection, GatewayConnectionPool, GatewayConnections};

const GATEWAY_PING_INTERVAL: Duration = Duration::from_secs(20);
const GATEWAY_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn connect_all_registered(
    config: &AccessConfig,
) -> Result<Arc<GatewayConnections>> {
    let mut pools = Vec::new();
    let pool_size = config.access.gateway_pool_size.max(1);

    for server_url in config.server_urls() {
        let connections = (0..pool_size)
            .map(|_| start_gateway_connection(config, server_url.clone()))
            .collect::<Vec<_>>();
        pools.push(GatewayConnectionPool::new(server_url, connections)?);
    }

    Ok(Arc::new(GatewayConnections::new(pools)?))
}

fn start_gateway_connection(config: &AccessConfig, server_url: String) -> Arc<GatewayConnection> {
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
    });

    tokio::spawn(run_gateway_connection(
        connection.clone(),
        config.access.token.clone(),
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
    let (ws, _) = connect_async(server_url.as_str()).await?;
    let (mut ws_sender, mut ws_receiver) = ws.split();

    ws_sender
        .send(WsMessage::Text(encode_message(&Message::RegisterAccess {
            token: token.to_string(),
        })?))
        .await?;

    let Some(frame) = ws_receiver.next().await else {
        return Err(anyhow!("gateway closed before RegisterOk"));
    };

    match decode_ws_message(frame?)? {
        Message::RegisterOk => {}
        Message::Error { code, message, .. } => {
            return Err(anyhow!("gateway error {code}: {message}"))
        }
        other => return Err(anyhow!("unexpected register response: {other:?}")),
    }

    connection.closed.store(false, Ordering::Release);
    connection.connected.notify_waiters();
    info!(server_url = %server_url, "gateway connected");

    let mut heartbeat = interval(GATEWAY_PING_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_received = Instant::now();

    loop {
        tokio::select! {
            _ = connection.reconnect_now.notified(), if connection.stopped.load(Ordering::Acquire) => {
                return Err(anyhow!("gateway connection stopped"));
            }
            _ = heartbeat.tick() => {
                if last_received.elapsed() > GATEWAY_READ_IDLE_TIMEOUT {
                    return Err(anyhow!("gateway websocket read idle timeout"));
                }

                ws_sender
                    .send(WsMessage::Ping(Vec::new()))
                    .await
                    .context("gateway websocket heartbeat failed")?;
            }
            message = outbound_rx.recv() => {
                let Some(message) = message else {
                    return Err(anyhow!("gateway outbound channel closed"));
                };

                ws_sender
                    .send(message)
                    .await
                    .context("gateway websocket write failed")?;
            }
            frame = ws_receiver.next() => {
                let Some(frame) = frame else {
                    return Err(anyhow!("gateway websocket closed"));
                };

                let frame = frame.context("gateway websocket read failed")?;
                last_received = Instant::now();
                handle_gateway_frame(connection, frame).await;
            }
        }
    }
}

async fn handle_gateway_frame(connection: &GatewayConnection, frame: WsMessage) {
    match frame {
        WsMessage::Text(text) => match decode_message(&text) {
            Ok(message) => handle_gateway_message(connection, message).await,
            Err(err) => warn!(error = %err, "failed to decode gateway text message"),
        },
        WsMessage::Binary(bytes) => {
            if let Some((stream_id, payload)) = decode_data_frame_owned(bytes) {
                if let Some(tx) = connection
                    .tcp_streams
                    .get(&stream_id)
                    .map(|entry| entry.value().clone())
                {
                    if tx.try_send(payload).is_err() {
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
                }
            }
        }
        WsMessage::Ping(payload) => {
            let _ = connection.outbound.send(WsMessage::Pong(payload)).await;
        }
        WsMessage::Pong(_) => {}
        WsMessage::Close(_) => {
            close_gateway_connection(connection, "gateway websocket closed");
        }
        _ => {}
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
        Message::Close { stream_id, .. } => {
            connection.tcp_streams.remove(&stream_id);
            if let Some((_, tx)) = connection.open_waiters.remove(&stream_id) {
                let _ = tx.send(Err("stream closed".to_string()));
            }
            if let Some((_, tx)) = connection.http_waiters.remove(&stream_id) {
                let _ = tx.send(Err("stream closed".to_string()));
            }
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
                    let _ = tx.send(Err(error));
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

    warn!(server_url = %connection.server_url, reason = %reason, "gateway connection closed");
}

fn decode_ws_message(message: WsMessage) -> Result<Message> {
    match message {
        WsMessage::Text(text) => Ok(decode_message(&text)?),
        WsMessage::Binary(bytes) => Ok(decode_message(std::str::from_utf8(&bytes)?)?),
        other => Err(anyhow!("unexpected websocket message: {other:?}")),
    }
}

pub(crate) fn next_stream_id(connection: &GatewayConnection) -> StreamId {
    connection.stream_ids.fetch_add(1, Ordering::Relaxed)
}
