use std::{io, time::Duration};

use anyhow::{anyhow, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::{timeout, Instant},
};
use tracing::{debug, info, warn};
use ws_net_common::{
    new_data_frame_buffer, DataFramePayload, ListenerConfig, Message, StreamId,
    DATA_FRAME_HEADER_LEN,
};

use crate::{
    app::{current_listener, AppState},
    gateway::{ensure_gateway_ready, next_stream_id, send_binary, send_text},
};

const TCP_BUFFER_SIZE: usize = 64 * 1024;
const TCP_STREAM_CHANNEL_CAPACITY: usize = 64;
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_SLOW_IO: Duration = Duration::from_millis(20);

pub(crate) async fn run_tcp_listener(state: AppState, listener: ListenerConfig) -> Result<()> {
    let tcp_listener = TcpListener::bind(&listener.listen).await?;
    info!(name = %listener.name, listen = %listener.listen, target = %listener.host, port = listener.port, "tcp listener started");

    loop {
        let (socket, peer) = tcp_listener.accept().await?;
        let state = state.clone();
        let listener = listener.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_tcp_connection(state, listener, socket).await {
                warn!(peer = %peer, error = %err, "tcp connection ended");
            }
        });
    }
}

async fn handle_tcp_connection(
    state: AppState,
    listener: ListenerConfig,
    socket: TcpStream,
) -> Result<()> {
    let session_started = Instant::now();
    socket.set_nodelay(true)?;

    let listener = current_listener(&state, &listener).await;
    let default_server_url = state.default_server_url.read().await.clone();
    let connections = state.connections.read().await.clone();
    let connection = connections.for_listener(&listener, default_server_url.as_deref())?;
    let stream_id = next_stream_id(&connection);

    info!(
        stream_id,
        listener = %listener.name,
        gateway = %connection.server_url,
        elapsed_ms = session_started.elapsed().as_millis(),
        "tcp session accepted"
    );

    let gateway_ready_started = Instant::now();
    ensure_gateway_ready(&connection).await?;
    info!(
        stream_id,
        listener = %listener.name,
        elapsed_ms = session_started.elapsed().as_millis(),
        gateway_ready_wait_ms = gateway_ready_started.elapsed().as_millis(),
        "tcp gateway ready"
    );

    let target = listener.target_name();
    let target_config = listener.target_config();
    let (open_tx, open_rx) = oneshot::channel();
    connection.open_waiters.insert(stream_id, open_tx);

    let (write_tx, mut write_rx) = mpsc::channel::<DataFramePayload>(TCP_STREAM_CHANNEL_CAPACITY);
    connection.tcp_streams.insert(stream_id, write_tx);

    let open_send_started = Instant::now();
    if let Err(err) = send_text(
        &connection,
        &Message::Open {
            stream_id,
            target,
            config: target_config,
        },
    )
    .await
    {
        connection.open_waiters.remove(&stream_id);
        connection.tcp_streams.remove(&stream_id);
        return Err(err);
    }

    info!(
        stream_id,
        listener = %listener.name,
        elapsed_ms = session_started.elapsed().as_millis(),
        open_queue_ms = open_send_started.elapsed().as_millis(),
        "tcp OPEN queued"
    );

    let open_wait_started = Instant::now();
    match timeout(STREAM_OPEN_TIMEOUT, open_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(err))) => {
            connection.tcp_streams.remove(&stream_id);
            return Err(anyhow!("gateway error {err}"));
        }
        Ok(Err(_)) => {
            connection.tcp_streams.remove(&stream_id);
            return Err(anyhow!("gateway open waiter canceled"));
        }
        Err(_) => {
            connection.open_waiters.remove(&stream_id);
            connection.tcp_streams.remove(&stream_id);
            let _ = send_text(
                &connection,
                &Message::Close {
                    stream_id,
                    reason: "open_timeout".to_string(),
                },
            )
            .await;
            return Err(anyhow!("gateway open timeout"));
        }
    }

    info!(
        stream_id,
        listener = %listener.name,
        elapsed_ms = session_started.elapsed().as_millis(),
        open_wait_ms = open_wait_started.elapsed().as_millis(),
        "tcp OPEN_OK received; forwarding started"
    );

    let (mut local_read, mut local_write) = socket.into_split();
    let mut local_read_closed = false;
    let mut remote_closed = false;
    let mut local_frame_count = 0_u64;
    let mut remote_frame_count = 0_u64;
    let mut local_bytes = 0_u64;
    let mut remote_bytes = 0_u64;
    let mut max_gateway_queue_ms = 0_u128;
    let mut max_local_write_ms = 0_u128;

    let result: Result<()> = async {
        loop {
        tokio::select! {
            read = read_data_frame(&mut local_read, stream_id), if !local_read_closed => {
                let frame = read?;
                let Some(frame) = frame else {
                    local_read_closed = true;
                    let _ = send_text(&connection, &Message::TcpEof { stream_id }).await;
                    if remote_closed {
                        break;
                    }
                    continue;
                };
                local_frame_count += 1;
                let bytes = frame.len().saturating_sub(DATA_FRAME_HEADER_LEN);
                local_bytes += bytes as u64;
                let queue_started = Instant::now();
                send_binary(&connection, frame).await?;
                let queue_elapsed = queue_started.elapsed();
                max_gateway_queue_ms = max_gateway_queue_ms.max(queue_elapsed.as_millis());
                if queue_elapsed >= TCP_SLOW_IO {
                    warn!(
                        stream_id,
                        listener = %listener.name,
                        queue_ms = queue_elapsed.as_millis(),
                        bytes,
                        "slow local-to-gateway channel send"
                    );
                }
                debug!(
                    stream_id,
                    listener = %listener.name,
                    direction = "local_to_gateway",
                    frame = local_frame_count,
                    bytes,
                    elapsed_ms = session_started.elapsed().as_millis(),
                    queue_ms = queue_elapsed.as_millis(),
                    "tcp data forwarded"
                );
            }
            bytes = write_rx.recv(), if !remote_closed => {
                let Some(bytes) = bytes else {
                    info!(stream_id, listener = %listener.name, "tcp stream remote side closed");
                    remote_closed = true;
                    local_write.shutdown().await?;
                    if local_read_closed {
                        break;
                    }
                    continue;
                };
                remote_frame_count += 1;
                let bytes_len = bytes.as_slice().len();
                remote_bytes += bytes_len as u64;
                let write_started = Instant::now();
                local_write.write_all(bytes.as_slice()).await?;
                let write_elapsed = write_started.elapsed();
                max_local_write_ms = max_local_write_ms.max(write_elapsed.as_millis());
                if write_elapsed >= TCP_SLOW_IO {
                    warn!(
                        stream_id,
                        listener = %listener.name,
                        local_write_ms = write_elapsed.as_millis(),
                        bytes = bytes_len,
                        "slow gateway-to-local tcp write"
                    );
                }
                debug!(
                    stream_id,
                    listener = %listener.name,
                    direction = "gateway_to_local",
                    frame = remote_frame_count,
                    bytes = bytes_len,
                    elapsed_ms = session_started.elapsed().as_millis(),
                    local_write_ms = write_elapsed.as_millis(),
                    "tcp data forwarded"
                );
            }
            else => break,
        }
    }

        Ok(())
    }
    .await;

    connection.tcp_streams.remove(&stream_id);
    info!(
        stream_id,
        listener = %listener.name,
        elapsed_ms = session_started.elapsed().as_millis(),
        local_frames = local_frame_count,
        local_bytes,
        remote_frames = remote_frame_count,
        remote_bytes,
        max_gateway_queue_ms,
        max_local_write_ms,
        ok = result.is_ok(),
        "tcp session forwarding ended"
    );
    let _ = send_text(
        &connection,
        &Message::Close {
            stream_id,
            reason: if result.is_ok() {
                "local_closed".to_string()
            } else {
                "local_error".to_string()
            },
        },
    )
    .await;

    result
}

async fn read_data_frame(
    reader: &mut OwnedReadHalf,
    stream_id: StreamId,
) -> Result<Option<Vec<u8>>> {
    let mut frame = new_data_frame_buffer(stream_id, TCP_BUFFER_SIZE);
    let mut payload_len = reader.read(&mut frame[DATA_FRAME_HEADER_LEN..]).await?;
    if payload_len == 0 {
        return Ok(None);
    }

    while payload_len < TCP_BUFFER_SIZE {
        match reader.try_read(
            &mut frame
                [DATA_FRAME_HEADER_LEN + payload_len..DATA_FRAME_HEADER_LEN + TCP_BUFFER_SIZE],
        ) {
            Ok(0) => break,
            Ok(n) => payload_len += n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err.into()),
        }
    }

    frame.truncate(DATA_FRAME_HEADER_LEN + payload_len);
    Ok(Some(frame))
}
