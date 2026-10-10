use std::{io, time::Duration};

use anyhow::{anyhow, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::{timeout, Instant},
};
use tracing::{debug, info, warn};
use ws_net_common::{
    new_data_frame_buffer, DataFramePayload, GatewayError, ListenerConfig, Message, StreamId,
    DATA_FRAME_HEADER_LEN,
};

use crate::{
    app::AppState,
    gateway::{ensure_gateway_ready, gateway_closed, next_stream_id, send_binary, send_text},
};

const TCP_BUFFER_SIZE: usize = 64 * 1024;
const TCP_STREAM_CHANNEL_CAPACITY: usize = 64;
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_SLOW_IO: Duration = Duration::from_millis(20);

pub(crate) async fn run_tcp_listener(
    state: AppState,
    listener: ListenerConfig,
    tcp_listener: TcpListener,
    mut shutdown: watch::Receiver<()>,
) -> Result<()> {
    info!(name = %listener.name, listen = %listener.listen, target = %listener.host, port = listener.port, "TCP 监听器已启动");

    let mut sessions = JoinSet::new();
    let result = loop {
        let accepted = tokio::select! {
            biased;
            _ = shutdown.changed() => break Ok(()),
            _ = sessions.join_next(), if !sessions.is_empty() => continue,
            accepted = tcp_listener.accept() => accepted,
        };
        let (socket, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => break Err(error.into()),
        };
        let state = state.clone();
        let listener = listener.clone();
        sessions.spawn(async move {
            if let Err(err) = handle_tcp_connection(state, listener, socket).await {
                match err.downcast_ref::<GatewayError>() {
                    Some(error) if error.code == "UNAUTHORIZED" => {
                        warn!(peer = %peer, code = %error.code, "{}", error.message);
                    }
                    Some(error) if error.terminal() || error.code == "FORBIDDEN" => {}
                    _ => warn!(peer = %peer, error = %err, "TCP 连接结束"),
                }
            }
        });
    };
    sessions.shutdown().await;
    result
}

async fn handle_tcp_connection(
    state: AppState,
    listener: ListenerConfig,
    socket: TcpStream,
) -> Result<()> {
    let session_started = Instant::now();
    socket.set_nodelay(true)?;

    let connection = state
        .connections
        .for_listener(&listener, state.default_server_url.as_deref())?;
    let stream_id = next_stream_id(&connection);

    info!(
        stream_id,
        listener = %listener.name,
        gateway = %connection.server_url,
        elapsed_ms = session_started.elapsed().as_millis(),
        "已接受 TCP 连接"
    );

    let gateway_ready_started = Instant::now();
    ensure_gateway_ready(&connection).await?;
    info!(
        stream_id,
        listener = %listener.name,
        elapsed_ms = session_started.elapsed().as_millis(),
        gateway_ready_wait_ms = gateway_ready_started.elapsed().as_millis(),
        "TCP 所用网关已就绪"
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
        "TCP 建连请求已发送"
    );

    let open_wait_started = Instant::now();
    match timeout(STREAM_OPEN_TIMEOUT, open_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(err))) => {
            connection.tcp_streams.remove(&stream_id);
            return Err(err.into());
        }
        Ok(Err(_)) => {
            connection.tcp_streams.remove(&stream_id);
            return Err(anyhow!("网关建连等待已取消"));
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
            return Err(anyhow!("等待网关建立目标连接超时"));
        }
    }

    info!(
        stream_id,
        listener = %listener.name,
        elapsed_ms = session_started.elapsed().as_millis(),
        open_wait_ms = open_wait_started.elapsed().as_millis(),
        "目标 TCP 连接建立成功，开始转发"
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

    let forwarding = async {
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
                            "本地数据发送到网关耗时较长"
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
                        "TCP 数据已转发"
                    );
                }
                bytes = write_rx.recv(), if !remote_closed => {
                    let Some(bytes) = bytes else {
                        info!(stream_id, listener = %listener.name, "TCP 远端已关闭发送方向");
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
                            "网关数据写入本地 TCP 耗时较长"
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
                        "TCP 数据已转发"
                    );
                }
                else => break,
            }
        }

        Ok(())
    };
    let result: Result<()> = tokio::select! {
        biased;
        error = gateway_closed(&connection) => Err(error.into()),
        result = forwarding => result,
    };

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
        "TCP 会话转发结束"
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
