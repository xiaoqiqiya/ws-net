use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::timeout,
};
use tracing::{info, warn};
use ws_net_common::{new_data_frame_buffer, DataFramePayload, ListenerConfig, Message, StreamId};

use crate::{
    app::{current_listener, AppState},
    gateway::{ensure_gateway_ready, next_stream_id, send_binary, send_text},
};

const TCP_BUFFER_SIZE: usize = 128 * 1024;
const TCP_STREAM_CHANNEL_CAPACITY: usize = 64;
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

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
    socket.set_nodelay(true)?;

    let listener = current_listener(&state, &listener).await;
    let default_server_url = state.default_server_url.read().await.clone();
    let connections = state.connections.read().await.clone();
    let connection = connections.for_listener(&listener, default_server_url.as_deref())?;
    let stream_id = next_stream_id(&connection);
    ensure_gateway_ready(&connection).await?;
    let target = listener.target_name();
    let target_config = listener.target_config();
    let (open_tx, open_rx) = oneshot::channel();
    connection.open_waiters.insert(stream_id, open_tx);

    let (write_tx, mut write_rx) = mpsc::channel::<DataFramePayload>(TCP_STREAM_CHANNEL_CAPACITY);
    connection.tcp_streams.insert(stream_id, write_tx);

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

    let (mut local_read, mut local_write) = socket.into_split();
    let mut local_read_closed = false;
    let mut remote_closed = false;

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
                send_binary(&connection, frame).await?;
            }
            bytes = write_rx.recv() => {
                let Some(bytes) = bytes else {
                    info!(stream_id, listener = %listener.name, "tcp stream remote side closed");
                    remote_closed = true;
                    local_write.shutdown().await?;
                    if local_read_closed {
                        break;
                    }
                    continue;
                };
                local_write.write_all(bytes.as_slice()).await?;
            }
            else => break,
        }
    }

        Ok(())
    }
    .await;

    connection.tcp_streams.remove(&stream_id);
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
    let n = reader.read(&mut frame[8..]).await?;
    if n == 0 {
        return Ok(None);
    }

    frame.truncate(8 + n);
    Ok(Some(frame))
}
