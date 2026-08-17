use std::{io, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, TcpStream},
    sync::{mpsc, watch},
    time::Instant,
};
use tracing::{info, warn};
use ws_net_common::{
    new_data_frame_buffer, DataFramePayload, Message, TargetConfig, DATA_FRAME_HEADER_LEN,
};

use crate::ws::{send_error, send_text, Outbound};

const TCP_BUFFER_SIZE: usize = 64 * 1024;
const TCP_STREAM_CHANNEL_CAPACITY: usize = 64;
const TCP_SLOW_IO: Duration = Duration::from_millis(20);

pub(crate) type TcpStreams = Arc<DashMap<u64, mpsc::Sender<DataFramePayload>>>;
pub(crate) type TcpStreamCancels = Arc<DashMap<u64, watch::Sender<()>>>;

pub(crate) async fn handle_tcp_stream(
    stream_id: u64,
    target_name: String,
    target: TargetConfig,
    outbound: Outbound,
    streams: TcpStreams,
    cancels: TcpStreamCancels,
    cancel_rx: watch::Receiver<()>,
) {
    if let Err(err) = handle_tcp_stream_result(
        stream_id,
        target_name,
        target,
        &outbound,
        &streams,
        cancel_rx,
    )
    .await
    {
        let _ = send_error(
            &outbound,
            Some(stream_id),
            "TCP_TARGET_ERROR",
            &err.to_string(),
        )
        .await;
    }
    streams.remove(&stream_id);
    cancels.remove(&stream_id);
    let _ = send_text(
        &outbound,
        &Message::Close {
            stream_id,
            reason: "target_closed".to_string(),
        },
    )
    .await;
}

async fn handle_tcp_stream_result(
    stream_id: u64,
    target_name: String,
    target: TargetConfig,
    outbound: &Outbound,
    streams: &TcpStreams,
    mut cancel_rx: watch::Receiver<()>,
) -> Result<()> {
    let session_started = Instant::now();
    let addr = format!("{}:{}", target.host, target.port);
    let socket = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connect target {addr}"))?;
    socket.set_nodelay(true)?;
    info!(stream_id, target = %target_name, addr = %addr, "tcp target connected");

    let (write_tx, mut write_rx) = mpsc::channel::<DataFramePayload>(TCP_STREAM_CHANNEL_CAPACITY);
    streams.insert(stream_id, write_tx);
    send_text(outbound, &Message::OpenOk { stream_id }).await?;

    let (mut tcp_read, mut tcp_write) = socket.into_split();
    let mut target_read_closed = false;
    let mut access_closed = false;
    let mut target_frames = 0_u64;
    let mut target_bytes = 0_u64;
    let mut access_frames = 0_u64;
    let mut access_bytes = 0_u64;
    let mut max_outbound_wait_ms = 0_u128;
    let mut max_target_write_ms = 0_u128;

    let result: Result<()> = async {
        loop {
            tokio::select! {
                _ = cancel_rx.changed() => {
                    info!(stream_id, target = %target_name, "tcp stream canceled by access close");
                    break;
                }
                read = read_data_frame(&mut tcp_read, stream_id), if !target_read_closed => {
                    let frame = read?;
                    let Some(frame) = frame else {
                        target_read_closed = true;
                        let _ = send_text(outbound, &Message::TcpEof { stream_id }).await;
                        if access_closed {
                            break;
                        }
                        continue;
                    };
                    target_frames += 1;
                    target_bytes += frame.len().saturating_sub(DATA_FRAME_HEADER_LEN) as u64;
                    let send_started = Instant::now();
                    outbound.send(axum::extract::ws::Message::Binary(frame)).await?;
                    let send_elapsed = send_started.elapsed();
                    max_outbound_wait_ms = max_outbound_wait_ms.max(send_elapsed.as_millis());
                    if send_elapsed >= TCP_SLOW_IO {
                        warn!(
                            stream_id,
                            target = %target_name,
                            wait_ms = send_elapsed.as_millis(),
                            "slow target-to-websocket channel send"
                        );
                    }
                }
                bytes = write_rx.recv(), if !access_closed => {
                    let Some(bytes) = bytes else {
                        info!(stream_id, target = %target_name, "tcp stream access side closed");
                        access_closed = true;
                        tcp_write.shutdown().await?;
                        if target_read_closed {
                            break;
                        }
                        continue;
                    };
                    access_frames += 1;
                    access_bytes += bytes.as_slice().len() as u64;
                    let write_started = Instant::now();
                    tcp_write.write_all(bytes.as_slice()).await?;
                    let write_elapsed = write_started.elapsed();
                    max_target_write_ms = max_target_write_ms.max(write_elapsed.as_millis());
                    if write_elapsed >= TCP_SLOW_IO {
                        warn!(
                            stream_id,
                            target = %target_name,
                            write_ms = write_elapsed.as_millis(),
                            "slow websocket-to-target tcp write"
                        );
                    }
                }
                else => break,
            }
        }

        Ok(())
    }
    .await;

    info!(
        stream_id,
        target = %target_name,
        elapsed_ms = session_started.elapsed().as_millis(),
        target_frames,
        target_bytes,
        access_frames,
        access_bytes,
        max_outbound_wait_ms,
        max_target_write_ms,
        ok = result.is_ok(),
        "tcp target session ended"
    );

    result
}

async fn read_data_frame(reader: &mut OwnedReadHalf, stream_id: u64) -> Result<Option<Vec<u8>>> {
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
