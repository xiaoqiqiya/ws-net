use std::sync::Arc;

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};
use tracing::info;
use ws_net_common::{new_data_frame_buffer, DataFramePayload, Message, TargetConfig};

use crate::ws::{send_error, send_text, Outbound};

const TCP_BUFFER_SIZE: usize = 128 * 1024;
const TCP_STREAM_CHANNEL_CAPACITY: usize = 64;

pub(crate) type TcpStreams = Arc<DashMap<u64, mpsc::Sender<DataFramePayload>>>;

pub(crate) async fn handle_tcp_stream(
    stream_id: u64,
    target_name: String,
    target: TargetConfig,
    outbound: Outbound,
    streams: TcpStreams,
) {
    if let Err(err) =
        handle_tcp_stream_result(stream_id, target_name, target, &outbound, &streams).await
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
) -> Result<()> {
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

    loop {
        tokio::select! {
            read = read_data_frame(&mut tcp_read, stream_id) => {
                let frame = read?;
                let Some(frame) = frame else {
                    break;
                };
                outbound.send(axum::extract::ws::Message::Binary(frame)).await?;
            }
            Some(bytes) = write_rx.recv() => {
                tcp_write.write_all(bytes.as_slice()).await?;
            }
            else => break,
        }
    }

    Ok(())
}

async fn read_data_frame<R>(reader: &mut R, stream_id: u64) -> Result<Option<Vec<u8>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut frame = new_data_frame_buffer(stream_id, TCP_BUFFER_SIZE);
    let n = reader.read(&mut frame[8..]).await?;
    if n == 0 {
        return Ok(None);
    }

    frame.truncate(8 + n);
    Ok(Some(frame))
}
