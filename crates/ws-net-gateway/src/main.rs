use std::{collections::HashSet, sync::Arc};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{ws::WebSocketUpgrade, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use clap::Parser;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{info, warn};
use ws_net_common::{
    decode_data_frame_owned, decode_message, encode_message, new_data_frame_buffer,
    DataFramePayload, GatewayConfig, HttpRequestPayload, HttpResponsePayload, Message, Mode,
    TargetConfig,
};

const TCP_BUFFER_SIZE: usize = 128 * 1024;
const TCP_STREAM_CHANNEL_CAPACITY: usize = 64;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, default_value = "gateway.toml")]
    config: String,
}

#[derive(Clone)]
struct AppState {
    config: Arc<GatewayConfig>,
    http: reqwest::Client,
    http_insecure: reqwest::Client,
}

type Outbound = mpsc::Sender<axum::extract::ws::Message>;
type TcpStreams = Arc<DashMap<u64, mpsc::Sender<DataFramePayload>>>;

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_crypto_provider();
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    let config = Arc::new(GatewayConfig::load(&args.config).context("load gateway config")?);
    let state = AppState {
        config: config.clone(),
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        http_insecure: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .build()?,
    };

    let app = Router::new()
        .route(&config.gateway.path, get(ws_entry))
        .with_state(state);

    let listener = TcpListener::bind(&config.gateway.listen).await?;
    info!(listen = %config.gateway.listen, path = %config.gateway.path, "gateway listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn ws_entry(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
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
        while let Some(message) = outbound_rx.recv().await {
            if ws_sender.send(message).await.is_err() {
                break;
            }
        }
    });

    let streams: TcpStreams = Arc::new(DashMap::new());

    while let Some(frame) = ws_receiver.next().await {
        match frame? {
            axum::extract::ws::Message::Text(text) => {
                handle_text_message(&state, &outbound, &streams, &text).await?;
            }
            axum::extract::ws::Message::Binary(bytes) => {
                if let Some((stream_id, payload)) = decode_data_frame_owned(bytes) {
                    if let Some(tx) = streams.get(&stream_id).map(|entry| entry.value().clone()) {
                        let _ = tx.send(payload).await;
                    }
                }
            }
            axum::extract::ws::Message::Close(_) => break,
            _ => {}
        }
    }

    writer.abort();
    Ok(())
}

async fn handle_text_message(
    state: &AppState,
    outbound: &Outbound,
    streams: &TcpStreams,
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
                match handle_http_request(&state, &config, &request).await {
                    Ok(response) => {
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
        Message::Close { stream_id, .. } => {
            streams.remove(&stream_id);
        }
        Message::Ping => {
            send_text(outbound, &Message::Pong).await?;
        }
        other => warn!(?other, "unexpected gateway message"),
    }
    Ok(())
}

async fn handle_tcp_stream(
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

async fn handle_http_request(
    state: &AppState,
    target: &TargetConfig,
    request: &HttpRequestPayload,
) -> Result<HttpResponsePayload> {
    let scheme = target.scheme.as_deref().unwrap_or("http");
    let url = format!(
        "{}://{}:{}{}",
        scheme, target.host, target.port, request.path_and_query
    );
    let method = reqwest::Method::from_bytes(request.method.as_bytes())?;
    let client = if target.accept_invalid_certs {
        &state.http_insecure
    } else {
        &state.http
    };
    let mut builder = client.request(method, &url);

    let skip_headers = hop_by_hop_headers();
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if skip_headers.contains(lower.as_str()) || lower == "host" {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder
        .header("host", &target.host)
        .body(request.body.clone());

    let response = builder.send().await?;
    let status = response.status().as_u16();
    let mut headers = Vec::new();
    let skip_headers = response_headers_to_skip();
    for (name, value) in response.headers() {
        let name = name.as_str().to_string();
        let lower = name.to_ascii_lowercase();
        if skip_headers.contains(lower.as_str()) {
            continue;
        }

        if let Ok(value) = value.to_str() {
            let value = rewrite_header(target, &name, value);
            headers.push((name, value));
        }
    }
    let body = response.bytes().await?.to_vec();

    Ok(HttpResponsePayload {
        status,
        headers,
        body,
    })
}

fn format_error_chain(err: &anyhow::Error) -> String {
    err.chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn rewrite_header(target: &TargetConfig, name: &str, value: &str) -> String {
    if target.rewrite_location && name.eq_ignore_ascii_case("location") {
        let scheme = target.scheme.as_deref().unwrap_or("http");
        let prefix = format!("{}://{}", scheme, target.host);
        if let Some(rest) = value.strip_prefix(&prefix) {
            return rest.to_string();
        }
    }

    if target.rewrite_cookie && name.eq_ignore_ascii_case("set-cookie") {
        return value
            .split(';')
            .filter(|part| {
                let trimmed = part.trim().to_ascii_lowercase();
                !trimmed.starts_with("domain=") && trimmed != "secure"
            })
            .collect::<Vec<_>>()
            .join(";");
    }

    value.to_string()
}

fn hop_by_hop_headers() -> HashSet<&'static str> {
    HashSet::from([
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ])
}

fn response_headers_to_skip() -> HashSet<&'static str> {
    let mut headers = hop_by_hop_headers();
    headers.insert("content-length");
    headers
}

async fn send_text(outbound: &Outbound, message: &Message) -> Result<()> {
    outbound
        .send(axum::extract::ws::Message::Text(encode_message(message)?))
        .await?;
    Ok(())
}

async fn send_error(
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
