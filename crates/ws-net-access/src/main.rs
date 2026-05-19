use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Response, StatusCode},
    response::IntoResponse,
    routing::any,
    Router,
};
use clap::Parser;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{error, info, warn};
use ws_net_common::{
    decode_data_frame, decode_message, encode_data_frame, encode_message, AccessConfig,
    HttpRequestPayload, HttpResponsePayload, ListenerConfig, Message, Mode, StreamId,
};

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, default_value = "access.toml")]
    config: String,
}

#[derive(Clone)]
struct AppState {
    connection: Arc<GatewayConnection>,
}

#[derive(Clone)]
struct HttpListenerState {
    app: AppState,
    listener: ListenerConfig,
}

struct GatewayConnection {
    outbound: mpsc::Sender<WsMessage>,
    stream_ids: AtomicU64,
    tcp_streams: DashMap<StreamId, mpsc::Sender<Vec<u8>>>,
    open_waiters: DashMap<StreamId, oneshot::Sender<Result<(), String>>>,
    http_waiters: DashMap<StreamId, oneshot::Sender<Result<HttpResponsePayload, String>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    let config = Arc::new(AccessConfig::load(&args.config).context("load access config")?);
    let connection = connect_registered(&config).await?;
    let state = AppState { connection };

    for listener in config.listeners.clone() {
        let state = state.clone();
        match listener.mode {
            Mode::Tcp => {
                tokio::spawn(async move {
                    if let Err(err) = run_tcp_listener(state, listener).await {
                        error!(error = %err, "tcp listener stopped");
                    }
                });
            }
            Mode::Http => {
                tokio::spawn(async move {
                    if let Err(err) = run_http_listener(state, listener).await {
                        error!(error = %err, "http listener stopped");
                    }
                });
            }
        }
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn connect_registered(config: &AccessConfig) -> Result<Arc<GatewayConnection>> {
    let (ws, _) = connect_async(config.access.server_url.as_str()).await?;
    let (mut ws_sender, mut ws_receiver) = ws.split();

    ws_sender
        .send(WsMessage::Text(encode_message(&Message::RegisterAccess {
            token: config.access.token.clone(),
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

    let (outbound, mut outbound_rx) = mpsc::channel::<WsMessage>(1024);
    let connection = GatewayConnection {
        outbound: outbound.clone(),
        stream_ids: AtomicU64::new(1),
        tcp_streams: DashMap::new(),
        open_waiters: DashMap::new(),
        http_waiters: DashMap::new(),
    };
    let connection = Arc::new(connection);

    tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            if ws_sender.send(message).await.is_err() {
                break;
            }
        }
    });

    let reader_connection = connection.clone();
    tokio::spawn(async move {
        while let Some(frame) = ws_receiver.next().await {
            match frame {
                Ok(frame) => handle_gateway_frame(&reader_connection, frame).await,
                Err(err) => {
                    warn!(error = %err, "gateway websocket read failed");
                    break;
                }
            }
        }
    });

    Ok(connection)
}

async fn handle_gateway_frame(connection: &GatewayConnection, frame: WsMessage) {
    match frame {
        WsMessage::Text(text) => match decode_message(&text) {
            Ok(message) => handle_gateway_message(connection, message).await,
            Err(err) => warn!(error = %err, "failed to decode gateway text message"),
        },
        WsMessage::Binary(bytes) => {
            if let Some((stream_id, payload)) = decode_data_frame(&bytes) {
                if let Some(tx) = connection
                    .tcp_streams
                    .get(&stream_id)
                    .map(|entry| entry.value().clone())
                {
                    let _ = tx.send(payload).await;
                }
            }
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
        other => warn!(?other, "unexpected gateway message"),
    }
}

async fn run_tcp_listener(state: AppState, listener: ListenerConfig) -> Result<()> {
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
    let stream_id = next_stream_id(&state);
    let target = listener.target_name();
    let target_config = listener.target_config();
    let (open_tx, open_rx) = oneshot::channel();
    state.connection.open_waiters.insert(stream_id, open_tx);

    send_text(
        &state.connection,
        &Message::Open {
            stream_id,
            target,
            config: target_config,
        },
    )
    .await?;

    match open_rx.await? {
        Ok(()) => {}
        Err(err) => return Err(anyhow!("gateway error {err}")),
    }

    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(256);
    state.connection.tcp_streams.insert(stream_id, write_tx);

    let (mut local_read, mut local_write) = socket.into_split();
    let mut local_buf = vec![0_u8; 16 * 1024];

    loop {
        tokio::select! {
            read = local_read.read(&mut local_buf) => {
                let n = read?;
                if n == 0 {
                    send_text(&state.connection, &Message::Close { stream_id, reason: "local_closed".to_string() }).await?;
                    break;
                }
                state.connection.outbound.send(WsMessage::Binary(encode_data_frame(stream_id, &local_buf[..n]))).await?;
            }
            Some(bytes) = write_rx.recv() => {
                local_write.write_all(&bytes).await?;
            }
            else => break,
        }
    }

    state.connection.tcp_streams.remove(&stream_id);
    Ok(())
}

async fn run_http_listener(state: AppState, listener: ListenerConfig) -> Result<()> {
    let addr: SocketAddr = listener.listen.parse()?;
    let http_state = HttpListenerState {
        app: state,
        listener: listener.clone(),
    };
    let app = Router::new()
        .fallback(any(handle_http_request))
        .with_state(http_state);
    let tcp_listener = TcpListener::bind(addr).await?;
    info!(name = %listener.name, listen = %listener.listen, target = %listener.host, port = listener.port, "http listener started");
    axum::serve(tcp_listener, app).await?;
    Ok(())
}

async fn handle_http_request(
    State(state): State<HttpListenerState>,
    request: Request<Body>,
) -> impl IntoResponse {
    match handle_http_request_result(state, request).await {
        Ok(response) => response,
        Err(err) => {
            error!(error = %err, "http proxy request failed");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("gateway request failed: {err}")))
                .unwrap()
        }
    }
}

async fn handle_http_request_result(
    state: HttpListenerState,
    request: Request<Body>,
) -> Result<Response<Body>> {
    let stream_id = next_stream_id(&state.app);
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 32 * 1024 * 1024).await?.to_vec();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|v| v.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();

    let request_payload = HttpRequestPayload {
        method: parts.method.as_str().to_string(),
        path_and_query,
        headers,
        body,
    };

    let target = state.listener.target_name();
    let target_config = state.listener.target_config();
    let (response_tx, response_rx) = oneshot::channel();
    state
        .app
        .connection
        .http_waiters
        .insert(stream_id, response_tx);

    send_text(
        &state.app.connection,
        &Message::HttpRequest {
            stream_id,
            target,
            config: target_config,
            request: request_payload,
        },
    )
    .await?;

    let response = match response_rx.await? {
        Ok(response) => response,
        Err(err) => return Err(anyhow!("gateway error {err}")),
    };

    let mut builder = Response::builder().status(response.status);
    let skip_headers = response_headers_to_skip();
    for (name, value) in response.headers {
        let lower = name.to_ascii_lowercase();
        if skip_headers.contains(lower.as_str()) {
            continue;
        }

        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            builder = builder.header(name, value);
        }
    }
    Ok(builder.body(Body::from(response.body))?)
}

fn response_headers_to_skip() -> HashSet<&'static str> {
    HashSet::from([
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    ])
}

async fn send_text(connection: &GatewayConnection, message: &Message) -> Result<()> {
    connection
        .outbound
        .send(WsMessage::Text(encode_message(message)?))
        .await?;
    Ok(())
}

fn decode_ws_message(message: WsMessage) -> Result<Message> {
    match message {
        WsMessage::Text(text) => Ok(decode_message(&text)?),
        WsMessage::Binary(bytes) => Ok(decode_message(std::str::from_utf8(&bytes)?)?),
        other => Err(anyhow!("unexpected websocket message: {other:?}")),
    }
}

fn next_stream_id(state: &AppState) -> StreamId {
    state.connection.stream_ids.fetch_add(1, Ordering::Relaxed)
}
