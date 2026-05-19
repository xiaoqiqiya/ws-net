use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
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
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::sleep,
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{error, info, warn};
use ws_net_common::{
    decode_data_frame_owned, decode_message, encode_data_frame, encode_message, AccessConfig,
    DataFramePayload, HttpRequestPayload, HttpResponsePayload, ListenerConfig, Message, Mode,
    StreamId,
};

const TCP_BUFFER_SIZE: usize = 128 * 1024;
const TCP_STREAM_CHANNEL_CAPACITY: usize = 64;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, default_value = "access.toml")]
    config: String,
}

#[derive(Clone)]
struct AppState {
    default_server_url: Option<String>,
    connections: Arc<GatewayConnections>,
}

#[derive(Clone)]
struct HttpListenerState {
    app: AppState,
    listener: ListenerConfig,
}

struct GatewayConnection {
    server_url: String,
    outbound: mpsc::Sender<WsMessage>,
    closed: AtomicBool,
    stream_ids: AtomicU64,
    tcp_streams: DashMap<StreamId, mpsc::Sender<DataFramePayload>>,
    open_waiters: DashMap<StreamId, oneshot::Sender<Result<(), String>>>,
    http_waiters: DashMap<StreamId, oneshot::Sender<Result<HttpResponsePayload, String>>>,
}

struct GatewayConnections {
    pools: Vec<GatewayConnectionPool>,
}

struct GatewayConnectionPool {
    server_url: String,
    connections: Vec<Arc<GatewayConnection>>,
    next: AtomicUsize,
}

impl GatewayConnections {
    fn new(pools: Vec<GatewayConnectionPool>) -> Result<Self> {
        if pools.is_empty() {
            return Err(anyhow!("no gateway connection pools available"));
        }

        Ok(Self { pools })
    }

    fn for_listener(
        &self,
        listener: &ListenerConfig,
        default_server_url: Option<&str>,
    ) -> Result<Arc<GatewayConnection>> {
        let server_url = listener
            .server_url
            .as_deref()
            .map(str::trim)
            .filter(|server_url| !server_url.is_empty())
            .or(default_server_url);

        match (server_url, self.pools.as_slice()) {
            (Some(server_url), _) => self
                .pools
                .iter()
                .find(|pool| pool.server_url == server_url)
                .map(GatewayConnectionPool::next_connection)
                .ok_or_else(|| {
                    anyhow!(
                        "listener '{}' references unavailable gateway '{}'",
                        listener.name,
                        server_url
                    )
                }),
            (None, [pool]) => Ok(pool.next_connection()),
            (None, _) => Err(anyhow!("listener '{}' must set server_url", listener.name)),
        }
    }
}

impl GatewayConnectionPool {
    fn new(server_url: String, connections: Vec<Arc<GatewayConnection>>) -> Result<Self> {
        if connections.is_empty() {
            return Err(anyhow!("gateway pool '{server_url}' has no connections"));
        }

        Ok(Self {
            server_url,
            connections,
            next: AtomicUsize::new(0),
        })
    }

    fn next_connection(&self) -> Arc<GatewayConnection> {
        let start = self.next.fetch_add(1, Ordering::Relaxed);

        for offset in 0..self.connections.len() {
            let connection = &self.connections[(start + offset) % self.connections.len()];
            if !connection.closed.load(Ordering::Acquire) && !connection.outbound.is_closed() {
                return connection.clone();
            }
        }

        self.connections[start % self.connections.len()].clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_crypto_provider();
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    let config = Arc::new(AccessConfig::load(&args.config).context("load access config")?);
    let connections = connect_all_registered(&config).await?;
    let default_server_url = config
        .access
        .server_url
        .as_deref()
        .map(str::trim)
        .and_then(|url| {
            if url.is_empty() {
                None
            } else {
                Some(url.to_string())
            }
        });
    for listener in &config.listeners {
        connections
            .for_listener(listener, default_server_url.as_deref())
            .with_context(|| format!("validate listener '{}' gateway", listener.name))?;
    }
    let state = AppState {
        default_server_url,
        connections,
    };

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

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn connect_all_registered(config: &AccessConfig) -> Result<Arc<GatewayConnections>> {
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
        closed: AtomicBool::new(true),
        stream_ids: AtomicU64::new(1),
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

    loop {
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
        sleep(retry_after).await;
        retry_after = (retry_after * 2).min(Duration::from_secs(30));
    }
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
    info!(server_url = %server_url, "gateway connected");

    loop {
        tokio::select! {
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
    socket.set_nodelay(true)?;

    let connection = state
        .connections
        .for_listener(&listener, state.default_server_url.as_deref())?;
    let stream_id = next_stream_id(&connection);
    ensure_gateway_open(&connection)?;
    let target = listener.target_name();
    let target_config = listener.target_config();
    let (open_tx, open_rx) = oneshot::channel();
    connection.open_waiters.insert(stream_id, open_tx);

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
        return Err(err);
    }

    match open_rx.await? {
        Ok(()) => {}
        Err(err) => return Err(anyhow!("gateway error {err}")),
    }

    let (write_tx, mut write_rx) = mpsc::channel::<DataFramePayload>(TCP_STREAM_CHANNEL_CAPACITY);
    connection.tcp_streams.insert(stream_id, write_tx);

    let (mut local_read, mut local_write) = socket.into_split();
    let mut local_buf = vec![0_u8; TCP_BUFFER_SIZE];

    loop {
        tokio::select! {
            read = local_read.read(&mut local_buf) => {
                let n = read?;
                if n == 0 {
                    send_text(&connection, &Message::Close { stream_id, reason: "local_closed".to_string() }).await?;
                    break;
                }
                send_binary(&connection, stream_id, &local_buf[..n]).await?;
            }
            Some(bytes) = write_rx.recv() => {
                local_write.write_all(bytes.as_slice()).await?;
            }
            else => break,
        }
    }

    connection.tcp_streams.remove(&stream_id);
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

    if listener.local_scheme.as_deref() == Some("https") {
        if !listener.auto_cert {
            return Err(anyhow!(
                "listener '{}' uses local_scheme=https but auto_cert is false",
                listener.name
            ));
        }

        info!(name = %listener.name, listen = %listener.listen, host = %listener.host, target = %listener.host, port = listener.port, "https listener started with in-memory self-signed certificate");
        serve_https_listener(tcp_listener, app, &listener.host).await?;
    } else {
        info!(name = %listener.name, listen = %listener.listen, target = %listener.host, port = listener.port, "http listener started");
        axum::serve(tcp_listener, app).await?;
    }

    Ok(())
}

async fn serve_https_listener(tcp_listener: TcpListener, app: Router, host: &str) -> Result<()> {
    let tls_acceptor = TlsAcceptor::from(Arc::new(self_signed_tls_config(host)?));
    let host = host.to_string();

    loop {
        let (mut socket, peer) = tcp_listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();
        let host = host.clone();

        tokio::spawn(async move {
            if let Err(err) = reject_plain_http_on_https(&mut socket, &host).await {
                warn!(peer = %peer, error = %err, "failed to reject plain http on https listener");
                return;
            }

            let tls_stream = match tls_acceptor.accept(socket).await {
                Ok(stream) => stream,
                Err(err) => {
                    warn!(peer = %peer, error = %err, "tls handshake failed");
                    return;
                }
            };

            let service = TowerToHyperService::new(app);
            let io = TokioIo::new(tls_stream);
            if let Err(err) = HyperBuilder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                warn!(peer = %peer, error = %err, "https connection failed");
            }
        });
    }
}

async fn reject_plain_http_on_https(socket: &mut TcpStream, host: &str) -> Result<()> {
    let mut first = [0_u8; 1];
    let read = socket.peek(&mut first).await?;
    if read == 0 || first[0] == 0x16 {
        return Ok(());
    }

    let response = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nThis listener expects HTTPS. Open https://{host}/ instead of http://{host}/.\r\n"
    );
    socket.write_all(response.as_bytes()).await?;
    Err(anyhow!("plain HTTP request received on HTTPS listener"))
}

fn self_signed_tls_config(host: &str) -> Result<rustls::ServerConfig> {
    let mut params = CertificateParams::new(vec![host.to_string()]);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, host.to_string());
    params
        .subject_alt_names
        .push(SanType::DnsName(host.to_string()));

    let cert = rcgen::Certificate::from_params(params)?;
    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));

    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?)
}

async fn handle_http_request(
    State(state): State<HttpListenerState>,
    request: Request<Body>,
) -> impl IntoResponse {
    match handle_http_request_result(state, request).await {
        Ok(response) => response,
        Err(err) => {
            if is_gateway_disconnected_error(&err) {
                return Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("connection", "close")
                    .body(Body::from("gateway disconnected"))
                    .unwrap();
            }

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
    let connection = state
        .app
        .connections
        .for_listener(&state.listener, state.app.default_server_url.as_deref())?;
    let stream_id = next_stream_id(&connection);
    ensure_gateway_open(&connection)?;
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
    connection.http_waiters.insert(stream_id, response_tx);

    if let Err(err) = send_text(
        &connection,
        &Message::HttpRequest {
            stream_id,
            target,
            config: target_config,
            request: request_payload,
        },
    )
    .await
    {
        connection.http_waiters.remove(&stream_id);
        return Err(err);
    }

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
    ensure_gateway_open(connection)?;
    connection
        .outbound
        .send(WsMessage::Text(encode_message(message)?))
        .await?;
    Ok(())
}

async fn send_binary(
    connection: &GatewayConnection,
    stream_id: StreamId,
    bytes: &[u8],
) -> Result<()> {
    ensure_gateway_open(connection)?;
    connection
        .outbound
        .send(WsMessage::Binary(encode_data_frame(stream_id, bytes)))
        .await?;
    Ok(())
}

fn ensure_gateway_open(connection: &GatewayConnection) -> Result<()> {
    if connection.closed.load(Ordering::Acquire) || connection.outbound.is_closed() {
        return Err(anyhow!("gateway disconnected"));
    }

    Ok(())
}

fn is_gateway_disconnected_error(err: &anyhow::Error) -> bool {
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

fn close_gateway_connection(connection: &GatewayConnection, reason: &str) {
    if connection.closed.swap(true, Ordering::AcqRel) {
        return;
    }

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

fn next_stream_id(connection: &GatewayConnection) -> StreamId {
    connection.stream_ids.fetch_add(1, Ordering::Relaxed)
}
