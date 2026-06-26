use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Response, StatusCode},
    response::IntoResponse,
    routing::any,
    Router,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use ws_net_common::{HttpRequestPayload, ListenerConfig, Message};

use crate::{
    app::{current_listener, AppState},
    gateway::{ensure_gateway_ready, is_gateway_disconnected_error, next_stream_id, send_text},
};

#[derive(Clone)]
struct HttpListenerState {
    app: AppState,
    listener: ListenerConfig,
}

pub(crate) async fn run_http_listener(state: AppState, listener: ListenerConfig) -> Result<()> {
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
    let listener = current_listener(&state.app, &state.listener).await;
    let default_server_url = state.app.default_server_url.read().await.clone();
    let connections = state.app.connections.read().await.clone();
    let connection = connections.for_listener(&listener, default_server_url.as_deref())?;
    let stream_id = next_stream_id(&connection);
    ensure_gateway_ready(&connection).await?;
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
