use std::{collections::HashSet, net::SocketAddr};

use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use ws_net_common::{HttpRequestHead, HttpResponseHead, TargetConfig};

use crate::app::AppState;

pub(crate) async fn handle_http_request(
    _state: &AppState,
    target: &TargetConfig,
    address: Vec<SocketAddr>,
    request: HttpRequestHead,
    body_rx: mpsc::Receiver<Result<Bytes, std::io::Error>>,
    on_response_head: impl FnOnce(HttpResponseHead) -> BoxFuture<'static, Result<()>>,
    mut on_body_chunk: impl FnMut(Bytes) -> BoxFuture<'static, Result<()>>,
) -> Result<()> {
    let scheme = target.scheme.as_deref().unwrap_or("http");
    if !matches!(scheme, "http" | "https") || !request.path_and_query.starts_with('/') {
        anyhow::bail!("HTTP 目标协议或请求路径不合法");
    }
    let host = target.host.trim_start_matches('[').trim_end_matches(']');
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let url = reqwest::Url::parse(&format!(
        "{scheme}://{authority}:{}{}",
        target.port, request.path_and_query
    ))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("HTTP 目标缺少主机"))?;
    let literal = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>();
    if url.port_or_known_default() != Some(target.port)
        || literal.is_ok_and(|ip| !address.contains(&SocketAddr::new(ip, target.port)))
    {
        anyhow::bail!("HTTP 目标与已授权地址不一致");
    }
    // Pin the checked address while preserving the URL hostname for Host/SNI and header rewriting.
    // ponytail: one client per request prevents stale DNS authorization; pool by checked addresses if throughput requires it.
    let http = reqwest::Client::builder()
        .use_native_tls()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .resolve_to_addrs(host, &address)
        .build()?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes())?;
    let mut builder = http.request(method, url.clone());

    let skip_headers = hop_by_hop_headers();
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if skip_headers.contains(lower.as_str()) || lower == "host" {
            continue;
        }
        builder = builder.header(name, value);
    }
    let body = reqwest::Body::wrap_stream(ReceiverStream::new(body_rx));
    builder = builder.header("host", &target.host).body(body);

    let response = builder.send().await?;
    let status = response.status().as_u16();
    tracing::info!(host = %target.host, port = target.port, scheme, status, "目标 HTTP 响应头已接收");
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
    on_response_head(HttpResponseHead { status, headers }).await?;

    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        on_body_chunk(chunk?).await?;
    }

    tracing::info!(host = %target.host, port = target.port, scheme, status, "目标 HTTP 请求处理完成");
    Ok(())
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

pub(crate) fn format_error_chain(err: &anyhow::Error) -> String {
    err.chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}
