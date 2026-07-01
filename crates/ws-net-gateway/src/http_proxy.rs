use std::collections::HashSet;

use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use ws_net_common::{HttpRequestHead, HttpResponseHead, TargetConfig};

use crate::app::AppState;

pub(crate) async fn handle_http_request(
    state: &AppState,
    target: &TargetConfig,
    request: HttpRequestHead,
    body_rx: mpsc::Receiver<Result<Bytes, std::io::Error>>,
    on_response_head: impl FnOnce(HttpResponseHead) -> BoxFuture<'static, Result<()>>,
    mut on_body_chunk: impl FnMut(Bytes) -> BoxFuture<'static, Result<()>>,
) -> Result<()> {
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
    let body = reqwest::Body::wrap_stream(ReceiverStream::new(body_rx));
    builder = builder.header("host", &target.host).body(body);

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
    on_response_head(HttpResponseHead { status, headers }).await?;

    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        on_body_chunk(chunk?).await?;
    }

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
