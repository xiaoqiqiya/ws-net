use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, Weak,
};
use std::{collections::HashMap, io};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use ws_net_common::{
    access_credential_id, random_id, AccessConfig, DataFramePayload, GatewayError,
    HttpResponseHead, HttpResponsePayload, ListenerConfig, StreamId,
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) default_server_url: Option<String>,
    pub(crate) connections: Arc<GatewayConnections>,
    pub(crate) runtime: Arc<AccessRuntime>,
}

pub(crate) struct AccessRuntime {
    pub(crate) instance_id: String,
    identities: Mutex<HashMap<(String, String), Arc<AccessIdentity>>>,
}

pub(crate) struct AccessIdentity {
    pub(crate) blocked: Mutex<Option<GatewayError>>,
    pub(crate) changed: Notify,
    pub(crate) connections: Mutex<Vec<Weak<GatewayConnection>>>,
}

impl AccessRuntime {
    pub(crate) fn new() -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            instance_id: random_id()?,
            identities: Mutex::new(HashMap::new()),
        }))
    }

    pub(crate) fn identity(
        &self,
        server_url: &str,
        token: &str,
        user_token: Option<&str>,
    ) -> Result<Arc<AccessIdentity>> {
        let url = url::Url::parse(server_url).map_err(|_| anyhow!("网关地址格式错误"))?;
        if !matches!(url.scheme(), "ws" | "wss") || url.host_str().is_none() {
            return Err(anyhow!("网关地址必须使用 ws 或 wss，并包含主机地址"));
        }
        let key = (url.to_string(), access_credential_id(token, user_token));
        Ok(self
            .identities
            .lock()
            .expect("identity registry poisoned")
            .entry(key)
            .or_insert_with(|| {
                Arc::new(AccessIdentity {
                    blocked: Mutex::new(None),
                    changed: Notify::new(),
                    connections: Mutex::new(Vec::new()),
                })
            })
            .clone())
    }
}

impl AccessIdentity {
    pub(crate) fn error(&self) -> Option<GatewayError> {
        self.blocked.lock().expect("identity lock poisoned").clone()
    }

    pub(crate) async fn cancelled(&self) -> GatewayError {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(error) = self.error() {
                return error;
            }
            notified.await;
        }
    }
}

pub(crate) struct GatewayConnection {
    pub(crate) server_url: String,
    pub(crate) identity: Arc<AccessIdentity>,
    pub(crate) outbound: mpsc::Sender<WsMessage>,
    pub(crate) closed: AtomicBool,
    pub(crate) stopped: AtomicBool,
    pub(crate) reconnect_requested: AtomicBool,
    pub(crate) reconnect_now: Notify,
    pub(crate) connected: Notify,
    pub(crate) stream_ids: AtomicU64,
    pub(crate) tcp_streams: DashMap<StreamId, mpsc::Sender<DataFramePayload>>,
    pub(crate) open_waiters: DashMap<StreamId, oneshot::Sender<Result<(), GatewayError>>>,
    pub(crate) http_waiters:
        DashMap<StreamId, oneshot::Sender<Result<HttpResponsePayload, GatewayError>>>,
    pub(crate) http_head_waiters:
        DashMap<StreamId, oneshot::Sender<Result<HttpResponseHead, GatewayError>>>,
    pub(crate) http_body_streams: DashMap<StreamId, mpsc::Sender<Result<Bytes, io::Error>>>,
    pub(crate) unknown_streams: DashMap<StreamId, ()>,
}

pub(crate) struct GatewayConnections {
    pub(crate) pools: Vec<GatewayConnectionPool>,
}

pub(crate) struct GatewayConnectionPool {
    pub(crate) gateway_name: String,
    pub(crate) server_url: String,
    pub(crate) connections: Vec<Arc<GatewayConnection>>,
    next: AtomicUsize,
}

impl GatewayConnections {
    pub(crate) fn new(pools: Vec<GatewayConnectionPool>) -> Result<Self> {
        if pools.is_empty() {
            return Err(anyhow!("没有可用的网关连接池"));
        }

        Ok(Self { pools })
    }

    pub(crate) fn for_listener(
        &self,
        listener: &ListenerConfig,
        default_server_url: Option<&str>,
    ) -> Result<Arc<GatewayConnection>> {
        let gateway_name = listener
            .gateway
            .as_deref()
            .map(str::trim)
            .filter(|gateway_name| !gateway_name.is_empty());
        let listener_server_url = listener
            .server_url
            .as_deref()
            .map(str::trim)
            .filter(|server_url| !server_url.is_empty());

        if gateway_name.is_some() && listener_server_url.is_some() {
            return Err(anyhow!(
                "监听器“{}”不能同时配置 gateway 和 server_url",
                listener.name
            ));
        }

        let server_url = listener_server_url.or(default_server_url);

        match (gateway_name, server_url, self.pools.as_slice()) {
            (Some(gateway_name), _, _) => self
                .pools
                .iter()
                .find(|pool| pool.gateway_name == gateway_name)
                .map(GatewayConnectionPool::next_connection)
                .ok_or_else(|| {
                    anyhow!(
                        "监听器“{}”引用了不存在的网关“{}”",
                        listener.name,
                        gateway_name
                    )
                }),
            (None, Some(server_url), _) => self
                .pools
                .iter()
                .find(|pool| pool.server_url == server_url)
                .map(GatewayConnectionPool::next_connection)
                .ok_or_else(|| {
                    anyhow!(
                        "监听器“{}”引用了不存在的网关“{}”",
                        listener.name,
                        server_url
                    )
                }),
            (None, None, [pool]) => Ok(pool.next_connection()),
            (None, None, _) => Err(anyhow!(
                "监听器“{}”必须指定 gateway 或 server_url",
                listener.name
            )),
        }
    }
}

impl GatewayConnectionPool {
    pub(crate) fn new(
        gateway_name: String,
        server_url: String,
        connections: Vec<Arc<GatewayConnection>>,
    ) -> Result<Self> {
        if connections.is_empty() {
            return Err(anyhow!("网关连接池“{server_url}”没有连接"));
        }

        Ok(Self {
            gateway_name,
            server_url,
            connections,
            next: AtomicUsize::new(0),
        })
    }

    fn next_connection(&self) -> Arc<GatewayConnection> {
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let mut best: Option<Arc<GatewayConnection>> = None;
        let mut best_load = usize::MAX;
        let mut best_capacity = 0;

        for offset in 0..self.connections.len() {
            let connection = &self.connections[(start + offset) % self.connections.len()];
            if !connection.closed.load(Ordering::Acquire) && !connection.outbound.is_closed() {
                let load = connection_load(connection);
                let capacity = connection.outbound.capacity();
                if best.is_none()
                    || load < best_load
                    || (load == best_load && capacity > best_capacity)
                {
                    best = Some(connection.clone());
                    best_load = load;
                    best_capacity = capacity;
                }
            }
        }

        best.unwrap_or_else(|| self.connections[start % self.connections.len()].clone())
    }
}

fn connection_load(connection: &GatewayConnection) -> usize {
    connection.tcp_streams.len()
        + connection.open_waiters.len()
        + connection.http_waiters.len()
        + connection.http_head_waiters.len()
        + connection.http_body_streams.len()
}

pub(crate) fn default_server_url(config: &AccessConfig) -> Option<String> {
    if !config.gateways.is_empty() {
        return match config.gateways.as_slice() {
            [gateway] => Some(gateway.server_url.trim().to_string()),
            _ => None,
        };
    }

    let legacy_default = config
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

    legacy_default.or_else(|| {
        let gateways = config.gateway_configs().ok()?;
        match gateways.as_slice() {
            [gateway] => Some(gateway.server_url.clone()),
            _ => None,
        }
    })
}
