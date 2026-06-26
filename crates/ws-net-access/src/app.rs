use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc,
};

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot, Notify, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use ws_net_common::{
    AccessConfig, DataFramePayload, HttpResponsePayload, ListenerConfig, StreamId,
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<RwLock<AccessConfig>>,
    pub(crate) default_server_url: Arc<RwLock<Option<String>>>,
    pub(crate) connections: Arc<RwLock<Arc<GatewayConnections>>>,
}

pub(crate) struct GatewayConnection {
    pub(crate) server_url: String,
    pub(crate) outbound: mpsc::Sender<WsMessage>,
    pub(crate) closed: AtomicBool,
    pub(crate) stopped: AtomicBool,
    pub(crate) reconnect_requested: AtomicBool,
    pub(crate) reconnect_now: Notify,
    pub(crate) connected: Notify,
    pub(crate) stream_ids: AtomicU64,
    pub(crate) tcp_streams: DashMap<StreamId, mpsc::Sender<DataFramePayload>>,
    pub(crate) open_waiters: DashMap<StreamId, oneshot::Sender<Result<(), String>>>,
    pub(crate) http_waiters:
        DashMap<StreamId, oneshot::Sender<Result<HttpResponsePayload, String>>>,
}

pub(crate) struct GatewayConnections {
    pub(crate) pools: Vec<GatewayConnectionPool>,
}

pub(crate) struct GatewayConnectionPool {
    pub(crate) server_url: String,
    pub(crate) connections: Vec<Arc<GatewayConnection>>,
    next: AtomicUsize,
}

impl GatewayConnections {
    pub(crate) fn new(pools: Vec<GatewayConnectionPool>) -> Result<Self> {
        if pools.is_empty() {
            return Err(anyhow!("no gateway connection pools available"));
        }

        Ok(Self { pools })
    }

    pub(crate) fn for_listener(
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
    pub(crate) fn new(
        server_url: String,
        connections: Vec<Arc<GatewayConnection>>,
    ) -> Result<Self> {
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

pub(crate) fn default_server_url(config: &AccessConfig) -> Option<String> {
    config
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
        })
}

pub(crate) async fn current_listener(
    state: &AppState,
    fallback: &ListenerConfig,
) -> ListenerConfig {
    state
        .config
        .read()
        .await
        .listeners
        .iter()
        .find(|listener| listener.name == fallback.name)
        .cloned()
        .unwrap_or_else(|| fallback.clone())
}
