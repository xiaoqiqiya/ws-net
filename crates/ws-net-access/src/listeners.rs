use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tracing::error;
use ws_net_common::{ListenerConfig, Mode};

use crate::{
    app::AppState,
    http::{listener_tls_acceptor, run_http_listener},
    tcp::run_tcp_listener,
};

pub(crate) struct PreparedListeners(Vec<(ListenerConfig, Option<TlsAcceptor>)>);

pub(crate) struct BoundListener {
    config: ListenerConfig,
    socket: TcpListener,
    tls: Option<TlsAcceptor>,
}

pub(crate) struct Listeners {
    shutdown: watch::Sender<()>,
    tasks: JoinSet<()>,
}

impl PreparedListeners {
    pub(crate) fn new(configs: &[ListenerConfig]) -> Result<Self> {
        let mut names = HashSet::new();
        let mut listeners = Vec::new();
        for config in configs {
            if config.name.trim().is_empty() || !names.insert(&config.name) {
                bail!("监听器名称不能为空或重复：{}", config.name);
            }
            let tls = if config.mode == Mode::Http {
                listener_tls_acceptor(config)?
            } else {
                None
            };
            listeners.push((config.clone(), tls));
        }
        Ok(Self(listeners))
    }

    pub(crate) async fn bind(self) -> Result<Vec<BoundListener>> {
        let mut listeners = Vec::new();
        for (config, tls) in self.0 {
            let socket = TcpListener::bind(&config.listen)
                .await
                .with_context(|| format!("监听器“{}”无法绑定 {}", config.name, config.listen))?;
            listeners.push(BoundListener {
                config,
                socket,
                tls,
            });
        }
        Ok(listeners)
    }
}

impl Listeners {
    pub(crate) fn start(state: AppState, listeners: Vec<BoundListener>) -> Self {
        let (shutdown, _) = watch::channel(());
        let mut tasks = JoinSet::new();
        for listener in listeners {
            let state = state.clone();
            let shutdown = shutdown.subscribe();
            tasks.spawn(async move {
                let name = listener.config.name.clone();
                let result = match listener.config.mode {
                    Mode::Tcp => {
                        run_tcp_listener(state, listener.config, listener.socket, shutdown).await
                    }
                    Mode::Http => {
                        run_http_listener(
                            state,
                            listener.config,
                            listener.socket,
                            listener.tls,
                            shutdown,
                        )
                        .await
                    }
                };
                if let Err(error) = result {
                    error!(name, error = %error, "监听器已停止");
                }
            });
        }
        Self { shutdown, tasks }
    }

    pub(crate) async fn stop(&mut self) {
        self.shutdown.send_replace(());
        while let Some(result) = self.tasks.join_next().await {
            if let Err(error) = result {
                error!(error = %error, "监听任务退出异常");
            }
        }
    }
}
