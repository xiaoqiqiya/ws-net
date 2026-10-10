use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use tokio::time::{interval, sleep, MissedTickBehavior};
use tracing::{info, warn};
use ws_net_common::AccessConfig;

use crate::{
    app::{default_server_url, AppState},
    gateway::{connect_all_registered, stop_gateway_connections},
    listeners::{Listeners, PreparedListeners},
};

const ACCESS_CONFIG_RELOAD_INTERVAL: Duration = Duration::from_secs(2);
const ACCESS_CONFIG_RELOAD_DEBOUNCE: Duration = Duration::from_millis(300);

pub(crate) async fn watch_access_config(
    config_path: PathBuf,
    mut config: AccessConfig,
    mut state: AppState,
    mut listeners: Listeners,
) {
    let mut last_modified = config_modified_at(&config_path).ok();
    let mut reload_interval = interval(ACCESS_CONFIG_RELOAD_INTERVAL);
    reload_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        reload_interval.tick().await;
        let modified = match config_modified_at(&config_path) {
            Ok(modified) => modified,
            Err(err) => {
                warn!(path = %config_path.display(), error = %err, "无法读取 access 配置文件状态");
                continue;
            }
        };

        if last_modified == Some(modified) {
            continue;
        }

        last_modified = Some(modified);
        sleep(ACCESS_CONFIG_RELOAD_DEBOUNCE).await;

        match reload_access_config(&config_path, &mut config, &mut state, &mut listeners).await {
            Ok(()) => info!(path = %config_path.display(), "配置重新加载成功"),
            Err(err) => {
                warn!(path = %config_path.display(), error = %format!("{err:#}"), "配置重新加载失败")
            }
        }
    }
}

fn config_modified_at(config_path: &PathBuf) -> Result<SystemTime> {
    Ok(std::fs::metadata(config_path)?.modified()?)
}

async fn reload_access_config(
    config_path: &PathBuf,
    current_config: &mut AccessConfig,
    state: &mut AppState,
    listeners: &mut Listeners,
) -> Result<()> {
    let config = AccessConfig::load(config_path).context("加载 access 配置失败")?;
    let prepared = PreparedListeners::new(&config.listeners)?;
    let previous = PreparedListeners::new(&current_config.listeners)?;
    for gateway in config.gateway_configs()? {
        state.runtime.identity(
            &gateway.server_url,
            &gateway.token,
            gateway.user_token.as_deref(),
        )?;
    }

    // Release old sockets before binding so address swaps and HTTP/HTTPS changes also work.
    listeners.stop().await;
    stop_gateway_connections(&state.connections, "access 配置正在重新加载").await;
    let replacement = async {
        let bound = prepared.bind().await?;
        let connections = connect_all_registered(&config, &state.runtime).await?;
        Ok::<_, anyhow::Error>((bound, connections))
    }
    .await;
    let (bound, connections) = match replacement {
        Ok(replacement) => replacement,
        Err(error) => {
            let restored = previous.bind().await.with_context(|| {
                format!("新配置应用失败（{error:#}），旧监听器恢复也失败，请检查端口占用后重新加载或重启客户端")
            })?;
            state.connections = connect_all_registered(current_config, &state.runtime)
                .await
                .context("恢复原配置的网关连接失败")?;
            *listeners = Listeners::start(state.clone(), restored);
            return Err(error.context("已恢复原配置的监听器"));
        }
    };
    state.connections = connections;
    state.default_server_url = default_server_url(&config);
    *listeners = Listeners::start(state.clone(), bound);
    *current_config = config;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::{io::AsyncReadExt, net::TcpListener, net::TcpStream, time::timeout};

    struct ConfigFile(PathBuf);

    impl ConfigFile {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "ws-net-reload-{}.toml",
                ws_net_common::random_id().unwrap()
            )))
        }

        fn write(&self, listeners: &[(&str, SocketAddr, &str)]) {
            let mut content = String::from(
                "[access]\ngateway_pool_size = 1\n[[gateways]]\nname = 'test'\nserver_url = 'ws://127.0.0.1:9/tunnel'\ntoken = 'test'\n",
            );
            for (name, address, mode) in listeners {
                content.push_str(&format!(
                    "[[listeners]]\nname = '{name}'\nmode = '{mode}'\nlisten = '{address}'\nhost = '127.0.0.1'\nport = 9\n"
                ));
            }
            std::fs::write(&self.0, content).unwrap();
        }
    }

    impl Drop for ConfigFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    async fn start(file: &ConfigFile) -> (AccessConfig, AppState, Listeners) {
        let config = AccessConfig::load(&file.0).unwrap();
        let runtime = crate::app::AccessRuntime::new().unwrap();
        let state = AppState {
            default_server_url: default_server_url(&config),
            connections: connect_all_registered(&config, &runtime).await.unwrap(),
            runtime,
        };
        let bound = PreparedListeners::new(&config.listeners)
            .unwrap()
            .bind()
            .await
            .unwrap();
        let listeners = Listeners::start(state.clone(), bound);
        (config, state, listeners)
    }

    async fn reload(
        file: &ConfigFile,
        config: &mut AccessConfig,
        state: &mut AppState,
        listeners: &mut Listeners,
    ) -> Result<()> {
        timeout(
            Duration::from_secs(3),
            reload_access_config(&file.0, config, state, listeners),
        )
        .await
        .expect("重载不能等待已有连接结束")
    }

    #[tokio::test]
    async fn reload_adds_renames_swaps_protocols_and_removes_listeners() {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let third = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = first.local_addr().unwrap();
        let b = second.local_addr().unwrap();
        let c = third.local_addr().unwrap();
        drop((first, second, third));

        let file = ConfigFile::new();
        file.write(&[("tcp", a, "tcp"), ("http", b, "http")]);
        let (mut config, mut state, mut listeners) = start(&file).await;
        let mut idle_http = TcpStream::connect(b).await.unwrap();

        file.write(&[
            ("renamed", b, "tcp"),
            ("http", a, "http"),
            ("new", c, "tcp"),
        ]);
        reload(&file, &mut config, &mut state, &mut listeners)
            .await
            .unwrap();
        let closed = timeout(Duration::from_secs(1), idle_http.read(&mut [0; 1]))
            .await
            .unwrap();
        assert!(matches!(closed, Ok(0) | Err(_)), "旧 HTTP 连接必须关闭");
        for address in [a, b, c] {
            assert!(TcpStream::connect(address).await.is_ok());
        }

        file.write(&[("renamed", c, "tcp")]);
        reload(&file, &mut config, &mut state, &mut listeners)
            .await
            .unwrap();
        assert!(TcpListener::bind(a).await.is_ok());
        assert!(TcpListener::bind(b).await.is_ok());
        assert!(TcpStream::connect(c).await.is_ok());

        file.write(&[]);
        reload(&file, &mut config, &mut state, &mut listeners)
            .await
            .unwrap();
        assert!(TcpListener::bind(c).await.is_ok());
        listeners.stop().await;
        stop_gateway_connections(&state.connections, "test complete").await;
    }

    #[tokio::test]
    async fn failed_bind_releases_partial_bindings_and_restores_old_listener() {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old = first.local_addr().unwrap();
        let new = second.local_addr().unwrap();
        drop((first, second));
        let file = ConfigFile::new();
        file.write(&[("original", old, "tcp")]);
        let (mut config, mut state, mut listeners) = start(&file).await;

        file.write(&[
            ("new", new, "tcp"),
            ("occupied", occupied.local_addr().unwrap(), "http"),
        ]);
        let error = reload(&file, &mut config, &mut state, &mut listeners)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("已恢复原配置"));
        assert_eq!(config.listeners[0].name, "original");
        assert!(TcpStream::connect(old).await.is_ok());
        assert!(TcpListener::bind(new).await.is_ok());

        drop(occupied);
        reload(&file, &mut config, &mut state, &mut listeners)
            .await
            .unwrap();
        assert!(TcpListener::bind(old).await.is_ok());
        assert!(TcpStream::connect(new).await.is_ok());
        listeners.stop().await;
        stop_gateway_connections(&state.connections, "test complete").await;
    }

    #[tokio::test]
    async fn invalid_https_and_duplicate_names_leave_old_listener_running() {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old = first.local_addr().unwrap();
        drop(first);
        let file = ConfigFile::new();
        file.write(&[("original", old, "http")]);
        let (mut config, mut state, mut listeners) = start(&file).await;
        let old_connections = state.connections.clone();

        file.write(&[("https", old, "http")]);
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&file.0)
                .unwrap(),
            "local_scheme = 'https'\nauto_cert = false"
        )
        .unwrap();
        assert!(reload(&file, &mut config, &mut state, &mut listeners)
            .await
            .is_err());
        file.write(&[("same", old, "tcp"), ("same", old, "http")]);
        assert!(reload(&file, &mut config, &mut state, &mut listeners)
            .await
            .is_err());
        assert!(std::sync::Arc::ptr_eq(&old_connections, &state.connections));
        assert!(TcpStream::connect(old).await.is_ok());
        assert_eq!(config.listeners[0].name, "original");
        listeners.stop().await;
        stop_gateway_connections(&state.connections, "test complete").await;
    }

    #[tokio::test]
    async fn reload_switches_http_and_https_on_same_port_and_closes_idle_tls() {
        crate::install_rustls_crypto_provider();
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = first.local_addr().unwrap();
        drop(first);
        let file = ConfigFile::new();
        file.write(&[("web", address, "http")]);
        let (mut config, mut state, mut listeners) = start(&file).await;
        *state.connections.pools[0].connections[0]
            .identity
            .blocked
            .lock()
            .unwrap() = Some(ws_net_common::GatewayError::unauthorized());

        async fn request(address: SocketAddr) -> String {
            use tokio::io::AsyncWriteExt;
            let mut socket = TcpStream::connect(address).await.unwrap();
            socket
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut bytes = Vec::new();
            timeout(Duration::from_secs(2), socket.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            String::from_utf8(bytes).unwrap()
        }

        assert!(request(address).await.starts_with("HTTP/1.1 401"));
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&file.0)
                .unwrap(),
            "local_scheme = 'https'\nauto_cert = true"
        )
        .unwrap();
        reload(&file, &mut config, &mut state, &mut listeners)
            .await
            .unwrap();
        let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        ));
        let error = timeout(
            Duration::from_secs(2),
            tls.connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(address).await.unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        // Receiving a self-signed certificate proves the listener has switched to TLS.
        assert!(
            matches!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ),
            "{error}"
        );
        let mut idle_tls = TcpStream::connect(address).await.unwrap();

        file.write(&[("renamed", address, "http")]);
        reload(&file, &mut config, &mut state, &mut listeners)
            .await
            .unwrap();
        assert!(request(address).await.starts_with("HTTP/1.1 401"));
        let closed = timeout(Duration::from_secs(1), idle_tls.read(&mut [0; 1]))
            .await
            .unwrap();
        assert!(matches!(closed, Ok(0) | Err(_)), "旧 TLS 连接必须关闭");
        listeners.stop().await;
        stop_gateway_connections(&state.connections, "test complete").await;
    }
}
