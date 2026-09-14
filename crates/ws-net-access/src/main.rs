use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::RwLock;
use tracing::error;
use ws_net_common::{AccessConfig, Mode};

mod app;
mod config_reload;
mod gateway;
mod http;
mod tcp;

use app::{default_server_url, AccessRuntime, AppState};
use config_reload::watch_access_config;
use gateway::connect_all_registered;
use http::run_http_listener;
use tcp::run_tcp_listener;

#[derive(Debug, Parser)]
#[command(about = "本地访问客户端")]
struct Args {
    #[arg(short, long, default_value = "access.toml", help = "配置文件路径")]
    config: String,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("客户端启动失败：{error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    install_rustls_crypto_provider();
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    let config_path = PathBuf::from(&args.config);
    let config = AccessConfig::load(&config_path).context("加载 access 配置失败")?;
    let runtime = AccessRuntime::new()?;
    let connections = connect_all_registered(&config, &runtime).await?;
    let default_server_url = default_server_url(&config);
    for listener in &config.listeners {
        connections
            .for_listener(listener, default_server_url.as_deref())
            .with_context(|| format!("监听器“{}”的网关配置校验失败", listener.name))?;
    }
    let state = AppState {
        config: Arc::new(RwLock::new(config.clone())),
        default_server_url: Arc::new(RwLock::new(default_server_url)),
        connections: Arc::new(RwLock::new(connections)),
        runtime,
    };

    tokio::spawn(watch_access_config(config_path, state.clone()));

    for listener in config.listeners.clone() {
        let state = state.clone();
        match listener.mode {
            Mode::Tcp => {
                tokio::spawn(async move {
                    if let Err(err) = run_tcp_listener(state, listener).await {
                        error!(error = %err, "TCP 监听器已停止");
                    }
                });
            }
            Mode::Http => {
                tokio::spawn(async move {
                    if let Err(err) = run_http_listener(state, listener).await {
                        error!(error = %err, "HTTP 监听器已停止");
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
