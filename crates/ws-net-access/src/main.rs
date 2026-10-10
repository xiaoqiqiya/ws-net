use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use ws_net_common::AccessConfig;

mod app;
mod config_reload;
mod gateway;
mod http;
mod listeners;
mod tcp;

use app::{default_server_url, AccessRuntime, AppState};
use config_reload::watch_access_config;
use gateway::connect_all_registered;
use listeners::{Listeners, PreparedListeners};

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
    let config_path = PathBuf::from(&args.config)
        .canonicalize()
        .context("无法确定 access 配置文件路径")?;
    let config = AccessConfig::load(&config_path).context("加载 access 配置失败")?;
    let bound_listeners = PreparedListeners::new(&config.listeners)?.bind().await?;
    let runtime = AccessRuntime::new()?;
    let connections = connect_all_registered(&config, &runtime).await?;
    let default_server_url = default_server_url(&config);
    for listener in &config.listeners {
        connections
            .for_listener(listener, default_server_url.as_deref())
            .with_context(|| format!("监听器“{}”的网关配置校验失败", listener.name))?;
    }
    let state = AppState {
        default_server_url,
        connections,
        runtime,
    };

    let listeners = Listeners::start(state.clone(), bound_listeners);
    tracing::info!(path = %config_path.display(), "客户端配置已加载，开始监测配置变化");
    tokio::spawn(watch_access_config(config_path, config, state, listeners));

    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
