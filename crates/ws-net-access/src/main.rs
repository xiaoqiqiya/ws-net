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

use app::{default_server_url, AppState};
use config_reload::watch_access_config;
use gateway::connect_all_registered;
use http::run_http_listener;
use tcp::run_tcp_listener;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, default_value = "access.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_crypto_provider();
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    let config_path = PathBuf::from(&args.config);
    let config = AccessConfig::load(&config_path).context("load access config")?;
    let connections = connect_all_registered(&config).await?;
    let default_server_url = default_server_url(&config);
    for listener in &config.listeners {
        connections
            .for_listener(listener, default_server_url.as_deref())
            .with_context(|| format!("validate listener '{}' gateway", listener.name))?;
    }
    let state = AppState {
        config: Arc::new(RwLock::new(config.clone())),
        default_server_url: Arc::new(RwLock::new(default_server_url)),
        connections: Arc::new(RwLock::new(connections)),
    };

    tokio::spawn(watch_access_config(config_path, state.clone()));

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
