use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{routing::get, Router};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;
use ws_net_common::GatewayConfig;

mod app;
mod http_proxy;
mod tcp;
mod ws;

use app::AppState;
use ws::ws_entry;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, default_value = "gateway.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_crypto_provider();
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    let config = Arc::new(GatewayConfig::load(&args.config).context("load gateway config")?);
    let state = AppState::new(config.clone())?;

    let app = Router::new()
        .route(&config.gateway.path, get(ws_entry))
        .with_state(state);

    let listener = TcpListener::bind(&config.gateway.listen).await?;
    info!(listen = %config.gateway.listen, path = %config.gateway.path, "gateway listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
