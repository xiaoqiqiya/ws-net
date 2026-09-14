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
};

const ACCESS_CONFIG_RELOAD_INTERVAL: Duration = Duration::from_secs(2);
const ACCESS_CONFIG_RELOAD_DEBOUNCE: Duration = Duration::from_millis(300);

pub(crate) async fn watch_access_config(config_path: PathBuf, state: AppState) {
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

        match reload_access_config(&config_path, &state).await {
            Ok(()) => info!(path = %config_path.display(), "配置重新加载成功"),
            Err(err) => {
                warn!(path = %config_path.display(), error = %err, "配置重新加载失败，继续使用原配置")
            }
        }
    }
}

fn config_modified_at(config_path: &PathBuf) -> Result<SystemTime> {
    Ok(std::fs::metadata(config_path)?.modified()?)
}

async fn reload_access_config(config_path: &PathBuf, state: &AppState) -> Result<()> {
    let config = AccessConfig::load(config_path).context("加载 access 配置失败")?;
    let default_server_url = default_server_url(&config);

    let current_config = state.config.read().await;
    let mut effective_config = config.clone();
    for listener in &current_config.listeners {
        if !config
            .listeners
            .iter()
            .any(|candidate| candidate.name == listener.name)
        {
            effective_config.listeners.push(listener.clone());
        }
    }
    drop(current_config);
    // Existing listeners keep their original route if removed from the file.
    // Reject a broken fallback before spawning replacement connections.
    effective_config.gateway_configs()?;
    let connections = connect_all_registered(&config, &state.runtime).await?;

    let old_connections = {
        let mut current_connections = state.connections.write().await;
        std::mem::replace(&mut *current_connections, connections)
    };
    stop_gateway_connections(&old_connections, "access 配置已重新加载").await;

    *state.config.write().await = config;
    *state.default_server_url.write().await = default_server_url;

    Ok(())
}
