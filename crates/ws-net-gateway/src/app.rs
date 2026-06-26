use std::sync::Arc;

use anyhow::Result;
use ws_net_common::GatewayConfig;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<GatewayConfig>,
    pub(crate) http: reqwest::Client,
    pub(crate) http_insecure: reqwest::Client,
}

impl AppState {
    pub(crate) fn new(config: Arc<GatewayConfig>) -> Result<Self> {
        Ok(Self {
            config,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            http_insecure: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .danger_accept_invalid_certs(true)
                .build()?,
        })
    }
}
