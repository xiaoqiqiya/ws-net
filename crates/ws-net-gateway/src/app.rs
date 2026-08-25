use std::sync::Arc;

use anyhow::Result;
use ws_net_common::GatewayConfig;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<GatewayConfig>,
    pub(crate) http: reqwest::Client,
}

impl AppState {
    pub(crate) fn new(config: Arc<GatewayConfig>) -> Result<Self> {
        Ok(Self {
            config,
            http: reqwest::Client::builder()
                .use_native_tls()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()?,
        })
    }
}
