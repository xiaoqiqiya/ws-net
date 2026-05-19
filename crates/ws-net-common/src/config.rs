use std::{fs, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::Mode;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub gateway: GatewaySection,
    pub auth: GatewayAuth,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewaySection {
    pub listen: String,
    #[serde(default = "default_tunnel_path")]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayAuth {
    pub access_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TargetConfig {
    pub mode: Mode,
    pub host: String,
    pub port: u16,
    pub scheme: Option<String>,
    #[serde(default)]
    pub accept_invalid_certs: bool,
    #[serde(default)]
    pub rewrite_location: bool,
    #[serde(default)]
    pub rewrite_cookie: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessConfig {
    pub access: AccessSection,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessSection {
    pub token: String,
    pub server_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub mode: Mode,
    pub listen: String,
    pub host: String,
    pub port: u16,
    pub scheme: Option<String>,
    #[serde(default)]
    pub accept_invalid_certs: bool,
    #[serde(default)]
    pub rewrite_location: bool,
    #[serde(default)]
    pub rewrite_cookie: bool,
}

impl ListenerConfig {
    pub fn target_name(&self) -> String {
        self.name.clone()
    }

    pub fn target_config(&self) -> TargetConfig {
        TargetConfig {
            mode: self.mode,
            host: self.host.clone(),
            port: self.port,
            scheme: self.scheme.clone(),
            accept_invalid_certs: self.accept_invalid_certs,
            rewrite_location: self.rewrite_location,
            rewrite_cookie: self.rewrite_cookie,
        }
    }
}

impl GatewayConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}

impl AccessConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}

fn default_tunnel_path() -> String {
    "/tunnel".to_string()
}
