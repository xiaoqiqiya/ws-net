use std::{fs, path::Path};

use anyhow::{bail, Result};
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
    pub gateways: Vec<AccessGatewayConfig>,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessSection {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub server_urls: Vec<String>,
    #[serde(default = "default_gateway_pool_size")]
    pub gateway_pool_size: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AccessGatewayConfig {
    pub name: String,
    pub server_url: String,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub mode: Mode,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub server_url: Option<String>,
    pub listen: String,
    pub host: String,
    pub port: u16,
    pub scheme: Option<String>,
    #[serde(default)]
    pub local_scheme: Option<String>,
    #[serde(default)]
    pub auto_cert: bool,
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
        let config: Self = toml::from_str(&content)?;
        config.gateway_configs()?;
        Ok(config)
    }

    pub fn gateway_configs(&self) -> Result<Vec<AccessGatewayConfig>> {
        let gateways = if self.gateways.is_empty() {
            let token = self
                .access
                .token
                .as_deref()
                .filter(|token| !token.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("legacy access config requires access.token"))?;
            let mut urls = Vec::new();
            if let Some(server_url) = self.access.server_url.as_ref() {
                let server_url = server_url.trim();
                if !server_url.is_empty() {
                    urls.push(server_url.to_string());
                }
            }
            for server_url in &self.access.server_urls {
                let server_url = server_url.trim();
                if !server_url.is_empty() && !urls.iter().any(|url| url == server_url) {
                    urls.push(server_url.to_string());
                }
            }
            for listener in &self.listeners {
                if let Some(server_url) = listener.server_url.as_ref() {
                    let server_url = server_url.trim();
                    if !server_url.is_empty() && !urls.iter().any(|url| url == server_url) {
                        urls.push(server_url.to_string());
                    }
                }
            }
            urls.into_iter()
                .enumerate()
                .map(|(index, server_url)| AccessGatewayConfig {
                    name: format!("gateway-{}", index + 1),
                    server_url,
                    token: token.to_string(),
                })
                .collect()
        } else {
            self.gateways.clone()
        };

        let mut gateways = gateways;
        for gateway in &mut gateways {
            gateway.name = gateway.name.trim().to_string();
            gateway.server_url = gateway.server_url.trim().to_string();
        }

        if gateways.is_empty() {
            bail!("access config requires at least one gateway");
        }

        for gateway in &gateways {
            if gateway.name.is_empty() {
                bail!("gateway name must not be empty");
            }
            if gateway.server_url.is_empty() {
                bail!("gateway '{}' server_url must not be empty", gateway.name);
            }
            if gateway.token.trim().is_empty() {
                bail!("gateway '{}' token must not be empty", gateway.name);
            }
        }

        for (index, gateway) in gateways.iter().enumerate() {
            if gateways[..index]
                .iter()
                .any(|candidate| candidate.name == gateway.name)
            {
                bail!("duplicate gateway name '{}'", gateway.name);
            }
        }

        let has_default_gateway = gateways.len() == 1
            || (self.gateways.is_empty()
                && self
                    .access
                    .server_url
                    .as_deref()
                    .is_some_and(|server_url| !server_url.trim().is_empty()));
        for listener in &self.listeners {
            let gateway_name = listener
                .gateway
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty());
            let server_url = listener
                .server_url
                .as_deref()
                .map(str::trim)
                .filter(|url| !url.is_empty());

            if gateway_name.is_some() && server_url.is_some() {
                bail!(
                    "listener '{}' must not set both gateway and server_url",
                    listener.name
                );
            }

            if let Some(gateway_name) = gateway_name {
                if !gateways.iter().any(|gateway| gateway.name == gateway_name) {
                    bail!(
                        "listener '{}' references unavailable gateway '{}'",
                        listener.name,
                        gateway_name
                    );
                }
            } else if let Some(server_url) = server_url {
                if !gateways
                    .iter()
                    .any(|gateway| gateway.server_url == server_url)
                {
                    bail!(
                        "listener '{}' references unavailable gateway '{}'",
                        listener.name,
                        server_url
                    );
                }
            } else if !has_default_gateway {
                bail!(
                    "listener '{}' must set gateway or server_url",
                    listener.name
                );
            }
        }

        Ok(gateways)
    }

    pub fn server_urls(&self) -> Vec<String> {
        self.gateway_configs()
            .map(|gateways| {
                gateways
                    .into_iter()
                    .map(|gateway| gateway.server_url)
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn default_tunnel_path() -> String {
    "/tunnel".to_string()
}

fn default_gateway_pool_size() -> usize {
    8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_specific_tokens() {
        let config: AccessConfig = toml::from_str(
            r#"
                [access]
                gateway_pool_size = 2

                [[gateways]]
                name = "east"
                server_url = "wss://east.example/tunnel"
                token = "east-token"

                [[gateways]]
                name = "west"
                server_url = "wss://west.example/tunnel"
                token = "west-token"

                [[listeners]]
                name = "east-db"
                mode = "tcp"
                gateway = "east"
                listen = "127.0.0.1:3308"
                host = "10.0.0.10"
                port = 3306
            "#,
        )
        .unwrap();

        assert_eq!(
            config.gateway_configs().unwrap(),
            vec![
                AccessGatewayConfig {
                    name: "east".to_string(),
                    server_url: "wss://east.example/tunnel".to_string(),
                    token: "east-token".to_string(),
                },
                AccessGatewayConfig {
                    name: "west".to_string(),
                    server_url: "wss://west.example/tunnel".to_string(),
                    token: "west-token".to_string(),
                },
            ]
        );
        assert_eq!(config.listeners[0].gateway.as_deref(), Some("east"));
    }

    #[test]
    fn access_example_uses_valid_gateway_references() {
        let config: AccessConfig =
            toml::from_str(include_str!("../../../access.example.toml")).unwrap();
        let gateways = config.gateway_configs().unwrap();

        assert_eq!(gateways.len(), 2);
        assert!(config
            .listeners
            .iter()
            .all(|listener| listener.gateway.is_some()));
    }

    #[test]
    fn preserves_legacy_single_token_configuration() {
        let config: AccessConfig = toml::from_str(
            r#"
                [access]
                token = "shared-token"
                server_urls = ["ws://a/tunnel", "ws://b/tunnel"]
            "#,
        )
        .unwrap();

        assert_eq!(config.gateway_configs().unwrap()[1].token, "shared-token");
        assert_eq!(config.gateway_configs().unwrap()[1].name, "gateway-2");
    }

    #[test]
    fn rejects_duplicate_gateway_names() {
        let config: AccessConfig = toml::from_str(
            r#"
                [access]
                [[gateways]]
                name = "same"
                server_url = "ws://a/tunnel"
                token = "a"

                [[gateways]]
                name = "same"
                server_url = "ws://b/tunnel"
                token = "b"
            "#,
        )
        .unwrap();

        assert!(config.gateway_configs().is_err());
    }

    #[test]
    fn requires_listener_gateway_when_multiple_gateways_exist() {
        let config: AccessConfig = toml::from_str(
            r#"
                [access]

                [[gateways]]
                name = "east"
                server_url = "ws://east/tunnel"
                token = "east-token"

                [[gateways]]
                name = "west"
                server_url = "ws://west/tunnel"
                token = "west-token"

                [[listeners]]
                name = "ambiguous"
                mode = "tcp"
                listen = "127.0.0.1:3308"
                host = "10.0.0.10"
                port = 3306
            "#,
        )
        .unwrap();

        assert!(config.gateway_configs().is_err());
    }
}
