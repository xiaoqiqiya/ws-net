use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    str::FromStr,
};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::Mode;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub gateway: GatewaySection,
    pub auth: GatewayAuth,
    #[serde(default)]
    pub users: Vec<GatewayUser>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GatewaySection {
    pub listen: String,
    #[serde(default = "default_tunnel_path")]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayAuth {
    pub access_token: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_single_access")]
    pub single_access: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayUser {
    pub name: String,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_access: Option<bool>,
    #[serde(default)]
    pub allow: Vec<String>,
}

impl GatewayUser {
    pub fn single_access(&self, auth: &GatewayAuth) -> bool {
        self.single_access.unwrap_or(auth.single_access)
    }

    pub fn rules(&self) -> Result<Vec<AccessRule>> {
        self.allow.iter().map(|rule| rule.parse()).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessRule {
    Any,
    Address { ip: IpAddr, port: Option<u16> },
}

impl FromStr for AccessRule {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if value == "*" {
            return Ok(Self::Any);
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("访问规则必须为 IP:port、IP:* 或 *"))?;
        let host = if host.starts_with('[') && host.ends_with(']') {
            &host[1..host.len() - 1]
        } else {
            if host.contains(':') {
                bail!("IPv6 访问规则必须使用 [地址]:port 格式");
            }
            host
        };
        let ip = host
            .parse()
            .map_err(|_| anyhow::anyhow!("访问规则包含非法 IP 地址"))?;
        let port = if port == "*" {
            None
        } else {
            if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) {
                bail!("访问规则包含非法端口");
            }
            let port: u16 = port
                .parse()
                .map_err(|_| anyhow::anyhow!("端口必须为 1～65535"))?;
            if port == 0 {
                bail!("端口必须为 1～65535");
            }
            Some(port)
        };
        Ok(Self::Address { ip, port })
    }
}

impl AccessRule {
    pub fn allows(&self, address: SocketAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Address { ip, port } => {
                *ip == address.ip() && port.is_none_or(|port| port == address.port())
            }
        }
    }

    pub fn covers(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) => true,
            (
                Self::Address { ip, port },
                Self::Address {
                    ip: other_ip,
                    port: other_port,
                },
            ) => ip == other_ip && (port.is_none() || port == other_port),
            _ => false,
        }
    }
}

pub fn validate_username(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.chars().any(char::is_control) {
        bail!("用户名不能为空、纯空白或包含控制字符");
    }
    Ok(())
}

fn default_single_access() -> bool {
    true
}

fn config_parse_error(content: &str, error: toml::de::Error) -> anyhow::Error {
    // Parser diagnostics can contain the offending string, including a Token.
    let line = error.span().map(|span| {
        1 + content.as_bytes()[..span.start.min(content.len())]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
    });
    match line {
        Some(line) => anyhow::anyhow!("配置格式错误（第 {line} 行），请检查 TOML 语法及字段类型"),
        None => anyhow::anyhow!("配置格式错误，请检查 TOML 语法及字段类型"),
    }
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
    #[serde(default)]
    pub user_token: Option<String>,
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
        let config: Self =
            toml::from_str(&content).map_err(|error| config_parse_error(&content, error))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.auth.access_token.trim().is_empty() {
            bail!("共享 access_token 不能为空");
        }
        self.gateway
            .listen
            .parse::<SocketAddr>()
            .map_err(|_| anyhow::anyhow!("gateway.listen 必须为合法的 IP:port"))?;
        if !self.gateway.path.starts_with('/') || self.gateway.path.contains(['?', '#']) {
            bail!("gateway.path 必须为以 / 开头的路径");
        }
        for (index, user) in self.users.iter().enumerate() {
            validate_username(&user.name)?;
            if user.token.trim().is_empty() {
                bail!("用户“{}”的 Token 不能为空", user.name);
            }
            if user.token == self.auth.access_token {
                bail!("用户 Token 不能与共享 Token 相同");
            }
            if self.users[..index]
                .iter()
                .any(|previous| previous.name == user.name)
            {
                bail!("用户“{}”重复", user.name);
            }
            if self.users[..index]
                .iter()
                .any(|previous| previous.token == user.token)
            {
                bail!("用户“{}”的 Token 与其他用户重复", user.name);
            }
            user.rules()
                .map_err(|err| anyhow::anyhow!("用户“{}”的访问规则错误：{err}", user.name))?;
        }
        Ok(())
    }
}

impl AccessConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self =
            toml::from_str(&content).map_err(|error| config_parse_error(&content, error))?;
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
                .ok_or_else(|| anyhow::anyhow!("未鉴权：请在 access 配置中填写 Token"))?;
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
                    user_token: None,
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
            bail!("access 至少需要配置一个网关");
        }

        for gateway in &gateways {
            if gateway.name.is_empty() {
                bail!("网关名称不能为空");
            }
            if gateway.server_url.is_empty() {
                bail!("网关“{}”的 server_url 不能为空", gateway.name);
            }
            if gateway.token.trim().is_empty() {
                bail!("未鉴权：网关“{}”的 Token 不能为空", gateway.name);
            }
            if gateway
                .user_token
                .as_ref()
                .is_some_and(|token| token.trim().is_empty())
            {
                bail!("未鉴权：网关“{}”的 user_token 不能为空", gateway.name);
            }
        }

        for (index, gateway) in gateways.iter().enumerate() {
            if gateways[..index]
                .iter()
                .any(|candidate| candidate.name == gateway.name)
            {
                bail!("网关名称“{}”重复", gateway.name);
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
                    "监听器“{}”不能同时配置 gateway 和 server_url",
                    listener.name
                );
            }

            if let Some(gateway_name) = gateway_name {
                if !gateways.iter().any(|gateway| gateway.name == gateway_name) {
                    bail!(
                        "监听器“{}”引用了不存在的网关“{}”",
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
                        "监听器“{}”引用了不存在的网关“{}”",
                        listener.name,
                        server_url
                    );
                }
            } else if !has_default_gateway {
                bail!("监听器“{}”必须指定 gateway 或 server_url", listener.name);
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
    fn parse_diagnostics_locate_error_without_echoing_token() {
        let content = "[gateway]\nlisten = \"127.0.0.1:8443\"\n[auth]\naccess_token = \"shared\"\nenabled = \"private-token-must-not-be-logged\"\n";
        let error = toml::from_str::<GatewayConfig>(content).unwrap_err();
        let message = config_parse_error(content, error).to_string();
        assert!(message.contains("第 5 行"));
        assert!(!message.contains("private-token"));
    }

    #[test]
    fn user_defaults_overrides_rules_and_validation() {
        let mut config: GatewayConfig = toml::from_str(
            r#"
            [gateway]
            listen = "127.0.0.1:8443"
            [auth]
            enabled = true
            access_token = "shared"
            single_access = false
            [[users]]
            name = "研发 李四"
            token = "user"
            allow = ["192.168.1.20:*", "127.0.0.1:22", "[::1]:443"]
        "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.users[0].single_access, None);
        assert!(!config.users[0].single_access(&config.auth));
        config.users[0].single_access = Some(true);
        assert!(config.users[0].single_access(&config.auth));
        config.auth.single_access = true;
        config.users[0].single_access = Some(false);
        assert!(!config.users[0].single_access(&config.auth));
        let rules = config.users[0].rules().unwrap();
        for address in ["192.168.1.20:3306", "127.0.0.1:22", "[::1]:443"] {
            assert!(rules
                .iter()
                .any(|rule| rule.allows(address.parse().unwrap())));
        }
        assert!(!rules
            .iter()
            .any(|rule| rule.allows("127.0.0.1:3306".parse().unwrap())));
        for bad in [
            "",
            "host:22",
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "127.0.0.1:+22",
            "::1:22",
            "10.0.0.0/24:*",
        ] {
            assert!(bad.parse::<AccessRule>().is_err(), "{bad}");
        }
        assert!("*".parse::<AccessRule>().unwrap().covers(&rules[0]));
        assert!(rules[0].covers(&"192.168.1.20:22".parse().unwrap()));
        config.users.push(config.users[0].clone());
        assert!(config.validate().is_err());
        config.users.pop();
        config.users[0].token = "shared".into();
        assert!(config.validate().is_err());
        assert!(validate_username(" \t").is_err());
        assert!(validate_username("张\n三").is_err());
    }

    #[test]
    fn named_gateway_user_token_is_optional_and_validated() {
        let mut config: AccessConfig = toml::from_str(
            r#"
            [access]
            [[gateways]]
            name = "a"
            server_url = "ws://a/tunnel"
            token = "gateway-a"
            user_token = "same-user"
            [[gateways]]
            name = "b"
            server_url = "ws://b/tunnel"
            token = "gateway-b"
            user_token = "same-user"
        "#,
        )
        .unwrap();
        let gateways = config.gateway_configs().unwrap();
        assert_ne!(gateways[0].token, gateways[1].token);
        assert_eq!(gateways[0].user_token.as_deref(), Some("same-user"));
        assert_eq!(gateways[0].user_token, gateways[1].user_token);
        config.gateways[0].user_token = None;
        assert!(config.gateway_configs().unwrap()[0].user_token.is_none());
        config.gateways[0].user_token = Some(" ".into());
        assert!(config
            .gateway_configs()
            .unwrap_err()
            .to_string()
            .contains("user_token"));
    }

    #[test]
    fn legacy_gateway_and_cross_gateway_same_token_remain_valid() {
        let config: GatewayConfig = toml::from_str(
            r#"
            [gateway]
            listen = "127.0.0.1:8443"
            [auth]
            access_token = "shared"
        "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert!(!config.auth.enabled);
        assert!(config.auth.single_access);
        let config: AccessConfig = toml::from_str(
            r#"
            [access]
            [[gateways]]
            name = "a"
            server_url = "ws://a/tunnel"
            token = "same"
            [[gateways]]
            name = "b"
            server_url = "ws://b/tunnel"
            token = "same"
        "#,
        )
        .unwrap();
        assert_eq!(config.gateway_configs().unwrap().len(), 2);
    }

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
                    user_token: None,
                },
                AccessGatewayConfig {
                    name: "west".to_string(),
                    server_url: "wss://west.example/tunnel".to_string(),
                    token: "west-token".to_string(),
                    user_token: None,
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
