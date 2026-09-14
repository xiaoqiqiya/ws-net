use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, Weak},
};

use anyhow::{anyhow, Result};
use tokio::sync::watch;
use ws_net_common::{
    credential_id, random_id, valid_id, AccessRule, GatewayConfig, GatewayError, TargetConfig,
};

#[derive(Clone)]
pub(crate) struct AppState {
    inner: Arc<Mutex<Runtime>>,
}

#[derive(Clone)]
struct Credential {
    token: String,
    name: String,
    single: bool,
    rules: Vec<AccessRule>,
}

impl Credential {
    fn forbidden(&self, target: &TargetConfig) -> GatewayError {
        tracing::warn!(
            "访问被拒绝：用户{}无权访问 {}:{}",
            self.name,
            target.host,
            target.port
        );
        GatewayError::new(
            "FORBIDDEN",
            format!("无权访问 {}:{}", target.host, target.port),
        )
    }
}

struct Runtime {
    config: GatewayConfig,
    credentials: HashMap<String, Credential>,
    sessions: HashMap<String, SessionInfo>,
    // ponytail: history grows with instance restarts for this process lifetime; signed session epochs if long-running churn needs a bound.
    orders: HashMap<(String, String), u64>,
    retired: HashSet<(String, String)>,
    next_order: u64,
}

struct SessionInfo {
    credential: String,
    instance: String,
    order: u64,
    signal: watch::Sender<Option<GatewayError>>,
}

pub(crate) struct SessionLease {
    id: String,
    pub(crate) user_name: Option<String>,
    credential: String,
    inner: Weak<Mutex<Runtime>>,
    signal: watch::Sender<Option<GatewayError>>,
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            inner
                .lock()
                .expect("runtime lock poisoned")
                .sessions
                .remove(&self.id);
        }
    }
}

impl SessionLease {
    pub(crate) fn check(&self) -> Result<()> {
        if let Some(error) = self.signal.borrow().clone() {
            return Err(error.into());
        }
        Ok(())
    }

    pub(crate) async fn cancelled(&self) -> GatewayError {
        let mut receiver = self.signal.subscribe();
        loop {
            if let Some(error) = receiver.borrow().clone() {
                return error;
            }
            if receiver.changed().await.is_err() {
                return GatewayError::changed();
            }
        }
    }

    pub(crate) async fn run<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        self.check()?;
        tokio::select! {
            biased;
            error = self.cancelled() => Err(error.into()),
            result = future => result,
        }
    }
}

fn credentials(config: &GatewayConfig) -> Result<HashMap<String, Credential>> {
    config.validate()?;
    let mut credentials = HashMap::new();
    if config.auth.enabled {
        for user in &config.users {
            if credentials
                .insert(
                    credential_id(&user.token),
                    Credential {
                        token: user.token.clone(),
                        name: user.name.clone(),
                        single: user.single_access(&config.auth),
                        rules: user.rules()?,
                    },
                )
                .is_some()
            {
                return Err(anyhow!("凭证选择标识冲突"));
            }
        }
    } else {
        credentials.insert(
            credential_id(&config.auth.access_token),
            Credential {
                token: config.auth.access_token.clone(),
                name: "共享 Token".into(),
                single: false,
                rules: vec![AccessRule::Any],
            },
        );
    }
    Ok(credentials)
}

impl AppState {
    pub(crate) fn new(config: GatewayConfig) -> Result<Self> {
        let credentials = credentials(&config)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Runtime {
                config,
                credentials,
                sessions: HashMap::new(),
                orders: HashMap::new(),
                retired: HashSet::new(),
                next_order: 0,
            })),
        })
    }

    pub(crate) fn config(&self) -> GatewayConfig {
        self.inner
            .lock()
            .expect("runtime lock poisoned")
            .config
            .clone()
    }

    pub(crate) fn bootstrap_tokens(
        &self,
        gateway_id: &str,
        user_id: Option<&str>,
    ) -> Result<(String, Option<String>)> {
        let runtime = self.inner.lock().expect("runtime lock poisoned");
        if credential_id(&runtime.config.auth.access_token) != gateway_id {
            return Err(GatewayError::new(
                "UNAUTHORIZED",
                "未认证：网关鉴权失败，gateway Token 无效或已撤销，连接已拒绝，已停止自动重连。",
            )
            .into());
        }
        let user_token = if runtime.config.auth.enabled {
            Some(runtime.credentials.get(user_id.unwrap_or(""))
                .ok_or_else(|| GatewayError::new("UNAUTHORIZED", "未认证：用户鉴权失败，user_token 未配置、无效或已被撤销，连接已拒绝，已停止自动重连。"))?
                .token.clone())
        } else {
            None
        };
        Ok((runtime.config.auth.access_token.clone(), user_token))
    }

    pub(crate) fn register(
        &self,
        gateway_token: &str,
        user_token: Option<&str>,
        instance: &str,
        legacy: bool,
    ) -> Result<(Arc<SessionLease>, String)> {
        let session_id = random_id()?;
        let mut runtime = self.inner.lock().expect("runtime lock poisoned");
        if gateway_token != runtime.config.auth.access_token
            || (legacy && runtime.config.auth.enabled)
        {
            return Err(GatewayError::unauthorized().into());
        }
        let token = if runtime.config.auth.enabled {
            user_token.ok_or_else(GatewayError::unauthorized)?
        } else {
            gateway_token
        };
        let id = credential_id(token);
        let credential = runtime
            .credentials
            .get(&id)
            .filter(|credential| credential.token == token)
            .cloned()
            .ok_or_else(GatewayError::unauthorized)?;
        if !valid_id(instance) {
            return Err(GatewayError::unauthorized().into());
        }
        let key = (id.clone(), instance.to_string());
        if runtime.retired.contains(&key) {
            return Err(GatewayError::replaced().into());
        }
        if credential.single {
            let previous: Vec<String> = runtime
                .orders
                .keys()
                .filter(|(credential, previous)| credential == &id && previous != instance)
                .map(|(_, previous)| previous.clone())
                .collect();
            for previous in previous {
                runtime.retired.insert((id.clone(), previous));
            }
            for session in runtime.sessions.values() {
                if session.credential == id && session.instance != instance {
                    session.signal.send_replace(Some(GatewayError::replaced()));
                }
            }
        }
        let order = if let Some(order) = runtime.orders.get(&key) {
            *order
        } else {
            runtime.next_order += 1;
            let order = runtime.next_order;
            runtime.orders.insert(key, order);
            order
        };
        let (signal, _) = watch::channel(None);
        runtime.sessions.insert(
            session_id.clone(),
            SessionInfo {
                credential: id.clone(),
                instance: instance.to_string(),
                order,
                signal: signal.clone(),
            },
        );
        Ok((
            Arc::new(SessionLease {
                id: session_id,
                user_name: runtime.config.auth.enabled.then(|| credential.name.clone()),
                credential: id,
                inner: Arc::downgrade(&self.inner),
                signal,
            }),
            credential.name,
        ))
    }

    pub(crate) fn reload(&self, config: GatewayConfig) -> Result<()> {
        let next = credentials(&config)?;
        let mut runtime = self.inner.lock().expect("runtime lock poisoned");
        if runtime.config.gateway != config.gateway {
            return Err(anyhow!(
                "listen 或 path 已修改，需要重启 gateway；本次重载未生效"
            ));
        }
        let gateway_changed = runtime.config.auth.access_token != config.auth.access_token;
        if gateway_changed {
            // Both credentials have changed identity: old gateway-Token histories cannot block a new pair.
            runtime.orders.clear();
            runtime.retired.clear();
        }
        let mut winners = HashMap::<String, (u64, String)>::new();
        for session in runtime.sessions.values() {
            if !gateway_changed
                && session.signal.borrow().is_none()
                && next
                    .get(&session.credential)
                    .is_some_and(|credential| credential.single)
            {
                let winner = winners
                    .entry(session.credential.clone())
                    .or_insert((session.order, session.instance.clone()));
                if session.order > winner.0 {
                    *winner = (session.order, session.instance.clone());
                }
            }
        }
        for (id, (_, instance)) in &winners {
            let previous: Vec<_> = runtime
                .orders
                .keys()
                .filter(|(credential, old)| credential == id && old != instance)
                .cloned()
                .collect();
            runtime.retired.extend(previous);
        }
        for session in runtime.sessions.values() {
            let error = if gateway_changed {
                Some(GatewayError::changed())
            } else {
                match (
                    runtime.credentials.get(&session.credential),
                    next.get(&session.credential),
                ) {
                    (_, None) => Some(GatewayError::changed()),
                    (Some(old), Some(new))
                        if old.name != new.name
                            || !old
                                .rules
                                .iter()
                                .all(|rule| new.rules.iter().any(|new| new.covers(rule))) =>
                    {
                        Some(GatewayError::changed())
                    }
                    (_, Some(_))
                        if winners
                            .get(&session.credential)
                            .is_some_and(|(_, winner)| winner != &session.instance) =>
                    {
                        Some(GatewayError::replaced())
                    }
                    _ => None,
                }
            };
            if session.signal.borrow().is_none() {
                if let Some(error) = error {
                    session.signal.send_replace(Some(error));
                }
            }
        }
        runtime.credentials = next;
        runtime.config = config;
        Ok(())
    }

    pub(crate) async fn authorize_target(
        &self,
        lease: &SessionLease,
        target: &TargetConfig,
    ) -> Result<Vec<SocketAddr>> {
        lease.check()?;
        if target.port == 0 {
            return Err(anyhow!("目标端口必须为 1～65535"));
        }
        {
            let runtime = self.inner.lock().expect("runtime lock poisoned");
            lease.check()?;
            let credential = runtime
                .credentials
                .get(&lease.credential)
                .ok_or_else(GatewayError::unauthorized)?;
            if credential.rules.is_empty() {
                return Err(credential.forbidden(target).into());
            }
        }
        let host = target.host.trim_start_matches('[').trim_end_matches(']');
        let addresses: Vec<_> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, target.port)]
        } else {
            if host.is_empty()
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
            {
                return Err(anyhow!("目标主机地址格式错误"));
            }
            lease
                .run(async {
                    Ok(tokio::net::lookup_host((host, target.port))
                        .await?
                        .collect::<Vec<_>>())
                })
                .await?
        };
        let runtime = self.inner.lock().expect("runtime lock poisoned");
        lease.check()?;
        let credential = runtime
            .credentials
            .get(&lease.credential)
            .ok_or_else(GatewayError::unauthorized)?;
        let addresses: Vec<_> = addresses
            .into_iter()
            .filter(|address| credential.rules.iter().any(|rule| rule.allows(*address)))
            .collect();
        if addresses.is_empty() {
            return Err(credential.forbidden(target).into());
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(single: bool) -> GatewayConfig {
        toml::from_str(&format!(
            r#"
            [gateway]
            listen = "127.0.0.1:8443"
            [auth]
            access_token = "shared"
            enabled = true
            single_access = {single}
            [[users]]
            name = "李四"
            token = "user"
            allow = ["127.0.0.1:*"]
        "#
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn takeover_retirement_reload_and_stale_cleanup() {
        let state = AppState::new(config(false)).unwrap();
        let a = random_id().unwrap();
        let b = random_id().unwrap();
        let (first, _) = state.register("shared", Some("user"), &a, false).unwrap();
        let (second, _) = state.register("shared", Some("user"), &b, false).unwrap();
        let (same_pool, _) = state.register("shared", Some("user"), &a, false).unwrap();
        state.reload(config(true)).unwrap();
        assert!(first.check().is_err());
        assert!(same_pool.check().is_err());
        second.check().unwrap();
        assert_eq!(
            state
                .register("shared", Some("user"), &a, false)
                .err()
                .unwrap()
                .downcast_ref::<GatewayError>()
                .unwrap()
                .code,
            "SESSION_REPLACED"
        );
        drop(first);
        drop(same_pool);
        second.check().unwrap();
        state.reload(config(true)).unwrap();
        second.check().unwrap();
        let c = random_id().unwrap();
        assert!(state.register("shared", Some("wrong"), &c, false).is_err());
        second.check().unwrap();
        let (third, _) = state.register("shared", Some("user"), &c, false).unwrap();
        assert!(second.check().is_err());
        third.check().unwrap();
        let mut narrowed = config(true);
        narrowed.users[0].allow.clear();
        state.reload(narrowed).unwrap();
        assert_eq!(third.cancelled().await.code, "AUTH_CHANGED");
        let mut invalid = config(true);
        invalid.users[0].token = "shared".into();
        assert!(state.reload(invalid).is_err());
        assert_eq!(state.config().users[0].allow.len(), 0);
        let other = AppState::new(config(true)).unwrap();
        other.register("shared", Some("user"), &a, false).unwrap();
    }

    #[tokio::test]
    async fn empty_permissions_reject_before_domain_resolution() {
        let mut config = config(true);
        config.users[0].allow.clear();
        let state = AppState::new(config).unwrap();
        let (lease, _) = state
            .register("shared", Some("user"), &random_id().unwrap(), false)
            .unwrap();
        assert_eq!(lease.user_name.as_deref(), Some("李四"));
        let target = TargetConfig {
            mode: ws_net_common::Mode::Tcp,
            host: "must-not-resolve.invalid".into(),
            port: 22,
            scheme: None,
            accept_invalid_certs: false,
            rewrite_cookie: false,
            rewrite_location: false,
        };
        let error = futures_util::FutureExt::now_or_never(state.authorize_target(&lease, &target))
            .expect("empty permissions must not wait for DNS")
            .unwrap_err();
        let error = error.downcast_ref::<GatewayError>().unwrap();
        assert_eq!(error.code, "FORBIDDEN");
        assert_eq!(error.http_status(), 403);
        assert_eq!(error.message, "无权访问 must-not-resolve.invalid:22");
        assert!(!error.terminal());
        lease.check().unwrap();
    }

    #[tokio::test]
    async fn both_tokens_and_gateway_rotation_enforce_user_identity() {
        let mut config = config(false);
        config.users[0].single_access = Some(true);
        let state = AppState::new(config.clone()).unwrap();
        let a = random_id().unwrap();
        let b = random_id().unwrap();
        let (first, _) = state.register("shared", Some("user"), &a, false).unwrap();
        let (second, _) = state.register("shared", Some("user"), &b, false).unwrap();
        assert_eq!(first.cancelled().await.code, "SESSION_REPLACED");
        for (gateway, user) in [
            ("shared", None),
            ("wrong", Some("user")),
            ("shared", Some("wrong")),
        ] {
            assert!(state.register(gateway, user, &a, false).is_err());
            second.check().unwrap();
        }
        assert!(state
            .bootstrap_tokens(&credential_id("wrong"), Some(&credential_id("user")))
            .is_err());
        assert!(state
            .bootstrap_tokens(&credential_id("shared"), None)
            .is_err());

        config.auth.access_token = "replacement-shared".into();
        state.reload(config).unwrap();
        assert_eq!(second.cancelled().await.code, "AUTH_CHANGED");
        let error = state
            .register("shared", Some("user"), &b, false)
            .err()
            .unwrap();
        assert_eq!(
            error.downcast_ref::<GatewayError>().unwrap().code,
            "UNAUTHORIZED"
        );
        let (replacement, _) = state
            .register("replacement-shared", Some("user"), &a, false)
            .unwrap();
        replacement.check().unwrap();
    }

    #[tokio::test]
    async fn shared_disabled_users_and_exact_target_rules() {
        let mut disabled = config(true);
        disabled.auth.enabled = false;
        let state = AppState::new(disabled).unwrap();
        let (shared_a, _) = state
            .register("shared", None, &random_id().unwrap(), true)
            .unwrap();
        let (shared_b, _) = state
            .register("shared", None, &random_id().unwrap(), true)
            .unwrap();
        shared_a.check().unwrap();
        shared_b.check().unwrap();
        assert!(shared_a.user_name.is_none());
        assert!(shared_b.user_name.is_none());
        assert!(state
            .bootstrap_tokens(
                &credential_id("shared"),
                Some(&credential_id("unused-user"))
            )
            .unwrap()
            .1
            .is_none());
        let target = TargetConfig {
            mode: ws_net_common::Mode::Tcp,
            host: "127.0.0.1".into(),
            port: 22,
            scheme: None,
            accept_invalid_certs: false,
            rewrite_cookie: false,
            rewrite_location: false,
        };
        assert_eq!(
            state.authorize_target(&shared_a, &target).await.unwrap()[0].port(),
            22
        );
        state.reload(config(true)).unwrap();
        assert_eq!(shared_a.cancelled().await.code, "AUTH_CHANGED");
        assert_eq!(shared_b.cancelled().await.code, "AUTH_CHANGED");
        assert!(state
            .register("shared", None, &random_id().unwrap(), false)
            .is_err());
        assert!(state
            .register("shared", Some("user"), &random_id().unwrap(), true)
            .is_err());
        state
            .register("shared", Some("user"), &random_id().unwrap(), false)
            .unwrap();
    }
}
