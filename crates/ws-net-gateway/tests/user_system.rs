//! Run after `cargo build --workspace`: actual gateway/access processes, not only mocked state.
use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message as WsMessage},
    MaybeTlsStream, WebSocketStream,
};
use ws_net_common::*;

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(binary: &Path, directory: &Path, args: &[&str], log: &Path) -> Result<Process> {
    let output = fs::File::create(log)?;
    Ok(Process(
        Command::new(binary)
            .current_dir(directory)
            .args(args)
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn()?,
    ))
}

fn free_address() -> SocketAddr {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

async fn wait_listen(address: SocketAddr) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(address).await.is_ok() {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(anyhow!("listener did not start: {address}"));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn echo(address: SocketAddr) -> Result<TcpStream> {
    timeout(Duration::from_secs(12), async {
        let mut socket = TcpStream::connect(address).await?;
        socket.write_all(b"hello").await?;
        let mut response = [0; 5];
        socket.read_exact(&mut response).await?;
        if &response != b"hello" {
            return Err(anyhow!("echo mismatch"));
        }
        Ok(socket)
    })
    .await?
}

async fn http(address: SocketAddr) -> Result<String> {
    timeout(Duration::from_secs(12), async {
        let mut socket = TcpStream::connect(address).await?;
        socket
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = String::new();
        socket.read_to_string(&mut response).await?;
        Ok(response)
    })
    .await?
}

fn gateway_config(address: SocketAddr, allowed: &[SocketAddr]) -> String {
    let allow = allowed
        .iter()
        .map(|address| format!("\"{address}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"# 保留原有注释
[gateway]
listen = "{address}"
[auth]
enabled = true
access_token = "shared"
single_access = true
[[users]]
name = "李四"
token = "user"
allow = [{allow}]
[[users]]
name = "history"
token = "history"
allow = ["*"]
"#
    )
}

fn listener(
    name: &str,
    gateway: &str,
    local: SocketAddr,
    target: SocketAddr,
    mode: &str,
    scheme: &str,
) -> String {
    format!(
        r#"
[[listeners]]
name = "{name}"
gateway = "{gateway}"
mode = "{mode}"
listen = "{local}"
host = "{}"
port = {}
scheme = "{scheme}"
"#,
        target.ip(),
        target.port()
    )
}

struct Peer {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    cipher: TunnelCipher,
}
impl Peer {
    async fn connect(
        address: SocketAddr,
        token: &str,
        instance: &str,
        legacy: bool,
    ) -> Result<Self> {
        Self::connect_register(address, token, instance, legacy, None).await
    }

    async fn connect_register(
        address: SocketAddr,
        token: &str,
        instance: &str,
        legacy: bool,
        public_key: Option<Vec<u8>>,
    ) -> Result<Self> {
        let gateway_token = if legacy { token } else { "shared" };
        Self::connect_tokens(
            address,
            gateway_token,
            (!legacy).then_some(token),
            instance,
            legacy,
            public_key,
        )
        .await
    }

    async fn connect_tokens(
        address: SocketAddr,
        gateway_token: &str,
        user_token: Option<&str>,
        instance: &str,
        legacy: bool,
        public_key: Option<Vec<u8>>,
    ) -> Result<Self> {
        let mut request = format!("ws://{address}/tunnel").into_client_request()?;
        let nonce = random_id()?;
        if !legacy {
            request.headers_mut().insert(PROTOCOL_HEADER, "4".parse()?);
            request.headers_mut().insert(
                CREDENTIAL_HEADER,
                credential_id(user_token.unwrap_or(gateway_token)).parse()?,
            );
            request.headers_mut().insert(
                GATEWAY_CREDENTIAL_HEADER,
                credential_id(gateway_token).parse()?,
            );
            request
                .headers_mut()
                .insert(CLIENT_NONCE_HEADER, nonce.parse()?);
        }
        let (mut socket, response) = connect_async(request).await?;
        let bootstrap = if legacy {
            TunnelCipher::from_shared_key(gateway_token)?
        } else {
            assert_eq!(response.headers()[PROTOCOL_HEADER], "4");
            let user_auth = response.headers()[USER_AUTH_HEADER] == "true";
            TunnelCipher::from_tokens(
                gateway_token,
                if user_auth { user_token } else { None },
                &nonce,
                response.headers()[SERVER_NONCE_HEADER].to_str()?,
            )?
        };
        let pair = EphemeralKeyPair::generate()?;
        let public_key = public_key.unwrap_or_else(|| pair.public_key().to_vec());
        let register = if legacy {
            Message::RegisterAccess {
                token: gateway_token.into(),
                client_public_key: public_key,
            }
        } else {
            Message::RegisterAccessV4 {
                instance_id: instance.into(),
                client_public_key: public_key,
            }
        };
        socket
            .send(WsMessage::Binary(bootstrap.encrypt_from_access(
                TunnelFrameKind::Text,
                encode_message(&register)?.as_bytes(),
            )?))
            .await?;
        let WsMessage::Binary(frame) = timeout(Duration::from_secs(5), socket.next())
            .await?
            .ok_or_else(|| anyhow!("no register response"))??
        else {
            return Err(anyhow!("unencrypted response"));
        };
        let (_, bytes) = bootstrap.decrypt_from_gateway(frame)?;
        let key = match decode_message(std::str::from_utf8(&bytes)?)? {
            Message::RegisterOkV4 {
                gateway_public_key, ..
            }
            | Message::RegisterOk { gateway_public_key } => gateway_public_key,
            Message::Error { code, message, .. } => {
                return Err(GatewayError::new(&code, message).into())
            }
            _ => return Err(anyhow!("unexpected registration")),
        };
        Ok(Self {
            socket,
            cipher: pair.derive_session_cipher(&key)?,
        })
    }

    async fn send(&mut self, message: Message) -> Result<()> {
        self.socket
            .send(WsMessage::Binary(self.cipher.encrypt_from_access(
                TunnelFrameKind::Text,
                encode_message(&message)?.as_bytes(),
            )?))
            .await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message> {
        timeout(Duration::from_secs(5), async {
            loop {
                let WsMessage::Binary(frame) = self
                    .socket
                    .next()
                    .await
                    .ok_or_else(|| anyhow!("peer closed"))??
                else {
                    return Err(anyhow!("unencrypted message"));
                };
                let (kind, bytes) = self.cipher.decrypt_from_gateway(frame)?;
                if kind != TunnelFrameKind::Text {
                    continue;
                }
                let message = decode_message(std::str::from_utf8(&bytes)?)?;
                if matches!(message, Message::Ping) {
                    self.send(Message::Pong).await?;
                    continue;
                }
                return Ok(message);
            }
        })
        .await?
    }
}

fn target(address: SocketAddr, mode: Mode, scheme: &str) -> TargetConfig {
    TargetConfig {
        mode,
        host: address.ip().to_string(),
        port: address.port(),
        scheme: Some(scheme.into()),
        accept_invalid_certs: true,
        rewrite_cookie: false,
        rewrite_location: false,
    }
}

fn edit(path: &Path, change: impl FnOnce(&mut toml_edit::DocumentMut)) -> Result<()> {
    let mut document: toml_edit::DocumentMut = fs::read_to_string(path)?.parse()?;
    change(&mut document);
    fs::write(path, document.to_string())?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_processes_add_reload_permissions_takeover_and_gateway_isolation() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/user-system-e2e")
        .join(random_id()?);
    fs::create_dir_all(&root)?;
    println!("端到端测试日志目录：{}", root.display());
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_gateway"));
    let access = binary
        .parent()
        .unwrap()
        .join(format!("ws-net-access{}", std::env::consts::EXE_SUFFIX));
    if !access.exists() {
        return Err(anyhow!("请先执行 cargo build --workspace，再运行本测试"));
    }
    let a_dir = root.join("installed-gateway-a");
    let b_dir = root.join("installed-gateway-b");
    fs::create_dir(&a_dir)?;
    fs::create_dir(&b_dir)?;
    let a_bin = a_dir.join(binary.file_name().unwrap());
    let b_bin = b_dir.join(binary.file_name().unwrap());
    fs::copy(&binary, &a_bin)?;
    fs::copy(&binary, &b_bin)?;
    let a = free_address();
    let b = free_address();
    let echo_server = TcpListener::bind("127.0.0.1:0").await?;
    let echo_address = echo_server.local_addr()?;
    let count = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let count = count.clone();
        async move {
            loop {
                let Ok((mut socket, _)) = echo_server.accept().await else {
                    break;
                };
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut bytes = [0; 1024];
                    while let Ok(n) = socket.read(&mut bytes).await {
                        if n == 0 || socket.write_all(&bytes[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });
    let http_server = TcpListener::bind("127.0.0.1:0").await?;
    let http_address = http_server.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = http_server.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut bytes = [0; 4096];
                let _ = socket.read(&mut bytes).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await;
            });
        }
    });
    let tls_server = TcpListener::bind("127.0.0.1:0").await?;
    let https_address = tls_server.local_addr()?;
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.serialize_der()?.into()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der())
                .into(),
        )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = tls_server.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut socket) = acceptor.accept(socket).await {
                    let mut bytes = [0; 4096];
                    let _ = socket.read(&mut bytes).await;
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .await;
                }
            });
        }
    });
    let a_config = a_dir.join("gateway.toml");
    let b_config = b_dir.join("gateway.toml");
    fs::write(
        &a_config,
        gateway_config(a, &[echo_address, http_address, https_address]),
    )?;
    fs::write(
        &b_config,
        gateway_config(b, &[echo_address])
            .replace("access_token = \"shared\"", "access_token = \"shared-b\""),
    )?;
    let _a = spawn(&a_bin, &root, &[], &root.join("gateway-a.log"))?;
    let mut gateway_b = spawn(&b_bin, &root, &[], &root.join("gateway-b.log"))?;
    wait_listen(a).await?;
    wait_listen(b).await?;

    // Installed command resolves its own config even when the current directory is elsewhere.
    let added = Command::new(&a_bin)
        .current_dir(&root)
        .args(["adduser", "研发 李四"])
        .output()?;
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let added_output = String::from_utf8(added.stdout)?;
    assert!(added_output.contains("已生效"));
    let saved = GatewayConfig::load(&a_config)?;
    let new_user = saved
        .users
        .iter()
        .find(|user| user.name == "研发 李四")
        .unwrap();
    assert!(added_output.contains(&new_user.token));
    assert_eq!(new_user.single_access, None);
    assert!(fs::read_to_string(&a_config)?.contains("# 保留原有注释"));
    let mut added_peer = Peer::connect(a, &new_user.token, &random_id()?, false).await?;
    let before = count.load(Ordering::SeqCst);
    for host in ["127.0.0.1", "must-not-resolve.invalid"] {
        let mut config = target(echo_address, Mode::Tcp, "http");
        config.host = host.into();
        added_peer
            .send(Message::Open {
                stream_id: 1,
                target: "forbidden".into(),
                config,
            })
            .await?;
        assert!(
            matches!(added_peer.receive().await?, Message::Error { code, message, .. }
                if code == "FORBIDDEN" && message == format!("无权访问 {host}:{}", echo_address.port()))
        );
    }
    assert_eq!(count.load(Ordering::SeqCst), before);
    for (streaming, host, scheme) in [
        (false, "127.0.0.1", "http"),
        (true, "127.0.0.1", "http"),
        (false, "must-not-resolve.invalid", "http"),
        (true, "must-not-resolve.invalid", "http"),
        (false, "must-not-resolve.invalid", "https"),
        (true, "must-not-resolve.invalid", "https"),
    ] {
        let mut config = target(http_address, Mode::Http, scheme);
        config.host = host.into();
        let message = if streaming {
            Message::HttpRequestStart {
                stream_id: 2,
                target: "forbidden-http".into(),
                config,
                request: HttpRequestHead {
                    method: "GET".into(),
                    path_and_query: "/".into(),
                    headers: vec![],
                },
            }
        } else {
            Message::HttpRequest {
                stream_id: 2,
                target: "forbidden-http".into(),
                config,
                request: HttpRequestPayload {
                    method: "GET".into(),
                    path_and_query: "/".into(),
                    headers: vec![],
                    body: vec![],
                },
            }
        };
        added_peer.send(message).await?;
        assert!(
            matches!(added_peer.receive().await?, Message::Error { code, message, .. }
                if code == "FORBIDDEN" && message == format!("无权访问 {host}:{}", http_address.port()))
        );
    }
    let gateway_log = fs::read_to_string(root.join("gateway-a.log"))?;
    assert!(gateway_log.contains(&format!(
        "访问被拒绝：用户研发 李四无权访问 must-not-resolve.invalid:{}",
        http_address.port()
    )));
    let duplicate = Command::new(&a_bin)
        .args(["adduser", "研发 李四"])
        .output()?;
    assert!(!duplicate.status.success());

    for name in ["zhangsan", "lisi"] {
        let result = Command::new(&a_bin).args(["adduser", name]).output()?;
        assert!(result.status.success());
        assert!(String::from_utf8(result.stdout)?.contains("已生效"));
        assert!(GatewayConfig::load(&a_config)?
            .users
            .iter()
            .any(|user| user.name == name));
    }
    // Permission widening preserves an authenticated session; narrowing closes its live stream.
    edit(&a_config, |document| {
        document["users"]
            .as_array_of_tables_mut()
            .unwrap()
            .iter_mut()
            .find(|user| user["name"].as_str() == Some("研发 李四"))
            .unwrap()["allow"] = toml_edit::value(toml_edit::Array::from_iter(["127.0.0.1:*"]));
    })?;
    let reload_logs_before = fs::read_to_string(root.join("gateway-a.log"))?
        .matches("gateway 配置重新加载成功")
        .count();
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    let reload_log = fs::read_to_string(root.join("gateway-a.log"))?;
    assert_eq!(
        reload_log.matches("gateway 配置重新加载成功").count(),
        reload_logs_before + 1
    );
    assert!(reload_log.lines().any(|line| {
        line.contains("gateway 配置重新加载成功")
            && line.contains("installed-gateway-a")
            && line.contains("gateway.toml")
    }));
    let mut hostname_target = target(http_address, Mode::Http, "http");
    hostname_target.host = "LOCALHOST".into();
    added_peer
        .send(Message::HttpRequest {
            stream_id: 11,
            target: "域名HTTP".into(),
            config: hostname_target,
            request: HttpRequestPayload {
                method: "GET".into(),
                path_and_query: "/".into(),
                headers: vec![],
                body: vec![],
            },
        })
        .await?;
    assert!(
        matches!(added_peer.receive().await?, Message::HttpResponse { response, .. } if response.status == 200 && response.body == b"OK")
    );
    added_peer
        .send(Message::Open {
            stream_id: 12,
            target: "echo".into(),
            config: target(echo_address, Mode::Tcp, "http"),
        })
        .await?;
    assert!(matches!(
        added_peer.receive().await?,
        Message::OpenOk { stream_id: 12 }
    ));
    edit(&a_config, |document| {
        document["users"]
            .as_array_of_tables_mut()
            .unwrap()
            .iter_mut()
            .find(|user| user["name"].as_str() == Some("研发 李四"))
            .unwrap()["allow"] = toml_edit::value(toml_edit::Array::new());
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    assert!(
        matches!(added_peer.receive().await?, Message::Error { code, .. } if code == "AUTH_CHANGED")
    );
    let mut changed_peer = Peer::connect(a, &new_user.token, &random_id()?, false).await?;
    let rotated = random_id()?;
    edit(&a_config, |document| {
        document["users"]
            .as_array_of_tables_mut()
            .unwrap()
            .iter_mut()
            .find(|user| user["name"].as_str() == Some("研发 李四"))
            .unwrap()["token"] = toml_edit::value(&rotated);
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    assert!(
        matches!(changed_peer.receive().await?, Message::Error { code, .. } if code == "AUTH_CHANGED")
    );
    assert!(Peer::connect(a, &new_user.token, &random_id()?, false)
        .await
        .is_err());
    let mut rotated_peer = Peer::connect(a, &rotated, &random_id()?, false).await?;
    edit(&a_config, |document| {
        let users = document["users"].as_array_of_tables_mut().unwrap();
        let index = users
            .iter()
            .position(|user| user["name"].as_str() == Some("研发 李四"))
            .unwrap();
        users.remove(index);
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    assert!(
        matches!(rotated_peer.receive().await?, Message::Error { code, .. } if code == "AUTH_CHANGED")
    );
    assert!(Peer::connect(a, &rotated, &random_id()?, false)
        .await
        .is_err());

    // A saved user is not reported as online when the live gateway rejects the new config.
    edit(&a_config, |document| {
        document["gateway"]["path"] = toml_edit::value("/requires-restart");
    })?;
    let result = Command::new(&a_bin)
        .args(["adduser", "加载失败用户"])
        .output()?;
    assert!(!result.status.success());
    let output = String::from_utf8(result.stdout)?;
    assert!(output.contains("已保存，但自动加载失败"));
    let saved_failed = GatewayConfig::load(&a_config)?;
    let failed_token = &saved_failed
        .users
        .iter()
        .find(|user| user.name == "加载失败用户")
        .unwrap()
        .token;
    assert!(output.contains(failed_token));
    assert!(Peer::connect(a, failed_token, &random_id()?, false)
        .await
        .is_err());
    edit(&a_config, |document| {
        document["gateway"]["path"] = toml_edit::value("/tunnel");
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    Peer::connect(a, failed_token, &random_id()?, false).await?;

    let offline_config = root.join("offline.toml");
    fs::write(&offline_config, gateway_config(free_address(), &[]))?;
    let result = Command::new(&a_bin)
        .args([
            "--config",
            offline_config.to_str().unwrap(),
            "adduser",
            "离线用户",
        ])
        .output()?;
    assert!(result.status.success());
    assert!(String::from_utf8(result.stdout)?.contains("未运行，下次启动时生效"));
    assert!(!Command::new(&a_bin)
        .args(["--config", offline_config.to_str().unwrap(), "reload"])
        .output()?
        .status
        .success());
    edit(&b_config, |document| {
        document["auth"]["enabled"] = toml_edit::value(false);
    })?;
    let result = Command::new(&b_bin)
        .args(["adduser", "关闭体系用户"])
        .output()?;
    assert!(result.status.success());
    assert!(String::from_utf8(result.stdout)?.contains("用户体系当前已关闭"));
    edit(&b_config, |document| {
        document["auth"]["enabled"] = toml_edit::value(true);
    })?;
    assert!(Command::new(&b_bin)
        .arg("reload")
        .output()?
        .status
        .success());

    // A genuinely disconnected old instance cannot return after someone else takes over.
    let old_id = random_id()?;
    let mut old = Peer::connect(a, "history", &old_id, false).await?;
    old.socket.close(None).await?;
    drop(old);
    let _new = Peer::connect(a, "history", &random_id()?, false).await?;
    let error = Peer::connect(a, "history", &old_id, false)
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.downcast_ref::<GatewayError>().unwrap().code,
        "SESSION_REPLACED"
    );
    assert!(Peer::connect(a, "shared", &random_id()?, true)
        .await
        .is_err());
    assert!(
        Peer::connect_tokens(a, "shared", None, &random_id()?, false, None)
            .await
            .is_err()
    );
    assert!(
        Peer::connect_tokens(a, "wrong-gateway", Some("user"), &random_id()?, false, None)
            .await
            .is_err()
    );

    let local_a = free_address();
    let local_b = free_address();
    let local_http = free_address();
    let local_https = free_address();
    let local_denied = free_address();
    let local_denied_tcp = free_address();
    let mut access_a = format!(
        r#"[access]
gateway_pool_size = 2
[[gateways]]
name = "a"
server_url = "ws://{a}/tunnel"
token = "shared"
user_token = "user"
[[gateways]]
name = "b"
server_url = "ws://{b}/tunnel"
token = "shared-b"
user_token = "user"
"#
    );
    access_a += &listener("tcp-a", "a", local_a, echo_address, "tcp", "http");
    access_a += &listener("tcp-b", "b", local_b, echo_address, "tcp", "http");
    access_a += &listener("http", "a", local_http, http_address, "http", "http");
    access_a += &listener("https", "a", local_https, https_address, "http", "https");
    let denied_target = free_address();
    access_a += &listener("denied", "a", local_denied, denied_target, "http", "http");
    access_a += &listener(
        "denied-tcp",
        "a",
        local_denied_tcp,
        denied_target,
        "tcp",
        "http",
    );
    let access_config = root.join("access-a.toml");
    fs::write(&access_config, &access_a)?;
    let a_access_log = root.join("access-a.log");
    let _access_a = spawn(
        &access,
        &root,
        &["--config", access_config.to_str().unwrap()],
        &a_access_log,
    )?;
    wait_listen(local_a).await?;
    wait_listen(local_b).await?;
    wait_listen(local_denied_tcp).await?;
    let mut old_tcp = echo(local_a).await?;
    let _independent = echo(local_b).await?;
    assert!(http(local_http).await?.starts_with("HTTP/1.1 200"));
    assert!(http(local_https).await?.starts_with("HTTP/1.1 200"));
    let mut denied_tcp = TcpStream::connect(local_denied_tcp).await?;
    let mut denied_byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(10), denied_tcp.read(&mut denied_byte)).await??,
        0
    );
    let forbidden = http(local_denied).await?;
    assert!(forbidden.starts_with("HTTP/1.1 403"));
    let denied_message = format!("无权访问 {denied_target}");
    assert!(forbidden.ends_with(&denied_message));
    assert!(!forbidden.contains("李四"));
    assert!(fs::read_to_string(root.join("gateway-a.log"))?
        .contains(&format!("访问被拒绝：用户李四{denied_message}")));
    assert!(fs::read_to_string(root.join("gateway-a.log"))?
        .lines()
        .any(|line| line.contains("目标 TCP 连接成功") && line.contains("user=李四")));
    let access_log = fs::read_to_string(&a_access_log)?;
    assert!(!access_log.contains("李四"));
    assert!(!access_log.contains("user="));
    let denied_log = access_log
        .lines()
        .find(|line| line.contains(&denied_message))
        .unwrap();
    assert!(!denied_log.contains("李四"));
    assert!(!denied_log.contains("访问被拒绝"));
    assert!(!access_log
        .lines()
        .any(|line| { line.contains("TCP 连接结束") && line.contains(&denied_message) }));

    // An invalid curve key with the correct Token must fail before it can take ownership.
    assert!(
        Peer::connect_register(a, "user", &random_id()?, false, Some(vec![0; 32]))
            .await
            .is_err()
    );
    echo(local_a).await?;
    assert!(Peer::connect(a, "invalid-token", &random_id()?, false)
        .await
        .is_err());
    echo(local_a).await?;
    for (case, gateway_token, user_token) in [
        ("invalid-user", "shared", Some("invalid-token")),
        ("missing-user", "shared", None),
        ("invalid-gateway", "wrong-gateway", Some("user")),
        ("user-only", "user", None),
    ] {
        let invalid_local = free_address();
        let invalid_config = root.join(format!("access-{case}.toml"));
        let user_field = user_token
            .map(|token| format!("user_token = \"{token}\"\n"))
            .unwrap_or_default();
        fs::write(
            &invalid_config,
            format!(
                r#"[access]
gateway_pool_size = 2
[[gateways]]
name = "invalid"
server_url = "ws://{a}/tunnel"
token = "{gateway_token}"
{user_field}{}"#,
                listener(
                    "invalid",
                    "invalid",
                    invalid_local,
                    http_address,
                    "http",
                    "http"
                )
            ),
        )?;
        let mut invalid_access = spawn(
            &access,
            &root,
            &["--config", invalid_config.to_str().unwrap()],
            &root.join(format!("access-{case}.log")),
        )?;
        wait_listen(invalid_local).await?;
        let invalid_response = http(invalid_local).await?;
        assert!(invalid_response.starts_with("HTTP/1.1 401"));
        assert!(invalid_response.contains("鉴权失败"));
        assert!(invalid_access.0.try_wait()?.is_none());
        echo(local_a).await?;
    }

    let valid = fs::read_to_string(&a_config)?;
    fs::write(&a_config, "[broken")?;
    let failed = Command::new(&a_bin).arg("reload").output()?;
    assert!(!failed.status.success());
    assert!(fs::read_to_string(root.join("gateway-a.log"))?
        .contains("gateway 配置重新加载失败，继续使用原配置"));
    echo(local_a).await?;
    fs::write(&a_config, &valid)?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());

    let second_local = free_address();
    let second_config = root.join("access-second.toml");
    fs::write(
        &second_config,
        format!(
            r#"[access]
gateway_pool_size = 2
[[gateways]]
name = "a"
server_url = "ws://{a}/tunnel"
token = "shared"
user_token = "user"
{}"#,
            listener("tcp", "a", second_local, echo_address, "tcp", "http")
        ),
    )?;
    let _second = spawn(
        &access,
        &root,
        &["--config", second_config.to_str().unwrap()],
        &root.join("access-second.log"),
    )?;
    wait_listen(second_local).await?;
    echo(second_local).await?;
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(5), old_tcp.read(&mut byte)).await??,
        0
    );
    let kicked = http(local_http).await?;
    assert!(kicked.starts_with("HTTP/1.1 403"));
    assert!(kicked.contains("踢下线"));
    echo(local_b).await?;
    let connections_before = fs::read_to_string(&a_access_log)?
        .lines()
        .filter(|line| line.contains(&format!("ws://{a}/tunnel")) && line.contains("正在连接网关"))
        .count();
    for _ in 0..3 {
        assert!(echo(local_a).await.is_err());
    }
    fs::write(
        &access_config,
        format!("{access_a}\n# 重载同一个 Token 不恢复被踢身份\n"),
    )?;
    sleep(Duration::from_secs(4)).await;
    echo(local_b).await?;
    echo(second_local).await?;
    let log = fs::read_to_string(&a_access_log)?;
    assert_eq!(
        log.lines()
            .filter(
                |line| line.contains(&format!("ws://{a}/tunnel")) && line.contains("正在连接网关")
            )
            .count(),
        connections_before
    );
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("同一用户 Token 已在另一个 access 实例登录"))
            .count(),
        1
    );
    assert!(log.contains("配置重新加载成功"));
    assert!(!log.contains(&new_user.token));

    // Ordinary gateway downtime recovers; A's terminal state remains blocked.
    gateway_b.0.kill()?;
    gateway_b.0.wait()?;
    gateway_b = spawn(&b_bin, &root, &[], &root.join("gateway-b-restarted.log"))?;
    wait_listen(b).await?;
    echo(local_b).await?;
    assert!(echo(local_a).await.is_err());
    assert!(gateway_b.0.try_wait()?.is_none());

    // Global default changes apply to inherited users; an explicit user override wins.
    edit(&a_config, |document| {
        document["auth"]["single_access"] = toml_edit::value(false);
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    let mut third = Peer::connect(a, "user", &random_id()?, false).await?;
    echo(second_local).await?;
    edit(&a_config, |document| {
        document["auth"]["single_access"] = toml_edit::value(true);
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    third
        .send(Message::Open {
            stream_id: 3,
            target: "echo".into(),
            config: target(echo_address, Mode::Tcp, "http"),
        })
        .await?;
    assert!(matches!(third.receive().await?, Message::OpenOk { .. }));
    assert!(echo(second_local).await.is_err());
    edit(&a_config, |document| {
        document["users"]
            .as_array_of_tables_mut()
            .unwrap()
            .iter_mut()
            .find(|user| user["name"].as_str() == Some("李四"))
            .unwrap()["single_access"] = toml_edit::value(false);
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    let mut fourth = Peer::connect(a, "user", &random_id()?, false).await?;
    third
        .send(Message::Open {
            stream_id: 4,
            target: "echo-after-override".into(),
            config: target(echo_address, Mode::Tcp, "http"),
        })
        .await?;
    assert!(matches!(
        third.receive().await?,
        Message::OpenOk { stream_id: 4 }
    ));
    edit(&a_config, |document| {
        document["auth"]["single_access"] = toml_edit::value(false);
        document["users"]
            .as_array_of_tables_mut()
            .unwrap()
            .iter_mut()
            .find(|user| user["name"].as_str() == Some("李四"))
            .unwrap()["single_access"] = toml_edit::value(true);
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    assert!(
        matches!(third.receive().await?, Message::Error { code, .. } if code == "SESSION_REPLACED")
    );
    let mut fifth = Peer::connect(a, "user", &random_id()?, false).await?;
    assert!(
        matches!(fourth.receive().await?, Message::Error { code, .. } if code == "SESSION_REPLACED")
    );
    fifth
        .send(Message::Open {
            stream_id: 5,
            target: "explicit-single".into(),
            config: target(echo_address, Mode::Tcp, "http"),
        })
        .await?;
    assert!(matches!(
        fifth.receive().await?,
        Message::OpenOk { stream_id: 5 }
    ));
    edit(&a_config, |document| {
        document["auth"]["enabled"] = toml_edit::value(false);
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    assert!(
        Peer::connect_tokens(a, "user", None, &random_id()?, false, None)
            .await
            .is_err()
    );
    assert!(
        matches!(fifth.receive().await?, Message::Error { code, .. } if code == "AUTH_CHANGED")
    );
    Peer::connect(a, "shared", &random_id()?, false).await?;
    let mut legacy_a = Peer::connect(a, "shared", &random_id()?, true).await?;
    let mut legacy_b = Peer::connect(a, "shared", &random_id()?, true).await?;
    let shared_local = free_address();
    let shared_config = root.join("access-shared-only.toml");
    fs::write(
        &shared_config,
        format!(
            r#"[access]
gateway_pool_size = 2
[[gateways]]
name = "shared"
server_url = "ws://{a}/tunnel"
token = "shared"
{}"#,
            listener(
                "shared-only",
                "shared",
                shared_local,
                http_address,
                "http",
                "http"
            )
        ),
    )?;
    let _shared_access = spawn(
        &access,
        &root,
        &["--config", shared_config.to_str().unwrap()],
        &root.join("access-shared-only.log"),
    )?;
    wait_listen(shared_local).await?;
    assert!(http(shared_local).await?.starts_with("HTTP/1.1 200"));
    let rotated_shared = random_id()?;
    edit(&a_config, |document| {
        document["auth"]["access_token"] = toml_edit::value(&rotated_shared);
    })?;
    assert!(Command::new(&a_bin)
        .arg("reload")
        .output()?
        .status
        .success());
    for legacy in [&mut legacy_a, &mut legacy_b] {
        assert!(
            matches!(legacy.receive().await?, Message::Error { code, .. } if code == "AUTH_CHANGED")
        );
    }
    assert!(Peer::connect(a, "shared", &random_id()?, true)
        .await
        .is_err());
    let _replacement_a = Peer::connect(a, &rotated_shared, &random_id()?, true).await?;
    let _replacement_b = Peer::connect(a, &rotated_shared, &random_id()?, true).await?;
    echo(local_b).await?;
    let gateway_log = fs::read_to_string(root.join("gateway-a.log"))?;
    for event in [
        "客户端鉴权通过",
        "目标 TCP 连接成功",
        "目标 TCP 会话结束",
        "目标 HTTP 响应头已接收",
        "目标 HTTP 请求处理完成",
        "网关隧道会话已关闭",
        "SESSION_REPLACED",
    ] {
        assert!(
            gateway_log
                .lines()
                .any(|line| line.contains(event) && line.contains("user=李四")),
            "gateway 用户日志缺失：{event}"
        );
    }
    assert!(gateway_log.lines().any(|line| {
        line.contains("目标 TCP 连接成功")
            && line.contains("target=echo")
            && line.contains("user=研发 李四")
    }));
    assert!(gateway_log.lines().any(|line| {
        line.contains("目标 HTTP 请求处理完成") && !line.contains("user=")
    }));
    assert!(gateway_log.lines().any(|line| {
        line.contains("gateway 配置重新加载成功") && !line.contains("user=")
    }));
    let access_log = fs::read_to_string(&a_access_log)?;
    assert!(!access_log.contains("李四"));
    assert!(!access_log.contains("user="));
    println!("真实进程验证通过：双 Token 必须同时有效、关闭时只需 gateway Token、添加自动生效、资源权限、接管停重连、热重载及跨网关隔离。");
    Ok(())
}
