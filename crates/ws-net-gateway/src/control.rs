use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    time::{timeout, Duration},
};
use ws_net_common::{credential_id, random_id, validate_username, GatewayConfig};

use crate::app::AppState;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
struct Request {
    config: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Response {
    pub(crate) ok: bool,
    pub(crate) enabled: bool,
    pub(crate) error: Option<String>,
}

pub(crate) fn config_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    let path = match explicit {
        Some(path) => path,
        None => std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow!("无法定位程序目录"))?
            .join("gateway.toml"),
    };
    fs::canonicalize(&path).with_context(|| {
        format!(
            "无法读取配置文件 {}；可使用 --config 指定路径",
            path.display()
        )
    })
}

fn sidecar(config: &Path, suffix: &str) -> PathBuf {
    let id = credential_id(&config.to_string_lossy());
    config
        .parent()
        .expect("canonical config parent")
        .join(format!(".ws-net-{}{suffix}", &id[..16]))
}

#[cfg(any(unix, test))]
fn unix_endpoint(config: &Path) -> PathBuf {
    // Fixed short base: Unix socket paths are capped at about 104 bytes on macOS.
    // Do not use TMPDIR, which may differ between the daemon and the administrator.
    Path::new("/tmp")
        .join(format!(
            "ws-net-{}",
            credential_id(&config.to_string_lossy())
        ))
        .join("control.sock")
}

#[cfg(unix)]
fn private_control_directory(config: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let endpoint = unix_endpoint(config);
    let directory = endpoint.parent().expect("control directory");
    match fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(anyhow!(
            "本地控制目录必须由网关运行账户拥有、禁止组及其他用户访问，且不能是符号链接"
        ));
    }
    Ok(endpoint)
}

fn open_lock(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

pub(crate) fn add_user(path: &Path, name: &str) -> Result<String> {
    validate_username(name)?;
    let lock = open_lock(&sidecar(path, ".edit.lock"))?;
    lock.try_lock()
        .context("配置正在被其他管理命令修改，请稍后重试")?;
    let original = fs::read(path)?;
    let config = GatewayConfig::load(path)?;
    if config.users.iter().any(|user| user.name == name) {
        return Err(anyhow!("用户“{name}”已存在，未修改原有 Token。"));
    }
    let token = loop {
        let token = random_id()?;
        if token != config.auth.access_token && config.users.iter().all(|user| user.token != token)
        {
            break token;
        }
    };
    let content = std::str::from_utf8(&original).context("配置文件必须为 UTF-8")?;
    let mut document: toml_edit::DocumentMut =
        content.parse().map_err(|_| anyhow!("配置格式错误"))?;
    let array_decor = document
        .get("users")
        .and_then(toml_edit::Item::as_value)
        .map(|value| value.decor().clone());
    if document.get("users").is_none()
        || document["users"]
            .as_array()
            .is_some_and(|array| array.is_empty())
    {
        document["users"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    let users = document["users"]
        .as_array_of_tables_mut()
        .ok_or_else(|| anyhow!("users 必须使用 [[users]] 格式"))?;
    let mut user = toml_edit::Table::new();
    if let Some(decor) = array_decor {
        *user.decor_mut() = decor;
    }
    user["name"] = toml_edit::value(name);
    user["token"] = toml_edit::value(&token);
    user["allow"] = toml_edit::value(toml_edit::Array::new());
    users.push(user);
    let mut updated = document.to_string();
    if content.contains("\r\n") {
        updated = updated.replace("\r\n", "\n").replace('\n', "\r\n");
    }
    let parsed: GatewayConfig =
        toml::from_str(&updated).map_err(|_| anyhow!("生成的配置未通过格式校验"))?;
    parsed.validate()?;
    replace_config(path, &original, updated.as_bytes())?;
    Ok(token)
}

fn replace_config(path: &Path, expected: &[u8], updated: &[u8]) -> Result<()> {
    let temporary = path
        .parent()
        .expect("config parent")
        .join(format!(".ws-net-{}.tmp", random_id()?));
    let result = (|| -> Result<()> {
        #[cfg(windows)]
        let mut file = create_temporary(&temporary)?;
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?
        };
        file.write_all(updated)?;
        file.sync_all()?;
        drop(file);
        let original_metadata = fs::metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{chown, MetadataExt};
            chown(
                &temporary,
                Some(original_metadata.uid()),
                Some(original_metadata.gid()),
            )?;
        }
        fs::set_permissions(&temporary, original_metadata.permissions())?;
        if fs::read(path)? != expected {
            return Err(anyhow!("配置文件已被其他程序修改，未覆盖，请重试"));
        }
        #[cfg(unix)]
        {
            fs::rename(&temporary, path)?;
            // The replacement has committed: never report an unchanged file after this point.
            if let Err(error) = File::open(path.parent().expect("config parent"))
                .and_then(|directory| directory.sync_all())
            {
                eprintln!("配置已保存，但目录同步失败：{error}");
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
            let destination: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let source: Vec<_> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
            // ReplaceFile preserves the original file's ACL while atomically replacing its content.
            if unsafe {
                ReplaceFileW(
                    destination.as_ptr(),
                    source.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    })();
    if temporary.exists() {
        #[cfg(windows)]
        if let Ok(metadata) = fs::metadata(&temporary) {
            let mut permissions = metadata.permissions();
            #[allow(
                clippy::permissions_set_readonly_false,
                reason = "Windows-only cleanup of our own temporary file; Unix never runs this block"
            )]
            permissions.set_readonly(false);
            let _ = fs::set_permissions(&temporary, permissions);
        }
        let _ = fs::remove_file(&temporary);
    }
    result
}

async fn exchange(stream: impl AsyncRead + AsyncWrite + Unpin, path: &Path) -> Result<Response> {
    let mut stream = BufReader::new(stream);
    let mut request = serde_json::to_vec(&Request {
        config: path.to_path_buf(),
    })?;
    request.push(b'\n');
    stream.get_mut().write_all(&request).await?;
    let mut response = String::new();
    stream.take(16 * 1024).read_line(&mut response).await?;
    Ok(serde_json::from_str(&response)?)
}

pub(crate) async fn reload(path: &Path) -> Result<Option<Response>> {
    let lock = open_lock(&sidecar(path, ".runtime.lock"))?;
    match lock.try_lock() {
        Ok(()) => return Ok(None),
        Err(std::fs::TryLockError::WouldBlock) => {}
        Err(error) => return Err(error.into()),
    }
    timeout(CONTROL_TIMEOUT, async {
        #[cfg(unix)]
        {
            loop {
                match tokio::net::UnixStream::connect(unix_endpoint(path)).await {
                    Ok(stream) => return exchange(stream, path).await.map(Some),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ClientOptions;
            loop {
                match ClientOptions::new().open(pipe_name(path)) {
                    Ok(stream) => return exchange(stream, path).await.map(Some),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    Err(error) if error.raw_os_error() == Some(231) => {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    })
    .await
    .context("等待 gateway 确认重载超时")?
}

async fn handle(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    path: PathBuf,
    state: AppState,
) -> Result<()> {
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    let mut limited = (&mut stream).take(16 * 1024);
    limited.read_line(&mut line).await?;
    let request: Request = serde_json::from_str(&line)?;
    let result = if request.config == path {
        GatewayConfig::load(&path).and_then(|config| state.reload(config))
    } else {
        Err(anyhow!("配置路径与运行实例不匹配"))
    };
    let response = Response {
        ok: result.is_ok(),
        enabled: state.config().auth.enabled,
        error: result.err().map(|error| error.to_string()),
    };
    let mut response = serde_json::to_vec(&response)?;
    response.push(b'\n');
    stream.get_mut().write_all(&response).await?;
    stream.get_mut().shutdown().await?;
    Ok(())
}

#[cfg(windows)]
fn pipe_name(path: &Path) -> String {
    format!(
        "\\\\.\\pipe\\ws-net-{}",
        credential_id(&path.to_string_lossy())
    )
}

#[cfg(windows)]
fn with_owner_security<T>(
    create: impl FnOnce(&mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES) -> io::Result<T>,
) -> Result<T> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
    };
    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)\0"
        .encode_utf16()
        .collect();
    let mut descriptor = std::ptr::null_mut();
    // Use the same owner/admin/SYSTEM boundary for the control pipe and secret temporary files.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = create(&mut attributes);
    unsafe {
        LocalFree(descriptor);
    }
    Ok(result?)
}

#[cfg(windows)]
fn create_temporary(path: &Path) -> Result<File> {
    use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
    use windows_sys::Win32::{
        Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL},
    };
    let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    with_owner_security(|attributes| {
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_WRITE,
                0,
                attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_handle(handle) })
        }
    })
}

#[cfg(windows)]
fn pipe(path: &Path, first: bool) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    with_owner_security(|attributes| unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                pipe_name(path),
                (attributes as *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast(),
            )
    })
}

pub(crate) async fn serve(path: PathBuf, state: AppState) -> Result<tokio::task::JoinHandle<()>> {
    let lock = open_lock(&sidecar(&path, ".runtime.lock"))?;
    lock.try_lock().context("此配置已有运行中的 gateway")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let endpoint = private_control_directory(&path)?;
        if let Ok(metadata) = fs::symlink_metadata(&endpoint) {
            if !metadata.file_type().is_socket() {
                return Err(anyhow!("控制通道路径被非 socket 文件占用"));
            }
            fs::remove_file(&endpoint)?;
        }
        let listener = tokio::net::UnixListener::bind(&endpoint)?;
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))?;
        Ok(tokio::spawn(async move {
            let _lock = lock;
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state = state.clone();
                let path = path.clone();
                tokio::spawn(async move {
                    let _ = timeout(CONTROL_TIMEOUT, handle(stream, path, state)).await;
                });
            }
        }))
    }
    #[cfg(windows)]
    {
        let mut server = pipe(&path, true)?;
        Ok(tokio::spawn(async move {
            let _lock = lock;
            loop {
                if server.connect().await.is_err() {
                    break;
                }
                let next = match pipe(&path, false) {
                    Ok(next) => next,
                    Err(error) => {
                        tracing::error!(error = %error, "无法创建本地控制通道");
                        break;
                    }
                };
                let connected = std::mem::replace(&mut server, next);
                let state = state.clone();
                let path = path.clone();
                tokio::spawn(async move {
                    let _ = timeout(CONTROL_TIMEOUT, handle(connected, path, state)).await;
                });
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_control_path_stays_short_for_deep_config_directories() {
        let config = PathBuf::from(format!("/{} /gateway.toml", "very-deep/".repeat(100)));
        let endpoint = unix_endpoint(&config);
        assert!(endpoint.to_string_lossy().len() < 100);
        assert_ne!(endpoint, unix_endpoint(Path::new("/other/gateway.toml")));
    }

    #[test]
    fn adding_chinese_user_preserves_comments_defaults_and_conflict() {
        let directory = std::env::temp_dir().join(format!("ws-net-test-{}", random_id().unwrap()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("gateway.toml");
        let original = "# 保留注释\r\n[gateway]\r\nlisten = \"127.0.0.1:8443\"\r\n[auth]\r\naccess_token = \"shared\"\r\nsingle_access = false\r\n";
        fs::write(&path, original).unwrap();
        let token = add_user(&path, "研发 李四").unwrap();
        let updated = fs::read_to_string(&path).unwrap();
        assert!(updated.contains("# 保留注释\r\n"));
        let config = GatewayConfig::load(&path).unwrap();
        assert_eq!(config.users[0].token, token);
        assert_eq!(config.users[0].single_access, None);
        assert_eq!(config.users[0].allow.len(), 0);
        assert!(!config.auth.enabled);
        assert!(add_user(&path, "研发 李四").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), updated);
        assert!(replace_config(&path, original.as_bytes(), b"invalid").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), updated);
        fs::write(&path, format!("users = [] # 用户说明\r\n{original}")).unwrap();
        add_user(&path, "zhangsan").unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("# 用户说明"));
        #[cfg(windows)]
        {
            let expected = fs::read(&path).unwrap();
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            let original_permissions = permissions.clone();
            permissions.set_readonly(true);
            fs::set_permissions(&path, permissions.clone()).unwrap();
            assert!(add_user(&path, "不能保存的用户").is_err());
            assert_eq!(fs::read(&path).unwrap(), expected);
            fs::set_permissions(&path, original_permissions).unwrap();
            assert!(!fs::read_dir(&directory).unwrap().any(|entry| entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "tmp")));
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
