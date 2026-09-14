use std::path::PathBuf;

use anyhow::{Context, Result};
use axum::{routing::get, Router};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::info;
use ws_net_common::GatewayConfig;

mod app;
mod control;
mod http_proxy;
mod tcp;
mod ws;

use app::AppState;
use ws::ws_entry;

#[derive(Debug, Parser)]
#[command(about = "网关服务及用户管理", disable_help_subcommand = true)]
struct Args {
    #[arg(
        short,
        long,
        global = true,
        help = "配置文件路径，默认使用程序目录中的 gateway.toml"
    )]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "添加用户、返回 Token 并自动加载配置")]
    Adduser {
        #[arg(help = "用户名，支持中文；包含空格时使用引号")]
        username: String,
    },
    #[command(about = "让运行中的网关重新加载一次配置")]
    Reload,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("操作失败：{error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    install_rustls_crypto_provider();
    let args = Args::parse();
    let path = control::config_path(args.config)?;
    match args.command {
        Some(Command::Adduser { username }) => {
            let token = control::add_user(&path, &username).context("添加用户失败")?;
            match control::reload(&path).await {
                Ok(Some(response)) if response.ok => {
                    if response.enabled {
                        println!("用户“{username}”添加成功，已生效。");
                    } else {
                        println!("用户“{username}”已保存，配置已加载。用户体系当前已关闭，启用后该 Token 才能使用。");
                    }
                    println!("Token：{token}");
                    println!("默认未授权任何资源，请修改 allow 后执行 gateway reload。");
                }
                Ok(None) => {
                    println!("用户“{username}”已保存。\nToken：{token}\ngateway 未运行，下次启动时生效。");
                }
                result => {
                    let (reason, state_message) = match result {
                        Ok(Some(response)) => (
                            response.error.unwrap_or_else(|| "配置加载失败".into()),
                            "运行进程继续使用原配置，请修正问题后执行 gateway reload。",
                        ),
                        Err(error) => (
                            error.to_string(),
                            "未能确认运行进程是否已加载配置，请检查状态后执行 gateway reload。",
                        ),
                        _ => unreachable!(),
                    };
                    println!("用户“{username}”已保存，但自动加载失败：{reason}\nToken：{token}\n{state_message}");
                    anyhow::bail!("用户已保存但尚未在线生效");
                }
            }
            return Ok(());
        }
        Some(Command::Reload) => {
            let response = control::reload(&path)
                .await?
                .ok_or_else(|| anyhow::anyhow!("配置重载失败：gateway 进程未运行"))?;
            if !response.ok {
                anyhow::bail!(
                    "配置重载失败：{}。运行进程继续使用原配置。",
                    response.error.unwrap_or_default()
                );
            }
            println!("配置重载成功。");
            return Ok(());
        }
        None => {}
    }
    tracing_subscriber::fmt().with_env_filter("info").init();
    let config = GatewayConfig::load(&path).context("加载网关配置失败")?;
    let state = AppState::new(config.clone())?;
    let mut control = control::serve(path.clone(), state.clone())
        .await
        .context("启动本地管理通道失败")?;

    let app = Router::new()
        .route(&config.gateway.path, get(ws_entry))
        .with_state(state);

    let listener = TcpListener::bind(&config.gateway.listen).await?;
    info!(listen = %config.gateway.listen, path = %config.gateway.path, config = %path.display(), "网关服务已启动");
    let result = tokio::select! {
        result = async { axum::serve(listener, app).tcp_nodelay(true).await } => result.map_err(anyhow::Error::from),
        result = &mut control => Err(anyhow::anyhow!("本地管理通道已停止，网关退出：{result:?}")),
    };
    control.abort();
    result
}

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
