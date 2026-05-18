# ws-net

`ws-net` 是一个基于 Rust 实现的单端口 WebSocket 隧道工具，用于通过一个公网入口访问多个内网 TCP 服务或 HTTPS Web 服务。

当前架构包含两个端：

- `ws-net-gateway`：部署在有公网入口且能访问内网服务的机器上。
- `ws-net-access`：部署在使用者本地机器上，负责监听本地端口并连接 gateway。

```text
本地程序 / 浏览器
        ↓
ws-net-access 本地监听端口
        ↓ WebSocket 长连接
ws-net-gateway 公网入口
        ↓
内网 TCP / HTTP / HTTPS 服务
```

## 功能特性

- 公网侧只需要开放一个端口。
- access 侧支持多个本地自定义监听端口。
- 每个 listener 内直接配置对应的内网目标，配置简单直观。
- 支持 TCP 透明转发，适合 MySQL、Redis、SSH、PostgreSQL 等服务。
- 支持 HTTP/HTTPS 智能代理，适合内网 HTTPS 管理后台或 API。
- access 和 gateway 之间使用长期 WebSocket 连接。
- TCP 数据使用 WebSocket Binary frame 传输，避免 JSON 编码二进制数据带来的性能开销。
- 多个请求通过 `stream_id` 在同一条 WebSocket 连接中复用。

## 项目结构

```text
ws-net/
  Cargo.toml
  gateway.example.toml
  access.example.toml
  crates/
    ws-net-common/     # 公共协议、配置结构、消息编解码
    ws-net-gateway/    # 公网入口和内网访问端
    ws-net-access/     # 本地访问端
```

## 构建

在项目根目录执行：

```bash
cargo build --release --workspace
```

生成文件：

```text
target/release/ws-net-gateway.exe
target/release/ws-net-access.exe
```

只构建 gateway：

```bash
cargo build --release -p ws-net-gateway
```

只构建 access：

```bash
cargo build --release -p ws-net-access
```

## Gateway 配置

示例文件：

```text
gateway.example.toml
```

示例：

```toml
[gateway]
listen = "0.0.0.0:8443"
path = "/tunnel"

[auth]
access_token = "change-access-token"
```

字段说明：

| 字段 | 说明 |
|---|---|
| `gateway.listen` | gateway 监听地址。公网机器上开放这个端口。 |
| `gateway.path` | WebSocket 路径。 |
| `auth.access_token` | access 连接 gateway 时使用的认证 token。 |

启动 gateway：

```bash
target/release/ws-net-gateway.exe --config gateway.example.toml
```

开发模式也可以直接运行：

```bash
cargo run -p ws-net-gateway -- --config gateway.example.toml
```

## Access 配置

示例文件：

```text
access.example.toml
```

示例：

```toml
[access]
token = "change-access-token"
server_url = "ws://127.0.0.1:8443/tunnel"

[[listeners]]
name = "mysql"
mode = "tcp"
listen = "127.0.0.1:3308"
host = "10.0.0.10"
port = 3306

[[listeners]]
name = "redis"
mode = "tcp"
listen = "127.0.0.1:63790"
host = "10.0.0.11"
port = 6379

[[listeners]]
name = "admin"
mode = "http"
listen = "127.0.0.1:18080"
scheme = "https"
host = "admin.internal.local"
port = 443
rewrite_location = true
rewrite_cookie = true
```

字段说明：

| 字段 | 说明 |
|---|---|
| `access.token` | 连接 gateway 使用的 token，需要和 gateway 配置一致。 |
| `access.server_url` | gateway 的 WebSocket 地址。 |
| `listeners[].name` | listener 名称，用于日志和 stream 标识。 |
| `listeners[].mode` | 转发模式，支持 `tcp` 和 `http`。 |
| `listeners[].listen` | access 本地监听地址和端口。 |
| `listeners[].host` | 内网目标服务地址。 |
| `listeners[].port` | 内网目标服务端口。 |
| `listeners[].scheme` | HTTP 模式下目标协议，通常是 `http` 或 `https`。TCP 模式不需要。 |
| `listeners[].rewrite_location` | HTTP 模式下是否重写 `Location` 响应头。 |
| `listeners[].rewrite_cookie` | HTTP 模式下是否重写 `Set-Cookie` 响应头。 |

启动 access：

```bash
target/release/ws-net-access.exe --config access.example.toml
```

开发模式：

```bash
cargo run -p ws-net-access -- --config access.example.toml
```

## TCP 转发示例

配置：

```toml
[[listeners]]
name = "mysql"
mode = "tcp"
listen = "127.0.0.1:3308"
host = "10.0.0.10"
port = 3306
```

访问方式：

```text
127.0.0.1:3308
```

实际转发：

```text
127.0.0.1:3308 -> gateway -> 10.0.0.10:3306
```

适合：

- MySQL
- Redis
- PostgreSQL
- SSH
- MongoDB
- 其他普通 TCP 服务

## HTTPS 内网站点示例

配置：

```toml
[[listeners]]
name = "admin"
mode = "http"
listen = "127.0.0.1:18080"
scheme = "https"
host = "admin.internal.local"
port = 443
rewrite_location = true
rewrite_cookie = true
```

本地访问：

```text
http://127.0.0.1:18080
```

实际请求：

```text
https://admin.internal.local:443
```

这种模式适合解决内网 HTTPS 页面通过普通 TCP 映射访问时常见的问题，例如：

- 证书域名不匹配。
- SNI 不正确。
- 后端依赖 `Host`。
- 登录后跳转到内网域名。
- Cookie Domain 不适配本地访问地址。

## 本地自定义端口

每个 listener 的本地端口由 `listen` 控制。

例如：

```toml
listen = "127.0.0.1:18080"
```

改成：

```toml
listen = "127.0.0.1:18888"
```

则本地访问地址变为：

```text
http://127.0.0.1:18888
```

如果需要让局域网其他机器也访问 access 的本地端口，可以使用：

```toml
listen = "0.0.0.0:18080"
```

注意：`0.0.0.0` 会扩大暴露面，只建议在可信网络中使用。

## 运行顺序

1. 在公网/内网入口机器启动 gateway：

```bash
ws-net-gateway.exe --config gateway.example.toml
```

2. 在访问端机器启动 access：

```bash
ws-net-access.exe --config access.example.toml
```

3. 访问本地端口：

```text
127.0.0.1:3308
http://127.0.0.1:18080
```

## 检查命令

格式化：

```bash
cargo fmt --all
```

编译检查：

```bash
cargo check --workspace
```

测试：

```bash
cargo test --workspace
```

完整检查：

```bash
cargo fmt --all && cargo check --workspace && cargo test --workspace
```

## 当前限制

当前版本是 MVP，已经支持长连接复用和二进制 TCP 数据帧，但仍有一些限制：

- HTTP/HTTPS 模式目前是请求/响应整包转发，还不是响应体流式转发。
- WebSocket 内网站点升级代理尚未实现。
- gateway 和 access 之间当前示例使用 `ws://`，生产环境建议使用 `wss://`。
- token 是静态 token，后续可以升级为 HMAC timestamp/nonce 认证。
- access 与 gateway 的长连接断开后，目前还没有自动重连逻辑。

## 生产建议

- gateway 放到 Nginx/Caddy 后面，用 HTTPS/WSS 暴露。
- `access_token` 使用强随机字符串。
- 不要把 access 的监听地址随意配置为 `0.0.0.0`。
- 对外暴露 gateway 时，建议只开放一个 HTTPS 端口，例如 `443`。
- 对关键服务增加日志审计和访问控制。
