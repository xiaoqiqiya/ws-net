# ws-net

`ws-net` 是一个基于 Rust 实现的单端口 WebSocket 隧道工具。一个 `ws-net-access`
客户端可以同时连接一个或多个公网 gateway，通过不同 gateway 访问分布在不同网络中的
TCP 服务或 HTTP/HTTPS Web 服务。

当前架构包含两个端：

- `ws-net-gateway`：部署在有公网入口且能访问内网服务的机器上；可以按网络部署多个实例。
- `ws-net-access`：部署在使用者本地机器上，负责监听本地端口、维护多个 gateway 连接池，
  并按 listener 配置选择 gateway。

```text
本地程序 / 浏览器
        ↓
ws-net-access 本地监听端口
        ├─ listener: mysql ── WebSocket ── gateway: primary   ── 内网 A
        └─ listener: redis ── WebSocket ── gateway: secondary ── 内网 B
```

## 功能特性

- 每个 gateway 节点在公网侧只需要开放一个端口。
- 单个 access 进程可以连接多个 gateway，并为每个 gateway 配置独立 token。
- access 侧支持多个本地自定义监听端口。
- 每个 listener 内直接配置对应的内网目标，配置简单直观。
- 支持 TCP 透明转发，适合 MySQL、Redis、SSH、PostgreSQL 等服务。
- 支持 HTTP/HTTPS 智能代理，适合内网 HTTPS 管理后台或 API。
- access 和 gateway 之间使用长期 WebSocket 连接。
- TCP 数据使用 WebSocket Binary frame 传输，避免 JSON 编码二进制数据带来的性能开销。
- 多个请求通过 `stream_id` 在同一条 WebSocket 连接中复用。
- 所有隧道认证、控制、心跳和业务帧均使用 ChaCha20-Poly1305 内层认证加密。
- 每条 access-gateway WebSocket 连接自动通过 X25519 协商独立临时会话密钥；断线重连会自动生成新密钥。
- access→gateway 与 gateway→access 使用 HKDF-SHA256 派生的不同方向密钥，并校验严格递增的帧序号。
- TCP 和 HTTP stream 在关闭或会话断开时都会主动取消，避免目标连接或请求继续滞留。

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

## Docker 镜像

GitHub Actions 会额外使用 [docker/scratch.Dockerfile](docker/scratch.Dockerfile) 打包两个 `scratch` 基础镜像。非 PR 构建会推送到 GitHub Container Registry，并同时把镜像保存为 workflow artifact / tag release 附件：

- `ghcr.io/xiaoqiqiya/ws-net-access:<tag-or-sha>`
- `ghcr.io/xiaoqiqiya/ws-net-gateway:<tag-or-sha>`

镜像内入口固定为 `/bin/app`，默认读取 `/config.toml`：

```bash
docker pull ghcr.io/xiaoqiqiya/ws-net-gateway:v1.0.0
docker run --rm -v $PWD/gateway.toml:/config.toml:ro ghcr.io/xiaoqiqiya/ws-net-gateway:v1.0.0
```

也可以从 release 附件下载 tar 后手动加载：

```bash
docker load -i ws-net-gateway-v1.0.0.tar
```

本地手动构建镜像时，需要先构建 Linux musl 静态制品，再把二进制和配置文件放入 Docker 构建上下文：

```bash
sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl
cargo build --workspace --release --target x86_64-unknown-linux-musl

mkdir -p docker-context/access docker-context/gateway
cp target/x86_64-unknown-linux-musl/release/ws-net-access docker-context/access/app
cp access.example.toml docker-context/access/config.toml
cp docker/scratch.Dockerfile docker-context/access/Dockerfile
cp target/x86_64-unknown-linux-musl/release/ws-net-gateway docker-context/gateway/app
cp gateway.example.toml docker-context/gateway/config.toml
cp docker/scratch.Dockerfile docker-context/gateway/Dockerfile

docker build -t ws-net-access:local docker-context/access
docker build -t ws-net-gateway:local docker-context/gateway
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

## 隧道内层加密

`access_token` 是 access 与 gateway 唯一需要共同持有的长期秘密。它不会以明文出现在 WebSocket 隧道中：两端首先使用由 token 派生的 ChaCha20-Poly1305 握手加密器，保护注册认证和 X25519 临时公钥交换；随后各自从 X25519 共享秘密派生本连接专属的 ChaCha20-Poly1305 会话密钥。

后续每一个隧道协议帧均为认证密文，包括注册响应、OPEN/CLOSE、HTTP 元数据、TCP/HTTP 二进制 payload 与协议心跳。收到普通明文 WebSocket Text、Binary、Ping 或 Pong 帧会拒绝并关闭该连接。每个方向使用独立密钥，nonce 由固定方向前缀和严格递增的 64 位帧序号组成；接收端只接受下一个预期序号，因此重放、重复、丢失或乱序帧都会认证失败或被拒绝。每帧同时带有 Poly1305 认证 tag，抓包者无法读取或静默篡改内容。

- token 必须是高强度随机秘密，且 access 与对应 gateway 配置必须完全一致；不要提交到 Git、日志或聊天记录。
- 不需要配置 `tunnel_key`。每条新连接与每次重连都会自动协商新会话密钥，旧连接的临时私钥与会话密钥只保存在内存中。
- 单个加密 WebSocket 帧最大为 16 MiB；access 和 gateway 两端都会在协议入口和解密入口执行限制。
- v2 加密帧不再为每个数据帧调用系统随机数生成器，并减少了加解密过程中的缓冲区分配和复制，以降低大文件上传时的 CPU 开销。
- `wss://` 仍然是生产必需项：它保护 TLS/WebSocket 升级与网络层元数据，并验证 gateway 身份；内层加密会在 TLS 于 Nginx/Caddy 终止后继续保护隧道内容。
- WebSocket HTTP Upgrade、TLS 握手和 Close 控制帧是底层协议，不能被包装进自身的数据帧；它们不包含隧道业务 payload，在 `wss://` 下由 TLS 保护。

> 升级注意：当前 v2 加密帧格式与 v1.0.9 及更早版本不兼容。部署时必须同时升级 `ws-net-access` 和 `ws-net-gateway`，不要让新旧版本交叉连接。

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
gateway_pool_size = 8

[[gateways]]
name = "primary"
server_url = "ws://127.0.0.1:8443/tunnel"
token = "change-primary-access-token"

[[gateways]]
name = "secondary"
server_url = "ws://127.0.0.1:8444/tunnel"
token = "change-secondary-access-token"

[[listeners]]
name = "mysql"
mode = "tcp"
gateway = "primary"
listen = "127.0.0.1:3308"
host = "10.0.0.10"
port = 3306

[[listeners]]
name = "redis"
mode = "tcp"
gateway = "secondary"
listen = "127.0.0.1:63790"
host = "10.0.0.11"
port = 6379

[[listeners]]
name = "admin"
mode = "http"
gateway = "primary"
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
| `access.gateway_pool_size` | 为每个 gateway 建立的 WebSocket 长连接数量，默认值为 `8`。 |
| `gateways[].name` | gateway 的唯一名称，供 listener 引用。 |
| `gateways[].server_url` | gateway 的 WebSocket 地址。 |
| `gateways[].token` | 连接该 gateway 使用的独立 token，需要和对应 gateway 配置一致。 |
| `listeners[].name` | listener 名称，用于日志和 stream 标识。 |
| `listeners[].mode` | 转发模式，支持 `tcp` 和 `http`。 |
| `listeners[].gateway` | 当前 listener 使用的 gateway 名称。配置多个 gateway 时必须指定。 |
| `listeners[].listen` | access 本地监听地址和端口。 |
| `listeners[].host` | 内网目标服务地址。 |
| `listeners[].port` | 内网目标服务端口。 |
| `listeners[].scheme` | HTTP 模式下目标协议，通常是 `http` 或 `https`。TCP 模式不需要。 |
| `listeners[].rewrite_location` | HTTP 模式下是否重写 `Location` 响应头。 |
| `listeners[].rewrite_cookie` | HTTP 模式下是否重写 `Set-Cookie` 响应头。 |

### 多 Gateway 路由规则

- 每个 `[[gateways]]` 配置项注册一个 gateway，`name` 是客户端内部的路由名称，
  `server_url` 和 `token` 可以分别配置。
- 每个 `[[listeners]]` 通过 `gateway` 选择目标 gateway。这里是明确路由关系，
  不是在多个 gateway 之间随机选择或自动故障切换。
- 多个 listener 可以引用同一个 gateway，并共享该 gateway 的连接池。
- `access.gateway_pool_size` 对每个 gateway 分别生效。例如配置 2 个 gateway 且
  `gateway_pool_size = 8` 时，access 会为两个 gateway 创建共 16 个 WebSocket 连接槽位。
- 只有一个 gateway 时可以省略 listener 的 `gateway`；配置多个 gateway 时必须明确指定。

每个 gateway 的 `name` 必须唯一，`server_url` 和 `token` 不能为空。一个 listener
不能同时配置 `gateway` 和旧字段 `server_url`。

旧版单 token 配置仍然兼容：

```toml
[access]
token = "shared-token"
server_url = "ws://127.0.0.1:8443/tunnel"
gateway_pool_size = 8

[[listeners]]
name = "mysql"
mode = "tcp"
listen = "127.0.0.1:3308"
host = "10.0.0.10"
port = 3306
```

旧字段 `access.server_urls` 和 `listeners[].server_url` 也会继续使用
`access.token`。新部署建议使用 `[[gateways]]` 和 `listeners[].gateway`，避免多个
gateway 共用 token。

access 检测到配置文件更新后，会按新的 Gateway URL 和 token 重建连接池；已有连接
会在新配置验证成功后关闭。

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
gateway = "primary"
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
gateway = "primary"
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

1. 在各公网/内网入口机器启动 gateway。每个 gateway 使用自己的监听地址和 token：

```bash
ws-net-gateway.exe --config gateway.example.toml
```

2. 在访问端机器启动一个 access；其配置可以同时声明上述多个 gateway：

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

当前版本已经支持长连接复用、二进制 TCP 数据帧和 HTTP 请求/响应流式转发，但仍有一些限制：

- access 配置热重载会更新 gateway 连接、token 和已有 listener 使用的目标参数；新增/删除 listener，或修改 listener 的 `listen`、`mode` 时仍需重启 access 才会改变本地监听任务。
- gateway 和 access 之间的业务帧和认证帧都使用 ChaCha20-Poly1305 内层加密；`ws://` 下仍可防止被动窃听，生产环境仍必须使用 `wss://`。
- `token` 只用于保护认证握手；每条 WebSocket 连接都会自动通过 X25519 协商临时会话密钥，断开即丢弃。`token` 应是强随机秘密，不要提交到 Git、日志或聊天记录。

## 生产建议

- gateway 放到 Nginx/Caddy 后面，用 HTTPS/WSS 暴露；即使 TLS 在代理处终止，隧道帧仍保留内层加密。
- `access_token` 使用强随机字符串。
- 不要把 access 的监听地址随意配置为 `0.0.0.0`。
- 对外暴露 gateway 时，建议只开放一个 HTTPS 端口，例如 `443`。
- 对关键服务增加日志审计和访问控制。
