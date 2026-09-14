use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, Serialize, Deserialize, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct GatewayError {
    pub code: String,
    pub message: String,
}

impl GatewayError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn unauthorized() -> Self {
        Self::new(
            "UNAUTHORIZED",
            "未认证：鉴权失败，gateway Token 无效，或用户体系开启时 user_token 未配置、无效或已被撤销，连接已拒绝，已停止自动重连。",
        )
    }

    pub fn replaced() -> Self {
        Self::new("SESSION_REPLACED", "您的连接已被踢下线：同一用户 Token 已在另一个 access 实例登录。该 Token 的自动重连已停止。")
    }

    pub fn changed() -> Self {
        Self::new(
            "AUTH_CHANGED",
            "用户配置已更新，当前连接已关闭，需要重新鉴权。",
        )
    }

    pub fn network(message: impl Into<String>) -> Self {
        Self::new("GATEWAY_DISCONNECTED", message)
    }

    pub fn terminal(&self) -> bool {
        matches!(self.code.as_str(), "SESSION_REPLACED" | "UNAUTHORIZED")
    }

    pub fn http_status(&self) -> u16 {
        match self.code.as_str() {
            "UNAUTHORIZED" => 401,
            "FORBIDDEN" | "SESSION_REPLACED" => 403,
            "AUTH_CHANGED" | "GATEWAY_DISCONNECTED" => 503,
            _ => 502,
        }
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("failed to encode message: {0}")]
    Encode(#[from] serde_json::Error),
}
