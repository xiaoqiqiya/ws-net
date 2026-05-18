use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("failed to encode message: {0}")]
    Encode(#[from] serde_json::Error),
}
