use serde::{Deserialize, Serialize};

use crate::TargetConfig;

pub type StreamId = u64;

#[derive(Debug)]
pub struct DataFramePayload {
    frame: Vec<u8>,
    payload_offset: usize,
}

impl DataFramePayload {
    pub fn as_slice(&self) -> &[u8] {
        &self.frame[self.payload_offset..]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Tcp,
    Http,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetMeta {
    pub name: String,
    pub mode: Mode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestPayload {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponsePayload {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Message {
    RegisterAccess {
        token: String,
    },
    RegisterOk,
    Open {
        stream_id: StreamId,
        target: String,
        config: TargetConfig,
    },
    OpenOk {
        stream_id: StreamId,
    },
    Data {
        stream_id: StreamId,
        bytes: Vec<u8>,
    },
    Close {
        stream_id: StreamId,
        reason: String,
    },
    Error {
        stream_id: Option<StreamId>,
        code: String,
        message: String,
    },
    HttpRequest {
        stream_id: StreamId,
        target: String,
        config: TargetConfig,
        request: HttpRequestPayload,
    },
    HttpResponse {
        stream_id: StreamId,
        response: HttpResponsePayload,
    },
    Ping,
    Pong,
}

pub fn encode_message(message: &Message) -> Result<String, serde_json::Error> {
    serde_json::to_string(message)
}

pub fn decode_message(text: &str) -> Result<Message, serde_json::Error> {
    serde_json::from_str(text)
}

pub fn encode_data_frame(stream_id: StreamId, bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + bytes.len());
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(bytes);
    frame
}

pub fn new_data_frame_buffer(stream_id: StreamId, payload_capacity: usize) -> Vec<u8> {
    let mut frame = vec![0_u8; 8 + payload_capacity];
    frame[..8].copy_from_slice(&stream_id.to_be_bytes());
    frame
}

pub fn decode_data_frame(frame: &[u8]) -> Option<(StreamId, Vec<u8>)> {
    if frame.len() < 8 {
        return None;
    }

    let mut id = [0_u8; 8];
    id.copy_from_slice(&frame[..8]);
    Some((StreamId::from_be_bytes(id), frame[8..].to_vec()))
}

pub fn decode_data_frame_owned(frame: Vec<u8>) -> Option<(StreamId, DataFramePayload)> {
    if frame.len() < 8 {
        return None;
    }

    let mut id = [0_u8; 8];
    id.copy_from_slice(&frame[..8]);

    Some((
        StreamId::from_be_bytes(id),
        DataFramePayload {
            frame,
            payload_offset: 8,
        },
    ))
}
