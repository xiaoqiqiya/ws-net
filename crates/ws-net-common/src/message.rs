use serde::{Deserialize, Serialize};

use crate::TargetConfig;

pub type StreamId = u64;
pub const DATA_FRAME_HEADER_LEN: usize = std::mem::size_of::<StreamId>();

#[derive(Debug)]
pub struct DataFramePayload {
    frame: Vec<u8>,
    payload_offset: usize,
}

impl DataFramePayload {
    pub fn as_slice(&self) -> &[u8] {
        &self.frame[self.payload_offset..]
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.frame[self.payload_offset..].to_vec()
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
pub struct HttpRequestHead {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponsePayload {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Message {
    RegisterAccess {
        token: String,
        client_public_key: Vec<u8>,
    },
    RegisterOk {
        gateway_public_key: Vec<u8>,
    },
    Open {
        stream_id: StreamId,
        target: String,
        config: TargetConfig,
    },
    OpenOk {
        stream_id: StreamId,
    },
    Close {
        stream_id: StreamId,
        reason: String,
    },
    TcpEof {
        stream_id: StreamId,
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
    HttpRequestStart {
        stream_id: StreamId,
        target: String,
        config: TargetConfig,
        request: HttpRequestHead,
    },
    HttpRequestEnd {
        stream_id: StreamId,
    },
    HttpResponse {
        stream_id: StreamId,
        response: HttpResponsePayload,
    },
    HttpResponseStart {
        stream_id: StreamId,
        response: HttpResponseHead,
    },
    HttpResponseEnd {
        stream_id: StreamId,
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
    let mut frame = Vec::with_capacity(DATA_FRAME_HEADER_LEN + bytes.len());
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(bytes);
    frame
}

pub fn new_data_frame_buffer(stream_id: StreamId, payload_capacity: usize) -> Vec<u8> {
    let mut frame = vec![0_u8; DATA_FRAME_HEADER_LEN + payload_capacity];
    frame[..DATA_FRAME_HEADER_LEN].copy_from_slice(&stream_id.to_be_bytes());
    frame
}

pub fn try_merge_data_frames(current: &mut Vec<u8>, next: &[u8], max_payload_size: usize) -> bool {
    if current.len() < DATA_FRAME_HEADER_LEN || next.len() < DATA_FRAME_HEADER_LEN {
        return false;
    }

    if current[..DATA_FRAME_HEADER_LEN] != next[..DATA_FRAME_HEADER_LEN] {
        return false;
    }

    let current_payload_len = current.len() - DATA_FRAME_HEADER_LEN;
    let next_payload_len = next.len() - DATA_FRAME_HEADER_LEN;
    let Some(merged_payload_len) = current_payload_len.checked_add(next_payload_len) else {
        return false;
    };
    if merged_payload_len > max_payload_size {
        return false;
    }

    current.extend_from_slice(&next[DATA_FRAME_HEADER_LEN..]);
    true
}

pub fn decode_data_frame(frame: &[u8]) -> Option<(StreamId, Vec<u8>)> {
    if frame.len() < DATA_FRAME_HEADER_LEN {
        return None;
    }

    let mut id = [0_u8; DATA_FRAME_HEADER_LEN];
    id.copy_from_slice(&frame[..DATA_FRAME_HEADER_LEN]);
    Some((
        StreamId::from_be_bytes(id),
        frame[DATA_FRAME_HEADER_LEN..].to_vec(),
    ))
}

pub fn decode_data_frame_owned(frame: Vec<u8>) -> Option<(StreamId, DataFramePayload)> {
    if frame.len() < DATA_FRAME_HEADER_LEN {
        return None;
    }

    let mut id = [0_u8; DATA_FRAME_HEADER_LEN];
    id.copy_from_slice(&frame[..DATA_FRAME_HEADER_LEN]);

    Some((
        StreamId::from_be_bytes(id),
        DataFramePayload {
            frame,
            payload_offset: DATA_FRAME_HEADER_LEN,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{decode_data_frame, encode_data_frame, try_merge_data_frames};

    #[test]
    fn merges_consecutive_frames_for_the_same_stream() {
        let mut current = encode_data_frame(7, b"hello ");
        let next = encode_data_frame(7, b"world");

        assert!(try_merge_data_frames(&mut current, &next, 64));
        assert_eq!(
            decode_data_frame(&current),
            Some((7, b"hello world".to_vec()))
        );
    }

    #[test]
    fn does_not_merge_frames_from_different_streams() {
        let mut current = encode_data_frame(7, b"hello");
        let original = current.clone();
        let next = encode_data_frame(8, b"world");

        assert!(!try_merge_data_frames(&mut current, &next, 64));
        assert_eq!(current, original);
    }

    #[test]
    fn respects_the_merged_payload_limit() {
        let mut current = encode_data_frame(7, b"1234");
        let original = current.clone();
        let next = encode_data_frame(7, b"5678");

        assert!(!try_merge_data_frames(&mut current, &next, 7));
        assert_eq!(current, original);
    }

    #[test]
    fn rejects_invalid_frames_without_modifying_the_current_frame() {
        let mut current = vec![1, 2, 3];
        let original = current.clone();
        let next = encode_data_frame(7, b"payload");

        assert!(!try_merge_data_frames(&mut current, &next, 64));
        assert_eq!(current, original);

        let mut current = encode_data_frame(7, b"payload");
        let original = current.clone();
        assert!(!try_merge_data_frames(&mut current, &[1, 2, 3], 64));
        assert_eq!(current, original);
    }
}
