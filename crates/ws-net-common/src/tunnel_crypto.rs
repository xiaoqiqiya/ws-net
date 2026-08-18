use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, bail, Result};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    hkdf,
    rand::SystemRandom,
};

const FRAME_MAGIC: &[u8; 4] = b"WSNE";
const FRAME_SEQUENCE_LEN: usize = std::mem::size_of::<u64>();
const FRAME_HEADER_LEN: usize = FRAME_MAGIC.len() + FRAME_SEQUENCE_LEN;
const FRAME_TAG_LEN: usize = 16;
const KIND_TEXT: u8 = 1;
const KIND_BINARY: u8 = 2;
const ACCESS_TO_GATEWAY: &[u8] = b"ws-net/access-to-gateway/v2";
const GATEWAY_TO_ACCESS: &[u8] = b"ws-net/gateway-to-access/v2";
const BOOTSTRAP_CONTEXT: &[u8] = b"ws-net/bootstrap/v2";
const SESSION_CONTEXT: &[u8] = b"ws-net/session/v2";
pub const MAX_ENCRYPTED_TUNNEL_FRAME_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelFrameKind {
    Text,
    Binary,
}

struct AeadKeyLength;

impl hkdf::KeyType for AeadKeyLength {
    fn len(&self) -> usize {
        CHACHA20_POLY1305.key_len()
    }
}

struct DirectionCipher {
    key: LessSafeKey,
    nonce_prefix: [u8; 4],
    next_send_sequence: AtomicU64,
    next_receive_sequence: AtomicU64,
}

impl DirectionCipher {
    fn new(key: LessSafeKey, nonce_prefix: [u8; 4]) -> Self {
        Self {
            key,
            nonce_prefix,
            next_send_sequence: AtomicU64::new(0),
            next_receive_sequence: AtomicU64::new(0),
        }
    }

    fn encrypt(
        &self,
        kind: TunnelFrameKind,
        payload: &[u8],
        aad: &'static [u8],
    ) -> Result<Vec<u8>> {
        if payload.len() > MAX_ENCRYPTED_TUNNEL_FRAME_SIZE - FRAME_HEADER_LEN - FRAME_TAG_LEN - 1 {
            bail!("tunnel frame payload exceeds maximum size");
        }
        let sequence = self
            .next_send_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| anyhow!("tunnel send sequence exhausted"))?;
        let nonce = sequence_nonce(self.nonce_prefix, sequence);
        let plaintext_len = 1 + payload.len();
        let mut frame = vec![0_u8; FRAME_HEADER_LEN + plaintext_len + FRAME_TAG_LEN];
        frame[..FRAME_MAGIC.len()].copy_from_slice(FRAME_MAGIC);
        frame[FRAME_MAGIC.len()..FRAME_HEADER_LEN].copy_from_slice(&sequence.to_be_bytes());
        frame[FRAME_HEADER_LEN] = match kind {
            TunnelFrameKind::Text => KIND_TEXT,
            TunnelFrameKind::Binary => KIND_BINARY,
        };
        frame[FRAME_HEADER_LEN + 1..FRAME_HEADER_LEN + plaintext_len].copy_from_slice(payload);
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + plaintext_len],
            )
            .map_err(|_| anyhow!("failed to encrypt tunnel frame"))?;
        frame[FRAME_HEADER_LEN + plaintext_len..].copy_from_slice(tag.as_ref());
        Ok(frame)
    }

    fn decrypt(
        &self,
        mut frame: Vec<u8>,
        aad: &'static [u8],
    ) -> Result<(TunnelFrameKind, Vec<u8>)> {
        if frame.len() < FRAME_HEADER_LEN + 1 + FRAME_TAG_LEN
            || &frame[..FRAME_MAGIC.len()] != FRAME_MAGIC
        {
            bail!("invalid encrypted tunnel frame");
        }
        if frame.len() > MAX_ENCRYPTED_TUNNEL_FRAME_SIZE {
            bail!("encrypted tunnel frame exceeds maximum size");
        }
        let sequence = u64::from_be_bytes(
            frame[FRAME_MAGIC.len()..FRAME_HEADER_LEN]
                .try_into()
                .map_err(|_| anyhow!("invalid tunnel frame sequence"))?,
        );
        let expected = self.next_receive_sequence.load(Ordering::Acquire);
        if sequence != expected {
            bail!("unexpected tunnel frame sequence: expected {expected}, received {sequence}");
        }
        let nonce = sequence_nonce(self.nonce_prefix, sequence);
        let plaintext_len = {
            let plaintext = self
                .key
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    &mut frame[FRAME_HEADER_LEN..],
                )
                .map_err(|_| anyhow!("encrypted tunnel frame authentication failed"))?;
            plaintext.len()
        };
        let next = expected
            .checked_add(1)
            .ok_or_else(|| anyhow!("tunnel receive sequence exhausted"))?;
        self.next_receive_sequence
            .compare_exchange(expected, next, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow!("concurrent tunnel frame receive detected"))?;
        let kind = match frame[FRAME_HEADER_LEN] {
            KIND_TEXT => TunnelFrameKind::Text,
            KIND_BINARY => TunnelFrameKind::Binary,
            _ => bail!("encrypted tunnel frame has unknown type"),
        };
        let payload_len = plaintext_len - 1;
        frame.copy_within(FRAME_HEADER_LEN + 1..FRAME_HEADER_LEN + 1 + payload_len, 0);
        frame.truncate(payload_len);
        Ok((kind, frame))
    }
}

pub struct TunnelCipher {
    access_to_gateway: DirectionCipher,
    gateway_to_access: DirectionCipher,
}

pub struct EphemeralKeyPair {
    private_key: EphemeralPrivateKey,
    public_key: Vec<u8>,
}

impl EphemeralKeyPair {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| anyhow!("failed to generate tunnel ephemeral key"))?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| anyhow!("failed to compute tunnel public key"))?
            .as_ref()
            .to_vec();
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn derive_session_cipher(self, peer_public_key: &[u8]) -> Result<TunnelCipher> {
        let peer_public_key = UnparsedPublicKey::new(&X25519, peer_public_key);
        agreement::agree_ephemeral(self.private_key, &peer_public_key, |shared_secret| {
            TunnelCipher::from_key_material(shared_secret, SESSION_CONTEXT)
        })
        .map_err(|_| anyhow!("invalid tunnel peer public key"))?
    }
}

impl TunnelCipher {
    pub fn from_shared_key(shared_key: &str) -> Result<Self> {
        if shared_key.trim().is_empty() {
            bail!("tunnel bootstrap secret must not be empty");
        }
        Self::from_key_material(shared_key.as_bytes(), BOOTSTRAP_CONTEXT)
    }

    fn from_key_material(material: &[u8], context: &[u8]) -> Result<Self> {
        if material.is_empty() {
            bail!("empty tunnel key material");
        }
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"ws-net tunnel hkdf salt v2");
        let prk = salt.extract(material);
        Ok(Self {
            access_to_gateway: DirectionCipher::new(
                derive_key(&prk, context, ACCESS_TO_GATEWAY)?,
                *b"A2GW",
            ),
            gateway_to_access: DirectionCipher::new(
                derive_key(&prk, context, GATEWAY_TO_ACCESS)?,
                *b"G2AC",
            ),
        })
    }

    pub fn encrypt_from_access(&self, kind: TunnelFrameKind, payload: &[u8]) -> Result<Vec<u8>> {
        self.access_to_gateway
            .encrypt(kind, payload, ACCESS_TO_GATEWAY)
    }

    pub fn decrypt_from_access(&self, frame: Vec<u8>) -> Result<(TunnelFrameKind, Vec<u8>)> {
        self.access_to_gateway.decrypt(frame, ACCESS_TO_GATEWAY)
    }

    pub fn encrypt_from_gateway(&self, kind: TunnelFrameKind, payload: &[u8]) -> Result<Vec<u8>> {
        self.gateway_to_access
            .encrypt(kind, payload, GATEWAY_TO_ACCESS)
    }

    pub fn decrypt_from_gateway(&self, frame: Vec<u8>) -> Result<(TunnelFrameKind, Vec<u8>)> {
        self.gateway_to_access.decrypt(frame, GATEWAY_TO_ACCESS)
    }
}

fn derive_key(prk: &hkdf::Prk, context: &[u8], direction: &[u8]) -> Result<LessSafeKey> {
    let info = [context, direction];
    let okm = prk
        .expand(&info, AeadKeyLength)
        .map_err(|_| anyhow!("failed to derive tunnel direction key"))?;
    let mut key_bytes = [0_u8; 32];
    okm.fill(&mut key_bytes)
        .map_err(|_| anyhow!("failed to fill tunnel direction key"))?;
    let key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
        .map_err(|_| anyhow!("failed to initialize tunnel direction cipher"))?;
    Ok(LessSafeKey::new(key))
}

fn sequence_nonce(prefix: [u8; 4], sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_authenticates_and_rejects_replay() {
        let sender = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let receiver = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let frame = sender
            .encrypt_from_access(TunnelFrameKind::Binary, b"private payload")
            .unwrap();
        assert!(!frame
            .windows(b"private payload".len())
            .any(|part| part == b"private payload"));
        assert_eq!(
            receiver.decrypt_from_access(frame.clone()).unwrap(),
            (TunnelFrameKind::Binary, b"private payload".to_vec())
        );
        assert!(receiver.decrypt_from_access(frame).is_err());
    }

    #[test]
    fn rejects_tampering_and_wrong_direction() {
        let sender = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let receiver = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let frame = sender
            .encrypt_from_access(TunnelFrameKind::Text, b"authenticated")
            .unwrap();
        assert!(receiver.decrypt_from_gateway(frame.clone()).is_err());
        let mut tampered = frame;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(receiver.decrypt_from_access(tampered).is_err());
    }

    #[test]
    fn decrypts_sequential_frames_and_rejects_out_of_order_frames() {
        let sender = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let receiver = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let first = sender
            .encrypt_from_access(TunnelFrameKind::Text, b"first")
            .unwrap();
        let second = sender
            .encrypt_from_access(TunnelFrameKind::Binary, b"second")
            .unwrap();

        assert!(receiver.decrypt_from_access(second.clone()).is_err());
        assert_eq!(
            receiver.decrypt_from_access(first).unwrap(),
            (TunnelFrameKind::Text, b"first".to_vec())
        );
        assert_eq!(
            receiver.decrypt_from_access(second).unwrap(),
            (TunnelFrameKind::Binary, b"second".to_vec())
        );
    }

    #[test]
    fn direction_sequences_are_independent() {
        let sender = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let receiver = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let access_frame = sender
            .encrypt_from_access(TunnelFrameKind::Binary, b"request")
            .unwrap();
        let gateway_frame = sender
            .encrypt_from_gateway(TunnelFrameKind::Binary, b"response")
            .unwrap();

        assert_eq!(
            receiver.decrypt_from_gateway(gateway_frame).unwrap().1,
            b"response"
        );
        assert_eq!(
            receiver.decrypt_from_access(access_frame).unwrap().1,
            b"request"
        );
    }

    #[test]
    fn enforces_encrypted_frame_size_limit() {
        let cipher = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let maximum_payload =
            MAX_ENCRYPTED_TUNNEL_FRAME_SIZE - FRAME_HEADER_LEN - FRAME_TAG_LEN - 1;
        let frame = cipher
            .encrypt_from_access(TunnelFrameKind::Binary, &vec![0_u8; maximum_payload])
            .unwrap();
        assert_eq!(frame.len(), MAX_ENCRYPTED_TUNNEL_FRAME_SIZE);
        assert!(cipher
            .encrypt_from_gateway(TunnelFrameKind::Binary, &vec![0_u8; maximum_payload + 1])
            .is_err());

        let receiver = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let mut oversized = frame;
        oversized.push(0);
        assert!(receiver.decrypt_from_access(oversized).is_err());
    }

    #[test]
    fn derives_a_unique_matching_session_key_pair() {
        let access = EphemeralKeyPair::generate().unwrap();
        let gateway = EphemeralKeyPair::generate().unwrap();
        let access_public_key = access.public_key().to_vec();
        let gateway_public_key = gateway.public_key().to_vec();
        let access_cipher = access.derive_session_cipher(&gateway_public_key).unwrap();
        let gateway_cipher = gateway.derive_session_cipher(&access_public_key).unwrap();
        let frame = access_cipher
            .encrypt_from_access(TunnelFrameKind::Text, b"rotated session key")
            .unwrap();
        assert_eq!(
            gateway_cipher.decrypt_from_access(frame).unwrap(),
            (TunnelFrameKind::Text, b"rotated session key".to_vec())
        );
    }
}
