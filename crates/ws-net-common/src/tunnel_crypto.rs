use anyhow::{anyhow, bail, Result};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    digest,
    rand::{SecureRandom, SystemRandom},
};

const FRAME_MAGIC: &[u8; 4] = b"WSNE";
const FRAME_HEADER_LEN: usize = FRAME_MAGIC.len() + NONCE_LEN;
const FRAME_TAG_LEN: usize = 16;
const KIND_TEXT: u8 = 1;
const KIND_BINARY: u8 = 2;
const ACCESS_TO_GATEWAY: &[u8] = b"ws-net/access-to-gateway/v1";
const GATEWAY_TO_ACCESS: &[u8] = b"ws-net/gateway-to-access/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelFrameKind {
    Text,
    Binary,
}

pub struct TunnelCipher {
    key: LessSafeKey,
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
            TunnelCipher::from_session_secret(shared_secret)
        })
        .map_err(|_| anyhow!("invalid tunnel peer public key"))?
    }
}

impl TunnelCipher {
    pub fn from_shared_key(shared_key: &str) -> Result<Self> {
        if shared_key.trim().is_empty() {
            bail!("tunnel bootstrap secret must not be empty");
        }
        let mut material = b"ws-net tunnel encryption key v1\0".to_vec();
        material.extend_from_slice(shared_key.as_bytes());
        let digest = digest::digest(&digest::SHA256, &material);
        let key = UnboundKey::new(&CHACHA20_POLY1305, digest.as_ref())
            .map_err(|_| anyhow!("failed to initialize tunnel cipher"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
        })
    }

    fn from_session_secret(shared_secret: &[u8]) -> Result<Self> {
        if shared_secret.is_empty() {
            bail!("empty tunnel session secret");
        }
        let mut material = b"ws-net ephemeral tunnel session v1\0".to_vec();
        material.extend_from_slice(shared_secret);
        let digest = digest::digest(&digest::SHA256, &material);
        let key = UnboundKey::new(&CHACHA20_POLY1305, digest.as_ref())
            .map_err(|_| anyhow!("failed to initialize tunnel session cipher"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
        })
    }

    pub fn encrypt_from_access(&self, kind: TunnelFrameKind, payload: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(kind, payload, ACCESS_TO_GATEWAY)
    }

    pub fn decrypt_from_access(&self, frame: &[u8]) -> Result<(TunnelFrameKind, Vec<u8>)> {
        self.decrypt(frame, ACCESS_TO_GATEWAY)
    }

    pub fn encrypt_from_gateway(&self, kind: TunnelFrameKind, payload: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(kind, payload, GATEWAY_TO_ACCESS)
    }

    pub fn decrypt_from_gateway(&self, frame: &[u8]) -> Result<(TunnelFrameKind, Vec<u8>)> {
        self.decrypt(frame, GATEWAY_TO_ACCESS)
    }

    fn encrypt(
        &self,
        kind: TunnelFrameKind,
        payload: &[u8],
        aad: &'static [u8],
    ) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow!("failed to generate tunnel frame nonce"))?;
        let mut body = Vec::with_capacity(1 + payload.len() + FRAME_TAG_LEN);
        body.push(match kind {
            TunnelFrameKind::Text => KIND_TEXT,
            TunnelFrameKind::Binary => KIND_BINARY,
        });
        body.extend_from_slice(payload);
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad),
                &mut body,
            )
            .map_err(|_| anyhow!("failed to encrypt tunnel frame"))?;
        let mut encrypted = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
        encrypted.extend_from_slice(FRAME_MAGIC);
        encrypted.extend_from_slice(&nonce_bytes);
        encrypted.extend_from_slice(&body);
        Ok(encrypted)
    }

    fn decrypt(&self, frame: &[u8], aad: &'static [u8]) -> Result<(TunnelFrameKind, Vec<u8>)> {
        if frame.len() < FRAME_HEADER_LEN + 1 + FRAME_TAG_LEN || &frame[..4] != FRAME_MAGIC {
            bail!("invalid encrypted tunnel frame");
        }
        let nonce_bytes: [u8; NONCE_LEN] = frame[4..FRAME_HEADER_LEN]
            .try_into()
            .map_err(|_| anyhow!("invalid encrypted tunnel nonce"))?;
        let mut encrypted = frame[FRAME_HEADER_LEN..].to_vec();
        let plaintext = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad),
                &mut encrypted,
            )
            .map_err(|_| anyhow!("encrypted tunnel frame authentication failed"))?;
        let Some((&kind, payload)) = plaintext.split_first() else {
            bail!("encrypted tunnel frame has no type");
        };
        let kind = match kind {
            KIND_TEXT => TunnelFrameKind::Text,
            KIND_BINARY => TunnelFrameKind::Binary,
            _ => bail!("encrypted tunnel frame has unknown type"),
        };
        Ok((kind, payload.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_authenticates_each_direction() {
        let cipher = TunnelCipher::from_shared_key("0123456789abcdef0123456789abcdef").unwrap();
        let frame = cipher
            .encrypt_from_access(TunnelFrameKind::Binary, b"private payload")
            .unwrap();
        assert!(!frame
            .windows(b"private payload".len())
            .any(|part| part == b"private payload"));
        assert_eq!(
            cipher.decrypt_from_access(&frame).unwrap(),
            (TunnelFrameKind::Binary, b"private payload".to_vec())
        );
        assert!(cipher.decrypt_from_gateway(&frame).is_err());
        let mut tampered = frame;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(cipher.decrypt_from_access(&tampered).is_err());
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
            gateway_cipher.decrypt_from_access(&frame).unwrap(),
            (TunnelFrameKind::Text, b"rotated session key".to_vec())
        );
    }
}
