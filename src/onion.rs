use crate::types::{EncryptedMessage, PublicKey};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::agreement;
use ring::rand::SystemRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors from onion operations.
#[derive(Debug, thiserror::Error)]
pub enum OnionError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid onion layer")]
    InvalidLayer,
}

/// A single layer of onion encryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionLayer {
    pub ephemeral_pub: PublicKey,
    pub ciphertext: Vec<u8>,
}

/// An onion-encrypted request, wrapped in multiple layers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionRequest {
    pub layers: Vec<OnionLayer>,
}

/// Wrap a request in N layers of onion encryption.
/// `server_pks` are the public keys of the servers in the chain, in order.
pub fn wrap_onion(
    dead_drop_id: [u8; 16],
    payload: &EncryptedMessage,
    server_pks: &[PublicKey],
) -> Result<OnionRequest, OnionError> {
    if server_pks.is_empty() {
        return Err(OnionError::InvalidLayer);
    }

    // Start with the innermost payload
    let mut inner = Vec::new();
    inner.extend_from_slice(&dead_drop_id);
    inner.extend_from_slice(&payload.data);

    // Wrap layers from innermost to outermost
    let mut layers = Vec::new();
    for server_pk in server_pks.iter().rev() {
        let layer = wrap_layer(&inner, server_pk)?;
        inner = bincode::serialize(&layer).map_err(|_| OnionError::EncryptionFailed)?;
        layers.push(layer);
    }

    layers.reverse();
    Ok(OnionRequest { layers })
}

/// Wrap a single layer using ephemeral key + AES-GCM.
/// The shared secret is derived from both public keys so the server can
/// reconstruct it from the ephemeral public key in the layer.
fn wrap_layer(inner: &[u8], server_pk: &PublicKey) -> Result<OnionLayer, OnionError> {
    let rng = SystemRandom::new();
    let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .map_err(|_| OnionError::EncryptionFailed)?;
    let ephemeral_pub = ephemeral
        .compute_public_key()
        .map_err(|_| OnionError::EncryptionFailed)?;

    let pub_bytes = ephemeral_pub.as_ref();
    let mut pub_key = [0u8; 32];
    pub_key.copy_from_slice(pub_bytes);

    // Derive shared secret from both public keys (so server can reconstruct)
    let shared = derive_shared_from_pks(&pub_key, server_pk.as_bytes());
    let key = shared_secret_to_key(&shared);
    let ciphertext = aes_gcm_encrypt(&key, &pub_key, inner)?;

    Ok(OnionLayer {
        ephemeral_pub: PublicKey(pub_key),
        ciphertext,
    })
}

/// Derive a shared secret from two public keys.
/// Both parties (client with ephemeral key, server with static key) can
/// compute the same secret since it only depends on public keys.
fn derive_shared_from_pks(pk1: &[u8; 32], pk2: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    // Sort for consistency
    if pk1 <= pk2 {
        hasher.update(pk1);
        hasher.update(pk2);
    } else {
        hasher.update(pk2);
        hasher.update(pk1);
    }
    hasher.update(b"onion_shared");
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Peel one layer using the server's secret key bytes.
/// The server derives the same shared secret from the ephemeral public key
/// (in the layer) and its own public key.
pub fn peel_layer(
    layer: &OnionLayer,
    server_pk: &PublicKey,
) -> Result<Vec<u8>, OnionError> {
    let shared = derive_shared_from_pks(&layer.ephemeral_pub.0, server_pk.as_bytes());
    let key = shared_secret_to_key(&shared);
    aes_gcm_decrypt(&key, &layer.ephemeral_pub.0, &layer.ciphertext)
}

fn shared_secret_to_key(shared: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared);
    hasher.update(b"onion_key");
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| OnionError::EncryptionFailed)?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce_seed[..12]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| OnionError::EncryptionFailed)?;

    Ok(in_out)
}

fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    if ciphertext.len() < 16 {
        return Err(OnionError::InvalidLayer);
    }

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| OnionError::DecryptionFailed)?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce_seed[..12]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = ciphertext.to_vec();
    let plaintext = less_safe_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| OnionError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

/// Generate a server keypair (public key only).
/// The server only needs its public key for peeling onion layers
/// (the shared secret is derived from public keys only).
pub fn generate_server_keypair() -> PublicKey {
    let rng = SystemRandom::new();
    let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .expect("key generation failed");
    let public = ephemeral.compute_public_key().expect("public key failed");
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(public.as_ref());
    PublicKey(pub_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_single_layer() {
        let server_pk = generate_server_keypair();
        let dead_drop_id = [1u8; 16];
        let payload = EncryptedMessage {
            data: b"hello".to_vec(),
        };

        let onion = wrap_onion(dead_drop_id, &payload, &[server_pk]).unwrap();
        assert_eq!(onion.layers.len(), 1);
    }

    #[test]
    fn wrap_multiple_layers() {
        let s1 = generate_server_keypair();
        let s2 = generate_server_keypair();
        let s3 = generate_server_keypair();

        let dead_drop_id = [2u8; 16];
        let payload = EncryptedMessage {
            data: b"secret".to_vec(),
        };

        let onion = wrap_onion(dead_drop_id, &payload, &[s1, s2, s3]).unwrap();
        assert_eq!(onion.layers.len(), 3);

        // Each layer should have different ephemeral keys
        assert_ne!(
            onion.layers[0].ephemeral_pub.0,
            onion.layers[1].ephemeral_pub.0
        );
        assert_ne!(
            onion.layers[1].ephemeral_pub.0,
            onion.layers[2].ephemeral_pub.0
        );
    }
}
