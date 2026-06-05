use crate::types::{EncryptedMessage, SharedSecret, MESSAGE_SIZE};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::{Digest, Sha256};

/// Errors that can occur during cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid ciphertext length")]
    InvalidLength,
}

/// Derive a symmetric encryption key from a shared secret and round number.
/// Uses SHA-256 to produce a 256-bit key.
pub fn derive_key(secret: &SharedSecret, round: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(&round.to_le_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Derive a dead drop ID from a shared secret and round number.
/// Uses SHA-256 and takes the first 16 bytes.
pub fn derive_dead_drop_id(secret: &SharedSecret, round: u64) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(b"dead_drop");
    let result = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&result[..16]);
    id
}

/// Build a 96-bit nonce from a round number.
fn make_nonce(round: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&round.to_le_bytes());
    nonce_bytes[8..].copy_from_slice(&[0, 0, 0, 1]);
    Nonce::assume_unique_for_key(nonce_bytes)
}

/// Encrypt a plaintext message using AES-256-GCM with the given key.
/// The nonce is derived from the round number.
/// Returns the ciphertext with the 16-byte authentication tag appended.
pub fn encrypt(key: &[u8; 32], round: u64, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::EncryptionFailed)?;
    let less_safe_key = LessSafeKey::new(unbound_key);
    let nonce = make_nonce(round);

    // ring's AES-256-GCM appends the 16-byte tag to the ciphertext
    let mut in_out = plaintext.to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(in_out)
}

/// Decrypt a ciphertext using AES-256-GCM.
/// The nonce is derived from the round number.
pub fn decrypt(key: &[u8; 32], round: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < 16 {
        return Err(CryptoError::InvalidLength);
    }

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::DecryptionFailed)?;
    let less_safe_key = LessSafeKey::new(unbound_key);
    let nonce = make_nonce(round);

    let mut in_out = ciphertext.to_vec();
    let plaintext = less_safe_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

/// Pad a message to MESSAGE_SIZE bytes.
/// Uses a simple length-prefixed scheme: first 2 bytes are the message length
/// (little-endian u16), followed by the message, followed by zeros.
pub fn pad_message(msg: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; MESSAGE_SIZE];
    let len = msg.len().min(MESSAGE_SIZE - 2);
    result[0] = (len & 0xff) as u8;
    result[1] = ((len >> 8) & 0xff) as u8;
    result[2..2 + len].copy_from_slice(&msg[..len]);
    result
}

/// Remove length-padded message.
pub fn unpad_message(data: &[u8]) -> Vec<u8> {
    if data.len() < 2 {
        return data.to_vec();
    }
    let len = (data[0] as usize) | ((data[1] as usize) << 8);
    if len > data.len() - 2 {
        return data.to_vec();
    }
    data[2..2 + len].to_vec()
}

/// Encrypt a message for placement in a dead drop.
pub fn encrypt_message(
    secret: &SharedSecret,
    round: u64,
    plaintext: &[u8],
) -> Result<EncryptedMessage, CryptoError> {
    let key = derive_key(secret, round);
    let padded = pad_message(plaintext);
    let data = encrypt(&key, round, &padded)?;
    Ok(EncryptedMessage { data })
}

/// Decrypt a message from a dead drop.
pub fn decrypt_message(
    secret: &SharedSecret,
    round: u64,
    msg: &EncryptedMessage,
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_key(secret, round);
    let padded = decrypt(&key, round, &msg.data)?;
    Ok(unpad_message(&padded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Keypair;
    use crate::x25519::derive_shared_secret;

    fn test_secret() -> SharedSecret {
        let alice = Keypair::random();
        let bob = Keypair::random();
        derive_shared_secret(&alice.public, &bob.public, 1)
    }

    #[test]
    fn derive_key_deterministic() {
        let secret = test_secret();
        let k1 = derive_key(&secret, 42);
        let k2 = derive_key(&secret, 42);
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_different_rounds() {
        let secret = test_secret();
        let k1 = derive_key(&secret, 1);
        let k2 = derive_key(&secret, 2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_dead_drop_id_deterministic() {
        let secret = test_secret();
        let id1 = derive_dead_drop_id(&secret, 42);
        let id2 = derive_dead_drop_id(&secret, 42);
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_dead_drop_id_different_rounds() {
        let secret = test_secret();
        let id1 = derive_dead_drop_id(&secret, 1);
        let id2 = derive_dead_drop_id(&secret, 2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let secret = test_secret();
        let plaintext = b"Hello, Bob!";
        let encrypted = encrypt_message(&secret, 1, plaintext).unwrap();
        let decrypted = decrypt_message(&secret, 1, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_wrong_key_fails() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let charlie = Keypair::random();
        let secret_ab = derive_shared_secret(&alice.public, &bob.public, 1);
        let secret_ac = derive_shared_secret(&alice.public, &charlie.public, 1);
        let plaintext = b"Hello, Bob!";
        let encrypted = encrypt_message(&secret_ab, 1, plaintext).unwrap();
        let result = decrypt_message(&secret_ac, 1, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_wrong_round_fails() {
        let secret = test_secret();
        let plaintext = b"Hello, Bob!";
        let encrypted = encrypt_message(&secret, 1, plaintext).unwrap();
        let result = decrypt_message(&secret, 2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn pad_unpad_roundtrip() {
        let msg = b"short";
        let padded = pad_message(msg);
        assert_eq!(padded.len(), MESSAGE_SIZE);
        let unpadded = unpad_message(&padded);
        assert_eq!(unpadded, msg);
    }

    #[test]
    fn pad_unpad_empty() {
        let msg = b"";
        let padded = pad_message(msg);
        assert_eq!(padded.len(), MESSAGE_SIZE);
        assert_eq!(padded[0], 0);
        assert_eq!(padded[1], 0);
        let unpadded = unpad_message(&padded);
        assert_eq!(unpadded, msg);
    }

    #[test]
    fn pad_exact_size() {
        let msg = vec![0xABu8; MESSAGE_SIZE - 2];
        let padded = pad_message(&msg);
        assert_eq!(padded.len(), MESSAGE_SIZE);
        let unpadded = unpad_message(&padded);
        assert_eq!(unpadded, msg);
    }

    #[test]
    fn empty_message_encryption() {
        let secret = test_secret();
        let plaintext = b"";
        let encrypted = encrypt_message(&secret, 1, plaintext).unwrap();
        let decrypted = decrypt_message(&secret, 1, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
