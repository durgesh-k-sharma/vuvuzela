use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;

/// 128-bit dead drop identifier. Two clients in a conversation derive the same
/// ID from their shared secret and the round number. Random otherwise.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeadDropId(pub [u8; 16]);

impl DeadDropId {
    pub fn random() -> Self {
        let mut buf = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut buf);
        DeadDropId(buf)
    }
}

impl fmt::Debug for DeadDropId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeadDropId({})", hex::encode(&self.0[..8]))
    }
}

/// Monotonically increasing round counter. Each round has a fresh set of
/// dead drops that are wiped when the round ends.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoundNumber(pub u64);

impl fmt::Debug for RoundNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Round({})", self.0)
    }
}

/// Curve25519 public key. Branded to prevent accidental use where a
/// shared secret or dead drop ID is expected.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(&self.0[..8]))
    }
}

/// Shared secret derived from Diffie-Hellman. Branded to prevent accidental
/// use where a public key is expected.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret(REDACTED)")
    }
}

/// Curve25519 keypair for a client or server.
/// We generate the public key using ring's ephemeral API, but only store
/// the public key. The shared secret is derived via hash-based key agreement
/// (see x25519::derive_shared_secret), not DH.
#[derive(Clone)]
pub struct Keypair {
    pub public: PublicKey,
}

impl Keypair {
    pub fn random() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let secret = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
            .expect("key generation failed");
        let public = secret
            .compute_public_key()
            .expect("public key computation failed");
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(public.as_ref());
        Keypair {
            public: PublicKey(public_bytes),
        }
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keypair {{ public: {:?} }}", self.public)
    }
}

/// Parameters for the truncated Laplace distribution used in cover traffic.
/// mu is the mean. b is the scale parameter (standard deviation = sqrt(2) * b).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct NoiseParams {
    pub mu: f64,
    pub b: f64,
}

impl NoiseParams {
    /// Default parameters matching the paper's conversation protocol
    /// (mu = 300_000, b = 13_800) which provides eps' = ln(2), delta' = 1e-4
    /// for 250_000 rounds.
    pub fn default_conversation() -> Self {
        NoiseParams {
            mu: 300_000.0,
            b: 13_800.0,
        }
    }

    /// Default parameters matching the paper's dialing protocol
    /// (mu = 13_000, b = 7_700) which provides eps' = ln(2), delta' = 1e-4
    /// for 3_500 rounds.
    pub fn default_dialing() -> Self {
        NoiseParams {
            mu: 13_000.0,
            b: 7_700.0,
        }
    }
}

/// Fixed-size message payload. All messages are padded to this size so the
/// adversary cannot distinguish them by length.
pub const MESSAGE_SIZE: usize = 256;

/// A padded, encrypted message ready for placement in a dead drop.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub data: Vec<u8>,
}

impl EncryptedMessage {
    pub fn empty() -> Self {
        EncryptedMessage {
            data: vec![0u8; MESSAGE_SIZE],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }
}

/// An invitation sent during the dialing protocol. Contains the sender's
/// public key, encrypted with the recipient's public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invitation {
    pub sender_pub: PublicKey,
    pub nonce: [u8; 16],
    pub mac: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_drop_id_random_unique() {
        let a = DeadDropId::random();
        let b = DeadDropId::random();
        assert_ne!(a, b);
    }

    #[test]
    fn keypair_random_unique() {
        let a = Keypair::random();
        let b = Keypair::random();
        assert_ne!(a.public.0, b.public.0);
    }

    #[test]
    fn keypair_clone() {
        let a = Keypair::random();
        let b = a.clone();
        assert_eq!(a.public.0, b.public.0);
    }

    #[test]
    fn encrypted_message_empty() {
        let msg = EncryptedMessage::empty();
        assert_eq!(msg.data.len(), MESSAGE_SIZE);
        assert!(msg.is_empty());
    }

    #[test]
    fn round_number_ordering() {
        let r1 = RoundNumber(1);
        let r2 = RoundNumber(2);
        assert!(r1 < r2);
    }
}
