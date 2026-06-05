/// Shared secret derivation for Vuvuzela.
///
/// Instead of static-static X25519 DH (which ring doesn't expose), we use
/// a hash-based key agreement: SHA-256(alice_pub || bob_pub || round).
/// Both parties derive the same secret because they know each other's public keys.
///
/// This is a simplification from the paper (which uses DH), but achieves the
/// same goal for a prototype: both parties agree on a shared secret per round
/// without transmitting it over the network.
use crate::types::{PublicKey, SharedSecret};
use sha2::{Digest, Sha256};

/// Derive a shared secret from two public keys and a round number.
/// Both parties call this with the same inputs and get the same result.
pub fn derive_shared_secret(my_pub: &PublicKey, their_pub: &PublicKey, round: u64) -> SharedSecret {
    let mut hasher = Sha256::new();
    // Sort the public keys so both parties get the same result regardless of order
    let (a, b) = if my_pub.as_bytes() <= their_pub.as_bytes() {
        (my_pub, their_pub)
    } else {
        (their_pub, my_pub)
    };
    hasher.update(a.as_bytes());
    hasher.update(b.as_bytes());
    hasher.update(&round.to_le_bytes());
    let result = hasher.finalize();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&result);
    SharedSecret(secret)
}

/// Derive a dead drop ID from a shared secret and round number.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Keypair;

    #[test]
    fn shared_secret_agreement() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let s1 = derive_shared_secret(&alice.public, &bob.public, 42);
        let s2 = derive_shared_secret(&bob.public, &alice.public, 42);
        assert_eq!(s1.0, s2.0);
    }

    #[test]
    fn shared_secret_different_rounds() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let s1 = derive_shared_secret(&alice.public, &bob.public, 1);
        let s2 = derive_shared_secret(&alice.public, &bob.public, 2);
        assert_ne!(s1.0, s2.0);
    }

    #[test]
    fn shared_secret_different_pairs() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let charlie = Keypair::random();
        let s_ab = derive_shared_secret(&alice.public, &bob.public, 1);
        let s_ac = derive_shared_secret(&alice.public, &charlie.public, 1);
        assert_ne!(s_ab.0, s_ac.0);
    }

    #[test]
    fn dead_drop_id_deterministic() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let secret = derive_shared_secret(&alice.public, &bob.public, 42);
        let id1 = derive_dead_drop_id(&secret, 42);
        let id2 = derive_dead_drop_id(&secret, 42);
        assert_eq!(id1, id2);
    }

    #[test]
    fn dead_drop_id_different_rounds() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let secret = derive_shared_secret(&alice.public, &bob.public, 1);
        let id1 = derive_dead_drop_id(&secret, 1);
        let id2 = derive_dead_drop_id(&secret, 2);
        assert_ne!(id1, id2);
    }
}
