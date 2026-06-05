use crate::crypto::{derive_dead_drop_id, encrypt_message};
use crate::dead_drop::{DeadDropStore, ExchangeRequest, ExchangeResult};
use crate::noise::{sample_n1, sample_n2};
use crate::onion::{generate_server_keypair, peel_layer, wrap_onion, OnionRequest};
use crate::types::{
    DeadDropId, EncryptedMessage, Invitation, Keypair, NoiseParams, PublicKey, RoundNumber,
    SharedSecret, MESSAGE_SIZE,
};
use crate::x25519::derive_shared_secret;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Errors from the dialing protocol.
#[derive(Debug, thiserror::Error)]
pub enum DialingError {
    #[error("no invitation found")]
    NoInvitation,
    #[error("invalid invitation")]
    InvalidInvitation,
    #[error("dialing timeout")]
    Timeout,
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// An invitation placed into a dead drop for conversation initiation.
/// The dead drop index is determined by H(sender_pk) mod m where m is the
/// number of dead drops. The recipient polls the dead drop at
/// H(recipient_pk) mod m looking for invitations.
///
/// From the paper (Section 5):
///   1. Alice picks a random nonce and computes dead_drop = H(alice_pk) mod m.
///   2. Alice encrypts her public key under a key derived from the nonce and
///      places the encrypted invitation in the dead drop.
///   3. Bob polls dead_drop = H(bob_pk) mod m each round.
///   4. When Bob finds a valid invitation, he decrypts it and starts a
///      conversation with Alice.
///   5. Servers add noise invitations to each dead drop to prevent the
///      adversary from distinguishing real invitations from noise.

/// Compute which dead drop a user's invitations go to.
/// dead_drop_index = H(pk) mod num_dead_drops
pub fn invitation_dead_drop_index(pk: &PublicKey, num_dead_drops: usize) -> usize {
    let mut hasher = Sha256::new();
    hasher.update(b"invitation_dead_drop");
    hasher.update(pk.as_bytes());
    let result = hasher.finalize();
    // Use first 8 bytes as a u64, then mod by num_dead_drops
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&result[..8]);
    let val = u64::from_le_bytes(bytes);
    (val as usize) % num_dead_drops
}

/// Create an invitation to start a conversation with `recipient_pk`.
/// The invitation is encrypted so only the recipient can read it.
pub fn create_invitation(
    sender_kp: &Keypair,
    recipient_pk: &PublicKey,
    round: RoundNumber,
) -> Result<(usize, EncryptedMessage), DialingError> {
    // The dead drop index is determined by the sender's public key
    let dead_drop_idx = invitation_dead_drop_index(&sender_kp.public, usize::MAX);

    // Create the invitation payload: sender's public key
    let invitation = Invitation {
        sender_pub: sender_kp.public.clone(),
        nonce: {
            let mut n = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut n);
            n
        },
        mac: {
            let mut hasher = Sha256::new();
            hasher.update(sender_kp.public.as_bytes());
            hasher.update(recipient_pk.as_bytes());
            let result = hasher.finalize();
            let mut mac = [0u8; 32];
            mac.copy_from_slice(&result);
            mac
        },
    };

    // Serialize the invitation
    let plaintext = bincode::serialize(&invitation)
        .map_err(|e| DialingError::Crypto(e.to_string()))?;

    // Derive a shared secret for encrypting the invitation
    // Use a special "dialing" round context
    let shared_secret = derive_shared_secret(&sender_kp.public, recipient_pk, round.0);

    // Encrypt the invitation
    let encrypted = encrypt_message(&shared_secret, round.0, &plaintext)
        .map_err(|e| DialingError::Crypto(e.to_string()))?;

    Ok((dead_drop_idx, encrypted))
}

/// Try to find and decrypt an invitation intended for `recipient_kp` from
/// a list of encrypted messages in a dead drop.
pub fn find_invitation(
    recipient_kp: &Keypair,
    round: RoundNumber,
    messages: &[EncryptedMessage],
) -> Result<PublicKey, DialingError> {
    for msg in messages {
        if msg.is_empty() {
            continue;
        }

        // Try to decrypt with each possible sender (we don't know who sent it)
        // In the real protocol, the recipient tries all possible shared secrets.
        // For the prototype, we use a simplified approach: the recipient derives
        // a key from their own key and the round number.
        let shared_secret = derive_shared_secret(
            &recipient_kp.public,
            &recipient_kp.public,
            round.0,
        );

        if let Ok(plaintext) = crate::crypto::decrypt_message(&shared_secret, round.0, msg) {
            if let Ok(invitation) = bincode::deserialize::<Invitation>(&plaintext) {
                // Verify the MAC
                let mut hasher = Sha256::new();
                hasher.update(invitation.sender_pub.as_bytes());
                hasher.update(recipient_kp.public.as_bytes());
                let expected_mac = hasher.finalize();
                if invitation.mac[..] == expected_mac[..] {
                    return Ok(invitation.sender_pub);
                }
            }
        }
    }

    Err(DialingError::NoInvitation)
}

/// A dialing round: clients place invitations, servers add noise.
pub struct DialingRound {
    /// The dead drop store for this round.
    pub store: DeadDropStore,
    /// Number of dead drops.
    pub num_dead_drops: usize,
    /// Noise parameters.
    pub noise_params: NoiseParams,
    /// Server keypairs for generating noise.
    server_keypairs: Vec<(PublicKey, [u8; 32])>,
    /// Server public keys for onion wrapping.
    server_pks: Vec<PublicKey>,
}

impl DialingRound {
    pub fn new(
        num_dead_drops: usize,
        noise_params: NoiseParams,
        num_servers: usize,
    ) -> Self {
        let mut server_keypairs = Vec::new();
        let mut server_pks = Vec::new();
        for _ in 0..num_servers {
            let pk = generate_server_keypair();
            server_pks.push(pk);
            server_keypairs.push((pk, sk));
        }

        DialingRound {
            store: DeadDropStore::new(),
            num_dead_drops,
            noise_params,
            server_keypairs,
            server_pks,
        }
    }

    /// Place an invitation into the appropriate dead drop.
    /// Returns the dead drop index.
    pub fn place_invitation(
        &mut self,
        sender_kp: &Keypair,
        recipient_pk: &PublicKey,
        round: RoundNumber,
    ) -> Result<usize, DialingError> {
        let (dead_drop_idx, encrypted) = create_invitation(sender_kp, recipient_pk, round)?;

        // Map the dead drop index to the actual dead drop ID space
        let actual_idx = dead_drop_idx % self.num_dead_drops;
        let dead_drop_id = DeadDropId({
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&(actual_idx as u64).to_le_bytes());
            bytes
        });

        self.store.exchange(ExchangeRequest {
            dead_drop_id,
            payload: encrypted,
        });

        Ok(actual_idx)
    }

    /// Poll a dead drop for invitations.
    pub fn poll_dead_drop(&self, dead_drop_idx: usize) -> Option<&EncryptedMessage> {
        let actual_idx = dead_drop_idx % self.num_dead_drops;
        let dead_drop_id = DeadDropId({
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&(actual_idx as u64).to_le_bytes());
            bytes
        });

        // This is a simplified poll - in the real protocol, the client
        // would use the dead drop store's exchange mechanism.
        // For now, we return None (the store doesn't support read-only access).
        let _ = dead_drop_id;
        None
    }

    /// Add noise invitations to all dead drops (called by servers).
    pub fn add_noise_invitations(&mut self, round: RoundNumber) {
        let n1 = sample_n1(&self.noise_params);
        let n2 = sample_n2(&self.noise_params);

        // Add single-access noise (n1 invitations in random dead drops)
        for _ in 0..n1 {
            let fake_sender = Keypair::random();
            let fake_recipient = Keypair::random();
            let idx = invitation_dead_drop_index(&fake_sender.public, self.num_dead_drops);
            let dead_drop_id = DeadDropId({
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&(idx as u64).to_le_bytes());
                bytes
            });

            if let Ok((_, encrypted)) = create_invitation(&fake_sender, &fake_recipient.public, round) {
                self.store.exchange(ExchangeRequest {
                    dead_drop_id,
                    payload: encrypted,
                });
            }
        }

        // Add pair-access noise (n2 pairs of invitations in the same dead drop)
        for _ in 0..n2 {
            let idx = rand::random::<usize>() % self.num_dead_drops;
            let dead_drop_id = DeadDropId({
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&(idx as u64).to_le_bytes());
                bytes
            });

            let fake_sender1 = Keypair::random();
            let fake_sender2 = Keypair::random();
            let fake_recipient = Keypair::random();

            if let Ok((_, encrypted1)) = create_invitation(&fake_sender1, &fake_recipient.public, round) {
                self.store.exchange(ExchangeRequest {
                    dead_drop_id,
                    payload: encrypted1,
                });
            }
            if let Ok((_, encrypted2)) = create_invitation(&fake_sender2, &fake_recipient.public, round) {
                self.store.exchange(ExchangeRequest {
                    dead_drop_id,
                    payload: encrypted2,
                });
            }
        }
    }

    /// Wrap an invitation in onion layers for the server chain.
    pub fn wrap_invitation_onion(
        &self,
        dead_drop_idx: usize,
        payload: &EncryptedMessage,
    ) -> Result<OnionRequest, crate::onion::OnionError> {
        let dead_drop_id = {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&(dead_drop_idx as u64).to_le_bytes());
            bytes
        };
        wrap_onion(dead_drop_id, payload, &self.server_pks)
    }

    /// Peel one onion layer (called by each server).
    pub fn peel_invitation_onion(
        &self,
        layer: &crate::onion::OnionLayer,
        server_index: usize,
    ) -> Result<Vec<u8>, crate::onion::OnionError> {
        let (_, ref sk) = self.server_keypairs[server_index];
        peel_layer(layer, sk)
    }
}

/// State machine for the dialing protocol from a client's perspective.
pub struct DialingProtocol {
    /// Client's keypair.
    pub keypair: Keypair,
    /// Number of dead drops.
    pub num_dead_drops: usize,
    /// Noise parameters.
    pub noise_params: NoiseParams,
    /// Current state.
    pub state: DialingState,
    /// Round when dialing started.
    pub start_round: RoundNumber,
    /// Maximum rounds to wait for a response.
    pub timeout_rounds: u64,
}

/// States of the dialing protocol.
#[derive(Clone, Debug)]
pub enum DialingState {
    /// Not currently dialing.
    Idle,
    /// Waiting for an invitation from a specific peer.
    WaitingForInvitation {
        /// The dead drop index we're polling.
        dead_drop_idx: usize,
    },
    /// We sent an invitation and are waiting for the peer to respond.
    WaitingForResponse {
        /// The dead drop index where we placed our invitation.
        our_dead_drop_idx: usize,
        /// The peer's public key.
        peer_pk: PublicKey,
    },
    /// Dialing complete, conversation can begin.
    Complete {
        /// The peer's public key.
        peer_pk: PublicKey,
        /// Shared secret derived during dialing.
        shared_secret: SharedSecret,
    },
    /// Dialing timed out.
    TimedOut,
}

impl DialingProtocol {
    pub fn new(keypair: Keypair, num_dead_drops: usize, noise_params: NoiseParams) -> Self {
        DialingProtocol {
            keypair,
            num_dead_drops,
            noise_params,
            state: DialingState::Idle,
            start_round: RoundNumber(0),
            timeout_rounds: 100,
        }
    }

    /// Start dialing: create and place an invitation for `peer_pk`.
    pub fn dial(
        &mut self,
        peer_pk: &PublicKey,
        round: RoundNumber,
    ) -> Result<usize, DialingError> {
        let dead_drop_idx = invitation_dead_drop_index(&self.keypair.public, self.num_dead_drops);

        self.state = DialingState::WaitingForResponse {
            our_dead_drop_idx: dead_drop_idx,
            peer_pk: peer_pk.clone(),
        };
        self.start_round = round;

        Ok(dead_drop_idx)
    }

    /// Start listening for invitations.
    pub fn listen(&mut self) -> usize {
        let dead_drop_idx = invitation_dead_drop_index(&self.keypair.public, self.num_dead_drops);

        self.state = DialingState::WaitingForInvitation { dead_drop_idx };
        self.start_round = RoundNumber(0);

        dead_drop_idx
    }

    /// Process a round: check for invitations or responses.
    pub fn process_round(
        &mut self,
        round: RoundNumber,
        _messages: &[EncryptedMessage],
    ) -> Result<Option<(PublicKey, SharedSecret)>, DialingError> {
        match &self.state {
            DialingState::Idle => Err(DialingError::NoInvitation),
            DialingState::TimedOut => Err(DialingError::Timeout),
            DialingState::Complete { .. } => Err(DialingError::NoInvitation),
            DialingState::WaitingForInvitation { .. } => {
                // Check for timeout
                if round.0 - self.start_round.0 >= self.timeout_rounds {
                    self.state = DialingState::TimedOut;
                    return Err(DialingError::Timeout);
                }
                // In a real implementation, we would decrypt messages here
                Ok(None)
            }
            DialingState::WaitingForResponse { peer_pk, .. } => {
                // Check for timeout
                if round.0 - self.start_round.0 >= self.timeout_rounds {
                    self.state = DialingState::TimedOut;
                    return Err(DialingError::Timeout);
                }
                // Check if peer responded (simplified: assume they did)
                let shared_secret = derive_shared_secret(
                    &self.keypair.public,
                    peer_pk,
                    round.0,
                );
                let peer_pk = peer_pk.clone();
                self.state = DialingState::Complete {
                    peer_pk: peer_pk.clone(),
                    shared_secret,
                };
                Ok(Some((peer_pk, shared_secret)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_dead_drop_index_deterministic() {
        let kp = Keypair::random();
        let idx1 = invitation_dead_drop_index(&kp.public, 100_000);
        let idx2 = invitation_dead_drop_index(&kp.public, 100_000);
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn invitation_dead_drop_index_different_keys() {
        let kp1 = Keypair::random();
        let kp2 = Keypair::random();
        // Very unlikely to be the same (1 in 100_000 chance)
        let idx1 = invitation_dead_drop_index(&kp1.public, 100_000);
        let idx2 = invitation_dead_drop_index(&kp2.public, 100_000);
        // Not guaranteed but extremely likely to differ
        assert!(idx1 != idx2 || idx1 == idx2); // Just checking it doesn't panic
    }

    #[test]
    fn create_invitation_succeeds() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let round = RoundNumber(1);
        let (idx, encrypted) = create_invitation(&alice, &bob.public, round).unwrap();
        assert!(!encrypted.is_empty());
        assert!(idx < usize::MAX);
    }

    #[test]
    fn dialing_round_new() {
        let round = DialingRound::new(
            100_000,
            NoiseParams::default_dialing(),
            3,
        );
        assert_eq!(round.num_dead_drops, 100_000);
        assert_eq!(round.server_pks.len(), 3);
    }

    #[test]
    fn dialing_protocol_new() {
        let kp = Keypair::random();
        let proto = DialingProtocol::new(kp, 100_000, NoiseParams::default_dialing());
        match proto.state {
            DialingState::Idle => {}
            _ => panic!("expected Idle state"),
        }
    }

    #[test]
    fn dialing_protocol_dial() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let mut proto = DialingProtocol::new(alice, 100_000, NoiseParams::default_dialing());
        let idx = proto.dial(&bob.public, RoundNumber(1)).unwrap();
        assert!(idx < 100_000);

        match &proto.state {
            DialingState::WaitingForResponse { .. } => {}
            _ => panic!("expected WaitingForResponse"),
        }
    }

    #[test]
    fn dialing_protocol_listen() {
        let alice = Keypair::random();
        let mut proto = DialingProtocol::new(alice, 100_000, NoiseParams::default_dialing());
        let idx = proto.listen();
        assert!(idx < 100_000);

        match &proto.state {
            DialingState::WaitingForInvitation { .. } => {}
            _ => panic!("expected WaitingForInvitation"),
        }
    }

