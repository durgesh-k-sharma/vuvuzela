/// Conversation Protocol (Algorithms 1 and 2 from the Vuvuzela paper).
///
/// Algorithm 1 (Send): A client computes a dead drop ID from the shared secret
/// with their partner, encrypts the message, onion-wraps it through the server
/// chain, and places it into the dead drop store.
///
/// Algorithm 2 (Receive): A client computes the same dead drop ID, retrieves
/// the partner's message from the dead drop store, and decrypts it.
use crate::crypto::{self, decrypt_message, derive_dead_drop_id, encrypt_message};
use crate::dead_drop::{DeadDropStore, ExchangeRequest, ExchangeResult};
use crate::onion;
use crate::types::{DeadDropId, EncryptedMessage, Keypair, PublicKey, RoundNumber, SharedSecret, MESSAGE_SIZE};
use crate::x25519::derive_shared_secret;

/// Errors from conversation operations.
#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    #[error("no partner message available")]
    NoPartner,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("onion wrapping failed")]
    OnionError(#[from] onion::OnionError),
    #[error("crypto error")]
    CryptoError(#[from] crypto::CryptoError),
}

/// A conversation between two clients.
/// Each client holds their own keypair and their partner's public key.
pub struct Conversation {
    /// This client's keypair.
    pub my_keypair: Keypair,
    /// The partner's public key.
    pub partner_pub: PublicKey,
    /// The shared secret derived from both public keys.
    pub shared_secret: SharedSecret,
    /// Server public keys for onion wrapping (in chain order).
    pub server_pks: Vec<PublicKey>,
}

impl Conversation {
    /// Create a new conversation between two clients.
    /// Both clients must call this with the same round number to derive the
    /// same shared secret.
    pub fn new(my_keypair: Keypair, partner_pub: PublicKey, round: u64) -> Self {
        let shared_secret = derive_shared_secret(&my_keypair.public, &partner_pub, round);
        Conversation {
            my_keypair,
            partner_pub,
            shared_secret,
            server_pks: Vec::new(),
        }
    }

    /// Set the server public keys for onion wrapping.
    pub fn set_servers(&mut self, server_pks: Vec<PublicKey>) {
        self.server_pks = server_pks;
    }

    /// Algorithm 1: Send a message to the partner.
    ///
    /// 1. Compute the dead drop ID from the shared secret and round number.
    /// 2. Encrypt the message with the shared secret.
    /// 3. Onion-wrap the encrypted message through the server chain.
    /// 4. Place the onion request into the dead drop store.
    pub fn send(
        &self,
        round: RoundNumber,
        plaintext: &[u8],
        store: &mut DeadDropStore,
    ) -> Result<ExchangeResult, ConversationError> {
        // Step 1: Compute dead drop ID
        let dd_id_bytes = derive_dead_drop_id(&self.shared_secret, round.0);
        let dead_drop_id = DeadDropId(dd_id_bytes);

        // Step 2: Encrypt the message
        let encrypted = encrypt_message(&self.shared_secret, round.0, plaintext)?;

        // Step 3: Place the encrypted message in the dead drop
        // (Onion wrapping is a no-op in the prototype since we can't peel
        // without server cooperation. In production, the onion would be
        // peeled by each server in the chain.)
        let request = ExchangeRequest {
            dead_drop_id,
            payload: encrypted,
        };

        let result = store.exchange(request);
        Ok(result)
    }

    /// Algorithm 2: Receive a message from the partner.
    ///
    /// 1. Compute the dead drop ID from the shared secret and round number.
    /// 2. Retrieve the partner's message from the dead drop store.
    /// 3. Decrypt the message.
    pub fn receive(
        &self,
        round: RoundNumber,
        store: &mut DeadDropStore,
    ) -> Result<Vec<u8>, ConversationError> {
        // Step 1: Compute dead drop ID (same as partner's)
        let dd_id_bytes = derive_dead_drop_id(&self.shared_secret, round.0);
        let dead_drop_id = DeadDropId(dd_id_bytes);

        // Step 2: Create a "read" request to retrieve partner's message
        // without disturbing the store (empty payload = read-only)
        let request = ExchangeRequest {
            dead_drop_id,
            payload: EncryptedMessage::empty(),
        };

        let result = store.retrieve(request.dead_drop_id);
        match result {
            ExchangeResult::Success(partner_payload) if !partner_payload.is_empty() => {
                let plaintext = decrypt_message(&self.shared_secret, round.0, &partner_payload)?;
                Ok(plaintext)
            }
            ExchangeResult::Success(_) => {
                // Empty payload means no partner message yet
                Err(ConversationError::NoPartner)
            }
            ExchangeResult::NoPartner => Err(ConversationError::NoPartner),
        }
    }

    /// Prepare a message for sending (without placing in the store).
    /// Returns the exchange request with the encrypted payload.
    pub fn prepare_message(
        &self,
        round: RoundNumber,
        plaintext: &[u8],
    ) -> Result<ExchangeRequest, ConversationError> {
        let dd_id_bytes = derive_dead_drop_id(&self.shared_secret, round.0);
        let dead_drop_id = DeadDropId(dd_id_bytes);

        let encrypted = encrypt_message(&self.shared_secret, round.0, plaintext)?;

        Ok(ExchangeRequest {
            dead_drop_id,
            payload: encrypted,
        })
    }

    /// Decrypt a received message from a prepared exchange request.
    pub fn decrypt_received(
        &self,
        round: RoundNumber,
        payload: &EncryptedMessage,
    ) -> Result<Vec<u8>, ConversationError> {
        Ok(decrypt_message(&self.shared_secret, round.0, payload)?)
    }
}

/// Simulate a full round of conversation between Alice and Bob.
/// In the real protocol, both clients send simultaneously and the server
/// pairs them up. In our simulation, we model this as:
/// 1. Alice sends (stores her message)
/// 2. Bob sends (gets Alice's message, stores his)
/// 3. Alice retrieves (gets Bob's message)
pub fn simulate_round(
    alice: &Conversation,
    bob: &Conversation,
    round: RoundNumber,
    alice_msg: &[u8],
    bob_msg: &[u8],
    store: &mut DeadDropStore,
) -> Result<(Vec<u8>, Vec<u8>), ConversationError> {
    // Alice sends
    let _ = alice.send(round, alice_msg, store)?;

    // Bob sends (this triggers the exchange: Bob gets Alice's message)
    let bob_result = bob.send(round, bob_msg, store)?;
    let bob_received = match bob_result {
        crate::dead_drop::ExchangeResult::Success(payload) => {
            alice.decrypt_received(round, &payload)?
        }
        crate::dead_drop::ExchangeResult::NoPartner => {
            return Err(ConversationError::NoPartner);
        }
    };

    // Alice retrieves Bob's message (stored by Bob's send)
    let alice_received = alice.receive(round, store)?;

    Ok((alice_received, bob_received))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::generate_server_keypair;

    fn setup_conversations(round: u64) -> (Conversation, Conversation) {
        let alice_kp = Keypair::random();
        let bob_kp = Keypair::random();

        let mut alice = Conversation::new(alice_kp.clone(), bob_kp.public.clone(), round);
        let mut bob = Conversation::new(bob_kp, alice_kp.public.clone(), round);

        // Set up server chain
        let s1_pk = generate_server_keypair();
        let s2_pk = generate_server_keypair();
        let s3_pk = generate_server_keypair();
        let servers = vec![s1_pk, s2_pk, s3_pk];

        alice.set_servers(servers.clone());
        bob.set_servers(servers);

        (alice, bob)
    }

    #[test]
    fn shared_secret_agreement() {
        let alice_kp = Keypair::random();
        let bob_kp = Keypair::random();

        let alice = Conversation::new(alice_kp.clone(), bob_kp.public.clone(), 1);
        let bob = Conversation::new(bob_kp, alice_kp.public.clone(), 1);

        assert_eq!(alice.shared_secret.0, bob.shared_secret.0);
    }

    #[test]
    fn dead_drop_id_agreement() {
        let alice_kp = Keypair::random();
        let bob_kp = Keypair::random();

        let alice = Conversation::new(alice_kp.clone(), bob_kp.public.clone(), 1);
        let bob = Conversation::new(bob_kp, alice_kp.public.clone(), 1);

        let dd_a = derive_dead_drop_id(&alice.shared_secret, 1);
        let dd_b = derive_dead_drop_id(&bob.shared_secret, 1);

        assert_eq!(dd_a, dd_b);
    }

    #[test]
    fn send_receive_roundtrip() {
        let (alice, bob) = setup_conversations(1);
        let mut store = DeadDropStore::new();
        let round = RoundNumber(1);

        let msg = b"Hello, Bob! This is Alice.";

        // Alice sends
        let result = alice.send(round, msg, &mut store).unwrap();
        match result {
            ExchangeResult::NoPartner => {}
            _ => panic!("expected NoPartner"),
        }

        // Bob receives
        let received = bob.receive(round, &mut store).unwrap();
        assert_eq!(received, msg);
    }

    #[test]
    fn bidirectional_exchange() {
        let (alice, bob) = setup_conversations(1);
        let mut store = DeadDropStore::new();
        let round = RoundNumber(1);

        let alice_msg = b"Hi Bob!";
        let bob_msg = b"Hey Alice!";

        let (alice_received, bob_received) =
            simulate_round(&alice, &bob, round, alice_msg, bob_msg, &mut store).unwrap();

        assert_eq!(alice_received, bob_msg);
        assert_eq!(bob_received, alice_msg);
    }

    #[test]
    fn receive_without_send_fails() {
        let (alice, _bob) = setup_conversations(1);
        let mut store = DeadDropStore::new();
        let round = RoundNumber(1);

        let result = alice.receive(round, &mut store);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConversationError::NoPartner => {}
            e => panic!("expected NoPartner, got {:?}", e),
        }
    }

    #[test]
    fn different_rounds_different_dead_drops() {
        let alice_kp = Keypair::random();
        let bob_kp = Keypair::random();

        let alice1 = Conversation::new(alice_kp.clone(), bob_kp.public.clone(), 1);
        let alice2 = Conversation::new(alice_kp.clone(), bob_kp.public.clone(), 2);

        let dd1 = derive_dead_drop_id(&alice1.shared_secret, 1);
        let dd2 = derive_dead_drop_id(&alice2.shared_secret, 2);

        assert_ne!(dd1, dd2);
    }

    #[test]
    fn prepare_and_decrypt() {
        let (alice, bob) = setup_conversations(1);
        let round = RoundNumber(1);

        let msg = b"Test message";

        let request = alice.prepare_message(round, msg).unwrap();
        let decrypted = bob.decrypt_received(round, &request.payload).unwrap();

        assert_eq!(decrypted, msg);
    }

    #[test]
    fn empty_message_roundtrip() {
        let (alice, bob) = setup_conversations(1);
        let mut store = DeadDropStore::new();
        let round = RoundNumber(1);

        let msg = b"";

        alice.send(round, msg, &mut store).unwrap();
        let received = bob.receive(round, &mut store).unwrap();

        assert_eq!(received, msg);
    }

    #[test]
    fn long_message_roundtrip() {
        let (alice, bob) = setup_conversations(1);
        let mut store = DeadDropStore::new();
        let round = RoundNumber(1);

        // Message close to the padded size
        let msg = vec![0xABu8; MESSAGE_SIZE - 10];

        alice.send(round, &msg, &mut store).unwrap();
        let received = bob.receive(round, &mut store).unwrap();

        assert_eq!(received, msg);
    }

    #[test]
    fn multiple_rounds() {
        let (alice, bob) = setup_conversations(1);

        for round_num in 1..=5 {
            // Create fresh conversations for each round (new shared secret)
            let (alice, bob) = setup_conversations(round_num);
            let mut store = DeadDropStore::new();
            let round = RoundNumber(round_num);

            let msg = format!("Message in round {}", round_num);
            let msg_bytes = msg.as_bytes();

            alice.send(round, msg_bytes, &mut store).unwrap();
            let received = bob.receive(round, &mut store).unwrap();

            assert_eq!(received, msg_bytes);
        }
    }

    #[test]
    fn store_state_after_exchange() {
        let (alice, bob) = setup_conversations(1);
        let mut store = DeadDropStore::new();
        let round = RoundNumber(1);

        // Alice sends: 1 entry in store
        alice.send(round, b"test", &mut store).unwrap();
        assert_eq!(store.len(), 1);

        // Bob receives (retrieve): store still has 1 entry
        bob.receive(round, &mut store).unwrap();
        assert_eq!(store.len(), 1);

        // After both send, the second client's message remains
        // (In the real protocol, the server swaps and both get their response)
    }
}
