/// Phase 8: Integration Tests
///
/// Spins up a 3-server chain in-process, runs two clients exchanging messages,
/// and verifies:
///   1. Messages arrive correctly
///   2. Cover traffic is present
///   3. The system operates in rounds
///   4. Dialing works (one client dials another, conversation starts)
///
/// Architecture:
///   ClientA -> Server0 -> Server1 -> Server2 -> DeadDropStore
///   ClientB -> Server0 -> Server1 -> Server2 -> DeadDropStore
///
/// Each server peels one onion layer and forwards to the next.
/// The last server places the inner payload into the dead drop store.
/// Both clients derive the same dead drop IDs (via shared secret),
/// so their messages are matched pairwise.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Pull in the vuvuzela library types & helpers
// ---------------------------------------------------------------------------
use vuvuzela::types::{
    DeadDropId, EncryptedMessage, Keypair, PublicKey, RoundNumber, SharedSecret, MESSAGE_SIZE,
};
use vuvuzela::crypto::{self, derive_dead_drop_id as crypto_dead_drop_id};
use vuvuzela::dead_drop::{DeadDropStore, ExchangeRequest, ExchangeResult};
use vuvuzela::onion::{self, OnionRequest};
use vuvuzela::x25519;

// ---------------------------------------------------------------------------
// In-memory server simulation
// ---------------------------------------------------------------------------

/// Simulated server in the Vuvuzela chain.
struct SimServer {
    /// Index in the chain (0, 1, 2)
    id: usize,
    /// Public key known to clients
    pub public_key: PublicKey,
    /// The shared dead drop store (all servers share the last server's view)
    store: Arc<Mutex<DeadDropStore>>,
    /// Round counter
    current_round: Arc<Mutex<u64>>,
    /// Track how many requests this server processed per round
    requests_processed: Arc<Mutex<HashMap<u64, usize>>>,
}

impl SimServer {
    fn new(
        id: usize,
        store: Arc<Mutex<DeadDropStore>>,
        current_round: Arc<Mutex<u64>>,
        requests_processed: Arc<Mutex<HashMap<u64, usize>>>,
    ) -> Self {
        let public_key = onion::generate_server_keypair();
        SimServer {
            id,
            public_key,
            store,
            current_round,
            requests_processed,
        }
    }

    /// Process an onion request: peel one layer and forward the inner payload.
    /// For the last server in the chain, extract the dead drop ID and payload
    /// and place them into the store.
    fn process_onion(
        &self,
        onion: &OnionRequest,
        all_servers: &[ServerInfo],
    ) -> Result<(), String> {
        let round = *self.current_round.lock().unwrap();

        // Track that we processed a request
        {
            let mut counts = self.requests_processed.lock().unwrap();
            *counts.entry(round).or_insert(0) += 1;
        }

        if self.id == all_servers.len() - 1 {
            // Last server: peel all remaining layers and extract dead drop data
            let mut data = bincode::serialize(onion).map_err(|e| format!("serialize: {}", e))?;
            for layer in onion.layers.iter() {
                data = onion::peel_layer(layer, &self.public_key)
                    .map_err(|e| format!("peel: {:?}", e))?;
            }

            // The inner data should be: [dead_drop_id (16)] [payload_data]
            if data.len() < 16 {
                return Err("inner data too short".to_string());
            }
            let mut dd_id = [0u8; 16];
            dd_id.copy_from_slice(&data[..16]);
            let payload_data = data[16..].to_vec();

            let request = ExchangeRequest {
                dead_drop_id: DeadDropId(dd_id),
                payload: EncryptedMessage { data: payload_data },
            };

            let mut store = self.store.lock().unwrap();
            match store.exchange(request) {
                ExchangeResult::Success(partner) => {
                    // In a real system, the partner's response would be sent back.
                    // For the integration test, we just note the match.
                    let _ = partner;
                }
                ExchangeResult::NoPartner => {
                    // Waiting for partner
                }
            }
            Ok(())
        } else {
            // Intermediate server: peel one layer and forward
            if onion.layers.is_empty() {
                return Err("no onion layers".to_string());
            }
            let peeled = onion::peel_layer(&onion.layers[0], &self.public_key)
                .map_err(|e| format!("peel layer {}: {:?}", self.id, e))?;

            // The peeled data is the serialized next-layer onion
            let inner_onion: OnionRequest =
                bincode::deserialize(&peeled).map_err(|e| format!("deserialize: {}", e))?;

            // Forward to next server
            let next_server_idx = self.id + 1;
            if next_server_idx < all_servers.len() {
                // In our in-process simulation, we call the next server directly.
                // We need to look up the next server's info.
                // For simplicity, we return the peeled data and let the caller forward.
                // Actually, let's handle forwarding in the chain processor.
                let _ = inner_onion;
                let _ = next_server_idx;
            }
            Ok(())
        }
    }
}

/// Lightweight info about a server for routing.
#[derive(Clone)]
struct ServerInfo {
    pub public_key: PublicKey,
}

// ---------------------------------------------------------------------------
// Full chain processor — simulates the entire 3-server chain in one call
// ---------------------------------------------------------------------------

struct ChainProcessor {
    servers: Vec<ServerInfo>,
    store: Arc<Mutex<DeadDropStore>>,
    current_round: Arc<Mutex<u64>>,
    requests_processed: Arc<Mutex<HashMap<u64, usize>>>,
}

impl ChainProcessor {
    fn new(num_servers: usize) -> Self {
        let store = Arc::new(Mutex::new(DeadDropStore::new()));
        let current_round = Arc::new(Mutex::new(0u64));
        let requests_processed = Arc::new(Mutex::new(HashMap::new()));

        let mut servers = Vec::with_capacity(num_servers);
        for _ in 0..num_servers {
            let pk = onion::generate_server_keypair();
            servers.push(ServerInfo {
                public_key: pk,
            });
        }

        ChainProcessor {
            servers,
            store,
            current_round,
            requests_processed,
        }
    }

    /// Get the server public keys (for clients to build onions).
    fn server_public_keys(&self) -> Vec<PublicKey> {
        self.servers.iter().map(|s| s.public_key).collect()
    }

    /// Process an onion request through the full chain.
    /// Returns the ExchangeResult from the dead drop store.
    fn process(&self, onion: &OnionRequest) -> Result<ExchangeResult, String> {
        let round = *self.current_round.lock().unwrap();

        // Track request
        {
            let mut counts = self.requests_processed.lock().unwrap();
            *counts.entry(round).or_insert(0) += 1;
        }

        // Peel all layers: each layer's ciphertext contains the serialized next layer
        let mut data = Vec::new();
        for (i, (layer, server)) in onion.layers.iter().zip(self.servers.iter()).enumerate() {
            if i == 0 {
                // First layer: ciphertext is the serialized next layer (or the final payload)
                data = onion::peel_layer(layer, &server.public_key)
                    .map_err(|e| format!("peel layer {}: {:?}", i, e))?;
            } else {
                // Subsequent layers: deserialize the data as an OnionLayer, then peel
                let layer: onion::OnionLayer = bincode::deserialize(&data)
                    .map_err(|e| format!("deserialize layer {}: {}", i, e))?;
                data = onion::peel_layer(&layer, &server.public_key)
                    .map_err(|e| format!("peel layer {}: {:?}", i, e))?;
            }
        }

        // Extract dead drop ID and payload
        if data.len() < 16 {
            return Err(format!(
                "inner data too short: {} bytes (need >= 16)",
                data.len()
            ));
        }
        let mut dd_id = [0u8; 16];
        dd_id.copy_from_slice(&data[..16]);
        let payload_data = data[16..].to_vec();

        let request = ExchangeRequest {
            dead_drop_id: DeadDropId(dd_id),
            payload: EncryptedMessage { data: payload_data },
        };

        let mut store = self.store.lock().unwrap();
        Ok(store.exchange(request))
    }

    /// Advance to the next round: clear the store and increment the counter.
    fn advance_round(&self) -> u64 {
        let mut round = self.current_round.lock().unwrap();
        *round += 1;
        self.store.lock().unwrap().clear();
        *round
    }

    /// Get the current round number.
    fn current_round(&self) -> u64 {
        *self.current_round.lock().unwrap()
    }

    /// Get the number of single-access dead drops (cover traffic indicator).
    fn count_single_accesses(&self) -> usize {
        self.store.lock().unwrap().count_single_accesses()
    }

    /// Get the number of double-access dead drops.
    fn count_double_accesses(&self) -> usize {
        self.store.lock().unwrap().count_double_accesses()
    }

    /// Get total requests processed in a given round.
    fn requests_in_round(&self, round: u64) -> usize {
        let counts = self.requests_processed.lock().unwrap();
        *counts.get(&round).unwrap_or(&0)
    }
}

// ---------------------------------------------------------------------------
// Client simulation
// ---------------------------------------------------------------------------

struct SimClient {
    pub keypair: Keypair,
    pub name: String,
}

impl SimClient {
    fn new(name: &str) -> Self {
        SimClient {
            keypair: Keypair::random(),
            name: name.to_string(),
        }
    }

    /// Derive the shared secret with another client.
    fn shared_secret(&self, other: &SimClient, round: u64) -> SharedSecret {
        x25519::derive_shared_secret(&self.keypair.public, &other.keypair.public, round)
    }

    /// Derive the dead drop ID for a conversation with another client in a given round.
    fn derive_dead_drop_id(&self, other: &SimClient, round: u64) -> DeadDropId {
        let secret = self.shared_secret(other, round);
        let id_bytes = crypto_dead_drop_id(&secret, round);
        DeadDropId(id_bytes)
    }

    /// Build and send a message to the chain.
    /// Returns the ExchangeResult from the dead drop store.
    fn send_message(
        &self,
        recipient: &SimClient,
        plaintext: &[u8],
        round: u64,
        server_pks: &[PublicKey],
        chain: &ChainProcessor,
    ) -> Result<ExchangeResult, String> {
        let secret = self.shared_secret(recipient, round);
        let dd_id = self.derive_dead_drop_id(recipient, round);

        // Encrypt the message
        let encrypted = crypto::encrypt_message(&secret, round, plaintext)
            .map_err(|e| format!("encrypt: {:?}", e))?;

        // Wrap in onion layers
        let onion = onion::wrap_onion(dd_id.0, &encrypted, server_pks)
            .map_err(|e| format!("wrap_onion: {:?}", e))?;

        // Process through the chain
        chain.process(&onion)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration_tests {
    use super::*;

    // ========================================================================
    // Test 1: Messages arrive correctly
    // ========================================================================

    #[test]
    fn test_message_delivery_basic() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = chain.current_round();

        // Alice sends a message to Bob
        let plaintext = b"Hello Bob, this is Alice!";
        let result = alice
            .send_message(&bob, plaintext, round, &server_pks, &chain)
            .expect("send_message should succeed");

        // Alice's message should be stored (no partner yet)
        match result {
            ExchangeResult::NoPartner => {}
            ExchangeResult::Success(_) => panic!("expected NoPartner for first message"),
        }

        // Bob sends a message to Alice (same dead drop ID)
        let bob_plaintext = b"Hello Alice, this is Bob!";
        let result = bob
            .send_message(&alice, bob_plaintext, round, &server_pks, &chain)
            .expect("send_message should succeed");

        // Bob should receive Alice's message
        match result {
            ExchangeResult::Success(msg) => {
                // Decrypt Alice's message using Bob's shared secret
                let secret = bob.shared_secret(&alice, round);
                let decrypted = crypto::decrypt_message(&secret, round, &msg)
                    .expect("decryption should succeed");
                assert_eq!(decrypted, plaintext.to_vec());
            }
            ExchangeResult::NoPartner => panic!("expected Success — Bob should have gotten Alice's message"),
        }
    }

    #[test]
    fn test_message_delivery_multiple_rounds() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let messages = vec![
            ("Hello from Alice - round 0", "Hello from Bob - round 0"),
            ("Alice round 1", "Bob round 1"),
            ("Alice round 2", "Bob round 2"),
        ];

        for (round_idx, (alice_msg, bob_msg)) in messages.iter().enumerate() {
            let round = round_idx as u64;

            // Alice sends
            let result = alice
                .send_message(&bob, alice_msg.as_bytes(), round, &server_pks, &chain)
                .expect("Alice send should succeed");
            assert!(
                matches!(result, ExchangeResult::NoPartner),
                "Alice should get NoPartner in round {}",
                round
            );

            // Bob sends and receives Alice's message
            let result = bob
                .send_message(&alice, bob_msg.as_bytes(), round, &server_pks, &chain)
                .expect("Bob send should succeed");
            match result {
                ExchangeResult::Success(msg) => {
                    let secret = bob.shared_secret(&alice, round);
                    let decrypted = crypto::decrypt_message(&secret, round, &msg)
                        .expect("decryption should succeed");
                    assert_eq!(decrypted, alice_msg.as_bytes());
                }
                ExchangeResult::NoPartner => {
                    panic!("Bob should receive Alice's message in round {}", round)
                }
            }
        }
    }

    #[test]
    fn test_message_content_integrity() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;

        // Send a message with various byte patterns
        let plaintext = vec![0xABu8; 128];
        alice
            .send_message(&bob, &plaintext, round, &server_pks, &chain)
            .unwrap();

        let result = bob
            .send_message(&alice, b"response", round, &server_pks, &chain)
            .unwrap();

        match result {
            ExchangeResult::Success(msg) => {
                let secret = bob.shared_secret(&alice, round);
                let decrypted = crypto::decrypt_message(&secret, round, &msg).unwrap();
                assert_eq!(decrypted, plaintext);
            }
            _ => panic!("expected Success"),
        }
    }

    // ========================================================================
    // Test 2: Cover traffic is present
    // ========================================================================

    #[test]
    fn test_cover_traffic_single_accesses() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;

        // Alice sends a real message
        alice
            .send_message(&bob, b"real message", round, &server_pks, &chain)
            .unwrap();

        // Add cover traffic: send to random dead drop IDs
        let num_cover = 50;
        for _ in 0..num_cover {
            let fake_id = DeadDropId::random();
            let fake_payload = EncryptedMessage::empty();
            let onion = onion::wrap_onion(fake_id.0, &fake_payload, &server_pks).unwrap();
            chain.process(&onion).unwrap();
        }

        // There should be single-access dead drops (cover traffic + Alice's unmatched)
        let single = chain.count_single_accesses();
        assert!(
            single > 0,
            "Expected single-access dead drops from cover traffic, got {}",
            single
        );

        // Bob sends his message (matches Alice's dead drop)
        bob.send_message(&alice, b"bob reply", round, &server_pks, &chain)
            .unwrap();

        // After Bob's exchange, the paired dead drop should be removed
        // Cover traffic dead drops should remain as single accesses
        let single_after = chain.count_single_accesses();
        assert!(
            single_after >= num_cover,
            "Expected at least {} single-access dead drops from cover traffic, got {}",
            num_cover,
            single_after
        );
    }

    #[test]
    fn test_cover_traffic_statistics() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;

        // Send many cover traffic requests
        let num_cover = 200;
        for _ in 0..num_cover {
            let fake_id = DeadDropId::random();
            let fake_payload = EncryptedMessage::empty();
            let onion = onion::wrap_onion(fake_id.0, &fake_payload, &server_pks).unwrap();
            chain.process(&onion).unwrap();
        }

        let single = chain.count_single_accesses();
        // All cover traffic should be single-access (random IDs won't collide)
        assert_eq!(
            single, num_cover,
            "Expected {} single-access dead drops, got {}",
            num_cover, single
        );

        // No double-accesses expected (random IDs)
        let double = chain.count_double_accesses();
        assert_eq!(
            double, 0,
            "Expected 0 double-access dead drops from random cover traffic, got {}",
            double
        );
    }

    #[test]
    fn test_cover_traffic_with_real_traffic() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;

        // Alice sends real message
        alice
            .send_message(&bob, b"real", round, &server_pks, &chain)
            .unwrap();

        // Add cover traffic
        let num_cover = 100;
        for _ in 0..num_cover {
            let fake_id = DeadDropId::random();
            let fake_payload = EncryptedMessage::empty();
            let onion = onion::wrap_onion(fake_id.0, &fake_payload, &server_pks).unwrap();
            chain.process(&onion).unwrap();
        }

        // Bob sends real message (pairs with Alice's)
        bob.send_message(&alice, b"reply", round, &server_pks, &chain)
            .unwrap();

        // The paired dead drop (Alice+Bob) should be removed.
        // Only cover traffic should remain as single accesses.
        // Allow +/- 1 tolerance due to exchange behavior.
        let single = chain.count_single_accesses();
        assert!(
            single >= num_cover - 1 && single <= num_cover + 1,
            "Expected ~{} single-access dead drops (cover only), got {}",
            num_cover, single
        );
    }

    // ========================================================================
    // Test 3: System operates in rounds
    // ========================================================================

    #[test]
    fn test_round_progression() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        // Round 0
        assert_eq!(chain.current_round(), 0);
        alice
            .send_message(&bob, b"r0_alice", 0, &server_pks, &chain)
            .unwrap();
        bob.send_message(&alice, b"r0_bob", 0, &server_pks, &chain)
            .unwrap();

        // Advance to round 1
        let new_round = chain.advance_round();
        assert_eq!(new_round, 1);
        assert_eq!(chain.current_round(), 1);

        // Store should be cleared
        assert_eq!(chain.count_single_accesses(), 0);

        // Round 1: different dead drop IDs (derived from round number)
        alice
            .send_message(&bob, b"r1_alice", 1, &server_pks, &chain)
            .unwrap();
        let result = bob
            .send_message(&alice, b"r1_bob", 1, &server_pks, &chain)
            .unwrap();

        match result {
            ExchangeResult::Success(msg) => {
                let secret = bob.shared_secret(&alice, 1);
                let decrypted = crypto::decrypt_message(&secret, 1, &msg).unwrap();
                assert_eq!(decrypted, b"r1_alice");
            }
            _ => panic!("expected Success in round 1"),
        }
    }

    #[test]
    fn test_rounds_are_isolated() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        // Round 0: Alice sends, Bob doesn't respond
        alice
            .send_message(&bob, b"round0_secret", 0, &server_pks, &chain)
            .unwrap();

        // Advance to round 1 (clears store)
        chain.advance_round();

        // Round 1: Bob tries to read from round 0's dead drop
        // But the store was cleared, so he gets NoPartner
        let result = bob
            .send_message(&alice, b"round1", 1, &server_pks, &chain)
            .unwrap();

        match result {
            ExchangeResult::NoPartner => {
                // Expected: round 0's data was wiped
            }
            ExchangeResult::Success(_) => {
                panic!("Expected NoPartner — previous round's data should be wiped");
            }
        }
    }

    #[test]
    fn test_multiple_rounds_request_counting() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        // Round 0: 2 requests (Alice + Bob)
        alice
            .send_message(&bob, b"r0a", 0, &server_pks, &chain)
            .unwrap();
        bob.send_message(&alice, b"r0b", 0, &server_pks, &chain)
            .unwrap();
        assert_eq!(chain.requests_in_round(0), 2);

        // Round 1: 2 more requests
        chain.advance_round();
        alice
            .send_message(&bob, b"r1a", 1, &server_pks, &chain)
            .unwrap();
        bob.send_message(&alice, b"r1b", 1, &server_pks, &chain)
            .unwrap();
        assert_eq!(chain.requests_in_round(1), 2);

        // Round 2: add cover traffic
        chain.advance_round();
        alice
            .send_message(&bob, b"r2a", 2, &server_pks, &chain)
            .unwrap();
        bob.send_message(&alice, b"r2b", 2, &server_pks, &chain)
            .unwrap();
        // 2 real + 0 cover in this case
        assert!(chain.requests_in_round(2) >= 2);
    }

    // ========================================================================
    // Test 4: Dialing works
    // ========================================================================

    #[test]
    fn test_dialing_conversation_starts() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        // Alice "dials" Bob by sending the first message in a new conversation.
        // In the real system, this would involve a dialing protocol with
        // invitations. Here, we simulate it: Alice sends to Bob's public key,
        // and Bob responds.

        let round = chain.current_round();

        // Step 1: Alice sends an invitation-like first message
        let invite_plaintext = b"INVITE: Alice wants to chat";
        let result = alice
            .send_message(&bob, invite_plaintext, round, &server_pks, &chain)
            .expect("Alice's invite should be sent");

        assert!(
            matches!(result, ExchangeResult::NoPartner),
            "Alice should get NoPartner (waiting for Bob)"
        );

        // Step 2: Bob receives the invitation (by sending to the same dead drop)
        let accept_plaintext = b"ACCEPT: Bob accepts!";
        let result = bob
            .send_message(&alice, accept_plaintext, round, &server_pks, &chain)
            .expect("Bob's accept should be sent");

        match result {
            ExchangeResult::Success(msg) => {
                let secret = bob.shared_secret(&alice, round);
                let decrypted = crypto::decrypt_message(&secret, round, &msg)
                    .expect("decryption should succeed");
                assert_eq!(decrypted, invite_plaintext.to_vec());
            }
            ExchangeResult::NoPartner => {
                panic!("Bob should have received Alice's invitation");
            }
        }

        // Step 3: Conversation continues in subsequent rounds
        chain.advance_round();
        let round1 = chain.current_round();

        alice
            .send_message(&bob, b"Hello Bob!", round1, &server_pks, &chain)
            .unwrap();
        let result = bob
            .send_message(&alice, b"Hi Alice!", round1, &server_pks, &chain)
            .unwrap();

        match result {
            ExchangeResult::Success(msg) => {
                let secret = bob.shared_secret(&alice, round1);
                let decrypted = crypto::decrypt_message(&secret, round1, &msg).unwrap();
                assert_eq!(decrypted, b"Hello Bob!");
            }
            _ => panic!("expected Success in conversation round 1"),
        }
    }

    #[test]
    fn test_dialing_different_keys_produce_different_dead_drops() {
        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");
        let charlie = SimClient::new("Charlie");

        // Alice-Bob and Alice-Charlie should have different dead drop IDs
        let dd_ab = alice.derive_dead_drop_id(&bob, 0);
        let dd_ac = alice.derive_dead_drop_id(&charlie, 0);

        assert_ne!(
            dd_ab, dd_ac,
            "Different conversation pairs should have different dead drop IDs"
        );
    }

    #[test]
    fn test_dialing_both_parties_derive_same_dead_drop() {
        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        // Both parties should derive the same dead drop ID
        let dd_a = alice.derive_dead_drop_id(&bob, 42);
        let dd_b = bob.derive_dead_drop_id(&alice, 42);

        assert_eq!(
            dd_a, dd_b,
            "Both parties must derive the same dead drop ID"
        );
    }

    // ========================================================================
    // Test 5: End-to-end conversation across multiple rounds
    // ========================================================================

    #[test]
    fn test_full_conversation_e2e() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let conversation = vec![
            (b"Hi Bob!".to_vec(), b"Hi Alice!".to_vec()),
            (b"How are you?".to_vec(), b"Good, you?".to_vec()),
            (b"Doing great!".to_vec(), b"Nice!".to_vec()),
            (b"See you tomorrow.".to_vec(), b"Bye!".to_vec()),
        ];

        for (round_idx, (alice_msg, bob_msg)) in conversation.iter().enumerate() {
            let round = round_idx as u64;

            // Alice sends
            let result = alice
                .send_message(&bob, alice_msg, round, &server_pks, &chain)
                .unwrap();
            assert!(matches!(result, ExchangeResult::NoPartner));

            // Bob sends and receives
            let result = bob
                .send_message(&alice, bob_msg, round, &server_pks, &chain)
                .unwrap();
            match result {
                ExchangeResult::Success(msg) => {
                    let secret = bob.shared_secret(&alice, round);
                    let decrypted = crypto::decrypt_message(&secret, round, &msg).unwrap();
                    assert_eq!(&decrypted, alice_msg);
                }
                _ => panic!("Round {}: Bob should receive Alice's message", round),
            }
        }
    }

    // ========================================================================
    // Test 6: Onion layering through 3 servers
    // ========================================================================

    #[test]
    fn test_onion_3_layer_wrapping() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;
        let dd_id = alice.derive_dead_drop_id(&bob, round);
        let secret = alice.shared_secret(&bob, round);
        let encrypted = crypto::encrypt_message(&secret, round, b"3-layer test").unwrap();

        let onion = onion::wrap_onion(dd_id.0, &encrypted, &server_pks).unwrap();

        // Should have exactly 3 layers
        assert_eq!(onion.layers.len(), 3, "Expected 3 onion layers");

        // Each layer should have a different ephemeral public key
        assert_ne!(onion.layers[0].ephemeral_pub.0, onion.layers[1].ephemeral_pub.0);
        assert_ne!(onion.layers[1].ephemeral_pub.0, onion.layers[2].ephemeral_pub.0);
        assert_ne!(onion.layers[0].ephemeral_pub.0, onion.layers[2].ephemeral_pub.0);
    }

    #[test]
    fn test_onion_peeling_through_chain() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;
        let dd_id = alice.derive_dead_drop_id(&bob, round);
        let secret = alice.shared_secret(&bob, round);
        let encrypted = crypto::encrypt_message(&secret, round, b"peel test").unwrap();

        let onion = onion::wrap_onion(dd_id.0, &encrypted, &server_pks).unwrap();

        // Process through chain: Alice sends
        let result = chain.process(&onion).unwrap();
        assert!(matches!(result, ExchangeResult::NoPartner));

        // Bob sends to same dead drop
        let dd_id_bob = bob.derive_dead_drop_id(&alice, round);
        assert_eq!(dd_id.0, dd_id_bob.0);

        let secret_bob = bob.shared_secret(&alice, round);
        let encrypted_bob =
            crypto::encrypt_message(&secret_bob, round, b"bob response").unwrap();
        let onion_bob = onion::wrap_onion(dd_id_bob.0, &encrypted_bob, &server_pks).unwrap();

        let result = chain.process(&onion_bob).unwrap();
        match result {
            ExchangeResult::Success(msg) => {
                let decrypted = crypto::decrypt_message(&secret_bob, round, &msg).unwrap();
                assert_eq!(decrypted, b"peel test");
            }
            _ => panic!("expected Success after peeling"),
        }
    }

    // ========================================================================
    // Test 7: Server chain with different sizes
    // ========================================================================

    #[test]
    fn test_single_server_chain() {
        let chain = ChainProcessor::new(1);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;
        alice
            .send_message(&bob, b"single server", round, &server_pks, &chain)
            .unwrap();
        let result = bob
            .send_message(&alice, b"reply", round, &server_pks, &chain)
            .unwrap();

        match result {
            ExchangeResult::Success(msg) => {
                let secret = bob.shared_secret(&alice, round);
                let decrypted = crypto::decrypt_message(&secret, round, &msg).unwrap();
                assert_eq!(decrypted, b"single server");
            }
            _ => panic!("expected Success with single server"),
        }
    }

    // ========================================================================
    // Test 8: Empty messages
    // ========================================================================

    #[test]
    fn test_empty_message_delivery() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;

        // Alice sends an empty message
        alice
            .send_message(&bob, b"", round, &server_pks, &chain)
            .unwrap();
        let result = bob
            .send_message(&alice, b"bob reply", round, &server_pks, &chain)
            .unwrap();

        match result {
            ExchangeResult::Success(msg) => {
                let secret = bob.shared_secret(&alice, round);
                let decrypted = crypto::decrypt_message(&secret, round, &msg).unwrap();
                assert_eq!(decrypted, b"");
            }
            _ => panic!("expected Success"),
        }
    }

    // ========================================================================
    // Test 9: Large messages (up to MESSAGE_SIZE)
    // ========================================================================

    #[test]
    fn test_large_message_delivery() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;

        // Send a message that fills most of the padded payload
        let large_msg = vec![0xCDu8; MESSAGE_SIZE - 10];
        alice
            .send_message(&bob, &large_msg, round, &server_pks, &chain)
            .unwrap();
        let result = bob
            .send_message(&alice, b"ack", round, &server_pks, &chain)
            .unwrap();

        match result {
            ExchangeResult::Success(msg) => {
                let secret = bob.shared_secret(&alice, round);
                let decrypted = crypto::decrypt_message(&secret, round, &msg).unwrap();
                assert_eq!(decrypted, large_msg);
            }
            _ => panic!("expected Success"),
        }
    }

    // ========================================================================
    // Test 10: Concurrent cover traffic doesn't interfere with real messages
    // ========================================================================

    #[test]
    fn test_cover_traffic_does_not_interfere() {
        let chain = ChainProcessor::new(3);
        let server_pks = chain.server_public_keys();

        let alice = SimClient::new("Alice");
        let bob = SimClient::new("Bob");

        let round = 0u64;

        // Flood with cover traffic
        for _ in 0..500 {
            let fake_id = DeadDropId::random();
            let fake_payload = EncryptedMessage::empty();
            let onion = onion::wrap_onion(fake_id.0, &fake_payload, &server_pks).unwrap();
            chain.process(&onion).unwrap();
        }

        // Real conversation should still work
        alice
            .send_message(&bob, b"real message through noise", round, &server_pks, &chain)
            .unwrap();
        let result = bob
            .send_message(&alice, b"got it", round, &server_pks, &chain)
            .unwrap();

        match result {
            ExchangeResult::Success(msg) => {
                let secret = bob.shared_secret(&alice, round);
                let decrypted = crypto::decrypt_message(&secret, round, &msg).unwrap();
                assert_eq!(decrypted, b"real message through noise");
            }
            _ => panic!("Real messages should get through cover traffic"),
        }
    }
}
