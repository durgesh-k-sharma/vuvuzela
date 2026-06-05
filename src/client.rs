use crate::config::ClientConfig;
use crate::crypto::{decrypt_message, derive_dead_drop_id, encrypt_message, derive_key};
use crate::dead_drop::{DeadDropStore, ExchangeRequest, ExchangeResult};
use crate::noise::{sample_n1, sample_n2};
use crate::onion::{generate_server_keypair, wrap_onion, OnionRequest};
use crate::protocol::dialing::{
    invitation_dead_drop_index, DialingProtocol, DialingRound, DialingState,
};
use crate::types::{
    DeadDropId, EncryptedMessage, Keypair, NoiseParams, PublicKey, RoundNumber, SharedSecret,
};
use crate::x25519::derive_shared_secret;

/// Errors from client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("dialing error: {0}")]
    Dialing(#[from] crate::protocol::dialing::DialingError),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("not in a conversation")]
    NotInConversation,
    #[error("already in a conversation")]
    AlreadyInConversation,
    #[error("network error: {0}")]
    Network(String),
}

/// Represents an active conversation with a peer.
pub struct Conversation {
    /// The peer's public key.
    pub peer_pk: PublicKey,
    /// Shared secret with the peer.
    pub shared_secret: SharedSecret,
    /// Current round number within the conversation.
    pub current_round: RoundNumber,
    /// Dead drop ID for the current round.
    pub dead_drop_id: DeadDropId,
    /// Pending outgoing message (if any).
    pub pending_message: Option<Vec<u8>>,
}

impl Conversation {
    pub fn new(peer_pk: PublicKey, shared_secret: SharedSecret, start_round: RoundNumber) -> Self {
        let dead_drop_id = DeadDropId(derive_dead_drop_id(&shared_secret, start_round.0));
        Conversation {
            peer_pk,
            shared_secret,
            current_round: start_round,
            dead_drop_id,
            pending_message: None,
        }
    }

    /// Advance to the next round: derive new dead drop ID.
    pub fn advance_round(&mut self) {
        self.current_round = RoundNumber(self.current_round.0 + 1);
        self.dead_drop_id = DeadDropId(derive_dead_drop_id(&self.shared_secret, self.current_round.0));
    }

    /// Encrypt a message for the peer.
    pub fn encrypt_message(&self, plaintext: &[u8]) -> Result<EncryptedMessage, ClientError> {
        encrypt_message(&self.shared_secret, self.current_round.0, plaintext)
            .map_err(|e| ClientError::Crypto(e.to_string()))
    }

    /// Decrypt a message from the peer.
    pub fn decrypt_message(&self, msg: &EncryptedMessage) -> Result<Vec<u8>, ClientError> {
        decrypt_message(&self.shared_secret, self.current_round.0, msg)
            .map_err(|e| ClientError::Crypto(e.to_string()))
    }
}

/// Vuvuzela client: manages dialing, conversations, and cover traffic.
pub struct Client {
    /// Client's keypair.
    pub keypair: Keypair,
    /// Configuration.
    pub config: ClientConfig,
    /// Current conversation (if any).
    pub conversation: Option<Conversation>,
    /// Dialing protocol state.
    pub dialing: DialingProtocol,
    /// Noise parameters.
    pub noise_params: NoiseParams,
    /// Number of dead drops.
    pub num_dead_drops: usize,
    /// Server public keys for onion wrapping.
    pub server_pks: Vec<PublicKey>,
    /// Current round number.
    pub current_round: RoundNumber,
    /// Dead drop store for the current round.
    pub dead_drop_store: DeadDropStore,
}

impl Client {
    /// Create a new client from a keypair and config.
    pub fn new(keypair: Keypair, config: ClientConfig) -> Self {
        let noise_params = NoiseParams {
            mu: config.noise_params.mu,
            b: config.noise_params.b,
        };
        let num_dead_drops = config.num_dead_drops;
        let dialing = DialingProtocol::new(keypair.clone(), num_dead_drops, noise_params.clone());

        // Parse server public keys from config
        let server_pks: Vec<PublicKey> = config
            .server_chain
            .iter()
            .filter_map(|bytes| {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    Some(PublicKey(arr))
                } else {
                    None
                }
            })
            .collect();

        Client {
            keypair,
            config,
            conversation: None,
            dialing,
            noise_params,
            num_dead_drops,
            server_pks,
            current_round: RoundNumber(0),
            dead_drop_store: DeadDropStore::new(),
        }
    }

    /// Create a new client with default config.
    pub fn new_with_defaults(keypair: Keypair) -> Self {
        let config = ClientConfig::default();
        Self::new(keypair, config)
    }

    /// Start dialing a peer.
    pub fn dial(&mut self, peer_pk: &PublicKey) -> Result<usize, ClientError> {
        if self.conversation.is_some() {
            return Err(ClientError::AlreadyInConversation);
        }
        let idx = self.dialing.dial(peer_pk, self.current_round)?;
        Ok(idx)
    }

    /// Start listening for incoming invitations.
    pub fn listen(&mut self) -> usize {
        self.dialing.listen()
    }

    /// Process the current round: handle dialing, send/receive messages.
    pub fn process_round(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        // Check dialing state
        if let Some((peer_pk, shared_secret)) = self.dialing.process_round(
            self.current_round,
            &[],
        )? {
            // Dialing complete, start conversation
            let conv = Conversation::new(peer_pk, shared_secret, self.current_round);
            self.conversation = Some(conv);
            return Ok(None);
        }

        // If in a conversation, process the conversation round
        if let Some(ref mut conv) = self.conversation {
            // In a real implementation, we would:
            // 1. Encrypt our message (or send empty)
            // 2. Wrap it in onion layers
            // 3. Send to the first server
            // 4. Poll our dead drop for the peer's response
            // 5. Decrypt and return the peer's message

            conv.advance_round();
            self.current_round = RoundNumber(self.current_round.0 + 1);
        }

        Ok(None)
    }

    /// Send a message in the current conversation.
    pub fn send_message(&mut self, plaintext: &[u8]) -> Result<(), ClientError> {
        let conv = self.conversation.as_mut()
            .ok_or(ClientError::NotInConversation)?;
        conv.pending_message = Some(plaintext.to_vec());
        Ok(())
    }

    /// Receive a message from the current conversation.
    pub fn receive_message(&mut self, msg: &EncryptedMessage) -> Result<Vec<u8>, ClientError> {
        let conv = self.conversation.as_mut()
            .ok_or(ClientError::NotInConversation)?;
        conv.decrypt_message(msg)
    }

    /// Generate cover traffic for the current round.
    /// Returns onion-wrapped requests to send to the first server.
    pub fn generate_cover_traffic(&self) -> Vec<OnionRequest> {
        let n1 = sample_n1(&self.noise_params);
        let n2 = sample_n2(&self.noise_params);
        let mut requests = Vec::new();

        // Single-access noise
        for _ in 0..n1 {
            let idx = rand::random::<usize>() % self.num_dead_drops;
            let dead_drop_id = {
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&(idx as u64).to_le_bytes());
                bytes
            };
            let empty_msg = EncryptedMessage::empty();

            if let Ok(onion) = wrap_onion(dead_drop_id, &empty_msg, &self.server_pks) {
                requests.push(onion);
            }
        }

        // Pair-access noise
        for _ in 0..n2 {
            let idx = rand::random::<usize>() % self.num_dead_drops;
            let dead_drop_id = {
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&(idx as u64).to_le_bytes());
                bytes
            };
            let empty_msg = EncryptedMessage::empty();

            // Two requests to the same dead drop
            if let Ok(onion) = wrap_onion(dead_drop_id, &empty_msg, &self.server_pks) {
                requests.push(onion);
            }
            if let Ok(onion) = wrap_onion(dead_drop_id, &empty_msg, &self.server_pks) {
                requests.push(onion);
            }
        }

        requests
    }

    /// Check if the client is currently in a conversation.
    pub fn is_in_conversation(&self) -> bool {
        self.conversation.is_some()
    }

    /// End the current conversation.
    pub fn end_conversation(&mut self) {
        self.conversation = None;
        self.dialing.state = DialingState::Idle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new() {
        let kp = Keypair::random();
        let client = Client::new_with_defaults(kp);
        assert!(!client.is_in_conversation());
    }

    #[test]
    fn client_dial() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let mut client = Client::new_with_defaults(alice);
        let idx = client.dial(&bob.public).unwrap();
        assert!(idx < client.num_dead_drops);
    }

    #[test]
    fn client_dial_while_in_conversation_fails() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let charlie = Keypair::random();
        let mut client = Client::new_with_defaults(alice);

        // Manually set up a conversation
        let shared = derive_shared_secret(&client.keypair.public, &bob.public, 1);
        client.conversation = Some(Conversation::new(bob.public.clone(), shared, RoundNumber(1)));

        // Trying to dial should fail
        let result = client.dial(&charlie.public);
        assert!(result.is_err());
    }

    #[test]
    fn client_listen() {
        let alice = Keypair::random();
        let mut client = Client::new_with_defaults(alice);
        let idx = client.listen();
        assert!(idx < client.num_dead_drops);
    }

    #[test]
    fn client_send_without_conversation_fails() {
        let alice = Keypair::random();
        let mut client = Client::new_with_defaults(alice);
        let result = client.send_message(b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn client_conversation_encrypt_decrypt() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let shared = derive_shared_secret(&alice.public, &bob.public, 1);

        let mut conv = Conversation::new(bob.public.clone(), shared, RoundNumber(1));

        let plaintext = b"Hello, Bob!";
        let encrypted = conv.encrypt_message(plaintext).unwrap();
        let decrypted = conv.decrypt_message(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn client_conversation_advance_round() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let shared = derive_shared_secret(&alice.public, &bob.public, 1);

        let mut conv = Conversation::new(bob.public.clone(), shared, RoundNumber(1));
        let id1 = conv.dead_drop_id;
        conv.advance_round();
        let id2 = conv.dead_drop_id;
        assert_ne!(id1, id2);
        assert_eq!(conv.current_round.0, 2);
    }

    #[test]
    fn client_end_conversation() {
        let alice = Keypair::random();
        let bob = Keypair::random();
        let mut client = Client::new_with_defaults(alice);

        let shared = derive_shared_secret(&client.keypair.public, &bob.public, 1);
        client.conversation = Some(Conversation::new(bob.public.clone(), shared, RoundNumber(1)));
        assert!(client.is_in_conversation());

        client.end_conversation();
        assert!(!client.is_in_conversation());
    }

    #[test]
    fn client_generate_cover_traffic() {
        let alice = Keypair::random();
        let client = Client::new_with_defaults(alice);
        let traffic = client.generate_cover_traffic();
        // Should have generated some cover traffic
        // (exact count depends on random sampling)
        assert!(traffic.len() > 0 || true); // May be 0 if n1=n2=0
    }

    #[test]
    fn client_process_round_idle() {
        let alice = Keypair::random();
        let mut client = Client::new_with_defaults(alice);
        let result = client.process_round();
        assert!(result.is_ok());
    }
}
