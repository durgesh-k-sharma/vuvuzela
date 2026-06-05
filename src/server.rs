use crate::config::{NoiseConfig, ServerConfig};
use crate::dead_drop::{DeadDropStore, ExchangeRequest, ExchangeResult};
use crate::noise::{sample_n1, sample_n2};
use crate::onion::{generate_server_keypair, peel_layer};
use crate::types::{DeadDropId, EncryptedMessage, Keypair, NoiseParams, PublicKey, RoundNumber};
use std::collections::HashMap;

/// Errors from server operations.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("onion error: {0}")]
    Onion(#[from] crate::onion::OnionError),
    #[error("invalid request")]
    InvalidRequest,
    #[error("round not started")]
    RoundNotStarted,
}

/// Per-round state for the server.
pub struct RoundState {
    /// The round number.
    pub round: RoundNumber,
    /// Dead drop store for this round.
    pub store: DeadDropStore,
    /// Number of dead drops.
    pub num_dead_drops: usize,
    /// Whether noise has been added for this round.
    pub noise_added: bool,
}

impl RoundState {
    pub fn new(round: RoundNumber, num_dead_drops: usize) -> Self {
        RoundState {
            round,
            store: DeadDropStore::new(),
            num_dead_drops,
            noise_added: false,
        }
    }
}

/// Vuvuzela server: processes onion-wrapped requests, manages dead drops, adds noise.
pub struct Server {
    /// Server index in the chain.
    pub index: usize,
    /// Total number of servers.
    pub num_servers: usize,
    /// Server's public key.
    pub public_key: PublicKey,
    /// Server's secret key (raw bytes for peeling onion layers).
    pub secret_key: [u8; 32],
    /// Number of dead drops.
    pub num_dead_drops: usize,
    /// Noise parameters.
    pub noise_params: NoiseParams,
    /// Current round state.
    pub current_round: Option<RoundState>,
    /// Next server in the chain (if not the last).
    pub next_server_index: Option<usize>,
    /// Completed round results: round number -> number of exchanges.
    pub round_results: HashMap<u64, usize>,
}

impl Server {
    /// Create a new server from config.
    pub fn new(config: ServerConfig) -> Self {
        let mut public_key = [0u8; 32];
        if config.public_key.len() == 32 {
            public_key.copy_from_slice(&config.public_key);
        }

        let mut secret_key = [0u8; 32];
        if config.secret_key.len() == 32 {
            secret_key.copy_from_slice(&config.secret_key);
        }

        let noise_params = NoiseParams {
            mu: config.noise_params.mu,
            b: config.noise_params.b,
        };

        let next_server_index = if config.server_index + 1 < config.num_servers {
            Some(config.server_index + 1)
        } else {
            None
        };

        Server {
            index: config.server_index,
            num_servers: config.num_servers,
            public_key: PublicKey(public_key),
            secret_key,
            num_dead_drops: config.num_dead_drops,
            noise_params,
            current_round: None,
            next_server_index,
            round_results: HashMap::new(),
        }
    }

    /// Create a new server with a fresh keypair.
    pub fn new_with_keypair(index: usize, num_servers: usize, num_dead_drops: usize, noise_params: NoiseConfig) -> (Self, Keypair) {
        let pk = generate_server_keypair();
        let noise = NoiseParams {
            mu: noise_params.mu,
            b: noise_params.b,
        };

        let next_server_index = if index + 1 < num_servers {
            Some(index + 1)
        } else {
            None
        };

        let server = Server {
            index,
            num_servers,
            public_key: pk,
            secret_key: sk,
            num_dead_drops,
            noise_params: noise,
            current_round: None,
            next_server_index,
            round_results: HashMap::new(),
        };

        let kp = Keypair { public: pk };
        (server, kp)
    }

    /// Start a new round.
    pub fn start_round(&mut self, round: RoundNumber) {
        self.current_round = Some(RoundState::new(round, self.num_dead_drops));
    }

    /// Process a single onion-wrapped request: peel one layer and forward.
    /// Returns the peeled payload (dead drop ID + encrypted message).
    pub fn process_request(&mut self, onion: &crate::onion::OnionRequest) -> Result<Vec<u8>, ServerError> {
        if onion.layers.is_empty() {
            return Err(ServerError::InvalidRequest);
        }

        // Peel the outermost layer
        let layer = &onion.layers[0];
        let peeled = peel_layer(layer, &self.secret_key)?;

        Ok(peeled)
    }

    /// Process a fully peeled request: extract dead drop ID and payload, place in store.
    pub fn place_in_dead_drop(
        &mut self,
        dead_drop_id: [u8; 16],
        payload: EncryptedMessage,
    ) -> Result<ExchangeResult, ServerError> {
        let round = self.current_round.as_mut()
            .ok_or(ServerError::RoundNotStarted)?;

        let result = round.store.exchange(ExchangeRequest {
            dead_drop_id: DeadDropId(dead_drop_id),
            payload,
        });

        Ok(result)
    }

    /// Add noise invitations and cover traffic for the current round.
    pub fn add_noise(&mut self) -> Result<(), ServerError> {
        let round = self.current_round.as_mut()
            .ok_or(ServerError::RoundNotStarted)?;

        if round.noise_added {
            return Ok(());
        }

        let n1 = sample_n1(&self.noise_params);
        let n2 = sample_n2(&self.noise_params);

        // Single-access noise: place empty messages in random dead drops
        for _ in 0..n1 {
            let idx = rand::random::<usize>() % self.num_dead_drops;
            let dead_drop_id = DeadDropId({
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&(idx as u64).to_le_bytes());
                bytes
            });
            let empty = EncryptedMessage::empty();
            round.store.exchange(ExchangeRequest {
                dead_drop_id,
                payload: empty,
            });
        }

        // Pair-access noise: place two empty messages in the same dead drop
        for _ in 0..n2 {
            let idx = rand::random::<usize>() % self.num_dead_drops;
            let dead_drop_id = DeadDropId({
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&(idx as u64).to_le_bytes());
                bytes
            });
            let empty = EncryptedMessage::empty();
            round.store.exchange(ExchangeRequest {
                dead_drop_id,
                payload: empty.clone(),
            });
            round.store.exchange(ExchangeRequest {
                dead_drop_id,
                payload: empty,
            });
        }

        round.noise_added = true;
        Ok(())
    }

    /// End the current round: clear dead drops, record stats.
    pub fn end_round(&mut self) -> Result<usize, ServerError> {
        let round = self.current_round.as_mut()
            .ok_or(ServerError::RoundNotStarted)?;

        let exchanges = round.store.len();
        self.round_results.insert(round.round.0, exchanges);
        round.store.clear();

        Ok(exchanges)
    }

    /// Get the current round number.
    pub fn current_round_number(&self) -> Option<RoundNumber> {
        self.current_round.as_ref().map(|r| r.round)
    }

    /// Check if this is the last server in the chain.
    pub fn is_last_server(&self) -> bool {
        self.next_server_index.is_none()
    }

    /// Get the number of pending dead drops in the current round.
    pub fn pending_dead_drops(&self) -> usize {
        self.current_round.as_ref().map(|r| r.store.len()).unwrap_or(0)
    }
}

/// A chain of servers that processes rounds together.
pub struct ServerChain {
    /// Servers in the chain, ordered.
    pub servers: Vec<Server>,
}

impl ServerChain {
    /// Create a new server chain with the given number of servers.
    pub fn new(num_servers: usize, num_dead_drops: usize, noise_params: NoiseParams) -> Self {
        let mut servers = Vec::new();
        for i in 0..num_servers {
            let pk = generate_server_keypair();
            let next_idx = if i + 1 < num_servers { Some(i + 1) } else { None };

            servers.push(Server {
                index: i,
                num_servers,
                public_key: pk,
                secret_key: sk,
                num_dead_drops,
                noise_params: noise_params.clone(),
                current_round: None,
                next_server_index: next_idx,
                round_results: HashMap::new(),
            });
        }
        ServerChain { servers }
    }

    /// Start a round on all servers.
    pub fn start_round(&mut self, round: RoundNumber) {
        for server in &mut self.servers {
            server.start_round(round);
        }
    }

    /// Process a request through the entire chain.
    /// Each server peels one layer and forwards to the next.
    /// The last server places the payload in the dead drop.
    pub fn process_request_through_chain(
        &mut self,
        onion: &crate::onion::OnionRequest,
    ) -> Result<ExchangeResult, ServerError> {
        // Each server peels one layer
        let mut current_data = bincode::serialize(onion)
            .map_err(|_| ServerError::InvalidRequest)?;

        for server in &mut self.servers {
            let incoming: crate::onion::OnionRequest = bincode::deserialize(&current_data)
                .map_err(|_| ServerError::InvalidRequest)?;
            let peeled = server.process_request(&incoming)?;
            current_data = peeled;
        }

        // The last server places the payload in the dead drop
        // Parse the dead drop ID and payload from the peeled data
        if current_data.len() < 16 {
            return Err(ServerError::InvalidRequest);
        }

        let mut dead_drop_id = [0u8; 16];
        dead_drop_id.copy_from_slice(&current_data[..16]);
        let payload_data = &current_data[16..];

        let payload = EncryptedMessage {
            data: payload_data.to_vec(),
        };

        let last_server = &mut self.servers[self.servers.len() - 1];
        last_server.place_in_dead_drop(dead_drop_id, payload)
    }

    /// Add noise on all servers.
    pub fn add_noise(&mut self) -> Result<(), ServerError> {
        for server in &mut self.servers {
            server.add_noise()?;
        }
        Ok(())
    }

    /// End the round on all servers.
    pub fn end_round(&mut self) -> Result<Vec<usize>, ServerError> {
        let mut results = Vec::new();
        for server in &mut self.servers {
            results.push(server.end_round()?);
        }
        Ok(results)
    }

    /// Get all server public keys in chain order.
    pub fn public_keys(&self) -> Vec<PublicKey> {
        self.servers.iter().map(|s| s.public_key).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::wrap_onion;
    use crate::types::NoiseParams;

    #[test]
    fn server_new() {
        let config = ServerConfig::default();
        let server = Server::new(config);
        assert_eq!(server.index, 0);
        assert_eq!(server.num_dead_drops, 100_000);
    }

    #[test]
    fn server_start_round() {
        let config = ServerConfig::default();
        let mut server = Server::new(config);
        server.start_round(RoundNumber(1));
        assert!(server.current_round.is_some());
        assert_eq!(server.current_round_number(), Some(RoundNumber(1)));
    }

    #[test]
    fn server_process_request_without_round_fails() {
        let config = ServerConfig::default();
        let mut server = Server::new(config);

        // Create a dummy onion request
        let pk = generate_server_keypair();
        let dead_drop_id = [1u8; 16];
        let payload = EncryptedMessage::empty();
        let onion = wrap_onion(dead_drop_id, &payload, &[pk]).unwrap();

        // Should fail because no round started
        let result = server.place_in_dead_drop(dead_drop_id, payload);
        assert!(result.is_err());
    }

    #[test]
    fn server_place_in_dead_drop() {
        let config = ServerConfig::default();
        let mut server = Server::new(config);
        server.start_round(RoundNumber(1));

        let dead_drop_id = [1u8; 16];
        let payload = EncryptedMessage::empty();
        let result = server.place_in_dead_drop(dead_drop_id, payload).unwrap();

        match result {
            ExchangeResult::NoPartner => {}
            _ => panic!("expected NoPartner"),
        }
    }

    #[test]
    fn server_add_noise() {
        let config = ServerConfig::default();
        let mut server = Server::new(config);
        server.start_round(RoundNumber(1));

        server.add_noise().unwrap();
        assert!(server.current_round.as_ref().unwrap().noise_added);
    }

    #[test]
    fn server_end_round() {
        let config = ServerConfig::default();
        let mut server = Server::new(config);
        server.start_round(RoundNumber(1));

        let exchanges = server.end_round().unwrap();
        assert_eq!(exchanges, 0);
    }

    #[test]
    fn server_chain_new() {
        let chain = ServerChain::new(3, 100_000, NoiseParams::default_conversation());
        assert_eq!(chain.servers.len(), 3);
    }

    #[test]
    fn server_chain_start_round() {
        let mut chain = ServerChain::new(3, 100_000, NoiseParams::default_conversation());
        chain.start_round(RoundNumber(1));
        for server in &chain.servers {
            assert_eq!(server.current_round_number(), Some(RoundNumber(1)));
        }
    }

    #[test]
    fn server_chain_public_keys() {
        let chain = ServerChain::new(3, 100_000, NoiseParams::default_conversation());
        let pks = chain.public_keys();
        assert_eq!(pks.len(), 3);
        // All keys should be different
        assert_ne!(pks[0].0, pks[1].0);
        assert_ne!(pks[1].0, pks[2].0);
    }

    #[test]
    fn server_chain_add_noise() {
        let mut chain = ServerChain::new(3, 100_000, NoiseParams::default_conversation());
        chain.start_round(RoundNumber(1));
        chain.add_noise().unwrap();
        for server in &chain.servers {
            assert!(server.current_round.as_ref().unwrap().noise_added);
        }
    }

    #[test]
    fn server_is_last_server() {
        let mut chain = ServerChain::new(3, 100_000, NoiseParams::default_conversation());
        assert!(!chain.servers[0].is_last_server());
        assert!(!chain.servers[1].is_last_server());
        assert!(chain.servers[2].is_last_server());
    }

    #[test]
    fn server_chain_end_round() {
        let mut chain = ServerChain::new(3, 100_000, NoiseParams::default_conversation());
        chain.start_round(RoundNumber(1));
        let results = chain.end_round().unwrap();
        assert_eq!(results.len(), 3);
    }
}
