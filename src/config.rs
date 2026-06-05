use serde::{Deserialize, Serialize};

/// Server configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Index of this server in the chain (0-based).
    pub server_index: usize,
    /// Number of servers in the chain.
    pub num_servers: usize,
    /// Address this server listens on (e.g., "127.0.0.1:5000").
    pub listen_addr: String,
    /// Address of the next server in the chain (or client for the last server).
    pub next_addr: String,
    /// Raw secret key bytes for peeling onion layers.
    pub secret_key: Vec<u8>,
    /// Public key for this server.
    pub public_key: Vec<u8>,
    /// Number of dead drops per round.
    pub num_dead_drops: usize,
    /// Noise parameters for cover traffic.
    pub noise_params: NoiseConfig,
}

/// Client configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Client's public key (hex-encoded in config files).
    pub public_key: Vec<u8>,
    /// Server chain: ordered list of server public keys.
    pub server_chain: Vec<Vec<u8>>,
    /// Number of dead drops per round.
    pub num_dead_drops: usize,
    /// Noise parameters for cover traffic.
    pub noise_params: NoiseConfig,
    /// How many rounds to wait for a dialing response before timing out.
    pub dialing_timeout_rounds: u64,
    /// Maximum number of rounds for a conversation.
    pub max_conversation_rounds: u64,
}

/// Noise parameters for differential privacy cover traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoiseConfig {
    /// Mean of the Laplace distribution.
    pub mu: f64,
    /// Scale parameter of the Laplace distribution.
    pub b: f64,
}

impl NoiseConfig {
    /// Default conversation noise parameters (mu=300_000, b=13_800).
    pub fn default_conversation() -> Self {
        NoiseConfig {
            mu: 300_000.0,
            b: 13_800.0,
        }
    }

    /// Default dialing noise parameters (mu=13_000, b=7_700).
    pub fn default_dialing() -> Self {
        NoiseConfig {
            mu: 13_000.0,
            b: 7_700.0,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            server_index: 0,
            num_servers: 1,
            listen_addr: "127.0.0.1:5000".to_string(),
            next_addr: "127.0.0.1:5001".to_string(),
            secret_key: vec![0u8; 32],
            public_key: vec![0u8; 32],
            num_dead_drops: 100_000,
            noise_params: NoiseConfig::default_conversation(),
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            public_key: vec![0u8; 32],
            server_chain: vec![],
            num_dead_drops: 100_000,
            noise_params: NoiseConfig::default_conversation(),
            dialing_timeout_rounds: 100,
            max_conversation_rounds: 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_default() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.server_index, 0);
        assert_eq!(cfg.num_servers, 1);
        assert_eq!(cfg.num_dead_drops, 100_000);
    }

    #[test]
    fn client_config_default() {
        let cfg = ClientConfig::default();
        assert_eq!(cfg.num_dead_drops, 100_000);
        assert_eq!(cfg.dialing_timeout_rounds, 100);
        assert_eq!(cfg.max_conversation_rounds, 1000);
    }

    #[test]
    fn noise_config_conversation() {
        let nc = NoiseConfig::default_conversation();
        assert!((nc.mu - 300_000.0).abs() < 1.0);
        assert!((nc.b - 13_800.0).abs() < 1.0);
    }

    #[test]
    fn noise_config_dialing() {
        let nc = NoiseConfig::default_dialing();
        assert!((nc.mu - 13_000.0).abs() < 1.0);
        assert!((nc.b - 7_700.0).abs() < 1.0);
    }
}
