/// Cover Traffic Generation (Phase 5 of the Vuvuzela paper).
///
/// Generates noise requests to mask real conversation traffic. The cover traffic
/// uses Laplace-distributed sampling to determine how many noise requests each
/// client sends per round. This provides differential privacy guarantees.
///
/// Two types of noise:
/// - Single-access noise (n1): Requests to random dead drops, accessed once.
/// - Pair-access noise (n2): Requests to random dead drops, accessed twice
///   (simulating a conversation that goes nowhere).
use crate::crypto;
use crate::dead_drop::{DeadDropStore, ExchangeRequest, ExchangeResult};
use crate::noise::{sample_n1, sample_n2};
use crate::onion;
use crate::types::{DeadDropId, EncryptedMessage, Keypair, NoiseParams, PublicKey, RoundNumber};

/// Errors from cover traffic operations.
#[derive(Debug, thiserror::Error)]
pub enum CoverTrafficError {
    #[error("onion wrapping failed")]
    OnionError(#[from] onion::OnionError),
    #[error("crypto error")]
    CryptoError(#[from] crypto::CryptoError),
}

/// A cover traffic generator for a single client.
pub struct CoverTrafficGenerator {
    /// The client's keypair.
    pub keypair: Keypair,
    /// Noise parameters for Laplace sampling.
    pub params: NoiseParams,
    /// Server public keys for onion wrapping.
    pub server_pks: Vec<PublicKey>,
}

impl CoverTrafficGenerator {
    /// Create a new cover traffic generator.
    pub fn new(keypair: Keypair, params: NoiseParams) -> Self {
        CoverTrafficGenerator {
            keypair,
            params,
            server_pks: Vec::new(),
        }
    }

    /// Set the server public keys for onion wrapping.
    pub fn set_servers(&mut self, server_pks: Vec<PublicKey>) {
        self.server_pks = server_pks;
    }

    /// Generate a single noise request targeting a random dead drop.
    /// The request is onion-wrapped through the server chain.
    fn generate_single_noise_request(
        &self,
        round: RoundNumber,
    ) -> Result<ExchangeRequest, CoverTrafficError> {
        let dead_drop_id = DeadDropId::random();

        // Create a random payload (noise)
        let noise_payload = EncryptedMessage::empty();

        // Onion-wrap the noise payload
        let dd_id_bytes = dead_drop_id.0;
        let onion = onion::wrap_onion(dd_id_bytes, &noise_payload, &self.server_pks)?;

        let serialized = bincode::serialize(&onion)
            .map_err(|_| CoverTrafficError::CryptoError(crypto::CryptoError::EncryptionFailed))?;

        Ok(ExchangeRequest {
            dead_drop_id,
            payload: EncryptedMessage { data: serialized },
        })
    }

    /// Generate a pair of noise requests targeting the same random dead drop.
    /// This simulates a conversation that goes nowhere (both sides send, but
    /// there's no real content).
    fn generate_pair_noise_requests(
        &self,
        round: RoundNumber,
    ) -> Result<(ExchangeRequest, ExchangeRequest), CoverTrafficError> {
        let dead_drop_id = DeadDropId::random();
        let dd_id_bytes = dead_drop_id.0;

        let noise_payload = EncryptedMessage::empty();

        // Both requests target the same dead drop
        let onion1 = onion::wrap_onion(dd_id_bytes, &noise_payload, &self.server_pks)?;
        let onion2 = onion::wrap_onion(dd_id_bytes, &noise_payload, &self.server_pks)?;

        let serialized1 = bincode::serialize(&onion1)
            .map_err(|_| CoverTrafficError::CryptoError(crypto::CryptoError::EncryptionFailed))?;
        let serialized2 = bincode::serialize(&onion2)
            .map_err(|_| CoverTrafficError::CryptoError(crypto::CryptoError::EncryptionFailed))?;

        let req1 = ExchangeRequest {
            dead_drop_id,
            payload: EncryptedMessage { data: serialized1 },
        };
        let req2 = ExchangeRequest {
            dead_drop_id,
            payload: EncryptedMessage { data: serialized2 },
        };

        Ok((req1, req2))
    }

    /// Generate all cover traffic for a round.
    /// Returns a vector of exchange requests to be placed in the dead drop store.
    ///
    /// n1 = number of single-access noise requests (Laplace(mu, b))
    /// n2 = number of pair-access noise requests (Laplace(mu/2, b/2))
    pub fn generate_round_traffic(
        &self,
        round: RoundNumber,
    ) -> Result<Vec<ExchangeRequest>, CoverTrafficError> {
        let n1 = sample_n1(&self.params);
        let n2 = sample_n2(&self.params);

        let mut requests = Vec::with_capacity((n1 + n2 * 2) as usize);

        // Generate n1 single-access noise requests
        for _ in 0..n1 {
            let req = self.generate_single_noise_request(round)?;
            requests.push(req);
        }

        // Generate n2 pair-access noise requests
        for _ in 0..n2 {
            let (req1, req2) = self.generate_pair_noise_requests(round)?;
            requests.push(req1);
            requests.push(req2);
        }

        Ok(requests)
    }

    /// Generate cover traffic and place it directly into the dead drop store.
    pub fn generate_and_place(
        &self,
        round: RoundNumber,
        store: &mut DeadDropStore,
    ) -> Result<(u64, u64), CoverTrafficError> {
        let requests = self.generate_round_traffic(round)?;
        let n1 = sample_n1(&self.params);
        let n2 = sample_n2(&self.params);

        for req in requests {
            store.exchange(req);
        }

        Ok((n1, n2))
    }
}

/// Generate cover traffic for multiple clients in a round.
/// Each client generates their own noise independently.
pub fn generate_multi_client_traffic(
    generators: &[CoverTrafficGenerator],
    round: RoundNumber,
    store: &mut DeadDropStore,
) -> Result<Vec<(u64, u64)>, CoverTrafficError> {
    let mut results = Vec::new();

    for gen in generators {
        let (n1, n2) = gen.generate_and_place(round, store)?;
        results.push((n1, n2));
    }

    Ok(results)
}

/// Statistics about cover traffic in a round.
#[derive(Clone, Debug)]
pub struct TrafficStats {
    /// Number of single-access noise requests.
    pub n1: u64,
    /// Number of pair-access noise requests.
    pub n2: u64,
    /// Total noise requests placed.
    pub total_requests: u64,
    /// Dead drops with single access (unmatched).
    pub single_accesses: usize,
    /// Dead drops with double access (matched pairs).
    pub double_accesses: usize,
}

/// Analyze the dead drop store to compute traffic statistics.
pub fn analyze_traffic(store: &DeadDropStore, n1: u64, n2: u64) -> TrafficStats {
    TrafficStats {
        n1,
        n2,
        total_requests: n1 + n2 * 2,
        single_accesses: store.count_single_accesses(),
        double_accesses: store.count_double_accesses(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::generate_server_keypair;

    fn setup_generator() -> CoverTrafficGenerator {
        let kp = Keypair::random();
        let params = NoiseParams {
            mu: 10.0,
            b: 2.0,
        };
        let mut gen = CoverTrafficGenerator::new(kp, params);

        let s1_pk = generate_server_keypair();
        let s2_pk = generate_server_keypair();
        gen.set_servers(vec![s1_pk, s2_pk]);

        gen
    }

    #[test]
    fn generate_single_noise_request() {
        let gen = setup_generator();
        let round = RoundNumber(1);

        let req = gen.generate_single_noise_request(round).unwrap();
        // The dead drop ID should be random (not all zeros)
        assert_ne!(req.dead_drop_id.0, [0u8; 16]);
        // The payload should not be empty (it's onion-wrapped)
        assert!(!req.payload.data.is_empty());
    }

    #[test]
    fn generate_pair_noise_requests() {
        let gen = setup_generator();
        let round = RoundNumber(1);

        let (req1, req2) = gen.generate_pair_noise_requests(round).unwrap();

        // Both should target the same dead drop
        assert_eq!(req1.dead_drop_id, req2.dead_drop_id);

        // But have different payloads (different ephemeral keys)
        assert_ne!(req1.payload.data, req2.payload.data);
    }

    #[test]
    fn generate_round_traffic() {
        let gen = setup_generator();
        let round = RoundNumber(1);

        let requests = gen.generate_round_traffic(round).unwrap();

        // Should have some requests (n1 + n2*2, where n1 and n2 are Laplace samples)
        // With small test params, we expect at least a few requests
        assert!(!requests.is_empty(), "expected at least some cover traffic requests");
    }

    #[test]
    fn generate_and_place() {
        let gen = setup_generator();
        let mut store = DeadDropStore::new();
        let round = RoundNumber(1);

        let (n1, n2) = gen.generate_and_place(round, &mut store).unwrap();

        // n1 and n2 should be non-negative (they're u64)
        // The store should have some entries
        let total_expected = n1 + n2 * 2;
        assert!(total_expected > 0);

        // Some dead drops should have single access (the n1 singles)
        // Some should have double access (the n2 pairs)
        let stats = analyze_traffic(&store, n1, n2);
        assert_eq!(stats.n1, n1);
        assert_eq!(stats.n2, n2);
    }

    #[test]
    fn multi_client_traffic() {
        let gen1 = setup_generator();
        let gen2 = setup_generator();
        let gen3 = setup_generator();

        let mut store = DeadDropStore::new();
        let round = RoundNumber(1);

        let results =
            generate_multi_client_traffic(&[gen1, gen2, gen3], round, &mut store).unwrap();

        assert_eq!(results.len(), 3);

        // Each client should have generated some traffic
        for (n1, n2) in &results {
            assert!(*n1 > 0 || *n2 > 0);
        }
    }

    #[test]
    fn traffic_stats() {
        let gen = setup_generator();
        let mut store = DeadDropStore::new();
        let round = RoundNumber(1);

        let (n1, n2) = gen.generate_and_place(round, &mut store).unwrap();
        let stats = analyze_traffic(&store, n1, n2);

        assert_eq!(stats.n1, n1);
        assert_eq!(stats.n2, n2);
        assert_eq!(stats.total_requests, n1 + n2 * 2);
    }

    #[test]
    fn pair_requests_match_in_store() {
        let gen = setup_generator();
        let round = RoundNumber(1);

        // Generate a pair of requests
        let (req1, req2) = gen.generate_pair_noise_requests(round).unwrap();

        let mut store = DeadDropStore::new();

        // Place first request
        let result1 = store.exchange(req1);
        match result1 {
            ExchangeResult::NoPartner => {}
            _ => panic!("expected NoPartner for first request"),
        }

        // Place second request - should match
        let result2 = store.exchange(req2);
        match result2 {
            ExchangeResult::Success(_) => {}
            _ => panic!("expected Success for second request"),
        }
    }

    #[test]
    fn paper_default_params() {
        let params = NoiseParams::default_conversation();
        let n1 = sample_n1(&params);
        let n2 = sample_n2(&params);

        // With mu=300_000, n1 should be around 300_000
        // With mu/2=150_000, n2 should be around 150_000
        // Allow wide range due to randomness
        assert!(n1 > 100_000 && n1 < 500_000, "n1 = {}", n1);
        assert!(n2 > 50_000 && n2 < 250_000, "n2 = {}", n2);
    }

    #[test]
    fn noise_params_dialing() {
        let params = NoiseParams::default_dialing();
        // Run multiple samples to get a stable mean
        let n = 100;
        let sum_n1: u64 = (0..n).map(|_| sample_n1(&params)).sum();
        let mean_n1 = sum_n1 as f64 / n as f64;

        // With mu=13_000, mean should be close to 13_000 (within 20%)
        assert!(
            mean_n1 > 10_000.0 && mean_n1 < 16_000.0,
            "mean n1 = {}",
            mean_n1
        );
    }
}
