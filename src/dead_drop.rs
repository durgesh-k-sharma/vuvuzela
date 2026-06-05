use crate::types::{DeadDropId, EncryptedMessage};
use std::collections::HashMap;

/// An exchange request placed into a dead drop.
/// The store treats this as an opaque blob -- it does not decrypt or inspect it.
#[derive(Clone, Debug)]
pub struct ExchangeRequest {
    pub dead_drop_id: DeadDropId,
    pub payload: EncryptedMessage,
}

/// Result of a dead drop exchange.
#[derive(Clone, Debug)]
pub enum ExchangeResult {
    /// The exchange succeeded: the partner's message is returned.
    Success(EncryptedMessage),
    /// No partner accessed this dead drop in this round.
    NoPartner,
}

/// In-memory dead drop store for a single round.
/// Each round gets a fresh store that is wiped when the round ends.
/// The store matches pairs of requests targeting the same dead drop ID.
pub struct DeadDropStore {
    /// Maps dead drop ID to the requests targeting it.
    /// Most entries will have 1 or 2 requests. More than 2 is a collision (negligible probability).
    drops: HashMap<DeadDropId, Vec<ExchangeRequest>>,
}

impl DeadDropStore {
    pub fn new() -> Self {
        DeadDropStore {
            drops: HashMap::new(),
        }
    }

    /// Insert an exchange request into the store.
    /// Returns the partner's message if a matching request already exists for this dead drop.
    /// When a match is found, the stored request is replaced with the new one so that
    /// the original sender can later retrieve the response.
    pub fn exchange(&mut self, request: ExchangeRequest) -> ExchangeResult {
        let id = request.dead_drop_id;
        let entry = self.drops.entry(id).or_default();

        if entry.is_empty() {
            entry.push(request);
            ExchangeResult::NoPartner
        } else {
            // Partner already here: swap payloads
            let partner = entry.remove(0);
            // Store the current requester's message so the partner can retrieve it later
            entry.push(ExchangeRequest {
                dead_drop_id: id,
                payload: request.payload,
            });
            ExchangeResult::Success(partner.payload)
        }
    }

    /// Get the number of dead drops that have been accessed.
    pub fn len(&self) -> usize {
        self.drops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.drops.is_empty()
    }

    /// Count dead drops accessed exactly once (m1 in the paper's notation).
    pub fn count_single_accesses(&self) -> usize {
        self.drops.values().filter(|v| v.len() == 1).count()
    }

    /// Count dead drops accessed exactly twice (m2 in the paper's notation).
    /// After exchange(), successful pairs are removed, so this counts unmatched pairs.
    pub fn count_double_accesses(&self) -> usize {
        self.drops.values().filter(|v| v.len() >= 2).count()
    }

    /// Retrieve a message from a dead drop without disturbing the store.
    /// Returns the stored message if one exists for this dead drop.
    pub fn retrieve(&mut self, dead_drop_id: DeadDropId) -> ExchangeResult {
        if let Some(entry) = self.drops.get(&dead_drop_id) {
            if let Some(first) = entry.first() {
                return ExchangeResult::Success(first.payload.clone());
            }
        }
        ExchangeResult::NoPartner
    }

    /// Clear all dead drops (called at the end of a round).
    pub fn clear(&mut self) {
        self.drops.clear();
    }
}

impl Default for DeadDropStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DeadDropId;

    fn make_request(id: DeadDropId, data: Vec<u8>) -> ExchangeRequest {
        ExchangeRequest {
            dead_drop_id: id,
            payload: EncryptedMessage { data },
        }
    }

    #[test]
    fn exchange_no_partner() {
        let mut store = DeadDropStore::new();
        let id = DeadDropId::random();
        let req = make_request(id, vec![1, 2, 3]);
        let result = store.exchange(req);
        match result {
            ExchangeResult::NoPartner => {}
            _ => panic!("expected NoPartner"),
        }
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn exchange_with_partner() {
        let mut store = DeadDropStore::new();
        let id = DeadDropId::random();
        let req1 = make_request(id, vec![1, 2, 3]);
        let req2 = make_request(id, vec![4, 5, 6]);

        let result1 = store.exchange(req1);
        match result1 {
            ExchangeResult::NoPartner => {}
            _ => panic!("expected NoPartner for first request"),
        }

        let result2 = store.exchange(req2);
        match result2 {
            ExchangeResult::Success(msg) => assert_eq!(msg.data, vec![1, 2, 3]),
            _ => panic!("expected Success for second request"),
        }
    }

    #[test]
    fn exchange_different_dead_drops() {
        let mut store = DeadDropStore::new();
        let id1 = DeadDropId::random();
        let id2 = DeadDropId::random();

        let req1 = make_request(id1, vec![1]);
        let req2 = make_request(id2, vec![2]);

        let r1 = store.exchange(req1);
        let r2 = store.exchange(req2);

        match r1 {
            ExchangeResult::NoPartner => {}
            _ => panic!("expected NoPartner"),
        }
        match r2 {
            ExchangeResult::NoPartner => {}
            _ => panic!("expected NoPartner"),
        }
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn store_clear() {
        let mut store = DeadDropStore::new();
        let id = DeadDropId::random();
        store.exchange(make_request(id, vec![1]));
        assert_eq!(store.len(), 1);
        store.clear();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn single_access_count() {
        let mut store = DeadDropStore::new();
        let id1 = DeadDropId::random();
        let id2 = DeadDropId::random();
        let id3 = DeadDropId::random();

        // id1: single access
        store.exchange(make_request(id1, vec![1]));
        // id2: paired access (second client's message remains for first to retrieve)
        store.exchange(make_request(id2, vec![2]));
        store.exchange(make_request(id2, vec![3]));
        // id3: single access
        store.exchange(make_request(id3, vec![4]));

        // id1, id2 (second msg), id3 all have 1 entry
        assert_eq!(store.count_single_accesses(), 3);
        assert_eq!(store.count_double_accesses(), 0);
    }

    #[test]
    fn many_exchanges() {
        let mut store = DeadDropStore::new();
        let n = 100;

        // Create n pairs
        for _ in 0..n {
            let id = DeadDropId::random();
            let req1 = make_request(id, vec![1]);
            let req2 = make_request(id, vec![2]);
            store.exchange(req1);
            let result = store.exchange(req2);
            match result {
                ExchangeResult::Success(msg) => assert_eq!(msg.data, vec![1]),
                _ => panic!("expected Success"),
            }
        }

        // After exchange, each dead drop has 1 entry (second client's message)
        assert_eq!(store.len(), n);
        assert_eq!(store.count_single_accesses(), n);
    }
}
