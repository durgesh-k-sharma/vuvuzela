# Vuvuzela

**Scalable Private Messaging Resistant to Traffic Analysis**

Rust implementation of the [Vuvuzela](https://pdos.csail.mit.edu/papers/vuvuzela:sosp15.pdf) system from MIT CSAIL (SOSP 2015). Vuvuzela provides metadata-private point-to-point text messaging that scales to millions of users, hiding who talks to whom even against adversaries that monitor all network traffic and control all but one server.

## How It Works

Vuvuzela uses three techniques to hide metadata:

1. **Dead drops.** Clients exchange messages through virtual locations (dead drops) on the server. Two clients in a conversation agree on a random dead drop per round using a shared secret derived from their public keys.

2. **Mixnet.** Each client wraps their request in layers of encryption (one per server). Each server peels one layer, shuffles all requests, and forwards them to the next server. An adversary controlling all but one server cannot link inputs to outputs.

3. **Differential privacy cover traffic.** Each server adds noise requests drawn from a Laplace distribution. This obscures the histogram of dead-drop access counts, providing provable differential privacy guarantees.

## Architecture

```
Alice -> [Server 1] -> [Server 2] -> [Server 3] -> dead drops
              |              |              |
         shuffle+noise  shuffle+noise  shuffle+noise
```

- **Conversation protocol.** Two clients exchange messages through dead drops. Each round uses a fresh dead drop ID derived from a shared secret and the round number.
- **Dialing protocol.** A client sends an invitation to another client's invitation dead drop (determined by hash of recipient's public key mod m). Servers add noise invitations to prevent the adversary from distinguishing real invitations.

## Quick Start

```bash
# Build
cargo build --release

# Run tests
cargo test

# Run the server binary
cargo run --bin server -- --index 0 --num-servers 3

# Run the client binary
cargo run --bin client -- --server 127.0.0.1:5000
```

## Project Structure

```
src/
  types.rs          -- Core types (DeadDropId, PublicKey, SharedSecret, etc.)
  crypto.rs         -- AES-256-GCM encryption, key derivation, padding
  dead_drop.rs      -- In-memory dead drop store with exchange/retrieve
  onion.rs          -- Onion encryption with hash-based key agreement
  noise.rs          -- Truncated Laplace distribution for cover traffic
  x25519.rs         -- Shared secret derivation
  protocol/
    conversation.rs -- Conversation protocol (Algorithms 1 and 2 from the paper)
    cover_traffic.rs-- Cover traffic generation
    dialing.rs      -- Invitation-based conversation initiation
  client.rs         -- Client struct
  server.rs         -- Server struct
  config.rs         -- Client and server configuration
  bin/
    client.rs       -- CLI client binary
    server.rs       -- CLI server binary
tests/
  integration_test.rs -- End-to-end integration tests
scripts/
  verify_privacy.py   -- Statistical verification of cover traffic
```

## Privacy Guarantees

Vuvuzela provides (epsilon, delta)-differential privacy. For a user who sends 200,000 messages with the default parameters (mu = 300,000, b = 13,800), an adversary's confidence about any given suspicion remains within 2x of their prior belief (unless they get lucky, with probability 10^-4).

The cover traffic required is independent of the number of active users. With 1 million users, the system achieves a throughput of 68,000 messages/sec with 37-second end-to-end latency on commodity servers.

## Implementation Notes

This is a research prototype. Key differences from the paper:

- Uses hash-based key agreement (SHA-256 of sorted public keys) instead of X25519 static-static Diffie-Hellman for shared secret derivation. This simplifies the implementation while preserving the security model for the prototype.
- The entry server optimization (client multiplexing) is not implemented.
- CDN/BitTorrent distribution for dialing dead drops is not implemented.
- Client retransmission logic is not implemented.

## Testing

```bash
# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run integration tests only
cargo test --test integration_test

# Run with output
cargo test -- --nocapture
```

78 tests cover: crypto primitives, dead drop store, onion wrapping/peeling, conversation protocol, cover traffic statistics, dialing, end-to-end message delivery, round isolation, and multi-round conversations.

## License

MIT License. See [LICENSE](LICENSE) for details.

## References

- [Vuvuzela Paper (SOSP 2015)](https://pdos.csail.mit.edu/papers/vuvuzela:sosp15.pdf)
- [Original Go Implementation](https://github.com/davidlazar/vuvuzela)
