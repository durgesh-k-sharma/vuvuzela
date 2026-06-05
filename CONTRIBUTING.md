# Contributing to Vuvuzela

Thank you for your interest in contributing. This is a research prototype of the Vuvuzela privacy-preserving messaging system from MIT CSAIL (SOSP 2015).

## Development Setup

```bash
# Clone the repository
git clone https://github.com/durgesh-k-sharma/vuvuzela.git
cd vuvuzela

# Build
cargo build

# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture
```

## Code Style

- Follow the existing code patterns. The project uses branded types for all domain identifiers (DeadDropId, PublicKey, etc.).
- Keep functions small and single-purpose. The mixnet, dead drop store, and protocol layers should remain decoupled.
- Use `thiserror` for error types. Each module defines its own error enum.
- Comments should explain *why*, not *what*. The code should be self-documenting for the what.

## Testing

All changes must pass the existing test suite:

```bash
cargo test --lib          # Unit tests
cargo test --test integration_test  # Integration tests
```

New features should include tests. The integration test file (`tests/integration_test.rs`) demonstrates how to set up in-process server chains and clients.

## Architecture Decisions

- **Hash-based key agreement** is used instead of X25519 static-static DH. This is a prototype simplification. A production implementation should use a proper X25519 library.
- **In-memory dead drops** are ephemeral (per-round). No persistence layer is implemented.
- **Onion layers** use AES-256-GCM with nonces derived from ephemeral public keys. Each layer's ciphertext contains the serialized next layer.

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Make your changes and add tests.
3. Ensure `cargo test` passes and `cargo clippy` reports no warnings.
4. Update the README if your change affects the public API or architecture.
5. Submit a PR with a clear description of the change and its motivation.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
