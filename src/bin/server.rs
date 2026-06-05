use clap::Parser;
use vuvuzela::config::ServerConfig;
use vuvuzela::dead_drop::DeadDropStore;
use vuvuzela::onion::generate_server_keypair;
use vuvuzela::types::{EncryptedMessage, RoundNumber};
use vuvuzela::x25519::derive_shared_secret;

#[derive(Parser)]
#[command(name = "vuvuzela-server", about = "Vuvuzela privacy-preserving messaging server")]
struct Args {
    /// Server index in the chain
    #[arg(short, long, default_value = "0")]
    index: usize,
    /// Number of servers in the chain
    #[arg(short, long, default_value = "3")]
    num_servers: usize,
}

fn main() {
    let args = Args::parse();

    let config = ServerConfig {
        server_index: args.index,
        num_servers: args.num_servers,
        listen_addr: format!("127.0.0.1:{}", 5000 + args.index),
        next_addr: format!("127.0.0.1:{}", 5000 + args.index + 1),
        secret_key: vec![0u8; 32],
        public_key: vec![0u8; 32],
        num_dead_drops: 100_000,
        noise_params: vuvuzela::config::NoiseConfig::default_conversation(),
    };

    let _server_pk = generate_server_keypair();
    let _store = DeadDropStore::new();

    println!(
        "Vuvuzela server {} of {} starting on {}",
        args.index, args.num_servers, config.listen_addr
    );
    println!("(Prototype: server logic is exercised via integration tests)");
    println!("Run: cargo test --test integration_test");
}
