use clap::Parser;
use vuvuzela::config::{ClientConfig, NoiseConfig};
use vuvuzela::onion::generate_server_keypair;
use vuvuzela::types::Keypair;

#[derive(Parser)]
#[command(
    name = "vuvuzela-client",
    about = "Vuvuzela privacy-preserving messaging client"
)]
struct Args {
    /// Server address to connect to
    #[arg(short, long, default_value = "127.0.0.1:5000")]
    server: String,
}

fn main() {
    let args = Args::parse();

    let keypair = Keypair::random();
    let server_pk = generate_server_keypair();

    let config = ClientConfig {
        public_key: keypair.public.as_bytes().to_vec(),
        server_chain: vec![server_pk.as_bytes().to_vec()],
        num_dead_drops: 100_000,
        noise_params: NoiseConfig::default_conversation(),
        dialing_timeout_rounds: 100,
        max_conversation_rounds: 1000,
    };

    println!("Vuvuzela client starting");
    println!("Server: {}", args.server);
    println!("Public key: {}", hex::encode(keypair.public.as_bytes()));
    println!("(Prototype: client logic is exercised via integration tests)");
    println!("Run: cargo test --test integration_test");
}
