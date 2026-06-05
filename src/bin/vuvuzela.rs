use clap::Parser;
use std::sync::Arc;
use vuvuzela::config::NoiseConfig;
use vuvuzela::dead_drop::DeadDropStore;
use vuvuzela::types::NoiseParams;
use vuvuzela::onion::{generate_server_keypair, peel_layer, wrap_onion, OnionRequest};
use vuvuzela::protocol::conversation::Conversation;
use vuvuzela::types::{DeadDropId, EncryptedMessage, Keypair, PublicKey, RoundNumber, SharedSecret};
use vuvuzela::x25519::derive_shared_secret;

#[derive(Parser)]
#[command(
    name = "vuvuzela",
    about = "Vuvuzela privacy-preserving messaging demo",
    long_about = "Runs an in-process demo of the Vuvuzela system with 3 servers and 2 clients exchanging messages."
)]
struct Args {
    /// Number of rounds to run
    #[arg(short, long, default_value = "5")]
    rounds: u64,

    /// Number of servers in the chain
    #[arg(short, long, default_value = "3")]
    servers: usize,

    /// Cover traffic noise parameter (mu)
    #[arg(long, default_value = "100.0")]
    mu: f64,

    /// Cover traffic noise parameter (b)
    #[arg(long, default_value = "20.0")]
    b: f64,

    /// Message for Alice to send
    #[arg(short, long, default_value = "Hello Bob!")]
    alice_msg: String,

    /// Message for Bob to send
    #[arg(short, long, default_value = "Hi Alice!")]
    bob_msg: String,
}

struct DemoServer {
    public_key: PublicKey,
    store: DeadDropStore,
    noise_params: NoiseParams,
}

fn run_round(
    servers: &mut [DemoServer],
    alice: &Conversation,
    bob: &Conversation,
    round: RoundNumber,
    alice_msg: &[u8],
    bob_msg: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Alice sends
    let alice_encrypted = vuvuzela::crypto::encrypt_message(&alice.shared_secret, round.0, alice_msg)?;
    let alice_dd_id = DeadDropId(vuvuzela::crypto::derive_dead_drop_id(&alice.shared_secret, round.0));
    let alice_onion = wrap_onion(alice_dd_id.0, &alice_encrypted, &servers.iter().map(|s| s.public_key).collect::<Vec<_>>())?;

    // Bob sends
    let bob_encrypted = vuvuzela::crypto::encrypt_message(&bob.shared_secret, round.0, bob_msg)?;
    let bob_dd_id = DeadDropId(vuvuzela::crypto::derive_dead_drop_id(&bob.shared_secret, round.0));
    let bob_onion = wrap_onion(bob_dd_id.0, &bob_encrypted, &servers.iter().map(|s| s.public_key).collect::<Vec<_>>())?;

    // Process through server chain: each server peels one layer
    // After wrapping, layer 0 is outermost. After peeling, data = serialize(next layer).
    // The ciphertext of the innermost layer is the final payload (dead_drop_id + encrypted_message).
    let mut alice_data = bincode::serialize(&alice_onion)?;
    let mut bob_data = bincode::serialize(&bob_onion)?;

    for (i, server) in servers.iter().enumerate() {
        if i == 0 {
            // First iteration: deserialize the full onion, peel outermost layer
            let alice_onion: OnionRequest = bincode::deserialize(&alice_data)?;
            let bob_onion: OnionRequest = bincode::deserialize(&bob_data)?;
            alice_data = peel_layer(&alice_onion.layers[0], &server.public_key)?;
            bob_data = peel_layer(&bob_onion.layers[0], &server.public_key)?;
        } else {
            // Subsequent iterations: data is a serialized OnionLayer, deserialize and peel
            let alice_layer: vuvuzela::onion::OnionLayer = bincode::deserialize(&alice_data)?;
            let bob_layer: vuvuzela::onion::OnionLayer = bincode::deserialize(&bob_data)?;
            alice_data = peel_layer(&alice_layer, &server.public_key)?;
            bob_data = peel_layer(&bob_layer, &server.public_key)?;
        }
    }

    // After peeling all layers, data = dead_drop_id (16 bytes) + encrypted_message_data

    // Last server places in dead drop store
    let last_server = &mut servers[servers.len() - 1];

    // Extract dead drop ID and payload from peeled data
    let alice_dd_bytes: [u8; 16] = alice_data[..16].try_into()?;
    let alice_payload = EncryptedMessage { data: alice_data[16..].to_vec() };

    let bob_dd_bytes: [u8; 16] = bob_data[..16].try_into()?;
    let bob_payload = EncryptedMessage { data: bob_data[16..].to_vec() };

    // Place in dead drop store
    last_server.store.exchange(vuvuzela::dead_drop::ExchangeRequest {
        dead_drop_id: DeadDropId(alice_dd_bytes),
        payload: alice_payload,
    });

    let bob_result = last_server.store.exchange(vuvuzela::dead_drop::ExchangeRequest {
        dead_drop_id: DeadDropId(bob_dd_bytes),
        payload: bob_payload,
    });

    // Bob gets Alice's message from the exchange
    let bob_received = match bob_result {
        vuvuzela::dead_drop::ExchangeResult::Success(payload) => {
            vuvuzela::crypto::decrypt_message(&bob.shared_secret, round.0, &payload)?
        }
        vuvuzela::dead_drop::ExchangeResult::NoPartner => {
            return Err("Bob: no partner found".into());
        }
    };

    // Alice retrieves Bob's message
    let alice_result = last_server.store.retrieve(DeadDropId(alice_dd_bytes));
    let alice_received = match alice_result {
        vuvuzela::dead_drop::ExchangeResult::Success(payload) => {
            vuvuzela::crypto::decrypt_message(&alice.shared_secret, round.0, &payload)?
        }
        vuvuzela::dead_drop::ExchangeResult::NoPartner => {
            return Err("Alice: no partner found".into());
        }
    };

    Ok((alice_received, bob_received))
}

fn main() {
    let args = Args::parse();

    println!("Vuvuzela Privacy-Preserving Messaging Demo");
    println!("==========================================");
    println!("Servers: {}", args.servers);
    println!("Rounds: {}", args.rounds);
    println!("Noise: mu={}, b={}", args.mu, args.b);
    println!();

    // Generate server keypairs
    let mut servers: Vec<DemoServer> = (0..args.servers)
        .map(|_| {
            let pk = generate_server_keypair();
            DemoServer {
                public_key: pk,
                store: DeadDropStore::new(),
                noise_params: NoiseParams { mu: args.mu, b: args.b },
            }
        })
        .collect();

    println!("Server public keys:");
    for (i, server) in servers.iter().enumerate() {
        println!("  Server {}: {}", i, hex::encode(server.public_key.as_bytes()));
    }
    println!();

    // Generate client keypairs
    let alice_kp = Keypair::random();
    let bob_kp = Keypair::random();

    println!("Alice public key: {}", hex::encode(alice_kp.public.as_bytes()));
    println!("Bob public key:   {}", hex::encode(bob_kp.public.as_bytes()));
    println!();

    // Derive shared secret (both parties compute the same value)
    let shared_secret = derive_shared_secret(&alice_kp.public, &bob_kp.public, 1);

    // Create conversations
    let alice = Conversation::new(alice_kp.clone(), bob_kp.public.clone(), 1);
    let bob = Conversation::new(bob_kp, alice_kp.public.clone(), 1);

    // Run rounds
    for round_num in 1..=args.rounds {
        let round = RoundNumber(round_num);

        match run_round(
            &mut servers,
            &alice,
            &bob,
            round,
            args.alice_msg.as_bytes(),
            args.bob_msg.as_bytes(),
        ) {
            Ok((alice_received, bob_received)) => {
                println!("Round {}:", round_num);
                println!("  Alice sent: \"{}\"", args.alice_msg);
                println!("  Bob sent:   \"{}\"", args.bob_msg);
                println!("  Alice received: \"{}\"", String::from_utf8_lossy(&alice_received));
                println!("  Bob received:   \"{}\"", String::from_utf8_lossy(&bob_received));

                // Verify correctness
                let alice_ok = alice_received == args.bob_msg.as_bytes();
                let bob_ok = bob_received == args.alice_msg.as_bytes();
                println!("  Alice got Bob's message: {}", if alice_ok { "OK" } else { "FAIL" });
                println!("  Bob got Alice's message: {}", if bob_ok { "OK" } else { "FAIL" });
            }
            Err(e) => {
                println!("Round {}: ERROR - {}", round_num, e);
            }
        }

        // Clear dead drops between rounds
        for server in servers.iter_mut() {
            server.store.clear();
        }
        println!();
    }

    // Print cover traffic statistics
    let last_server = &servers[servers.len() - 1];
    let single = last_server.store.count_single_accesses();
    let double = last_server.store.count_double_accesses();
    println!("Final dead drop statistics:");
    println!("  Single-access dead drops: {}", single);
    println!("  Double-access dead drops: {}", double);
    println!();
    println!("Demo complete. In a real deployment, cover traffic would mask");
    println!("the communication patterns to provide differential privacy.");
}
