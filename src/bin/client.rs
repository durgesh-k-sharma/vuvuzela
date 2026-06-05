use clap::Parser;

#[derive(Parser)]
#[command(name = "vuvuzela-client", about = "Vuvuzela privacy-preserving messaging client")]
struct Args {
    /// Server address to connect to
    #[arg(short, long, default_value = "127.0.0.1:5000")]
    server: String,
}

fn main() {
    let _args = Args::parse();
    println!("Vuvuzela client");
    println!("Run the demo with: cargo run --bin vuvuzela -- --rounds 5");
}
