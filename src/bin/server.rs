use clap::Parser;

#[derive(Parser)]
#[command(name = "vuvuzela-server", about = "Vuvuzela privacy-preserving messaging server")]
struct Args {
    /// Server index in the chain
    #[arg(short, long, default_value = "0")]
    index: usize,
}

fn main() {
    let _args = Args::parse();
    println!("Vuvuzela server");
    println!("Run the demo with: cargo run --bin vuvuzela -- --rounds 5");
}
