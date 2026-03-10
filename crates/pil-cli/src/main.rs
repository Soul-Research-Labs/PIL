//! PIL CLI — Interactive command-line interface.

use clap::{Parser, Subcommand};
use pil_primitives::domain::ChainDomain;
use pil_sdk::Pil;

#[derive(Parser)]
#[command(name = "pil", about = "Privacy Interoperability Layer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start interactive REPL mode
    Run {
        /// Target chain (cardano, cosmos, osmosis, neutron, etc.)
        #[arg(short, long, default_value = "cardano")]
        chain: String,
    },
    /// Deposit tokens into the shielded pool
    Deposit {
        /// Amount to deposit
        amount: u64,
        /// Target chain
        #[arg(short, long, default_value = "cardano")]
        chain: String,
    },
    /// Check wallet balance
    Balance {
        #[arg(short, long, default_value = "cardano")]
        chain: String,
    },
    /// Show supported chains
    Chains,
    /// Generate Aiken validators for Cardano
    GenerateCardanoValidators {
        /// Output directory
        #[arg(short, long, default_value = "./cardano-validators")]
        output: String,
    },
    /// Start the RPC server
    Serve {
        /// Bind address
        #[arg(short, long, default_value = "127.0.0.1:3030")]
        bind: String,
    },
}

fn parse_chain(chain: &str) -> ChainDomain {
    match chain.to_lowercase().as_str() {
        "cardano" | "cardano-mainnet" => ChainDomain::CardanoMainnet,
        "cardano-preprod" => ChainDomain::CardanoPreprod,
        "cardano-preview" => ChainDomain::CardanoPreview,
        "cosmos" | "cosmos-hub" => ChainDomain::CosmosHub,
        "osmosis" => ChainDomain::Osmosis,
        "neutron" => ChainDomain::Neutron,
        "injective" => ChainDomain::Injective,
        "secret" | "secret-network" => ChainDomain::SecretNetwork,
        "celestia" => ChainDomain::Celestia,
        "sei" => ChainDomain::Sei,
        "archway" => ChainDomain::Archway,
        "dymension" => ChainDomain::Dymension,
        _ => ChainDomain::Custom(0),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { chain } => {
            let chain_domain = parse_chain(&chain);
            println!("Initializing PIL for {:?} (generating proving keys)...", chain_domain);

            match Pil::init(chain_domain) {
                Ok(mut pil) => {
                    println!("Ready. Wallet owner: {}", pil.wallet.owner());
                    println!("Type 'help' for available commands.\n");

                    // Simple REPL
                    let stdin = std::io::stdin();
                    let mut line = String::new();
                    loop {
                        print!("pil> ");
                        use std::io::Write;
                        std::io::stdout().flush().unwrap();
                        line.clear();
                        if stdin.read_line(&mut line).unwrap() == 0 {
                            break;
                        }
                        let parts: Vec<&str> = line.trim().split_whitespace().collect();
                        if parts.is_empty() {
                            continue;
                        }
                        match parts[0] {
                            "deposit" => {
                                if let Some(amount_str) = parts.get(1) {
                                    if let Ok(amount) = amount_str.parse::<u64>() {
                                        match pil.deposit(amount) {
                                            Ok(r) => println!(
                                                "Deposited {}. Leaf index: {}. Pool balance: {}",
                                                amount, r.leaf_index, r.pool_balance
                                            ),
                                            Err(e) => println!("Error: {e}"),
                                        }
                                    }
                                } else {
                                    println!("Usage: deposit <amount>");
                                }
                            }
                            "balance" => {
                                println!(
                                    "Wallet balance: {}\nPool balance: {}",
                                    pil.balance(),
                                    pil.pool_balance()
                                );
                            }
                            "send" => {
                                if parts.len() >= 3 {
                                    let recipient = pasta_curves::pallas::Base::from(
                                        u64::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                                            .unwrap_or(0),
                                    );
                                    if let Ok(amount) = parts[2].parse::<u64>() {
                                        match pil.send(recipient, amount) {
                                            Ok(r) => println!(
                                                "Sent {}. Nullifiers spent: {}",
                                                amount, r.nullifiers_spent
                                            ),
                                            Err(e) => println!("Error: {e}"),
                                        }
                                    }
                                } else {
                                    println!("Usage: send <recipient_hex> <amount>");
                                }
                            }
                            "withdraw" => {
                                if let Some(amount_str) = parts.get(1) {
                                    if let Ok(amount) = amount_str.parse::<u64>() {
                                        match pil.withdraw(amount) {
                                            Ok(r) => println!("Withdrew {}.", r.exit_value),
                                            Err(e) => println!("Error: {e}"),
                                        }
                                    }
                                } else {
                                    println!("Usage: withdraw <amount>");
                                }
                            }
                            "history" => {
                                for (i, tx) in pil.wallet.history().iter().enumerate() {
                                    println!("[{i}] {tx:?}");
                                }
                            }
                            "help" => {
                                println!("Commands:");
                                println!("  deposit <amount>              - Deposit into shielded pool");
                                println!("  send <recipient_hex> <amount> - Private transfer");
                                println!("  withdraw <amount>             - Withdraw to public address");
                                println!("  balance                       - Show wallet & pool balance");
                                println!("  history                       - Show transaction history");
                                println!("  quit                          - Exit");
                            }
                            "quit" | "exit" => break,
                            other => println!("Unknown command: {other}. Type 'help'."),
                        }
                    }
                }
                Err(e) => eprintln!("Failed to initialize: {e}"),
            }
        }
        Commands::Deposit { amount, chain } => {
            let chain_domain = parse_chain(&chain);
            match Pil::init(chain_domain) {
                Ok(mut pil) => match pil.deposit(amount) {
                    Ok(r) => println!("Deposited {amount}. Leaf: {}. Root: {:?}", r.leaf_index, r.root),
                    Err(e) => eprintln!("Error: {e}"),
                },
                Err(e) => eprintln!("Init error: {e}"),
            }
        }
        Commands::Balance { chain } => {
            let chain_domain = parse_chain(&chain);
            match Pil::init(chain_domain) {
                Ok(pil) => println!("Balance: {}", pil.balance()),
                Err(e) => eprintln!("Init error: {e}"),
            }
        }
        Commands::Chains => {
            println!("Supported chains:");
            println!("  Cardano:  cardano, cardano-preprod, cardano-preview");
            println!("  Cosmos:   cosmos-hub, osmosis, neutron, injective");
            println!("            secret-network, celestia, sei, archway, dymension");
        }
        Commands::GenerateCardanoValidators { output } => {
            let source = pil_cardano::validator::generate_pool_validator_aiken();
            let toml = pil_cardano::validator::generate_aiken_toml();
            println!("Generated Aiken validator source ({} bytes)", source.len());
            println!("Output directory: {output}");
            // In production: write files to disk
        }
        Commands::Serve { bind } => {
            println!("Starting PIL RPC server on {bind}...");
            let state = std::sync::Arc::new(tokio::sync::RwLock::new(pil_rpc::AppState {
                pool_balance: 0,
                note_count: 0,
                merkle_root: "0".repeat(64),
                current_epoch: 0,
            }));
            let router = pil_rpc::create_router(state);
            let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
            println!("PIL RPC server listening on {bind}");
            axum::serve(listener, router).await.unwrap();
        }
    }
}
