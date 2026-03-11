//! PIL CLI — Interactive command-line interface.

use clap::{Parser, Subcommand};
use pil_primitives::domain::ChainDomain;
use pil_sdk::Pil;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pil", about = "Privacy Interoperability Layer CLI")]
struct Cli {
    /// Path to encrypted wallet file
    #[arg(long, global = true, default_value = "~/.pil/wallet.enc")]
    wallet_file: String,

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
    /// Send a private transfer
    Send {
        /// Recipient public key (hex)
        recipient: String,
        /// Amount to send
        amount: u64,
        /// Target chain
        #[arg(short, long, default_value = "cardano")]
        chain: String,
    },
    /// Withdraw from the shielded pool
    Withdraw {
        /// Amount to withdraw
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
    /// Show wallet status (balance, notes, history)
    Status {
        #[arg(short, long, default_value = "cardano")]
        chain: String,
    },
    /// Show supported chains
    Chains,
    /// Generate a new spending key
    Keygen,
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

fn resolve_wallet_path(wallet_file: &str) -> PathBuf {
    if let Some(rest) = wallet_file.strip_prefix("~/") {
        if let Some(home) = dirs_or_home() {
            return home.join(rest);
        }
    }
    PathBuf::from(wallet_file)
}

fn dirs_or_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn read_password(prompt: &str) -> String {
    eprint!("{prompt}");
    use std::io::Write;
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim().to_string()
}

fn save_wallet(pil: &Pil, path: &std::path::Path, password: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match pil.wallet.save_encrypted(path, password.as_bytes()) {
        Ok(()) => eprintln!("Wallet saved to {}", path.display()),
        Err(e) => eprintln!("Warning: failed to save wallet: {e}"),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let wallet_path = resolve_wallet_path(&cli.wallet_file);

    match cli.command {
        Commands::Run { chain } => {
            let chain_domain = parse_chain(&chain);
            println!(
                "Initializing PIL for {:?} (generating proving keys)...",
                chain_domain
            );

            match Pil::init(chain_domain) {
                Ok(mut pil) => {
                    // Try loading existing wallet
                    if wallet_path.exists() {
                        let password = read_password("Wallet password: ");
                        match pil_client::Wallet::load_encrypted(&wallet_path, password.as_bytes())
                        {
                            Ok(w) => {
                                pil.wallet = w;
                                println!("Loaded wallet from {}", wallet_path.display());
                            }
                            Err(e) => eprintln!("Could not load wallet ({e}), using fresh wallet."),
                        }
                    }
                    println!("Ready. Wallet owner: {}", pil.wallet.owner());
                    println!("Type 'help' for available commands.\n");

                    let password = if !wallet_path.exists() {
                        let p = read_password("Set wallet password (for auto-save): ");
                        if !p.is_empty() {
                            Some(p)
                        } else {
                            None
                        }
                    } else {
                        // Reuse the password from above (we already read it)
                        None
                    };

                    let stdin = std::io::stdin();
                    let mut line = String::new();
                    loop {
                        print!("pil> ");
                        use std::io::Write;
                        if std::io::stdout().flush().is_err() {
                            break;
                        }
                        line.clear();
                        match stdin.read_line(&mut line) {
                            Ok(0) | Err(_) => break,
                            _ => {}
                        }
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.is_empty() {
                            continue;
                        }
                        match parts[0] {
                            "deposit" => {
                                if let Some(amount_str) = parts.get(1) {
                                    if let Ok(amount) = amount_str.parse::<u64>() {
                                        match pil.deposit(amount) {
                                            Ok(r) => {
                                                println!(
                                                    "Deposited {}. Leaf index: {}. Pool balance: {}",
                                                    amount, r.leaf_index, r.pool_balance
                                                );
                                                if let Some(ref pw) = password {
                                                    save_wallet(&pil, &wallet_path, pw);
                                                }
                                            }
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
                                            Ok(r) => {
                                                println!(
                                                    "Sent {}. Nullifiers spent: {}",
                                                    amount, r.nullifiers_spent
                                                );
                                                if let Some(ref pw) = password {
                                                    save_wallet(&pil, &wallet_path, pw);
                                                }
                                            }
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
                                            Ok(r) => {
                                                println!("Withdrew {}.", r.exit_value);
                                                if let Some(ref pw) = password {
                                                    save_wallet(&pil, &wallet_path, pw);
                                                }
                                            }
                                            Err(e) => println!("Error: {e}"),
                                        }
                                    }
                                } else {
                                    println!("Usage: withdraw <amount>");
                                }
                            }
                            "status" => {
                                println!("Owner:          {}", pil.wallet.owner());
                                println!("Wallet balance: {}", pil.balance());
                                println!("Pool balance:   {}", pil.pool_balance());
                                println!("Unspent notes:  {}", pil.wallet.unspent_notes().len());
                                println!("Tx history:     {} entries", pil.wallet.history().len());
                            }
                            "history" => {
                                for (i, tx) in pil.wallet.history().iter().enumerate() {
                                    println!("[{i}] {tx:?}");
                                }
                            }
                            "save" => {
                                let pw = if let Some(ref p) = password {
                                    p.clone()
                                } else {
                                    read_password("Password: ")
                                };
                                save_wallet(&pil, &wallet_path, &pw);
                            }
                            "help" => {
                                println!("Commands:");
                                println!(
                                    "  deposit <amount>              - Deposit into shielded pool"
                                );
                                println!("  send <recipient_hex> <amount> - Private transfer");
                                println!(
                                    "  withdraw <amount>             - Withdraw to public address"
                                );
                                println!(
                                    "  balance                       - Show wallet & pool balance"
                                );
                                println!("  status                        - Show wallet status");
                                println!(
                                    "  history                       - Show transaction history"
                                );
                                println!("  save                          - Save wallet to disk");
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
                    Ok(r) => println!(
                        "Deposited {amount}. Leaf: {}. Root: {:?}",
                        r.leaf_index, r.root
                    ),
                    Err(e) => eprintln!("Error: {e}"),
                },
                Err(e) => eprintln!("Init error: {e}"),
            }
        }
        Commands::Send {
            recipient,
            amount,
            chain,
        } => {
            let chain_domain = parse_chain(&chain);
            match Pil::init(chain_domain) {
                Ok(mut pil) => {
                    let recipient_field = pasta_curves::pallas::Base::from(
                        u64::from_str_radix(recipient.trim_start_matches("0x"), 16).unwrap_or(0),
                    );
                    match pil.send(recipient_field, amount) {
                        Ok(r) => println!(
                            "Sent {amount}. Nullifiers spent: {}. New leaf indices: {:?}",
                            r.nullifiers_spent, r.leaf_indices
                        ),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                Err(e) => eprintln!("Init error: {e}"),
            }
        }
        Commands::Withdraw { amount, chain } => {
            let chain_domain = parse_chain(&chain);
            match Pil::init(chain_domain) {
                Ok(mut pil) => match pil.withdraw(amount) {
                    Ok(r) => println!(
                        "Withdrew {}. New leaf indices: {:?}",
                        r.exit_value, r.leaf_indices
                    ),
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
        Commands::Status { chain } => {
            let chain_domain = parse_chain(&chain);
            match Pil::init(chain_domain) {
                Ok(pil) => {
                    println!("Chain:          {:?}", chain_domain);
                    println!("Owner:          {}", pil.wallet.owner());
                    println!("Wallet balance: {}", pil.balance());
                    println!("Pool balance:   {}", pil.pool_balance());
                    println!("Unspent notes:  {}", pil.wallet.unspent_notes().len());
                    println!("Tx history:     {} entries", pil.wallet.history().len());
                }
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
            let out_dir = PathBuf::from(&output);
            if let Err(e) = std::fs::create_dir_all(&out_dir) {
                eprintln!("Failed to create output directory: {e}");
                return;
            }
            let validator_path = out_dir.join("pool_validator.ak");
            let toml_path = out_dir.join("aiken.toml");
            if let Err(e) = std::fs::write(&validator_path, &source) {
                eprintln!("Failed to write validator: {e}");
                return;
            }
            if let Err(e) = std::fs::write(&toml_path, &toml) {
                eprintln!("Failed to write aiken.toml: {e}");
                return;
            }
            println!(
                "Generated Aiken validator ({} bytes) → {}",
                source.len(),
                validator_path.display()
            );
            println!(
                "Generated aiken.toml ({} bytes) → {}",
                toml.len(),
                toml_path.display()
            );
        }
        Commands::Keygen => {
            use ff::PrimeField;
            let mut rng = rand::thread_rng();
            let sk = pil_note::keys::SpendingKey::random(&mut rng);
            let owner = sk.owner();
            println!("New spending key generated.");
            println!(
                "  Spending key (base): {}",
                hex::encode(sk.to_base().to_repr().as_ref())
            );
            println!(
                "  Owner (public):      {}",
                hex::encode(owner.to_repr().as_ref())
            );
        }
        Commands::Serve { bind } => {
            println!("Starting PIL RPC server on {bind}...");
            println!("Generating proving keys (this may take a moment)...");
            let keys = match pil_prover::ProvingKeys::setup() {
                Ok(k) => std::sync::Arc::new(k),
                Err(e) => {
                    eprintln!("Failed to generate proving keys: {e}");
                    return;
                }
            };
            let state = std::sync::Arc::new(tokio::sync::RwLock::new(pil_rpc::AppState::new(keys)));
            let router = pil_rpc::create_router(state);
            let listener = match tokio::net::TcpListener::bind(&bind).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Failed to bind to {bind}: {e}");
                    return;
                }
            };
            println!("PIL RPC server listening on {bind}");
            if let Err(e) = axum::serve(listener, router).await {
                eprintln!("Server error: {e}");
            }
        }
    }
}
