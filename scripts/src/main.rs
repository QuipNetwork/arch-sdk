// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Testnet deployment script for quip-arch program.
//!
//! This script deploys the quip-arch program to Arch Network testnet and
//! initializes the factory with configurable fees.
//!
//! Usage:
//! ```bash
//! # Testnet deployment (uses null UTXO, no Bitcoin wallet access needed):
//! cargo run --release -- \
//!     --bitcoin-rpc-url "http://bitcoin-rpc.test.arch.network:80" \
//!     --arch-rpc-url "https://rpc.testnet.arch.network" \
//!     --titan-url "https://titan-public-http.test.arch.network" \
//!     --deployer-keypair ../keys/testnet_deployer.json
//!
//! # Localnet deployment (uses BitcoinHelper::send_utxo):
//! cargo run --release -- --localnet
//!
//! # Print factory PDA for a given program ID:
//! cargo run --release -- --print-factory-address <PROGRAM_ID_HEX>
//!
//! # Initialize factory only (skip deploy, for re-running init after prior deploy):
//! cargo run --release -- --init-only --program-id <HEX> \
//!     --arch-rpc-url ... --titan-url ... --bitcoin-rpc-url ...
//! ```

mod btc_helper;

use anyhow::{Context, Result};
use arch_program::{
    account::AccountMeta,
    instruction::Instruction,
    pubkey::Pubkey,
    sanitized::ArchMessage,
    system_program,
    utxo::UtxoMeta,
};
use arch_sdk::{
    build_and_sign_transaction, generate_new_keypair,
    ArchRpcClient, BitcoinHelper, Config, ProgramDeployer, Status,
};
use arch_sdk::arch_program::bitcoin::key::UntweakedKeypair;
use clap::Parser;
use std::path::PathBuf;

use quip_arch::instruction::QuipInstruction;
use quip_arch::utils::derive_factory_address;

/// Path to the compiled program ELF (relative to scripts/ directory)
const ELF_PATH: &str = "../target/sbpf-solana-solana/release/quip_arch.so";

/// Testnet deployment script for quip-arch program
#[derive(Parser, Debug)]
#[command(name = "quip-deploy")]
#[command(about = "Deploy quip-arch program to Arch Network testnet")]
struct Args {
    /// Path to the deployer keypair JSON file (becomes the factory admin)
    #[arg(long, default_value = "../keys/testnet_deployer.json")]
    deployer_keypair: PathBuf,

    /// Wallet creation fee in lamports
    #[arg(long, default_value = "1000")]
    creation_fee: u64,

    /// Transfer operation fee in lamports
    #[arg(long, default_value = "100")]
    transfer_fee: u64,

    /// Execute (CPI) operation fee in lamports
    #[arg(long, default_value = "100")]
    execute_fee: u64,

    /// Path to the compiled program ELF file
    #[arg(long, default_value = ELF_PATH)]
    elf_path: PathBuf,

    /// Bitcoin RPC endpoint URL
    #[arg(long, env = "BTC_RPC_URL")]
    bitcoin_rpc_url: Option<String>,

    /// Bitcoin RPC username
    #[arg(long, env = "BTC_RPC_USER", default_value = "bitcoin")]
    bitcoin_rpc_user: String,

    /// Bitcoin RPC password
    #[arg(long, env = "BTC_RPC_PASS", default_value = "bitcoinpass")]
    bitcoin_rpc_pass: String,

    /// Arch node RPC URL
    #[arg(long, env = "ARCH_RPC_URL")]
    arch_rpc_url: Option<String>,

    /// Titan indexer URL
    #[arg(long, env = "TITAN_URL")]
    titan_url: Option<String>,

    /// Use localnet configuration (for testing).
    /// On localnet, send_utxo is used to create real Bitcoin UTXOs via the local node.
    #[arg(long)]
    localnet: bool,

    /// Print the factory PDA address for a given program ID and exit
    #[arg(long)]
    print_factory_address: Option<String>,

    /// Skip deployment, only initialize factory (requires --program-id)
    #[arg(long)]
    init_only: bool,

    /// Existing program ID (hex) to use with --init-only
    #[arg(long)]
    program_id: Option<String>,

    /// Manually specify a factory UTXO as txid:vout (bypasses send_utxo).
    /// The txid should be in standard hex (big-endian, as shown on block explorers).
    #[arg(long)]
    factory_utxo: Option<String>,
}

/// Base58 alphabet (Bitcoin/Solana style)
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes to base58 string
fn base58_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    // Count leading zeros
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();

    // Convert to base58
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    // Build result string
    let mut result = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        result.push('1');
    }
    for digit in digits.iter().rev() {
        result.push(BASE58_ALPHABET[*digit as usize] as char);
    }
    result
}

/// Convert Pubkey to base58 string
fn pubkey_to_base58(pubkey: &Pubkey) -> String {
    base58_encode(&pubkey.serialize())
}

/// Load a keypair from a JSON file (arch-cli format)
fn load_keypair(path: &PathBuf) -> Result<UntweakedKeypair> {
    let json_str = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read keypair file: {}", path.display()))?;

    // arch-cli saves keypairs as a JSON array of bytes
    let bytes: Vec<u8> = serde_json::from_str(&json_str)
        .with_context(|| "Failed to parse keypair JSON")?;

    // Support both formats:
    // - 32 bytes: arch-cli format (secret key only)
    // - 64 bytes: Solana format (secret key + public key)
    let secret_bytes: [u8; 32] = match bytes.len() {
        32 => bytes.try_into().expect("checked length is 32"),
        64 => bytes[..32].try_into().expect("slice is 32 bytes"),
        n => anyhow::bail!("Invalid keypair length: expected 32 or 64 bytes, got {}", n),
    };

    let keypair = UntweakedKeypair::from_seckey_slice(&arch_program::bitcoin::secp256k1::Secp256k1::new(), &secret_bytes)
        .with_context(|| "Failed to create keypair from secret key")?;

    Ok(keypair)
}

/// Create configuration based on CLI args
fn create_config(args: &Args) -> Result<Config> {
    if args.localnet {
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        return Ok(config);
    }

    // Testnet configuration - requires user to provide endpoints
    let bitcoin_rpc_url = args.bitcoin_rpc_url.clone()
        .ok_or_else(|| anyhow::anyhow!(
            "Bitcoin RPC URL required for testnet. Set --bitcoin-rpc-url or BTC_RPC_URL env var"
        ))?;

    let arch_rpc_url = args.arch_rpc_url.clone()
        .ok_or_else(|| anyhow::anyhow!(
            "Arch RPC URL required for testnet. Set --arch-rpc-url or ARCH_RPC_URL env var"
        ))?;

    let titan_url = args.titan_url.clone()
        .ok_or_else(|| anyhow::anyhow!(
            "Titan URL required for testnet. Set --titan-url or TITAN_URL env var"
        ))?;

    Ok(Config {
        node_endpoint: bitcoin_rpc_url,
        node_username: args.bitcoin_rpc_user.clone(),
        node_password: args.bitcoin_rpc_pass.clone(),
        network: arch_program::bitcoin::Network::Testnet4,
        arch_node_url: arch_rpc_url,
        titan_url,
    })
}

/// Deploy the program and return the program pubkey
fn deploy_program(
    config: &Config,
    client: &ArchRpcClient,
    authority_keypair: UntweakedKeypair,
    elf_path: &PathBuf,
) -> Result<Pubkey> {
    println!("Deploying program...");

    // Generate a new keypair for the program account
    let (program_keypair, _, _) = generate_new_keypair(config.network);

    // Skip SDK faucet - fund manually with: arch-cli account airdrop --pubkey <PUBKEY> --amount 1000000000
    // The SDK's create_and_fund_account_with_faucet requires 1B lamports which exceeds faucet limits.
    println!("Skipping SDK faucet (fund manually with arch-cli if needed)...");

    // Deploy the program
    let deployer = ProgramDeployer::new(config);
    let elf_path_str = elf_path.to_string_lossy().to_string();
    let program_pubkey = deployer
        .try_deploy_program(
            "quip-arch".to_string(),
            program_keypair,
            authority_keypair,
            &elf_path_str,
        )
        .context("Failed to deploy program")?;

    println!("Program deployed successfully!");
    Ok(program_pubkey)
}

/// Parse a manual UTXO string in "txid:vout" format.
/// The txid is expected in big-endian hex (as shown on block explorers).
/// UtxoMeta::from stores txid in big-endian (display order) — no reversal needed.
fn parse_manual_utxo(utxo_str: &str) -> Result<UtxoMeta> {
    let parts: Vec<&str> = utxo_str.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("UTXO must be in format txid:vout (e.g., abc123...:0)");
    }

    let txid_bytes: [u8; 32] = hex::decode(parts[0])
        .context("Invalid hex for txid")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("txid must be 32 bytes (64 hex chars)"))?;

    let vout: u32 = parts[1].parse()
        .context("Invalid vout number")?;

    println!("Using manual UTXO: {}:{}", parts[0], vout);

    Ok(UtxoMeta::from(txid_bytes, vout))
}

/// Obtain the factory UTXO.
///
/// Priority:
/// 1. --factory-utxo: use a manually specified UTXO directly.
/// 2. Localnet: use `BitcoinHelper::send_utxo` (direct Bitcoin wallet access).
/// 3. Testnet/mainnet: use `btc_helper::send_utxo` to build and broadcast a P2TR tx
///    via mempool.space, sending 3000 sats to the factory's Arch-assigned address.
fn get_factory_utxo(
    helper: &BitcoinHelper,
    keypair: &UntweakedKeypair,
    factory_pubkey: Pubkey,
    manual_utxo: Option<&str>,
    localnet: bool,
    arch_rpc_url: &str,
    titan_url: &str,
    network: arch_program::bitcoin::Network,
) -> Result<UtxoMeta> {
    if let Some(utxo_str) = manual_utxo {
        return parse_manual_utxo(utxo_str);
    }

    if localnet {
        println!("Sending UTXO to factory address (localnet)...");
        let (factory_txid, factory_vout) = helper
            .send_utxo(factory_pubkey)
            .map_err(|e| anyhow::anyhow!("Failed to send UTXO for factory: {}", e))?;

        return Ok(UtxoMeta::from(
            hex::decode(&factory_txid)
                .context("Failed to decode factory txid")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid txid length"))?,
            factory_vout,
        ));
    }

    // Testnet/mainnet: build and broadcast P2TR tx via mempool.space
    println!("Sending UTXO to factory address via mempool.space...");
    let (txid_hex, vout) = btc_helper::send_utxo(keypair, &factory_pubkey, arch_rpc_url, titan_url, network)?;

    // txid from mempool.space is big-endian hex — same format UtxoMeta::from expects
    let txid_bytes: [u8; 32] = hex::decode(&txid_hex)
        .context("Failed to decode txid")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid txid length"))?;

    println!("Factory UTXO: {}:{}", txid_hex, vout);

    Ok(UtxoMeta::from(txid_bytes, vout))
}

/// Deployment result containing all info needed for deployment.json
struct DeploymentResult {
    factory_pubkey: Pubkey,
    factory_utxo_txid: String,
    factory_utxo_vout: u32,
}

/// Initialize the factory with the given fees
fn initialize_factory(
    config: &Config,
    client: &ArchRpcClient,
    helper: &BitcoinHelper,
    program_pubkey: Pubkey,
    authority_keypair: &UntweakedKeypair,
    creation_fee: u64,
    transfer_fee: u64,
    execute_fee: u64,
    manual_utxo: Option<&str>,
    localnet: bool,
) -> Result<DeploymentResult> {
    println!("Initializing factory...");

    // Derive factory PDA address
    let (factory_bytes, _bump) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    // Get authority pubkey
    let authority_pubkey = Pubkey::from_slice(
        &authority_keypair.x_only_public_key().0.serialize()
    );

    // Get UTXO for factory anchoring
    let factory_utxo = get_factory_utxo(
        helper,
        authority_keypair,
        factory_pubkey,
        manual_utxo,
        localnet,
        &config.arch_node_url,
        &config.titan_url,
        config.network,
    )?;

    // Capture UTXO info for deployment.json
    let factory_utxo_txid = hex::encode(factory_utxo.txid());
    let factory_utxo_vout = factory_utxo.vout();

    // Build InitializeFactory instruction
    let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
        admin: authority_pubkey.serialize(),
        creation_fee,
        transfer_fee,
        execute_fee,
        factory_utxo: factory_utxo.clone(),
    }).context("Failed to serialize instruction")?;

    let accounts = vec![
        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
        AccountMeta { pubkey: authority_pubkey, is_signer: true, is_writable: true },
        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
    ];

    // Build and send transaction
    let recent_blockhash = client
        .get_best_finalized_block_hash()
        .context("Failed to get recent blockhash")?;

    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts,
                data: instruction_data,
            }],
            Some(authority_pubkey),
            recent_blockhash,
        ),
        vec![authority_keypair.clone()],
        config.network,
    ).context("Failed to build transaction")?;

    println!("Sending InitializeFactory transaction...");
    let txid = client
        .send_transaction(tx)
        .context("Failed to send transaction")?;

    let processed_tx = client
        .wait_for_processed_transaction(&txid)
        .context("Failed to wait for transaction")?;

    // Print full transaction details for debugging
    println!("Transaction status: {:?}", processed_tx.status);
    if !processed_tx.logs.is_empty() {
        println!("Transaction logs:");
        for log in &processed_tx.logs {
            println!("  {}", log);
        }
    }
    if let Some(ref btc_txid) = processed_tx.bitcoin_txid {
        println!("Bitcoin txid: {:?}", btc_txid);
    }
    match &processed_tx.rollback_status {
        arch_sdk::RollbackStatus::Rolledback(msg) => println!("Rollback: {}", msg),
        _ => {}
    }

    if processed_tx.status != Status::Processed {
        anyhow::bail!("Factory initialization failed: {:?}", processed_tx.status);
    }

    println!("Factory initialized successfully!");
    Ok(DeploymentResult {
        factory_pubkey,
        factory_utxo_txid,
        factory_utxo_vout,
    })
}

/// Parse a hex program ID string into a Pubkey
fn parse_program_id(hex_str: &str) -> Result<Pubkey> {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .context("Invalid hex for program ID")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Program ID must be 32 bytes (64 hex chars)"))?;
    Ok(Pubkey::from_slice(&bytes))
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle --print-factory-address: derive and print, then exit
    if let Some(ref pid_hex) = args.print_factory_address {
        let program_pubkey = parse_program_id(pid_hex)?;
        let (factory_bytes, bump) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);
        println!("Program ID (hex):       {}", pid_hex);
        println!("Program ID (base58):    {}", pubkey_to_base58(&program_pubkey));
        println!("Factory PDA (hex):      {}", hex::encode(factory_bytes));
        println!("Factory PDA (base58):   {}", pubkey_to_base58(&factory_pubkey));
        println!("Factory bump:           {}", bump);
        return Ok(());
    }

    println!("=== Quip-Arch Testnet Deployment ===\n");

    // Load deployer keypair (will become the factory admin)
    println!("Loading deployer keypair from: {}", args.deployer_keypair.display());
    let deployer_keypair = load_keypair(&args.deployer_keypair)?;

    let deployer_pubkey = Pubkey::from_slice(
        &deployer_keypair.x_only_public_key().0.serialize()
    );
    println!("Deployer pubkey: {}", pubkey_to_base58(&deployer_pubkey));

    // Create configuration
    let config = create_config(&args)?;
    println!("Network: {:?}", config.network);
    println!("Arch RPC: {}", config.arch_node_url);
    println!("Titan URL: {}", config.titan_url);
    println!();

    // Create clients
    let client = ArchRpcClient::new(&config);
    let helper = BitcoinHelper::new(&config);

    // Determine program pubkey: either from --program-id or by deploying
    let program_pubkey = if args.init_only {
        let pid_hex = args.program_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--init-only requires --program-id <hex>"))?;
        let pubkey = parse_program_id(pid_hex)?;
        println!("Using existing program: {}", pubkey_to_base58(&pubkey));
        pubkey
    } else {
        // Verify ELF file exists
        if !args.elf_path.exists() {
            anyhow::bail!(
                "Program ELF not found at: {}\nRun `cargo build-sbpf` first.",
                args.elf_path.display()
            );
        }

        // Deploy program
        deploy_program(
            &config,
            &client,
            deployer_keypair.clone(),
            &args.elf_path,
        )?
    };

    // Initialize factory
    let deployment = initialize_factory(
        &config,
        &client,
        &helper,
        program_pubkey,
        &deployer_keypair,
        args.creation_fee,
        args.transfer_fee,
        args.execute_fee,
        args.factory_utxo.as_deref(),
        args.localnet,
    )?;

    let factory_pubkey = deployment.factory_pubkey;

    // Save deployment.json
    let deployment_json = serde_json::json!({
        "network": format!("{:?}", config.network).to_lowercase(),
        "deployed_at": chrono::Utc::now().to_rfc3339(),
        "program_id_hex": hex::encode(program_pubkey.serialize()),
        "program_id_base58": pubkey_to_base58(&program_pubkey),
        "factory_address_hex": hex::encode(factory_pubkey.serialize()),
        "factory_address_base58": pubkey_to_base58(&factory_pubkey),
        "factory_utxo": format!("{}:{}", deployment.factory_utxo_txid, deployment.factory_utxo_vout),
        "admin_hex": hex::encode(deployer_pubkey.serialize()),
        "admin_base58": pubkey_to_base58(&deployer_pubkey),
        "fees": {
            "creation_fee": args.creation_fee,
            "transfer_fee": args.transfer_fee,
            "execute_fee": args.execute_fee
        },
        "endpoints": {
            "arch_rpc": config.arch_node_url,
            "titan": config.titan_url,
            "bitcoin_rpc": config.node_endpoint
        }
    });

    let network_name = format!("{:?}", config.network).to_lowercase();
    let deployment_dir = std::path::PathBuf::from(format!("../deployments/{}", network_name));
    std::fs::create_dir_all(&deployment_dir)
        .with_context(|| format!("Failed to create deployment directory: {}", deployment_dir.display()))?;
    let deployment_path = deployment_dir.join("deployment.json");
    std::fs::write(&deployment_path, serde_json::to_string_pretty(&deployment_json)?)
        .with_context(|| format!("Failed to write deployment.json to {}", deployment_path.display()))?;
    println!("\nDeployment saved to: {}", deployment_path.display());

    // Print deployment summary
    println!("\n=== Deployment Complete ===\n");
    println!("Program ID: {}", pubkey_to_base58(&program_pubkey));
    println!("Factory Address: {}", pubkey_to_base58(&factory_pubkey));
    println!("Factory UTXO: {}:{}", deployment.factory_utxo_txid, deployment.factory_utxo_vout);
    println!();
    println!("Fee Configuration:");
    println!("  Creation Fee: {} lamports", args.creation_fee);
    println!("  Transfer Fee: {} lamports", args.transfer_fee);
    println!("  Execute Fee:  {} lamports", args.execute_fee);
    println!();
    println!("Admin: {}", pubkey_to_base58(&deployer_pubkey));
    println!();
    println!("Verification commands:");
    println!("  arch-cli show {}", pubkey_to_base58(&program_pubkey));
    println!("  arch-cli show {}", pubkey_to_base58(&factory_pubkey));

    Ok(())
}
