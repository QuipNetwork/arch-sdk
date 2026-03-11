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

//! Create a new quip-arch wallet with post-quantum (WOTS+) security.
//!
//! This script handles the entire wallet creation flow:
//! 1. Derives wallet PDA from (program_id, owner, vault_id)
//! 2. Sends a Bitcoin UTXO to the wallet's BTC address
//! 3. Waits for Titan to index the transaction
//! 4. Generates a WOTS+ keypair
//! 5. Sends DepositToWinternitz instruction to create the wallet
//! 6. Saves the keypair to a file for future signing
//!
//! Usage:
//! ```bash
//! cargo run --release --bin create-wallet -- \
//!   --program-id <hex> \
//!   --arch-rpc-url https://rpc.testnet.arch.network \
//!   --titan-url https://titan.testnet.arch.network \
//!   --deployer-keypair ../keys/testnet_deployer.json \
//!   --vault-id 1 \
//!   --deposit 0
//! ```

use anyhow::{Context, Result};
use arch_program::{
    account::AccountMeta,
    instruction::Instruction,
    pubkey::Pubkey,
    sanitized::ArchMessage,
    system_program,
    utxo::UtxoMeta,
};
use arch_sdk::{build_and_sign_transaction, ArchRpcClient, Config};
use arch_sdk::arch_program::bitcoin::key::UntweakedKeypair;
use bitcoin::Network;
use clap::Parser;
use hashsigs::WOTSPlus;
use rand::RngCore;
use std::path::PathBuf;

use quip_arch::instruction::QuipInstruction;
use quip_arch::state::WinternitzPublicKey;
use quip_arch::utils::{derive_factory_address, derive_wallet_address};

#[path = "../btc_helper.rs"]
mod btc_helper;

/// Create a new quip-arch wallet with WOTS+ post-quantum security
#[derive(Parser, Debug)]
#[command(name = "create-wallet")]
#[command(about = "Create a new quip-arch wallet with post-quantum security")]
struct Args {
    /// Program ID (hex, 64 chars). If not provided, reads from deployment.json
    #[arg(long)]
    program_id: Option<String>,

    /// Arch node RPC URL. If not provided, reads from deployment.json
    #[arg(long)]
    arch_rpc_url: Option<String>,

    /// Titan indexer URL. If not provided, reads from deployment.json
    #[arg(long)]
    titan_url: Option<String>,

    /// Path to the deployer keypair JSON file (will be the wallet owner)
    #[arg(long, default_value = "../keys/testnet_deployer.json")]
    deployer_keypair: PathBuf,

    /// Vault ID (integer, will be zero-padded to 32 bytes)
    #[arg(long, default_value = "1")]
    vault_id: u64,

    /// Initial deposit in lamports (0 for no deposit)
    #[arg(long, default_value = "0")]
    deposit: u64,

    /// Bitcoin network
    #[arg(long, default_value = "testnet4")]
    network: String,

    /// Output directory for keypair files
    #[arg(long, default_value = "../keys")]
    output_dir: PathBuf,
}

/// Compute Keccak256 hash (same as on-chain)
fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    use arch_program::hashing_functions::keccak256;
    keccak256(data).0
}

/// Generate a WOTS+ keypair with a random seed
fn generate_wots_keypair() -> (WinternitzPublicKey, [u8; 32]) {
    let winternitz = WOTSPlus::new(keccak256_hash);

    // Generate random seed
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);

    let (public_key, private_key) = winternitz.generate_key_pair(&seed);

    let wots_pubkey = WinternitzPublicKey {
        public_seed: public_key.public_seed,
        public_key_hash: public_key.public_key_hash,
    };

    (wots_pubkey, private_key)
}

fn load_keypair(path: &PathBuf) -> Result<UntweakedKeypair> {
    let json_str = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read keypair file: {}", path.display()))?;
    let bytes: Vec<u8> = serde_json::from_str(&json_str)
        .with_context(|| "Failed to parse keypair JSON")?;
    let secret_bytes: [u8; 32] = match bytes.len() {
        32 => bytes.try_into().expect("checked length is 32"),
        64 => bytes[..32].try_into().expect("slice is 32 bytes"),
        n => anyhow::bail!("Invalid keypair length: expected 32 or 64 bytes, got {}", n),
    };
    let keypair = UntweakedKeypair::from_seckey_slice(
        &arch_program::bitcoin::secp256k1::Secp256k1::new(),
        &secret_bytes,
    ).with_context(|| "Failed to create keypair from secret key")?;
    Ok(keypair)
}

fn parse_hex_32(hex_str: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .with_context(|| format!("Invalid hex for {}", label))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must be 32 bytes (64 hex chars)", label))
}

fn parse_network(s: &str) -> Result<Network> {
    match s {
        "testnet4" => Ok(Network::Testnet4),
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "regtest" => Ok(Network::Regtest),
        _ => anyhow::bail!("Unknown network: {} (expected testnet4, bitcoin, regtest)", s),
    }
}

/// Base58 alphabet (Bitcoin/Solana style)
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
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
    let mut result = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        result.push('1');
    }
    for digit in digits.iter().rev() {
        result.push(BASE58_ALPHABET[*digit as usize] as char);
    }
    result
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Derive deployment.json path from network
    let deployment_file = PathBuf::from(format!("../deployments/{}/deployment.json", args.network));

    // Load deployment.json if it exists
    let deployment: Option<serde_json::Value> = if deployment_file.exists() {
        let content = std::fs::read_to_string(&deployment_file)?;
        Some(serde_json::from_str(&content)?)
    } else {
        None
    };

    // Get program_id from args or deployment.json
    let program_id_hex = args.program_id.clone().or_else(|| {
        deployment.as_ref()?.get("program_id_hex")?.as_str().map(String::from)
    }).ok_or_else(|| anyhow::anyhow!(
        "program-id required (provide via --program-id or deployment.json)"
    ))?;

    // Get endpoints from args or deployment.json
    let arch_rpc_url = args.arch_rpc_url.clone().or_else(|| {
        deployment.as_ref()?.get("endpoints")?.get("arch_rpc")?.as_str().map(String::from)
    }).unwrap_or_else(|| "https://rpc.testnet.arch.network".to_string());

    let titan_url = args.titan_url.clone().or_else(|| {
        deployment.as_ref()?.get("endpoints")?.get("titan")?.as_str().map(String::from)
    }).unwrap_or_else(|| "https://titan.testnet.arch.network".to_string());

    let network = parse_network(&args.network)?;
    let keypair = load_keypair(&args.deployer_keypair)?;
    let owner_pubkey_bytes = keypair.x_only_public_key().0.serialize();
    let owner_pubkey = Pubkey::from_slice(&owner_pubkey_bytes);

    let program_id_bytes = parse_hex_32(&program_id_hex, "program-id")?;
    let program_id = Pubkey::from_slice(&program_id_bytes);

    // Create vault_id as 32-byte array (zero-padded)
    let mut vault_id = [0u8; 32];
    vault_id[..8].copy_from_slice(&args.vault_id.to_le_bytes());

    println!("=== Create Quip Wallet ===\n");
    println!("Program ID:     {}", program_id_hex);
    println!("Owner:          {}", hex::encode(owner_pubkey_bytes));
    println!("Vault ID:       {} (0x{})", args.vault_id, hex::encode(&vault_id[..8]));
    println!("Deposit:        {} lamports", args.deposit);
    println!("Network:        {:?}", network);
    println!();

    // Derive factory and wallet PDAs
    let (factory_bytes, _) = derive_factory_address(&program_id);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    let (wallet_bytes, wallet_bump) = derive_wallet_address(&program_id, &owner_pubkey_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    println!("Factory PDA:    {}", base58_encode(&factory_bytes));
    println!("Wallet PDA:     {}", base58_encode(&wallet_bytes));
    println!("Wallet bump:    {}", wallet_bump);
    println!();

    // Step 1: Send UTXO to wallet's Bitcoin address
    println!("Step 1: Sending UTXO to wallet's Bitcoin address...");
    let (txid, vout) = btc_helper::send_utxo(&keypair, &wallet_pubkey, &arch_rpc_url, &titan_url, network)?;
    println!("UTXO sent: {}:{}", txid, vout);

    let wallet_utxo = UtxoMeta::from(
        hex::decode(&txid)
            .context("Failed to decode txid")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid txid length"))?,
        vout,
    );

    // Step 2: Generate WOTS+ keypair
    println!("\nStep 2: Generating WOTS+ keypair...");
    let (pq_pubkey, pq_private_key) = generate_wots_keypair();
    println!("Public seed:    {}", hex::encode(pq_pubkey.public_seed));
    println!("Public key hash: {}", hex::encode(pq_pubkey.public_key_hash));

    // Step 3: Build and send DepositToWinternitz instruction
    println!("\nStep 3: Sending DepositToWinternitz transaction...");

    let config = Config {
        arch_node_url: arch_rpc_url.clone(),
        node_endpoint: String::new(),
        node_username: String::new(),
        node_password: String::new(),
        network,
        titan_url: titan_url.clone(),
    };
    let client = ArchRpcClient::new(&config);

    let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
        vault_id,
        pq_owner: pq_pubkey.clone(),
        deposit: args.deposit,
        wallet_utxo,
    }).context("Failed to serialize instruction")?;

    let accounts = vec![
        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
    ];

    let recent_blockhash = client
        .get_best_finalized_block_hash()
        .context("Failed to get recent blockhash")?;

    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id,
                accounts,
                data: instruction_data,
            }],
            Some(owner_pubkey),
            recent_blockhash,
        ),
        vec![keypair.clone()],
        network,
    ).context("Failed to build transaction")?;

    let arch_txid = client
        .send_transaction(tx)
        .context("Failed to send transaction")?;

    let processed_tx = client
        .wait_for_processed_transaction(&arch_txid)
        .context("Failed to wait for transaction")?;

    println!("Transaction status: {:?}", processed_tx.status);
    if !processed_tx.logs.is_empty() {
        println!("Logs:");
        for log in &processed_tx.logs {
            println!("  {}", log);
        }
    }

    if processed_tx.status != arch_sdk::Status::Processed {
        anyhow::bail!("Wallet creation failed: {:?}", processed_tx.status);
    }

    // Step 4: Save keypair to file
    println!("\nStep 4: Saving WOTS+ keypair...");
    std::fs::create_dir_all(&args.output_dir)?;
    let keypair_path = args.output_dir.join(format!(
        "wallet_{}_{}.json",
        hex::encode(&wallet_bytes[..8]),
        args.vault_id
    ));

    let keypair_json = serde_json::json!({
        "wallet_pubkey": hex::encode(wallet_bytes),
        "wallet_base58": base58_encode(&wallet_bytes),
        "vault_id": args.vault_id,
        "owner": hex::encode(owner_pubkey_bytes),
        "pq_public_seed": hex::encode(pq_pubkey.public_seed),
        "pq_public_key_hash": hex::encode(pq_pubkey.public_key_hash),
        "pq_private_key": hex::encode(pq_private_key),
        "created_at": chrono::Utc::now().to_rfc3339(),
    });

    std::fs::write(&keypair_path, serde_json::to_string_pretty(&keypair_json)?)
        .with_context(|| format!("Failed to write keypair to {}", keypair_path.display()))?;

    println!("Keypair saved to: {}", keypair_path.display());

    println!("\n=== Wallet Created Successfully ===\n");
    println!("Wallet Address: {}", base58_encode(&wallet_bytes));
    println!("Wallet (hex):   {}", hex::encode(wallet_bytes));
    println!("UTXO:           {}:{}", txid, vout);
    println!("Keypair File:   {}", keypair_path.display());
    println!();
    println!("IMPORTANT: Keep the keypair file safe! The private key is needed for signing transactions.");
    println!("           WOTS+ keys are ONE-TIME USE - after each transaction, rotate to a new key.");

    Ok(())
}
