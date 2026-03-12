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
use clap::Args as ClapArgs;
use hashsigs::WOTSPlus;
use rand::RngCore;
use std::path::PathBuf;

use quip_arch::instruction::QuipInstruction;
use quip_arch::state::WinternitzPublicKey;
use quip_arch::utils::{derive_factory_address, derive_wallet_address};

use crate::btc_helper;
use crate::common::{base58_encode, load_deployment, load_keypair, parse_hex_32, parse_network};

#[derive(ClapArgs, Debug)]
pub struct Args {
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
    #[arg(long, default_value = "keys/testnet_deployer.json")]
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
    #[arg(long, default_value = "keys")]
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

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);

    let (public_key, private_key) = winternitz.generate_key_pair(&seed);

    let wots_pubkey = WinternitzPublicKey {
        public_seed: public_key.public_seed,
        public_key_hash: public_key.public_key_hash,
    };

    (wots_pubkey, private_key)
}

pub fn run(args: Args) -> Result<()> {
    // Load deployment.json based on network
    let deployment = load_deployment(&args.network)?;

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
