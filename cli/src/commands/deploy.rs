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

//! Deploy quip-arch program to Arch Network and initialize factory.

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
use clap::Args as ClapArgs;
use std::path::PathBuf;

use quip_arch::instruction::QuipInstruction;
use quip_arch::utils::derive_factory_address;

use crate::btc_helper;
use crate::common::{load_keypair, parse_network, parse_program_id, pubkey_to_base58};

/// Path to the compiled program ELF (relative to project root)
const ELF_PATH: &str = "target/sbpf-solana-solana/release/quip_arch.so";

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the deployer keypair JSON file (becomes the factory admin)
    #[arg(long, default_value = "keys/testnet_deployer.json")]
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

    /// Bitcoin network (testnet4, bitcoin, regtest)
    #[arg(long, default_value = "testnet4")]
    network: String,

    /// Print the factory PDA address for a given program ID and exit
    #[arg(long)]
    print_factory_address: Option<String>,

    /// Skip deployment, only initialize factory (requires --program-id)
    #[arg(long)]
    init_only: bool,

    /// Existing program ID (hex) to use with --init-only
    #[arg(long)]
    program_id: Option<String>,

    /// Manually specify a factory UTXO as txid:vout (bypasses send_utxo)
    #[arg(long)]
    factory_utxo: Option<String>,
}

struct DeploymentResult {
    factory_pubkey: Pubkey,
    factory_utxo_txid: String,
    factory_utxo_vout: u32,
}

fn create_config(args: &Args) -> Result<Config> {
    let network = parse_network(&args.network)?;

    // Regtest uses localnet defaults
    if network == bitcoin::Network::Regtest {
        let mut config = Config::localnet();
        config.titan_url = args.titan_url.clone()
            .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
        return Ok(config);
    }

    let bitcoin_rpc_url = args.bitcoin_rpc_url.clone()
        .ok_or_else(|| anyhow::anyhow!(
            "Bitcoin RPC URL required. Set --bitcoin-rpc-url or BTC_RPC_URL env var"
        ))?;

    let arch_rpc_url = args.arch_rpc_url.clone()
        .ok_or_else(|| anyhow::anyhow!(
            "Arch RPC URL required. Set --arch-rpc-url or ARCH_RPC_URL env var"
        ))?;

    let titan_url = args.titan_url.clone()
        .ok_or_else(|| anyhow::anyhow!(
            "Titan URL required. Set --titan-url or TITAN_URL env var"
        ))?;

    Ok(Config {
        node_endpoint: bitcoin_rpc_url,
        node_username: args.bitcoin_rpc_user.clone(),
        node_password: args.bitcoin_rpc_pass.clone(),
        network,
        arch_node_url: arch_rpc_url,
        titan_url,
    })
}

fn deploy_program(
    config: &Config,
    _client: &ArchRpcClient,
    authority_keypair: UntweakedKeypair,
    elf_path: &PathBuf,
) -> Result<Pubkey> {
    println!("Deploying program...");

    let (program_keypair, _, _) = generate_new_keypair(config.network);

    println!("Skipping SDK faucet (fund manually with arch-cli if needed)...");

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

fn get_factory_utxo(
    helper: &BitcoinHelper,
    keypair: &UntweakedKeypair,
    factory_pubkey: Pubkey,
    manual_utxo: Option<&str>,
    arch_rpc_url: &str,
    titan_url: &str,
    network: arch_program::bitcoin::Network,
) -> Result<UtxoMeta> {
    if let Some(utxo_str) = manual_utxo {
        return parse_manual_utxo(utxo_str);
    }

    // Regtest: use BitcoinHelper (direct RPC to local node)
    if network == arch_program::bitcoin::Network::Regtest {
        println!("Sending UTXO to factory address (regtest)...");
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

    // Testnet/mainnet: use mempool.space API
    println!("Sending UTXO to factory address via mempool.space...");
    let (txid_hex, vout) = btc_helper::send_utxo(keypair, &factory_pubkey, arch_rpc_url, titan_url, network)?;

    let txid_bytes: [u8; 32] = hex::decode(&txid_hex)
        .context("Failed to decode txid")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid txid length"))?;

    println!("Factory UTXO: {}:{}", txid_hex, vout);

    Ok(UtxoMeta::from(txid_bytes, vout))
}

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
) -> Result<DeploymentResult> {
    println!("Initializing factory...");

    let (factory_bytes, _bump) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    let authority_pubkey = Pubkey::from_slice(
        &authority_keypair.x_only_public_key().0.serialize()
    );

    let factory_utxo = get_factory_utxo(
        helper,
        authority_keypair,
        factory_pubkey,
        manual_utxo,
        &config.arch_node_url,
        &config.titan_url,
        config.network,
    )?;

    let factory_utxo_txid = hex::encode(factory_utxo.txid());
    let factory_utxo_vout = factory_utxo.vout();

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

pub fn run(args: Args) -> Result<()> {
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

    println!("=== Quip-Arch Deployment ===\n");

    println!("Loading deployer keypair from: {}", args.deployer_keypair.display());
    let deployer_keypair = load_keypair(&args.deployer_keypair)?;

    let deployer_pubkey = Pubkey::from_slice(
        &deployer_keypair.x_only_public_key().0.serialize()
    );
    println!("Deployer pubkey: {}", pubkey_to_base58(&deployer_pubkey));

    let config = create_config(&args)?;
    println!("Network: {:?}", config.network);
    println!("Arch RPC: {}", config.arch_node_url);
    println!("Titan URL: {}", config.titan_url);
    println!();

    let client = ArchRpcClient::new(&config);
    let helper = BitcoinHelper::new(&config);

    let program_pubkey = if args.init_only {
        let pid_hex = args.program_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--init-only requires --program-id <hex>"))?;
        let pubkey = parse_program_id(pid_hex)?;
        println!("Using existing program: {}", pubkey_to_base58(&pubkey));
        pubkey
    } else {
        if !args.elf_path.exists() {
            anyhow::bail!(
                "Program ELF not found at: {}\nRun `cargo build-sbpf` first.",
                args.elf_path.display()
            );
        }

        deploy_program(
            &config,
            &client,
            deployer_keypair.clone(),
            &args.elf_path,
        )?
    };

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
    let deployment_dir = std::path::PathBuf::from(format!("deployments/{}", network_name));
    std::fs::create_dir_all(&deployment_dir)
        .with_context(|| format!("Failed to create deployment directory: {}", deployment_dir.display()))?;
    let deployment_path = deployment_dir.join("deployment.json");
    std::fs::write(&deployment_path, serde_json::to_string_pretty(&deployment_json)?)
        .with_context(|| format!("Failed to write deployment.json to {}", deployment_path.display()))?;
    println!("\nDeployment saved to: {}", deployment_path.display());

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
