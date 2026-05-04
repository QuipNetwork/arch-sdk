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

//! Integration tests for the Quip Arch post-quantum wallet program.
//!
//! These tests require a running Arch node and Bitcoin regtest node.
//! Run with: `cargo test --features "test no-entrypoint" -- --ignored --nocapture --test-threads=1`

pub use arch_program::{
    account::AccountMeta,
    bitcoin::hashes::Hash,
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::minimum_rent,
    sanitized::ArchMessage,
    system_instruction,
    system_program,
    utxo::UtxoMeta,
};
pub use arch_sdk::{
    build_and_sign_transaction, generate_new_keypair,
    ArchRpcClient, BitcoinHelper, Config, ProgramDeployer, Status,
};
pub use arch_sdk::arch_program::bitcoin::key::UntweakedKeypair;
pub use borsh::BorshDeserialize;
pub use hashsigs::WOTSPlus;
pub use serial_test::serial;

// APL Token imports for token transfer tests
pub use apl_token;
pub use apl_associated_token_account;

pub use crate::error::QuipError;
pub use crate::instruction::QuipInstruction;
pub use crate::state::{
    CpiAccountMeta, QuipFactory, QuipWallet,
    WinternitzPublicKey, WinternitzSignature,
};
pub use crate::utils::{
    create_btc_transfer_message, create_change_owner_message, create_execute_message,
    create_transfer_message, derive_factory_address, derive_wallet_address,
};

pub const ELF_PATH: &str = "target/sbpf-solana-solana/release/quip_arch.so";

/// Compute budget for WOTS+ signature verification.
/// WOTS+ verification requires ~1000 keccak256 hash operations (67 chunks × ~15 hashes each).
/// Default compute budget is insufficient, so we request 1.4M units for operations
/// that involve signature verification.
pub const WOTS_COMPUTE_BUDGET: u32 = 1_400_000;

/// Higher compute budget for BTC transfer operations.
/// In addition to WOTS+ verification, these need: bitcoin::consensus::deserialize,
/// get_account_script_pubkey syscall, Bitcoin tx construction, and
/// set_transaction_to_sign (2 syscalls + serialization).
pub const BTC_TRANSFER_COMPUTE_BUDGET: u32 = 3_000_000;

// =============================================================================
// Utility Functions (minimal, non-obfuscating)
// =============================================================================

/// Compute Keccak256 hash for WOTS+ signature generation
pub fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    arch_program::hashing_functions::keccak256(data).0
}

/// Generate a WOTS+ keypair with deterministic seed based on index.
/// The index is used as a test seed to create different keypairs for different tests.
pub fn generate_wots_keypair(index: u64) -> (WinternitzPublicKey, [u8; 32]) {
    let winternitz = WOTSPlus::new(keccak256_hash);

    let mut seed = [0u8; 32];
    let index_bytes = index.to_le_bytes();
    seed[..8].copy_from_slice(&index_bytes);
    for i in 8..32 {
        seed[i] = ((i as u8).wrapping_mul(41).wrapping_add(seed[i % 8])) ^ (index as u8);
    }

    let (public_key, private_key) = winternitz.generate_key_pair(&seed);

    let wots_pubkey = WinternitzPublicKey {
        public_seed: public_key.public_seed,
        public_key_hash: public_key.public_key_hash,
    };

    (wots_pubkey, private_key)
}

/// Derive a WOTS+ public key from a private key at a specific index.
/// This allows generating multiple public keys from the same private key,
/// which is the correct WOTS+ usage pattern (rotate public keys, not private keys).
pub fn derive_wots_pubkey_at_index(
    private_key: &[u8; 32],
    index: u64,
) -> WinternitzPublicKey {
    let winternitz = WOTSPlus::new(keccak256_hash);

    // Derive a unique public_seed based on private_key and index
    // Hash the private_key with the index to get a deterministic public_seed
    let mut seed_input = Vec::with_capacity(40);
    seed_input.extend_from_slice(private_key);
    seed_input.extend_from_slice(&index.to_le_bytes());
    let public_seed = keccak256_hash(&seed_input);

    let public_key = winternitz.get_public_key_with_public_seed(private_key, &public_seed);

    WinternitzPublicKey {
        public_seed: public_key.public_seed,
        public_key_hash: public_key.public_key_hash,
    }
}

/// Sign a message using WOTS+ private key
pub fn sign_message(private_key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let winternitz = WOTSPlus::new(keccak256_hash);
    let message_hash = keccak256_hash(message);
    let signature = winternitz.sign(private_key, &message_hash);
    signature.iter().flat_map(|chunk| chunk.iter().copied()).collect()
}

/// Prepare a fee transaction and wait for Titan to index the funding UTXO.
///
/// `arch_sdk::prepare_fees()` sends a Bitcoin transaction but does not wait
/// for Titan to index it. This wrapper deserializes the fee tx, extracts the
/// funding txid, and polls Titan until the transaction is indexed.
pub async fn prepare_fees_and_wait(helper: &BitcoinHelper) -> Vec<u8> {
    let fee_tx_hex = arch_sdk::prepare_fees().await.unwrap();
    let fee_tx = hex::decode(&fee_tx_hex).unwrap();

    // Deserialize to extract the funding UTXO txid
    let fee_btc_tx: arch_program::bitcoin::Transaction =
        arch_program::bitcoin::consensus::deserialize(&fee_tx).unwrap();
    let fee_funding_txid = fee_btc_tx.input[0].previous_output.txid;
    println!("Waiting for Titan to index fee UTXO: {}", fee_funding_txid);
    helper.wait_until_titan_indexes_transaction(&fee_funding_txid).await.unwrap();
    println!("Fee UTXO indexed by Titan");

    fee_tx
}

// =============================================================================
// Test Context and Helper Functions
// =============================================================================

/// Test context containing common infrastructure
pub struct TestContext {
    pub config: Config,
    pub client: ArchRpcClient,
    pub helper: BitcoinHelper,
}

impl TestContext {
    pub fn new() -> Self {
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config)
            .expect("Failed to create BitcoinHelper");
        Self { config, client, helper }
    }
}

/// Deploy the quip-arch program and return (program_pubkey, payer_keypair, payer_pubkey)
pub async fn deploy_program(ctx: &TestContext) -> (Pubkey, UntweakedKeypair, Pubkey) {
    let (authority_keypair, _, _) = generate_new_keypair(ctx.config.network);
    let (program_keypair, _, _) = generate_new_keypair(ctx.config.network);

    ctx.client
        .create_and_fund_account_with_faucet(&authority_keypair)
        .await
        .expect("Failed to fund authority");

    let deployer = ProgramDeployer::new(&ctx.config);
    let program_pubkey = deployer
        .try_deploy_program(
            "quip-arch".to_string(),
            program_keypair,
            authority_keypair,
            &ELF_PATH.to_string(),
        )
        .await
        .expect("Failed to deploy program");

    println!("Program deployed: {:?}", program_pubkey);

    // Generate and fund a payer keypair for tests to use
    let (payer_keypair, payer_pubkey, _) = generate_new_keypair(ctx.config.network);
    ctx.client
        .create_and_fund_account_with_faucet(&payer_keypair)
        .await
        .expect("Failed to fund payer");

    (program_pubkey, payer_keypair, payer_pubkey)
}

/// Initialize factory and return factory pubkey
pub async fn initialize_factory(
    ctx: &TestContext,
    program_pubkey: Pubkey,
    payer_keypair: &UntweakedKeypair,
    payer_pubkey: Pubkey,
    admin_pubkey: Pubkey,
    creation_fee: u64,
    transfer_fee: u64,
    execute_fee: u64,
) -> Pubkey {

    let (factory_bytes, _) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    let (factory_txid, factory_vout) = ctx.helper
        .send_utxo(factory_pubkey)
        .await
        .expect("Failed to send UTXO for factory");

    let factory_utxo = UtxoMeta::from(
        hex::decode(&factory_txid).unwrap().try_into().unwrap(),
        factory_vout,
    );

    let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
        admin: admin_pubkey.serialize(),
        creation_fee,
        transfer_fee,
        execute_fee,
        factory_utxo,
    }).expect("Failed to serialize instruction");

    let accounts = vec![
        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
    ];

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts,
                data: instruction_data,
            }],
            Some(payer_pubkey),
            recent_blockhash,
        ),
        vec![payer_keypair.clone()],
        ctx.config.network,
    ).expect("Failed to build transaction");

    let txid = ctx.client.send_transaction(tx).await.expect("Failed to send transaction");
    let processed_tx = ctx.client
        .wait_for_processed_transaction(&txid)
        .await
        .expect("Failed to wait for transaction");

    assert!(
        processed_tx.status == Status::Processed,
        "Factory initialization failed: {:?}",
        processed_tx.status
    );

    println!("Factory initialized: {:?}", factory_pubkey);
    factory_pubkey
}

/// Create a wallet with WOTS+ key
/// Create a wallet where the owner pays for creation and deposit.
/// Returns (wallet_pubkey, wallet_anchor_utxo)
pub async fn create_wallet(
    ctx: &TestContext,
    program_pubkey: Pubkey,
    factory_pubkey: Pubkey,
    owner_keypair: &UntweakedKeypair,
    owner_pubkey: Pubkey,
    vault_id: [u8; 32],
    pq_key: &WinternitzPublicKey,
    deposit: u64,
) -> (Pubkey, UtxoMeta) {
    let owner_bytes = owner_pubkey.serialize();

    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    let (wallet_txid, wallet_vout) = ctx.helper
        .send_utxo(wallet_pubkey)
        .await
        .expect("Failed to send UTXO for wallet");

    let wallet_utxo = UtxoMeta::from(
        hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
        wallet_vout,
    );

    let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
        vault_id,
        pq_owner: pq_key.clone(),
        deposit,
        wallet_utxo: wallet_utxo.clone(),
    }).expect("Failed to serialize instruction");

    let accounts = vec![
        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
    ];

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts,
                data: instruction_data,
            }],
            Some(owner_pubkey),
            recent_blockhash,
        ),
        vec![owner_keypair.clone()],
        ctx.config.network,
    ).expect("Failed to build transaction");

    let txid = ctx.client.send_transaction(tx).await.expect("Failed to send transaction");
    let processed_tx = ctx.client
        .wait_for_processed_transaction(&txid)
        .await
        .expect("Failed to wait for transaction");

    assert!(
        processed_tx.status == Status::Processed,
        "Wallet creation failed: {:?}",
        processed_tx.status
    );

    println!("Wallet created: {:?}", wallet_pubkey);
    (wallet_pubkey, wallet_utxo)
}

/// Verify factory state
pub async fn verify_factory_state(
    ctx: &TestContext,
    factory_pubkey: Pubkey,
    expected_admin: [u8; 32],
    expected_creation_fee: u64,
    expected_transfer_fee: u64,
    expected_execute_fee: u64,
    expected_total_wallets: u64,
    expected_accumulated_fees: u64,
) {
    let factory_account = ctx.client
        .read_account_info(factory_pubkey)
        .await
        .expect("Failed to read factory account");

    let factory = QuipFactory::try_from_slice(&factory_account.data)
        .expect("Failed to deserialize factory");

    assert_eq!(factory.admin, expected_admin, "Admin mismatch");
    assert_eq!(factory.creation_fee, expected_creation_fee, "Creation fee mismatch");
    assert_eq!(factory.transfer_fee, expected_transfer_fee, "Transfer fee mismatch");
    assert_eq!(factory.execute_fee, expected_execute_fee, "Execute fee mismatch");
    assert_eq!(factory.total_wallets, expected_total_wallets, "Total wallets mismatch");
    assert_eq!(factory.accumulated_fees, expected_accumulated_fees, "Accumulated fees mismatch");
}

/// Verify wallet state
pub async fn verify_wallet_state(
    ctx: &TestContext,
    wallet_pubkey: Pubkey,
    expected_owner: [u8; 32],
    expected_pq_owner: &WinternitzPublicKey,
    expected_transaction_count: u64,
) {
    let wallet_account = ctx.client
        .read_account_info(wallet_pubkey)
        .await
        .expect("Failed to read wallet account");

    let wallet = QuipWallet::try_from_slice(&wallet_account.data)
        .expect("Failed to deserialize wallet");

    assert_eq!(wallet.version, 1, "Version mismatch");
    assert_eq!(wallet.owner, expected_owner, "Owner mismatch");
    assert_eq!(wallet.pq_owner.public_seed, expected_pq_owner.public_seed, "PQ public_seed mismatch");
    assert_eq!(wallet.pq_owner.public_key_hash, expected_pq_owner.public_key_hash, "PQ public_key_hash mismatch");
    assert!(wallet.created_at > 0, "created_at should be set");
    assert!(wallet.last_activity >= wallet.created_at, "last_activity should be >= created_at");
    assert_eq!(wallet.transaction_count, expected_transaction_count, "Transaction count mismatch");
    // bump intentionally not checked (PDA implementation detail)
}

/// Capture balances for multiple accounts
pub async fn capture_balances(ctx: &TestContext, accounts: &[Pubkey]) -> Vec<u64> {
    let mut balances = Vec::with_capacity(accounts.len());
    for pubkey in accounts {
        balances.push(
            ctx.client.read_account_info(*pubkey).await.unwrap().lamports
        );
    }
    balances
}

/// Anchor an account to a Bitcoin UTXO
pub async fn anchor_account(ctx: &TestContext, account_keypair: &UntweakedKeypair, account_pubkey: Pubkey) {
    let (txid, vout) = ctx.helper.send_utxo(account_pubkey).await.unwrap();
    let anchor_ix = system_instruction::anchor(
        &account_pubkey,
        hex::decode(&txid).unwrap().try_into().unwrap(),
        vout,
    );
    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(&[anchor_ix], Some(account_pubkey), recent_blockhash),
        vec![account_keypair.clone()],
        ctx.config.network,
    ).unwrap();
    let txid = ctx.client.send_transaction(tx).await.unwrap();
    ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Account anchored: {:?}", account_pubkey);
}

/// Execute a transfer with Winternitz signature
pub async fn execute_transfer(
    ctx: &TestContext,
    program_pubkey: Pubkey,
    factory_pubkey: Pubkey,
    wallet_pubkey: Pubkey,
    recipient_pubkey: Pubkey,
    owner_keypair: &UntweakedKeypair,
    owner_pubkey: Pubkey,
    vault_id: [u8; 32],
    pq_key: &WinternitzPublicKey,
    pq_next: &WinternitzPublicKey,
    private_key: &[u8; 32],
    amount: u64,
) -> Status {
    let recipient_bytes = recipient_pubkey.serialize();
    let message = create_transfer_message(pq_key, pq_next, &recipient_bytes, amount);
    let signature_data = sign_message(private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[
                compute_budget_ix,
                Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                    ],
                    data: instruction_data,
                },
            ],
            Some(owner_pubkey),
            recent_blockhash,
        ),
        vec![owner_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Transfer status: {:?}", processed_tx.status);
    processed_tx.status
}

/// Execute a change PQ owner operation
pub async fn execute_change_pq_owner(
    ctx: &TestContext,
    program_pubkey: Pubkey,
    wallet_pubkey: Pubkey,
    owner_keypair: &UntweakedKeypair,
    owner_pubkey: Pubkey,
    vault_id: [u8; 32],
    pq_key: &WinternitzPublicKey,
    pq_next: &WinternitzPublicKey,
    private_key: &[u8; 32],
) -> Status {
    let message = create_change_owner_message(pq_key, pq_next);
    let signature_data = sign_message(private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
        vault_id,
        pq_next: pq_next.clone(),
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[
                compute_budget_ix,
                Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                    ],
                    data: instruction_data,
                },
            ],
            Some(owner_pubkey),
            recent_blockhash,
        ),
        vec![owner_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Change PQ owner status: {:?}", processed_tx.status);
    processed_tx.status
}

/// Execute a BTC transfer instruction (raw, without anchoring - caller must anchor first)
pub async fn execute_btc_transfer_raw(
    ctx: &TestContext,
    program_pubkey: Pubkey,
    factory_pubkey: Pubkey,
    wallet_pubkey: Pubkey,
    signer_keypair: &UntweakedKeypair,
    signer_pubkey: Pubkey,
    vault_id: [u8; 32],
    pq_key: &WinternitzPublicKey,
    pq_next: &WinternitzPublicKey,
    private_key: &[u8; 32],
    amount: u64,
    recipient_script_pubkey: Vec<u8>,
    fee_tx: Vec<u8>,
    source_utxo: &UtxoMeta,
) -> (Status, Option<arch_program::hash::Hash>) {
    let message = create_btc_transfer_message(pq_key, pq_next, &recipient_script_pubkey, amount, source_utxo);
    let signature_data = sign_message(private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount,
        recipient_script_pubkey,
        fee_tx,
        source_utxo: source_utxo.clone(),
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[
                compute_budget_ix,
                Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: signer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                },
            ],
            Some(signer_pubkey),
            recent_blockhash,
        ),
        vec![signer_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("BTC transfer status: {:?}", processed_tx.status);
    (processed_tx.status, processed_tx.bitcoin_txid)
}

/// Create a P2WPKH-style script pubkey
pub fn create_p2wpkh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut script = vec![0x00, 0x14]; // OP_0, PUSH20
    script.extend_from_slice(hash);
    script
}

/// Assert that a transaction failed with the expected QuipError
pub fn assert_error(status: &Status, expected: QuipError) {
    let expected_code = expected.clone() as u32;
    let expected_str = format!("custom program error: 0x{:x}", expected_code);

    match status {
        Status::Failed(err) => {
            assert!(
                err.contains(&expected_str),
                "Expected {:?}, got: {}",
                expected, err
            );
        }
        _ => panic!("Expected {:?}, got: {:?}", expected, status),
    }
}

pub fn assert_invalid_account_data(status: &Status) {
    match status {
        Status::Failed(err) => {
            assert!(
                err.contains("invalid account data"),
                "Expected InvalidAccountData, got: {}",
                err
            );
        }
        _ => panic!("Expected InvalidAccountData failure, got: {:?}", status),
    }
}


/// Execute a withdraw fees operation
pub async fn execute_withdraw_fees(
    ctx: &TestContext,
    program_pubkey: Pubkey,
    factory_pubkey: Pubkey,
    admin_keypair: &UntweakedKeypair,
    admin_pubkey: Pubkey,
    recipient_pubkey: Pubkey,
    amount: u64,
) -> Status {
    let instruction_data = borsh::to_vec(&QuipInstruction::WithdrawFees {
        amount,
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                    AccountMeta { pubkey: admin_pubkey, is_signer: true, is_writable: false },
                    AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
                ],
                data: instruction_data,
            }],
            Some(admin_pubkey),
            recent_blockhash,
        ),
        vec![admin_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Withdraw fees status: {:?}", processed_tx.status);
    processed_tx.status
}

/// Execute an update fees operation
pub async fn execute_update_fees(
    ctx: &TestContext,
    program_pubkey: Pubkey,
    factory_pubkey: Pubkey,
    admin_keypair: &UntweakedKeypair,
    admin_pubkey: Pubkey,
    creation_fee: u64,
    transfer_fee: u64,
    execute_fee: u64,
) -> Status {
    let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
        creation_fee,
        transfer_fee,
        execute_fee,
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                    AccountMeta { pubkey: admin_pubkey, is_signer: true, is_writable: false },
                ],
                data: instruction_data,
            }],
            Some(admin_pubkey),
            recent_blockhash,
        ),
        vec![admin_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Update fees status: {:?}", processed_tx.status);
    processed_tx.status
}

// =============================================================================
// Module declarations
// =============================================================================

pub mod test_initialize_factory;
pub mod test_deposit_to_winternitz;
pub mod test_transfer_with_winternitz;
pub mod test_change_pq_owner;
pub mod test_update_fees;
pub mod test_transfer_ownership;
pub mod test_withdraw_fees;
pub mod test_btc_transfer;
pub mod test_execute_with_winternitz;
pub mod test_misc;
