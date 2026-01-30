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

#[cfg(test)]
mod quip_tests {
    use arch_program::{
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
    use arch_sdk::{
        build_and_sign_transaction, generate_new_keypair,
        ArchRpcClient, BitcoinHelper, Config, ProgramDeployer, Status,
    };
    use arch_sdk::arch_program::bitcoin::key::UntweakedKeypair;
    use borsh::BorshDeserialize;
    use hashsigs::WOTSPlus;
    use serial_test::serial;

    // APL Token imports for token transfer tests
    use apl_token;
    use apl_associated_token_account;

    use crate::error::QuipError;
    use crate::instruction::QuipInstruction;
    use crate::state::{
        CpiAccountMeta, QuipFactory, QuipWallet,
        WinternitzPublicKey, WinternitzSignature,
    };
    use crate::utils::{
        create_btc_transfer_message, create_change_owner_message, create_execute_message,
        create_transfer_message, derive_factory_address, derive_wallet_address,
    };

    const ELF_PATH: &str = "target/sbpf-solana-solana/release/quip_arch.so";

    /// Compute budget for WOTS+ signature verification.
    /// WOTS+ verification requires ~1000 keccak256 hash operations (67 chunks × ~15 hashes each).
    /// Default compute budget is insufficient, so we request 1.4M units for operations
    /// that involve signature verification.
    const WOTS_COMPUTE_BUDGET: u32 = 1_400_000;

    /// Higher compute budget for BTC transfer operations.
    /// In addition to WOTS+ verification, these need: bitcoin::consensus::deserialize,
    /// get_account_script_pubkey syscall, Bitcoin tx construction, and
    /// set_transaction_to_sign (2 syscalls + serialization).
    const BTC_TRANSFER_COMPUTE_BUDGET: u32 = 3_000_000;

    // =============================================================================
    // Utility Functions (minimal, non-obfuscating)
    // =============================================================================

    /// Compute Keccak256 hash for WOTS+ signature generation
    fn keccak256_hash(data: &[u8]) -> [u8; 32] {
        arch_program::hashing_functions::keccak256(data).0
    }

    /// Generate a WOTS+ keypair with deterministic seed based on index.
    /// The index is used as a test seed to create different keypairs for different tests.
    fn generate_wots_keypair(index: u64) -> (WinternitzPublicKey, [u8; 32]) {
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
    fn derive_wots_pubkey_at_index(
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
    fn sign_message(private_key: &[u8; 32], message: &[u8]) -> Vec<u8> {
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
    fn prepare_fees_and_wait(helper: &BitcoinHelper) -> Vec<u8> {
        let fee_tx_hex = arch_sdk::prepare_fees();
        let fee_tx = hex::decode(&fee_tx_hex).unwrap();

        // Deserialize to extract the funding UTXO txid
        let fee_btc_tx: arch_program::bitcoin::Transaction =
            arch_program::bitcoin::consensus::deserialize(&fee_tx).unwrap();
        let fee_funding_txid = fee_btc_tx.input[0].previous_output.txid;
        println!("Waiting for Titan to index fee UTXO: {}", fee_funding_txid);
        helper.wait_until_titan_indexes_transaction(&fee_funding_txid).unwrap();
        println!("Fee UTXO indexed by Titan");

        fee_tx
    }

    // =============================================================================
    // Test Context and Helper Functions
    // =============================================================================

    /// Test context containing common infrastructure
    struct TestContext {
        config: Config,
        client: ArchRpcClient,
        helper: BitcoinHelper,
    }

    impl TestContext {
        fn new() -> Self {
            let mut config = Config::localnet();
            config.titan_url = "http://127.0.0.1:8080".to_string();
            let client = ArchRpcClient::new(&config);
            let helper = BitcoinHelper::new(&config);
            Self { config, client, helper }
        }
    }

    /// Deploy the quip-arch program and return (program_pubkey, payer_keypair, payer_pubkey)
    fn deploy_program(ctx: &TestContext) -> (Pubkey, UntweakedKeypair, Pubkey) {
        let (authority_keypair, _, _) = generate_new_keypair(ctx.config.network);
        let (program_keypair, _, _) = generate_new_keypair(ctx.config.network);

        ctx.client
            .create_and_fund_account_with_faucet(&authority_keypair)
            .expect("Failed to fund authority");

        let deployer = ProgramDeployer::new(&ctx.config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .expect("Failed to deploy program");

        println!("Program deployed: {:?}", program_pubkey);

        // Generate and fund a payer keypair for tests to use
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(ctx.config.network);
        ctx.client
            .create_and_fund_account_with_faucet(&payer_keypair)
            .expect("Failed to fund payer");

        (program_pubkey, payer_keypair, payer_pubkey)
    }

    /// Initialize factory and return factory pubkey
    fn initialize_factory(
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

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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

        let txid = ctx.client.send_transaction(tx).expect("Failed to send transaction");
        let processed_tx = ctx.client
            .wait_for_processed_transaction(&txid)
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
    fn create_wallet(
        ctx: &TestContext,
        program_pubkey: Pubkey,
        factory_pubkey: Pubkey,
        owner_keypair: &UntweakedKeypair,
        owner_pubkey: Pubkey,
        vault_id: [u8; 32],
        pq_key: &WinternitzPublicKey,
        deposit: u64,
    ) -> Pubkey {
        let owner_bytes = owner_pubkey.serialize();

        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = ctx.helper
            .send_utxo(wallet_pubkey)
            .expect("Failed to send UTXO for wallet");

        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            pq_owner: pq_key.clone(),
            deposit,
            wallet_utxo,
        }).expect("Failed to serialize instruction");

        let accounts = vec![
            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
            AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
        ];

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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

        let txid = ctx.client.send_transaction(tx).expect("Failed to send transaction");
        let processed_tx = ctx.client
            .wait_for_processed_transaction(&txid)
            .expect("Failed to wait for transaction");

        assert!(
            processed_tx.status == Status::Processed,
            "Wallet creation failed: {:?}",
            processed_tx.status
        );

        println!("Wallet created: {:?}", wallet_pubkey);
        wallet_pubkey
    }

    /// Verify factory state
    fn verify_factory_state(
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
    fn verify_wallet_state(
        ctx: &TestContext,
        wallet_pubkey: Pubkey,
        expected_owner: [u8; 32],
        expected_pq_owner: &WinternitzPublicKey,
        expected_transaction_count: u64,
    ) {
        let wallet_account = ctx.client
            .read_account_info(wallet_pubkey)
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
    fn capture_balances(ctx: &TestContext, accounts: &[Pubkey]) -> Vec<u64> {
        accounts.iter().map(|pubkey| {
            ctx.client.read_account_info(*pubkey).unwrap().lamports
        }).collect()
    }

    /// Anchor an account to a Bitcoin UTXO
    fn anchor_account(ctx: &TestContext, account_keypair: &UntweakedKeypair, account_pubkey: Pubkey) {
        let (txid, vout) = ctx.helper.send_utxo(account_pubkey).unwrap();
        let anchor_ix = system_instruction::anchor(
            &account_pubkey,
            hex::decode(&txid).unwrap().try_into().unwrap(),
            vout,
        );
        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(&[anchor_ix], Some(account_pubkey), recent_blockhash),
            vec![account_keypair.clone()],
            ctx.config.network,
        ).unwrap();
        let txid = ctx.client.send_transaction(tx).unwrap();
        ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Account anchored: {:?}", account_pubkey);
    }

    /// Execute a transfer with Winternitz signature
    fn execute_transfer(
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

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transfer status: {:?}", processed_tx.status);
        processed_tx.status
    }

    /// Execute a change PQ owner operation
    fn execute_change_pq_owner(
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

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Change PQ owner status: {:?}", processed_tx.status);
        processed_tx.status
    }

    /// Execute a BTC transfer instruction (raw, without anchoring - caller must anchor first)
    fn execute_btc_transfer_raw(
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
    ) -> (Status, Option<arch_program::hash::Hash>) {
        let message = create_btc_transfer_message(pq_key, pq_next, &recipient_script_pubkey, amount);
        let signature_data = sign_message(private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount,
            recipient_script_pubkey,
            fee_tx,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("BTC transfer status: {:?}", processed_tx.status);
        (processed_tx.status, processed_tx.bitcoin_txid)
    }

    /// Create a P2WPKH-style script pubkey
    fn create_p2wpkh_script(hash: &[u8; 20]) -> Vec<u8> {
        let mut script = vec![0x00, 0x14]; // OP_0, PUSH20
        script.extend_from_slice(hash);
        script
    }

    /// Assert that a transaction failed with the expected QuipError
    fn assert_error(status: &Status, expected: QuipError) {
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


    /// Execute a withdraw fees operation
    fn execute_withdraw_fees(
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

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Withdraw fees status: {:?}", processed_tx.status);
        processed_tx.status
    }

    /// Execute an update fees operation
    fn execute_update_fees(
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

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Update fees status: {:?}", processed_tx.status);
        processed_tx.status
    }

    // =============================================================================
    // Factory Initialization Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_initialize_factory() {
        println!("\n=== Test: Initialize Factory ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let creation_fee: u64 = 1000;
        let transfer_fee: u64 = 500;
        let execute_fee: u64 = 750;

        let factory_pubkey = initialize_factory(
            &ctx,
            program_pubkey,
            &payer_keypair,
            payer_pubkey,
            admin_pubkey,
            creation_fee,
            transfer_fee,
            execute_fee,
        );

        verify_factory_state(
            &ctx,
            factory_pubkey,
            admin_pubkey.serialize(),
            creation_fee,
            transfer_fee,
            execute_fee,
            0, // total_wallets
            0, // accumulated_fees
        );

        println!("\n=== Test PASSED: Initialize Factory ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_initialize_factory_already_initialized() {
        println!("\n=== Test: Initialize Factory Already Initialized ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        // First initialization
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );
        println!("First initialization successful");

        // Second initialization (should fail)
        let (factory_txid2, factory_vout2) = ctx.helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo2 = UtxoMeta::from(
            hex::decode(&factory_txid2).unwrap().try_into().unwrap(),
            factory_vout2,
        );

        let instruction_data2 = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee: 2000,
            transfer_fee: 1000,
            execute_fee: 1500,
            factory_utxo: factory_utxo2,
        }).unwrap();

        let recent_blockhash2 = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx2 = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data2,
                }],
                Some(payer_pubkey),
                recent_blockhash2,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid2 = ctx.client.send_transaction(tx2).unwrap();
        let processed_tx2 = ctx.client.wait_for_processed_transaction(&txid2).unwrap();
        println!("Second initialization status: {:?}", processed_tx2.status);

        // Double-init prevention is enforced by system program rejecting create_account
        // when the account already exists
        match &processed_tx2.status {
            Status::Failed(err) => {
                assert!(
                    err.contains("an account with the same address already exists"),
                    "Expected 'account already exists' error, got: {}",
                    err
                );
            }
            other => panic!("Expected Status::Failed, got: {:?}", other),
        }

        println!("\n=== Test PASSED: Initialize Factory Already Initialized ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_initialize_factory_wrong_pda() {
        println!("\n=== Test: Initialize Factory Wrong PDA ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Create a random account instead of the derived factory PDA
        let (_wrong_keypair, wrong_pubkey, _) = generate_new_keypair(ctx.config.network);

        let (factory_txid, factory_vout) = ctx.helper.send_utxo(wrong_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee: 1000,
            transfer_fee: 500,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: wrong_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wrong PDA initialization status: {:?}", processed_tx.status);

        assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

        println!("\n=== Test PASSED: Initialize Factory Wrong PDA ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_initialize_factory_wrong_system_program() {
        println!("\n=== Test: Initialize Factory Wrong System Program ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Create a fake system program account
        let (_fake_system_keypair, fake_system_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Derive correct factory PDA
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = ctx.helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee: 1000,
            transfer_fee: 500,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: fake_system_pubkey, is_signer: false, is_writable: false }, // Fake!
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wrong system program status: {:?}", processed_tx.status);

        match &processed_tx.status {
            Status::Failed(err) => {
                assert!(
                    err.contains("incorrect program id"),
                    "Expected 'incorrect program id' error, got: {}",
                    err
                );
            }
            other => panic!("Expected Status::Failed, got: {:?}", other),
        }

        println!("\n=== Test PASSED: Initialize Factory Wrong System Program ===\n");
    }

    // =============================================================================
    // Wallet Creation Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_with_deposit() {
        println!("\n=== Test: DepositToWinternitz With Deposit ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let creation_fee: u64 = 1000;
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, creation_fee, 500, 750,
        );

        // Capture factory balance before wallet creation
        let factory_balance_before = ctx.client.read_account_info(factory_pubkey).unwrap().lamports;

        // Create wallet (owner is the payer)
        let vault_id = [1u8; 32];
        let initial_deposit: u64 = 5000;
        let (pq_key, _private_key) = generate_wots_keypair(1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, initial_deposit,
        );

        // Verify wallet state
        verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_key, 0);

        // Verify wallet balance received the initial deposit + rent
        let wallet_account = ctx.client.read_account_info(wallet_pubkey).unwrap();
        let wallet_rent = minimum_rent(QuipWallet::SPACE);
        let expected_wallet_balance = initial_deposit + wallet_rent;
        assert_eq!(
            wallet_account.lamports, expected_wallet_balance,
            "Wallet balance {} should equal initial_deposit {} + rent {}",
            wallet_account.lamports, initial_deposit, wallet_rent
        );

        // Verify factory state
        verify_factory_state(
            &ctx, factory_pubkey, admin_pubkey.serialize(),
            creation_fee, 500, 750, 1, creation_fee,
        );

        // Verify factory balance increased by exactly creation_fee
        let factory_balance_after = ctx.client.read_account_info(factory_pubkey).unwrap().lamports;
        let factory_balance_increase = factory_balance_after - factory_balance_before;
        assert_eq!(
            factory_balance_increase, creation_fee,
            "Factory balance increase {} should equal creation_fee {}",
            factory_balance_increase, creation_fee
        );

        println!("\n=== Test PASSED: DepositToWinternitz With Deposit ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_no_deposit() {
        println!("\n=== Test: DepositToWinternitz No Deposit ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Create wallet with no deposit (owner is the payer)
        let vault_id = [2u8; 32];
        let (pq_key, _) = generate_wots_keypair(2);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 0, // No deposit
        );

        // Verify wallet
        verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_key, 0);

        println!("\n=== Test PASSED: DepositToWinternitz No Deposit ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_multiple_wallets_same_owner() {
        println!("\n=== Test: DepositToWinternitz Multiple Wallets Same Owner ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let creation_fee: u64 = 1000;
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, creation_fee, 500, 750,
        );

        // Create first wallet with vault_id_1 (owner is the payer)
        let vault_id_1 = [1u8; 32];
        let (pq_key_1, _) = generate_wots_keypair(100);
        let initial_deposit_1: u64 = 5000;

        let wallet_pubkey_1 = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id_1, &pq_key_1, initial_deposit_1,
        );
        println!("Wallet 1 created with deposit {}", initial_deposit_1);

        // Create second wallet with vault_id_2 for the same owner
        let vault_id_2 = [2u8; 32];
        let (pq_key_2, _) = generate_wots_keypair(200);
        let initial_deposit_2: u64 = 8000;

        let wallet_pubkey_2 = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id_2, &pq_key_2, initial_deposit_2,
        );
        println!("Wallet 2 created with deposit {}", initial_deposit_2);

        // Verify the two wallet PDAs are different
        assert_ne!(
            wallet_pubkey_1, wallet_pubkey_2,
            "Different vault_ids should produce different wallet PDAs"
        );

        // Verify both wallets exist and have correct state
        let owner_bytes = payer_pubkey.serialize();
        verify_wallet_state(&ctx, wallet_pubkey_1, owner_bytes, &pq_key_1, 0);
        verify_wallet_state(&ctx, wallet_pubkey_2, owner_bytes, &pq_key_2, 0);

        let wallet_rent = minimum_rent(QuipWallet::SPACE);
        let wallet_account_1 = ctx.client.read_account_info(wallet_pubkey_1).unwrap();
        let expected_balance_1 = initial_deposit_1 + wallet_rent;
        assert_eq!(
            wallet_account_1.lamports, expected_balance_1,
            "Wallet 1 balance {} should equal deposit {} + rent {}",
            wallet_account_1.lamports, initial_deposit_1, wallet_rent
        );

        let wallet_account_2 = ctx.client.read_account_info(wallet_pubkey_2).unwrap();
        let expected_balance_2 = initial_deposit_2 + wallet_rent;
        assert_eq!(
            wallet_account_2.lamports, expected_balance_2,
            "Wallet 2 balance {} should equal deposit {} + rent {}",
            wallet_account_2.lamports, initial_deposit_2, wallet_rent
        );

        // Verify factory tracked both wallet creations
        verify_factory_state(
            &ctx, factory_pubkey, admin_pubkey.serialize(),
            creation_fee, 500, 750, 2, creation_fee * 2,
        );

        println!("\n=== Test PASSED: DepositToWinternitz Multiple Wallets Same Owner ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_wrong_system_program() {
        println!("\n=== Test: DepositToWinternitz Wrong System Program ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Create a fake system program account
        let (_fake_system_keypair, fake_system_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Derive wallet PDA
        let vault_id = [42u8; 32];
        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let (pq_key, _) = generate_wots_keypair(42);
        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            pq_owner: pq_key,
            deposit: 1000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: fake_system_pubkey, is_signer: false, is_writable: false }, // Fake!
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wrong system program status: {:?}", processed_tx.status);

        match &processed_tx.status {
            Status::Failed(err) => {
                assert!(
                    err.contains("incorrect program id"),
                    "Expected 'incorrect program id' error, got: {}",
                    err
                );
            }
            other => panic!("Expected Status::Failed, got: {:?}", other),
        }

        println!("\n=== Test PASSED: DepositToWinternitz Wrong System Program ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_owner_not_signer() {
        println!("\n=== Test: DepositToWinternitz Owner Not Signer ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Create a separate owner account that we won't sign with
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Derive wallet PDA for the non-signing owner
        let vault_id = [43u8; 32];
        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let (pq_key, _) = generate_wots_keypair(43);
        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            pq_owner: pq_key,
            deposit: 1000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: true }, // Not a signer!
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Owner not signer status: {:?}", processed_tx.status);

        assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

        println!("\n=== Test PASSED: DepositToWinternitz Owner Not Signer ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_uninitialized_factory() {
        println!("\n=== Test: DepositToWinternitz Uninitialized Factory ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);

        // Derive factory PDA but don't initialize it
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        // Derive wallet PDA
        let vault_id = [44u8; 32];
        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let (pq_key, _) = generate_wots_keypair(44);
        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            pq_owner: pq_key,
            deposit: 1000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Uninitialized factory status: {:?}", processed_tx.status);

        // Factory not owned by program yet (uninitialized)
        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: DepositToWinternitz Uninitialized Factory ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_wrong_factory_pda() {
        println!("\n=== Test: DepositToWinternitz Wrong Factory PDA ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Initialize the real factory
        let _factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Create a wrong/random account to use as factory
        let (_wrong_keypair, wrong_factory_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Derive wallet PDA
        let vault_id = [45u8; 32];
        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let (pq_key, _) = generate_wots_keypair(45);
        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            pq_owner: pq_key,
            deposit: 1000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: wrong_factory_pubkey, is_signer: false, is_writable: true }, // Wrong!
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wrong factory PDA status: {:?}", processed_tx.status);

        // Wrong factory is not owned by program
        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: DepositToWinternitz Wrong Factory PDA ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_wrong_wallet_pda() {
        println!("\n=== Test: DepositToWinternitz Wrong Wallet PDA ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Derive wallet with WRONG vault_id, but pass different vault_id in instruction
        let correct_vault_id = [46u8; 32];
        let wrong_vault_id = [99u8; 32];
        let owner_bytes = payer_pubkey.serialize();

        // Derive wallet using wrong_vault_id
        let (wrong_wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &wrong_vault_id);
        let wrong_wallet_pubkey = Pubkey::from_slice(&wrong_wallet_bytes);

        let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wrong_wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let (pq_key, _) = generate_wots_keypair(46);
        // Pass correct_vault_id in instruction but wrong_wallet_pubkey in accounts
        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id: correct_vault_id, // Mismatch!
            pq_owner: pq_key,
            deposit: 1000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wrong_wallet_pubkey, is_signer: false, is_writable: true }, // Wrong!
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wrong wallet PDA status: {:?}", processed_tx.status);

        assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

        println!("\n=== Test PASSED: DepositToWinternitz Wrong Wallet PDA ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_already_exists() {
        println!("\n=== Test: DepositToWinternitz Already Exists ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Create wallet first time
        let vault_id = [47u8; 32];
        let (pq_key, _) = generate_wots_keypair(47);
        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 1000,
        );
        println!("Wallet created successfully: {:?}", wallet_pubkey);

        // Try to create the same wallet again (same vault_id, same owner)
        let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        // Use a different pq_key to show that even with different params, same PDA fails
        let (pq_key_2, _) = generate_wots_keypair(470);
        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            pq_owner: pq_key_2,
            deposit: 2000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Double creation status: {:?}", processed_tx.status);

        match &processed_tx.status {
            Status::Failed(err) => {
                assert!(
                    err.contains("already exists"),
                    "Expected 'already exists' error, got: {}",
                    err
                );
            }
            other => panic!("Expected Status::Failed, got: {:?}", other),
        }

        println!("\n=== Test PASSED: DepositToWinternitz Already Exists ===\n");
    }

    // =============================================================================
    // Transfer Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_success() {
        println!("\n=== Test: Transfer Success ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, _payer_keypair, _payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).unwrap();

        let transfer_fee: u64 = 500;
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &owner_keypair, owner_pubkey, admin_pubkey, 1000, transfer_fee, 750,
        );

        // Create wallet
        let vault_id = [10u8; 32];
        let initial_deposit: u64 = 10000;
        let (pq_key, private_key) = generate_wots_keypair(1);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &owner_keypair, owner_pubkey,
            vault_id, &pq_key, initial_deposit,
        );
        println!("Wallet created with {} deposit", initial_deposit);

        // Capture balances before transfer
        let balances_before = capture_balances(&ctx, &[wallet_pubkey, factory_pubkey, recipient_pubkey]);
        let wallet_balance_before = balances_before[0];
        let factory_balance_before = balances_before[1];
        let recipient_balance_before = balances_before[2];

        // Execute transfer
        let transfer_amount: u64 = 2000;
        let status = execute_transfer(
            &ctx, program_pubkey, factory_pubkey, wallet_pubkey, recipient_pubkey,
            &owner_keypair, owner_pubkey, vault_id, &pq_key, &pq_next, &private_key, transfer_amount,
        );
        assert!(status == Status::Processed);

        // Verify wallet state
        verify_wallet_state(&ctx, wallet_pubkey, owner_pubkey.serialize(), &pq_next, 1);

        // Verify balance changes
        let balances_after = capture_balances(&ctx, &[wallet_pubkey, factory_pubkey, recipient_pubkey]);
        let wallet_balance_after = balances_after[0];
        let factory_balance_after = balances_after[1];
        let recipient_balance_after = balances_after[2];

        // Wallet should have decreased by transfer_amount + transfer_fee
        let expected_wallet_decrease = transfer_amount + transfer_fee;
        let actual_wallet_decrease = wallet_balance_before - wallet_balance_after;
        assert_eq!(
            actual_wallet_decrease, expected_wallet_decrease,
            "Wallet balance decrease {} should equal transfer_amount {} + transfer_fee {}",
            actual_wallet_decrease, transfer_amount, transfer_fee
        );

        // Factory should have increased by transfer_fee
        let factory_balance_increase = factory_balance_after - factory_balance_before;
        assert_eq!(
            factory_balance_increase, transfer_fee,
            "Factory balance increase {} should equal transfer_fee {}",
            factory_balance_increase, transfer_fee
        );

        // Recipient should have increased by transfer_amount
        let recipient_balance_increase = recipient_balance_after - recipient_balance_before;
        assert_eq!(
            recipient_balance_increase, transfer_amount,
            "Recipient balance increase {} should equal transfer_amount {}",
            recipient_balance_increase, transfer_amount
        );

        println!("\n=== Test PASSED: Transfer Success ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_invalid_signature() {
        println!("\n=== Test: Transfer Invalid Signature ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, _payer_keypair, _payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &owner_keypair, owner_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Create wallet
        let vault_id = [12u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(5);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &owner_keypair, owner_pubkey,
            vault_id, &pq_key, 10000,
        );

        // Create INVALID signature (random data)
        let invalid_signature = vec![0xFFu8; 2112]; // WOTS+ signature size but random data

        // Attempt transfer with invalid signature
        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: 1000,
            signature: WinternitzSignature { signature_data: invalid_signature },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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
            vec![owner_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transfer status: {:?}", processed_tx.status);

        assert_error(&processed_tx.status, QuipError::InvalidWotsSignature);

        println!("\n=== Test PASSED: Transfer Invalid Signature ===\n");
    }

    // =============================================================================
    // Key Rotation Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_change_pq_owner_success() {
        println!("\n=== Test: Change PQ Owner Success ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, _payer_keypair, _payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &owner_keypair, owner_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Create wallet
        let vault_id = [20u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(10);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &owner_keypair, owner_pubkey,
            vault_id, &pq_key, 5000,
        );

        // Execute key change
        let status = execute_change_pq_owner(
            &ctx, program_pubkey, wallet_pubkey,
            &owner_keypair, owner_pubkey, vault_id, &pq_key, &pq_next, &private_key,
        );
        assert_eq!(status, Status::Processed);

        // Verify wallet state
        verify_wallet_state(&ctx, wallet_pubkey, owner_pubkey.serialize(), &pq_next, 0);

        println!("\n=== Test PASSED: Change PQ Owner Success ===\n");
    }

    // =============================================================================
    // Admin Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_update_fees() {
        println!("\n=== Test: Update Fees ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Update fees
        let new_creation_fee: u64 = 2000;
        let new_transfer_fee: u64 = 1000;
        let new_execute_fee: u64 = 1500;

        let status = execute_update_fees(
            &ctx, program_pubkey, factory_pubkey,
            &admin_keypair, admin_pubkey,
            new_creation_fee, new_transfer_fee, new_execute_fee,
        );
        assert!(status == Status::Processed);

        // Verify factory state
        verify_factory_state(
            &ctx, factory_pubkey, admin_pubkey.serialize(),
            new_creation_fee, new_transfer_fee, new_execute_fee, 0, 0,
        );

        println!("\n=== Test PASSED: Update Fees ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_update_fees_unauthorized() {
        println!("\n=== Test: Update Fees Unauthorized ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (non_admin_keypair, non_admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&non_admin_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Attempt unauthorized fee update
        let status = execute_update_fees(
            &ctx, program_pubkey, factory_pubkey,
            &non_admin_keypair, non_admin_pubkey,
            9999, 9999, 9999,
        );

        assert_error(&status, QuipError::UnauthorizedSigner);

        println!("\n=== Test PASSED: Update Fees Unauthorized ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_ownership() {
        println!("\n=== Test: Transfer Ownership ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (new_admin_keypair, new_admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();
        ctx.client.create_and_fund_account_with_faucet(&new_admin_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
        );

        // Transfer ownership
        let instruction_data = borsh::to_vec(&QuipInstruction::TransferOwnership {
            new_admin: new_admin_pubkey.serialize(),
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify new admin
        verify_factory_state(
            &ctx, factory_pubkey, new_admin_pubkey.serialize(), 1000, 500, 750, 0, 0,
        );

        // Verify new admin can update fees
        let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
            creation_fee: 5000,
            transfer_fee: 2500,
            execute_fee: 3000,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: new_admin_pubkey, is_signer: true, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(new_admin_pubkey),
                recent_blockhash,
            ),
            vec![new_admin_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("New admin fee update status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify old admin cannot update fees
        let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
            creation_fee: 9999,
            transfer_fee: 9999,
            execute_fee: 9999,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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
            vec![admin_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("Old admin fee update status: {:?}", processed_tx.status);

        assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

        println!("\n=== Test PASSED: Transfer Ownership ===\n");
    }

    // =============================================================================
    // System Program Verification Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_fake_system_program_rejected() {
        println!("\n=== Test: Fake System Program Rejected ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (_fake_system_keypair, fake_system_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Derive factory PDA and create UTXO
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = ctx.helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        // Attempt init with fake system program (should fail)
        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee: 1000,
            transfer_fee: 500,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: fake_system_pubkey, is_signer: false, is_writable: false }, // Fake!
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: Fake System Program Rejected ===\n");
    }

    // =============================================================================
    // Transfer Negative Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_with_winternitz_insufficient_balance() {
        println!("\n=== Test: TransferWithWinternitz Insufficient Balance ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Create wallet with very small deposit
        let vault_id = [7u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(7);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);
        let initial_deposit: u64 = 100; // Very small deposit

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, initial_deposit,
        );

        // Attempt transfer larger than balance (should fail)
        let transfer_amount: u64 = 100000; // Much larger than deposit
        let status = execute_transfer(
            &ctx, program_pubkey, factory_pubkey, wallet_pubkey, recipient_pubkey,
            &payer_keypair, payer_pubkey, vault_id, &pq_key, &pq_next, &private_key, transfer_amount,
        );

        assert_error(&status, QuipError::InsufficientWalletBalance);

        println!("\n=== Test PASSED: TransferWithWinternitz Insufficient Balance ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_with_winternitz_wrong_wallet_pda() {
        println!("\n=== Test: TransferWithWinternitz Wrong Wallet PDA ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Create wallet owned by payer
        let vault_id = [8u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(8);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 10000,
        );

        // Attacker attempts to transfer (with valid signature but wrong signer)
        // This fails at verify_wallet_address because the wallet PDA was derived
        // from the original owner, not the attacker
        let transfer_amount: u64 = 1000;
        let recipient_bytes = recipient_pubkey.serialize();
        let message = create_transfer_message(&pq_key, &pq_next, &recipient_bytes, transfer_amount);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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
                            AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: true }, // Attacker as owner
                        ],
                        data: instruction_data,
                    },
                ],
                Some(attacker_pubkey),
                recent_blockhash,
            ),
            vec![attacker_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // After refactor: fails at verify_wallet_address because wallet PDA
        // was derived from original owner, not attacker
        assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

        println!("\n=== Test PASSED: TransferWithWinternitz Wrong Wallet PDA ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_with_winternitz_owner_not_signer() {
        println!("\n=== Test: TransferWithWinternitz Owner Not Signer ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (other_keypair, other_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&other_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        let vault_id = [80u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(80);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 10000,
        );

        // Create valid signature
        let transfer_amount: u64 = 1000;
        let recipient_bytes = recipient_pubkey.serialize();
        let message = create_transfer_message(&pq_key, &pq_next, &recipient_bytes, transfer_amount);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        // Pass owner account without is_signer flag (other_keypair signs the tx, but owner is passed as non-signer)
        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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
                            AccountMeta { pubkey: payer_pubkey, is_signer: false, is_writable: true }, // Owner NOT a signer
                        ],
                        data: instruction_data,
                    },
                ],
                Some(other_pubkey),
                recent_blockhash,
            ),
            vec![other_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

        println!("\n=== Test PASSED: TransferWithWinternitz Owner Not Signer ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_with_winternitz_uninitialized_factory() {
        println!("\n=== Test: TransferWithWinternitz Uninitialized Factory ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Derive factory address but don't initialize it
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        // Derive a would-be wallet address
        let vault_id = [81u8; 32];
        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (pq_key, private_key) = generate_wots_keypair(81);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        // Create valid signature
        let transfer_amount: u64 = 1000;
        let recipient_bytes = recipient_pubkey.serialize();
        let message = create_transfer_message(&pq_key, &pq_next, &recipient_bytes, transfer_amount);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Factory not initialized = not owned by program
        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: TransferWithWinternitz Uninitialized Factory ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_with_winternitz_uninitialized_wallet() {
        println!("\n=== Test: TransferWithWinternitz Uninitialized Wallet ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Derive wallet address but don't create it
        let vault_id = [82u8; 32];
        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (pq_key, private_key) = generate_wots_keypair(82);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        // Create valid signature
        let transfer_amount: u64 = 1000;
        let recipient_bytes = recipient_pubkey.serialize();
        let message = create_transfer_message(&pq_key, &pq_next, &recipient_bytes, transfer_amount);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Wallet not created = not owned by program
        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: TransferWithWinternitz Uninitialized Wallet ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_with_winternitz_wrong_factory_pda() {
        println!("\n=== Test: TransferWithWinternitz Wrong Factory PDA ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (random_keypair, random_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&random_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        let vault_id = [83u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(83);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 10000,
        );

        // Create valid signature
        let transfer_amount: u64 = 1000;
        let recipient_bytes = recipient_pubkey.serialize();
        let message = create_transfer_message(&pq_key, &pq_next, &recipient_bytes, transfer_amount);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        // Pass random account instead of factory
        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: random_pubkey, is_signer: false, is_writable: true }, // Wrong factory
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Random account is not owned by program
        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: TransferWithWinternitz Wrong Factory PDA ===\n");
    }

    // =============================================================================
    // ChangePqOwner Negative Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_change_pq_owner_invalid_signature() {
        println!("\n=== Test: ChangePqOwner Invalid Signature ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        let vault_id = [9u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(9);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 5000,
        );

        // Attempt key change with invalid signature (should fail)
        let invalid_signature = vec![0xFFu8; 2144];

        let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
            vault_id,
            pq_next: pq_next.clone(),
            signature: WinternitzSignature { signature_data: invalid_signature },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        assert_error(&processed_tx.status, QuipError::InvalidWotsSignature);

        println!("\n=== Test PASSED: ChangePqOwner Invalid Signature ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_change_pq_owner_unauthorized() {
        println!("\n=== Test: ChangePqOwner Unauthorized ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        let vault_id = [10u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(10);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 5000,
        );

        // Attacker attempts key change (even with valid signature - should fail)
        let message = create_change_owner_message(&pq_key, &pq_next);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
            vault_id,
            pq_next: pq_next.clone(),
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: true }, // Attacker as signer
                        ],
                        data: instruction_data,
                    },
                ],
                Some(attacker_pubkey),
                recent_blockhash,
            ),
            vec![attacker_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Fails because attacker's pubkey doesn't derive the wallet PDA
        assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

        println!("\n=== Test PASSED: ChangePqOwner Unauthorized ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_change_pq_owner_uninitialized_wallet() {
        println!("\n=== Test: ChangePqOwner Uninitialized Wallet ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);

        // Derive a wallet address but don't create it
        let vault_id = [11u8; 32];
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &payer_pubkey.serialize(), &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (pq_key, private_key) = generate_wots_keypair(11);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let message = create_change_owner_message(&pq_key, &pq_next);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
            vault_id,
            pq_next: pq_next.clone(),
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Wallet not created = not owned by program
        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: ChangePqOwner Uninitialized Wallet ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_change_pq_owner_wrong_wallet_pda() {
        println!("\n=== Test: ChangePqOwner Wrong Wallet PDA ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Create wallet with one vault_id
        let vault_id = [12u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(12);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 5000,
        );

        // Try to change PQ owner with WRONG vault_id
        let wrong_vault_id = [99u8; 32];
        let message = create_change_owner_message(&pq_key, &pq_next);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
            vault_id: wrong_vault_id,
            pq_next: pq_next.clone(),
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Wrong vault_id means PDA derivation fails
        assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

        println!("\n=== Test PASSED: ChangePqOwner Wrong Wallet PDA ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_change_pq_owner_owner_not_signer() {
        println!("\n=== Test: ChangePqOwner Owner Not Signer ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (other_keypair, other_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&other_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        let vault_id = [13u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(13);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 5000,
        );

        let message = create_change_owner_message(&pq_key, &pq_next);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
            vault_id,
            pq_next: pq_next.clone(),
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        // Pass owner account but WITHOUT is_signer: true
        // Use other_keypair to sign the transaction (as fee payer), but pass payer_pubkey as non-signer
        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: payer_pubkey, is_signer: false, is_writable: true }, // Owner NOT a signer
                        ],
                        data: instruction_data,
                    },
                ],
                Some(other_pubkey),
                recent_blockhash,
            ),
            vec![other_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

        println!("\n=== Test PASSED: ChangePqOwner Owner Not Signer ===\n");
    }

    // =============================================================================
    // WithdrawFees Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_withdraw_fees_success() {
        println!("\n=== Test: WithdrawFees Success ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();
        ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).unwrap();

        let creation_fee: u64 = 1000;
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            creation_fee, 500, 750,
        );

        // Create a wallet to accumulate fees
        let vault_id = [11u8; 32];
        let (pq_key, _) = generate_wots_keypair(11);

        let _wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 5000,
        );

        // Capture recipient balance before withdrawal
        let recipient_balance_before = ctx.client.read_account_info(recipient_pubkey).unwrap().lamports;

        // Withdraw fees
        let withdraw_amount: u64 = 500;
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, factory_pubkey,
            &admin_keypair, admin_pubkey, recipient_pubkey, withdraw_amount,
        );

        assert!(status == Status::Processed, "WithdrawFees should succeed");

        // Verify factory state after withdrawal
        let factory_account = ctx.client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(factory.accumulated_fees, creation_fee - withdraw_amount);

        // Verify recipient received funds
        let recipient_balance_after = ctx.client.read_account_info(recipient_pubkey).unwrap().lamports;
        let recipient_balance_increase = recipient_balance_after - recipient_balance_before;
        assert_eq!(
            recipient_balance_increase, withdraw_amount,
            "Recipient balance increase {} should equal withdraw_amount {}",
            recipient_balance_increase, withdraw_amount
        );

        println!("\n=== Test PASSED: WithdrawFees Success ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_withdraw_fees_unauthorized() {
        println!("\n=== Test: WithdrawFees Unauthorized ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Create a wallet to accumulate fees
        let vault_id = [12u8; 32];
        let (pq_key, _) = generate_wots_keypair(12);

        let _wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 5000,
        );

        // Attacker attempts to withdraw fees (should fail)
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, factory_pubkey,
            &attacker_keypair, attacker_pubkey, attacker_pubkey, 500,
        );

        assert_error(&status, QuipError::UnauthorizedSigner);

        println!("\n=== Test PASSED: WithdrawFees Unauthorized ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_withdraw_fees_insufficient() {
        println!("\n=== Test: WithdrawFees Insufficient ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();

        let creation_fee: u64 = 100; // Small fee
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            creation_fee, 50, 75,
        );

        // Create a wallet to accumulate some fees
        let vault_id = [13u8; 32];
        let (pq_key, _) = generate_wots_keypair(13);

        let _wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 1000,
        );

        // Attempt to withdraw more than accumulated (should fail)
        let withdraw_amount: u64 = 10000; // Much more than accumulated
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, factory_pubkey,
            &admin_keypair, admin_pubkey, recipient_pubkey, withdraw_amount,
        );

        assert_error(&status, QuipError::InsufficientFunds);

        println!("\n=== Test PASSED: WithdrawFees Insufficient ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_withdraw_fees_wrong_factory() {
        println!("\n=== Test: WithdrawFees Wrong Factory ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();

        let creation_fee: u64 = 1000;
        let _factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            creation_fee, 500, 750,
        );

        // Create a wrong/random account to use as factory
        let (_wrong_keypair, wrong_factory_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Attempt to withdraw with wrong factory (should fail)
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, wrong_factory_pubkey,
            &admin_keypair, admin_pubkey, recipient_pubkey, 500,
        );

        assert_error(&status, QuipError::InvalidAccountDerivation);

        println!("\n=== Test PASSED: WithdrawFees Wrong Factory ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_withdraw_fees_zero_amount() {
        println!("\n=== Test: WithdrawFees Zero Amount ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();
        ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).unwrap();

        let creation_fee: u64 = 1000;
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            creation_fee, 500, 750,
        );

        // Create a wallet to accumulate fees
        let vault_id = [14u8; 32];
        let (pq_key, _) = generate_wots_keypair(14);

        let _wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 5000,
        );

        // Capture recipient balance before withdrawal
        let recipient_balance_before = ctx.client.read_account_info(recipient_pubkey).unwrap().lamports;

        // Withdraw zero fees (should succeed as no-op)
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, factory_pubkey,
            &admin_keypair, admin_pubkey, recipient_pubkey, 0,
        );

        assert!(status == Status::Processed, "WithdrawFees with zero amount should succeed");

        // Verify factory state unchanged
        let factory_account = ctx.client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(factory.accumulated_fees, creation_fee);

        // Verify recipient balance unchanged
        let recipient_balance_after = ctx.client.read_account_info(recipient_pubkey).unwrap().lamports;
        assert_eq!(recipient_balance_before, recipient_balance_after);

        println!("\n=== Test PASSED: WithdrawFees Zero Amount ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_withdraw_fees_exact_accumulated() {
        println!("\n=== Test: WithdrawFees Exact Accumulated ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();
        ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).unwrap();

        let creation_fee: u64 = 1000;
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            creation_fee, 500, 750,
        );

        // Create a wallet to accumulate fees
        let vault_id = [15u8; 32];
        let (pq_key, _) = generate_wots_keypair(15);

        let _wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 5000,
        );

        // Capture recipient balance before withdrawal
        let recipient_balance_before = ctx.client.read_account_info(recipient_pubkey).unwrap().lamports;

        // Withdraw exactly accumulated fees (should drain to 0)
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, factory_pubkey,
            &admin_keypair, admin_pubkey, recipient_pubkey, creation_fee,
        );

        assert!(status == Status::Processed, "WithdrawFees exact accumulated should succeed");

        // Verify factory accumulated_fees is now 0
        let factory_account = ctx.client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(factory.accumulated_fees, 0);

        // Verify recipient received funds
        let recipient_balance_after = ctx.client.read_account_info(recipient_pubkey).unwrap().lamports;
        let recipient_balance_increase = recipient_balance_after - recipient_balance_before;
        assert_eq!(recipient_balance_increase, creation_fee);

        println!("\n=== Test PASSED: WithdrawFees Exact Accumulated ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_withdraw_fees_multiple_sequential() {
        println!("\n=== Test: WithdrawFees Multiple Sequential ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();
        ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).unwrap();

        let creation_fee: u64 = 1000;
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            creation_fee, 500, 750,
        );

        // Create a wallet to accumulate fees
        let vault_id = [16u8; 32];
        let (pq_key, _) = generate_wots_keypair(16);

        let _wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 5000,
        );

        // Capture recipient balance before withdrawals
        let recipient_balance_before = ctx.client.read_account_info(recipient_pubkey).unwrap().lamports;

        // First withdrawal: 300
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, factory_pubkey,
            &admin_keypair, admin_pubkey, recipient_pubkey, 300,
        );
        assert!(status == Status::Processed, "First withdrawal should succeed");

        // Verify factory state after first withdrawal
        let factory_account = ctx.client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(factory.accumulated_fees, creation_fee - 300);

        // Second withdrawal: 400
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, factory_pubkey,
            &admin_keypair, admin_pubkey, recipient_pubkey, 400,
        );
        assert!(status == Status::Processed, "Second withdrawal should succeed");

        // Verify factory state after second withdrawal
        let factory_account = ctx.client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(factory.accumulated_fees, creation_fee - 300 - 400);

        // Third withdrawal: 300 (remaining)
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, factory_pubkey,
            &admin_keypair, admin_pubkey, recipient_pubkey, 300,
        );
        assert!(status == Status::Processed, "Third withdrawal should succeed");

        // Verify factory state after third withdrawal (should be 0)
        let factory_account = ctx.client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(factory.accumulated_fees, 0);

        // Verify recipient received total funds
        let recipient_balance_after = ctx.client.read_account_info(recipient_pubkey).unwrap().lamports;
        let recipient_balance_increase = recipient_balance_after - recipient_balance_before;
        assert_eq!(recipient_balance_increase, creation_fee);

        // Fourth withdrawal should fail (no more fees)
        let status = execute_withdraw_fees(
            &ctx, program_pubkey, factory_pubkey,
            &admin_keypair, admin_pubkey, recipient_pubkey, 1,
        );
        assert_error(&status, QuipError::InsufficientFunds);

        println!("\n=== Test PASSED: WithdrawFees Multiple Sequential ===\n");
    }

    // =============================================================================
    // BTC Transfer Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_partial_spend() {
        println!("\n=== Test: BTC Transfer Partial Spend ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let creation_fee: u64 = 1000;
        let transfer_fee: u64 = 500;
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            creation_fee, transfer_fee, 750,
        );

        let vault_id = [20u8; 32];
        let initial_deposit: u64 = 10000;
        let (pq_key, private_key) = generate_wots_keypair(30);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, initial_deposit,
        );

        // Anchor owner and capture balances before BTC transfer
        anchor_account(&ctx, &payer_keypair, payer_pubkey);
        let fee_tx = prepare_fees_and_wait(&ctx.helper);

        let wallet_balance_before = ctx.client.read_account_info(wallet_pubkey).unwrap().lamports;
        let factory_balance_before = ctx.client.read_account_info(factory_pubkey).unwrap().lamports;
        let owner_balance_before = ctx.client.read_account_info(payer_pubkey).unwrap().lamports;

        // Execute BTC transfer (partial spend: 1500 of 3000 sats)
        let transfer_amount: u64 = 1500;
        let recipient_script_pubkey = create_p2wpkh_script(&[0xABu8; 20]);

        let (status, bitcoin_txid) = execute_btc_transfer_raw(
            &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
            &payer_keypair, payer_pubkey,
            vault_id, &pq_key, &pq_next, &private_key,
            transfer_amount, recipient_script_pubkey, fee_tx,
        );

        assert!(status == Status::Processed, "BTC transfer tx should succeed");

        // Verify lamport fee was collected from wallet to factory
        let wallet_balance_after = ctx.client.read_account_info(wallet_pubkey).unwrap().lamports;
        let factory_balance_after = ctx.client.read_account_info(factory_pubkey).unwrap().lamports;
        let owner_balance_after = ctx.client.read_account_info(payer_pubkey).unwrap().lamports;

        let wallet_balance_decrease = wallet_balance_before - wallet_balance_after;
        let factory_balance_increase = factory_balance_after - factory_balance_before;
        let owner_balance_decrease = owner_balance_before - owner_balance_after;

        assert_eq!(wallet_balance_decrease, transfer_fee, "Wallet should have been debited exactly transfer_fee");
        assert_eq!(factory_balance_increase, transfer_fee, "Factory should have received exactly transfer_fee");
        assert!(owner_balance_decrease > 0, "Owner should have paid Arch tx fees");

        // Verify factory accumulated_fees
        let factory_account = ctx.client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(factory.accumulated_fees, creation_fee + transfer_fee);

        // Check Bitcoin transaction acceptance
        if let Some(ref btc_txid_hash) = bitcoin_txid {
            let raw_txid: arch_program::bitcoin::Txid = btc_txid_hash.into();
            let mut bytes = raw_txid.to_byte_array();
            bytes.reverse();
            let btc_txid = arch_program::bitcoin::Txid::from_byte_array(bytes);
            match ctx.helper.wait_until_titan_indexes_transaction(&btc_txid) {
                Ok(()) => println!("RESULT: Bitcoin transaction ACCEPTED"),
                Err(e) => println!("RESULT: Bitcoin transaction NOT accepted: {}", e),
            }
        }

        println!("\n=== Test Complete: BTC Transfer Partial Spend ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_full_spend() {
        println!("\n=== Test: BTC Transfer Full Spend ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let transfer_fee: u64 = 500;
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, transfer_fee, 750,
        );

        let vault_id = [21u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(40);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 10000,
        );

        // Anchor owner and capture balances
        anchor_account(&ctx, &payer_keypair, payer_pubkey);
        let fee_tx = prepare_fees_and_wait(&ctx.helper);

        let wallet_balance_before = ctx.client.read_account_info(wallet_pubkey).unwrap().lamports;
        let factory_balance_before = ctx.client.read_account_info(factory_pubkey).unwrap().lamports;
        let owner_balance_before = ctx.client.read_account_info(payer_pubkey).unwrap().lamports;

        // Full spend: 3000 - 330 (dust limit) = 2670 sats
        let transfer_amount: u64 = 2670;
        let recipient_script_pubkey = create_p2wpkh_script(&[0xCDu8; 20]);

        let (status, bitcoin_txid) = execute_btc_transfer_raw(
            &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
            &payer_keypair, payer_pubkey,
            vault_id, &pq_key, &pq_next, &private_key,
            transfer_amount, recipient_script_pubkey, fee_tx,
        );

        assert!(status == Status::Processed, "BTC max-spend tx should succeed");

        // Verify lamport fee was collected
        let wallet_balance_after = ctx.client.read_account_info(wallet_pubkey).unwrap().lamports;
        let factory_balance_after = ctx.client.read_account_info(factory_pubkey).unwrap().lamports;
        let owner_balance_after = ctx.client.read_account_info(payer_pubkey).unwrap().lamports;

        assert_eq!(wallet_balance_before - wallet_balance_after, transfer_fee);
        assert_eq!(factory_balance_after - factory_balance_before, transfer_fee);
        assert!(owner_balance_before - owner_balance_after > 0, "Owner should have paid Arch tx fees");

        // Check Bitcoin transaction acceptance
        if let Some(ref btc_txid_hash) = bitcoin_txid {
            let raw_txid: arch_program::bitcoin::Txid = btc_txid_hash.into();
            let mut bytes = raw_txid.to_byte_array();
            bytes.reverse();
            let btc_txid = arch_program::bitcoin::Txid::from_byte_array(bytes);
            match ctx.helper.wait_until_titan_indexes_transaction(&btc_txid) {
                Ok(()) => println!("RESULT: Bitcoin transaction ACCEPTED"),
                Err(e) => println!("RESULT: Bitcoin transaction NOT accepted: {}", e),
            }
        }

        println!("\n=== Test Complete: BTC Transfer Full Spend ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_invalid_signature() {
        println!("\n=== Test: BTC Transfer Invalid Signature ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        let vault_id = [22u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(50);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 10000,
        );

        // Anchor owner and prepare fee tx
        anchor_account(&ctx, &payer_keypair, payer_pubkey);
        let fee_tx = prepare_fees_and_wait(&ctx.helper);

        // Attempt BTC transfer with invalid signature (should fail)
        let recipient_script_pubkey = create_p2wpkh_script(&[0xAAu8; 20]);
        let invalid_signature = vec![0xFFu8; 2112];

        let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: 1500,
            recipient_script_pubkey,
            fee_tx,
            signature: WinternitzSignature { signature_data: invalid_signature },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        assert_error(&processed_tx.status, QuipError::InvalidWotsSignature);

        println!("\n=== Test PASSED: BTC Transfer Invalid Signature ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_insufficient_btc_balance() {
        println!("\n=== Test: BTC Transfer Insufficient BTC Balance ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        let vault_id = [23u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(60);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 10000,
        );

        // Anchor owner and prepare fee tx
        anchor_account(&ctx, &payer_keypair, payer_pubkey);
        let fee_tx = prepare_fees_and_wait(&ctx.helper);

        // Attempt BTC transfer with amount > UTXO value (3000 sats)
        let transfer_amount: u64 = 5000; // exceeds 3000-sat UTXO
        let recipient_script_pubkey = create_p2wpkh_script(&[0xBBu8; 20]);

        let (status, _) = execute_btc_transfer_raw(
            &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
            &payer_keypair, payer_pubkey,
            vault_id, &pq_key, &pq_next, &private_key,
            transfer_amount, recipient_script_pubkey, fee_tx,
        );

        assert_error(&status, QuipError::InsufficientBtcBalance);

        println!("\n=== Test PASSED: BTC Transfer Insufficient BTC Balance ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_unauthorized() {
        println!("\n=== Test: BTC Transfer Unauthorized ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
        let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);

        ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).unwrap();

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Create wallet owned by payer
        let vault_id = [24u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(70);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 10000,
        );

        // Anchor attacker (they will try to be the signer)
        anchor_account(&ctx, &attacker_keypair, attacker_pubkey);
        let fee_tx = prepare_fees_and_wait(&ctx.helper);

        // Attacker attempts BTC transfer using their own key as owner (should fail)
        let transfer_amount: u64 = 1500;
        let recipient_script_pubkey = create_p2wpkh_script(&[0xEEu8; 20]);

        let message = create_btc_transfer_message(&pq_key, &pq_next, &recipient_script_pubkey, transfer_amount);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            recipient_script_pubkey,
            fee_tx,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: true },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(attacker_pubkey),
                recent_blockhash,
            ),
            vec![attacker_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

        println!("\n=== Test PASSED: BTC Transfer Unauthorized ===\n");
    }

    // =============================================================================
    // ExecuteWithWinternitz Tests
    // =============================================================================

    /// Helper function to execute an ExecuteWithWinternitz instruction
    fn execute_with_winternitz(
        ctx: &TestContext,
        program_pubkey: Pubkey,
        factory_pubkey: Pubkey,
        wallet_pubkey: Pubkey,
        target_program_pubkey: Pubkey,
        signer_keypair: &UntweakedKeypair,
        signer_pubkey: Pubkey,
        vault_id: [u8; 32],
        pq_key: &WinternitzPublicKey,
        pq_next: &WinternitzPublicKey,
        private_key: &[u8; 32],
        instruction_data: Vec<u8>,
        account_metas: Vec<CpiAccountMeta>,
        remaining_accounts: Vec<AccountMeta>,
    ) -> Status {
        // Build account pubkeys for the message
        let account_pubkeys: Vec<[u8; 32]> = remaining_accounts
            .iter()
            .map(|a| a.pubkey.serialize())
            .collect();

        let target_bytes = target_program_pubkey.serialize();
        let message = create_execute_message(
            pq_key,
            pq_next,
            &target_bytes,
            &instruction_data,
            &account_pubkeys,
            &account_metas,
        );
        let signature_data = sign_message(private_key, &message);

        let cpi_instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
            pq_next: pq_next.clone(),
            vault_id,
            instruction_data,
            account_metas,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        // Build accounts: factory, wallet, target_program, owner, system_program, then remaining accounts
        let mut accounts = vec![
            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
            AccountMeta { pubkey: target_program_pubkey, is_signer: false, is_writable: false },
            AccountMeta { pubkey: signer_pubkey, is_signer: true, is_writable: true },
            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
        ];
        accounts.extend(remaining_accounts);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts,
                        data: cpi_instruction_data,
                    },
                ],
                Some(signer_pubkey),
                recent_blockhash,
            ),
            vec![signer_keypair.clone()],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        println!("ExecuteWithWinternitz status: {:?}", processed_tx.status);
        processed_tx.status
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_execute_with_winternitz_success() {
        println!("\n=== Test: ExecuteWithWinternitz Success ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let creation_fee: u64 = 1000;
        let transfer_fee: u64 = 500;
        let execute_fee: u64 = 750;

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            creation_fee, transfer_fee, execute_fee,
        );

        // Create wallet with deposit to cover execute fee
        let vault_id = [42u8; 32];
        let initial_deposit: u64 = 10_000;
        let (pq_key, private_key) = generate_wots_keypair(100);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, initial_deposit,
        );

        // Create a recipient account that will receive lamports via the CPI
        let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);
        ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).unwrap();

        // Capture balances before execute
        let balances_before = capture_balances(&ctx, &[factory_pubkey, wallet_pubkey, recipient_pubkey]);

        // Execute a CPI: system transfer from owner (payer) to recipient
        // The owner is a signer in the transaction, so it can authorize this transfer
        let cpi_transfer_amount: u64 = 1000;
        let transfer_ix = system_instruction::transfer(&payer_pubkey, &recipient_pubkey, cpi_transfer_amount);

        // Build CpiAccountMeta for the signature message
        let cpi_account_metas = vec![
            CpiAccountMeta { is_signer: true, is_writable: true },   // owner (source)
            CpiAccountMeta { is_signer: false, is_writable: true },  // recipient (dest)
        ];

        // Build remaining accounts for the CPI (these will be passed to invoke_signed)
        let remaining_accounts = vec![
            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
            AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
        ];

        let status = execute_with_winternitz(
            &ctx,
            program_pubkey,
            factory_pubkey,
            wallet_pubkey,
            system_program::SYSTEM_PROGRAM_ID, // target program
            &payer_keypair,
            payer_pubkey,
            vault_id,
            &pq_key,
            &pq_next,
            &private_key,
            transfer_ix.data.clone(), // system transfer instruction data
            cpi_account_metas,
            remaining_accounts,
        );

        assert_eq!(status, Status::Processed, "ExecuteWithWinternitz should succeed");

        // Verify balances changed correctly
        let balances_after = capture_balances(&ctx, &[factory_pubkey, wallet_pubkey, recipient_pubkey]);

        // Factory should have gained execute_fee
        let factory_gain = balances_after[0] - balances_before[0];
        assert_eq!(factory_gain, execute_fee, "Factory should gain execute_fee");

        // Wallet balance should be unchanged (owner pays the fee now)
        assert_eq!(balances_after[1], balances_before[1], "Wallet balance should be unchanged");

        // Recipient should have gained the CPI transfer amount
        let recipient_gain = balances_after[2] - balances_before[2];
        assert_eq!(recipient_gain, cpi_transfer_amount, "Recipient should gain CPI transfer amount");

        // Verify wallet state (WOTS+ key rotated, transaction count incremented)
        verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_next, 1);

        // Verify factory accumulated fees
        verify_factory_state(
            &ctx, factory_pubkey, admin_pubkey.serialize(),
            creation_fee, transfer_fee, execute_fee,
            1, // total_wallets
            creation_fee + execute_fee, // accumulated_fees
        );

        println!("\n=== Test PASSED: ExecuteWithWinternitz Success ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_execute_with_winternitz_owner_not_signer() {
        println!("\n=== Test: ExecuteWithWinternitz Owner Not Signer ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Create wallet
        let vault_id = [43u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(200);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 10_000,
        );

        // Create a different signer (attacker) who will sign but is not the owner
        let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);
        ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).unwrap();

        // Build message with owner's pubkey but sign with attacker
        let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
        let message = create_execute_message(
            &pq_key,
            &pq_next,
            &target_bytes,
            &[],
            &[],
            &[],
        );
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
            pq_next: pq_next.clone(),
            vault_id,
            instruction_data: vec![],
            account_metas: vec![],
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        // Use attacker as signer but they're not the wallet owner
        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                            AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: true }, // owner (attacker, not real owner)
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
                        ],
                        data: instruction_data,
                    },
                ],
                Some(attacker_pubkey),
                recent_blockhash,
            ),
            vec![attacker_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Should fail because attacker's pubkey doesn't derive the wallet PDA
        assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

        println!("\n=== Test PASSED: ExecuteWithWinternitz Owner Not Signer ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_execute_with_winternitz_uninitialized_factory() {
        println!("\n=== Test: ExecuteWithWinternitz Uninitialized Factory ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);

        // Derive factory address but don't initialize it
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        // Create a random wallet address (won't actually exist)
        let vault_id = [44u8; 32];
        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (pq_key, private_key) = generate_wots_keypair(300);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        // Build signature
        let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
        let message = create_execute_message(
            &pq_key,
            &pq_next,
            &target_bytes,
            &[],
            &[],
            &[],
        );
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
            pq_next: pq_next.clone(),
            vault_id,
            instruction_data: vec![],
            account_metas: vec![],
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true }, // owner
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Should fail because factory is not owned by program (not initialized)
        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: ExecuteWithWinternitz Uninitialized Factory ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_execute_with_winternitz_uninitialized_wallet() {
        println!("\n=== Test: ExecuteWithWinternitz Uninitialized Wallet ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Initialize factory but don't create wallet
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Derive wallet address but don't create it
        let vault_id = [45u8; 32];
        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (pq_key, private_key) = generate_wots_keypair(400);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        // Build signature
        let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
        let message = create_execute_message(
            &pq_key,
            &pq_next,
            &target_bytes,
            &[],
            &[],
            &[],
        );
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
            pq_next: pq_next.clone(),
            vault_id,
            instruction_data: vec![],
            account_metas: vec![],
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true }, // owner
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Should fail because wallet is not owned by program (not created)
        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: ExecuteWithWinternitz Uninitialized Wallet ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_execute_with_winternitz_wrong_factory_pda() {
        println!("\n=== Test: ExecuteWithWinternitz Wrong Factory PDA ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Initialize factory
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Create wallet
        let vault_id = [46u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(500);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, 10_000,
        );

        // Create a fake factory account (random address)
        let (_fake_factory_keypair, fake_factory_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Build signature
        let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
        let message = create_execute_message(
            &pq_key,
            &pq_next,
            &target_bytes,
            &[],
            &[],
            &[],
        );
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
            pq_next: pq_next.clone(),
            vault_id,
            instruction_data: vec![],
            account_metas: vec![],
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            // Use fake factory instead of real one
                            AccountMeta { pubkey: fake_factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true }, // owner
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Should fail because fake factory is not owned by program
        assert_error(&processed_tx.status, QuipError::IncorrectProgramOwner);

        println!("\n=== Test PASSED: ExecuteWithWinternitz Wrong Factory PDA ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_execute_with_winternitz_wrong_wallet_pda() {
        println!("\n=== Test: ExecuteWithWinternitz Wrong Wallet PDA ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        // Initialize factory
        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            1000, 500, 750,
        );

        // Create wallet with vault_id_1
        let vault_id_1 = [47u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(600);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id_1, &pq_key, 10_000,
        );

        // Use a different vault_id in the instruction
        let wrong_vault_id = [48u8; 32];

        // Build signature with wrong vault_id
        let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
        let message = create_execute_message(
            &pq_key,
            &pq_next,
            &target_bytes,
            &[],
            &[],
            &[],
        );
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
            pq_next: pq_next.clone(),
            vault_id: wrong_vault_id, // Wrong vault_id
            instruction_data: vec![],
            account_metas: vec![],
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                            AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true }, // owner
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
                        ],
                        data: instruction_data,
                    },
                ],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

        // Should fail because wallet PDA doesn't match with wrong_vault_id
        assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

        println!("\n=== Test PASSED: ExecuteWithWinternitz Wrong Wallet PDA ===\n");
    }

    // =============================================================================
    // APL Token Transfer via ExecuteWithWinternitz Tests
    // =============================================================================

    /// Create a token mint account
    fn create_token_mint(
        ctx: &TestContext,
        mint_keypair: &UntweakedKeypair,
        mint_pubkey: Pubkey,
        mint_authority_pubkey: Pubkey,
        mint_authority_keypair: &UntweakedKeypair,
        decimals: u8,
    ) {
        // Send UTXO to mint account
        let (mint_txid, mint_vout) = ctx.helper.send_utxo(mint_pubkey).unwrap();

        // Create mint account with anchor
        let create_mint_ix = system_instruction::create_account_with_anchor(
            &mint_authority_pubkey,
            &mint_pubkey,
            minimum_rent(apl_token::state::Mint::LEN),
            apl_token::state::Mint::LEN as u64,
            &apl_token::id(),
            hex::decode(&mint_txid).unwrap().try_into().unwrap(),
            mint_vout,
        );

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[create_mint_ix],
                Some(mint_authority_pubkey),
                recent_blockhash,
            ),
            vec![mint_authority_keypair.clone(), mint_keypair.clone()],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        assert_eq!(processed_tx.status, Status::Processed, "Create mint account failed");

        // Initialize mint
        let init_mint_ix = apl_token::instruction::initialize_mint(
            &apl_token::id(),
            &mint_pubkey,
            &mint_authority_pubkey,
            Some(&mint_authority_pubkey),
            decimals,
        ).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[init_mint_ix],
                Some(mint_authority_pubkey),
                recent_blockhash,
            ),
            vec![mint_authority_keypair.clone()],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        assert_eq!(processed_tx.status, Status::Processed, "Initialize mint failed");

        println!("Token mint created: {:?}", mint_pubkey);
    }

    /// Create an Associated Token Account (ATA)
    fn create_ata(
        ctx: &TestContext,
        funder_keypair: &UntweakedKeypair,
        funder_pubkey: Pubkey,
        wallet_pubkey: Pubkey,
        mint_pubkey: Pubkey,
    ) -> Pubkey {
        let (ata_pubkey, _) = apl_associated_token_account::get_associated_token_address_and_bump_seed(
            &wallet_pubkey,
            &mint_pubkey,
            &apl_associated_token_account::id(),
        );

        // Send UTXO to ATA
        let (ata_txid, ata_vout) = ctx.helper.send_utxo(ata_pubkey).unwrap();

        // Build ATA creation instruction data (txid + vout)
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(ata_txid.as_bytes());
        data.extend_from_slice(&ata_vout.to_le_bytes());

        let accounts = vec![
            AccountMeta::new(funder_pubkey, true),
            AccountMeta::new(ata_pubkey, false),
            AccountMeta::new(wallet_pubkey, false),
            AccountMeta::new(mint_pubkey, false),
            AccountMeta::new(Pubkey::system_program(), false),
            AccountMeta::new(apl_token::id(), false),
        ];

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: apl_associated_token_account::id(),
                    accounts,
                    data,
                }],
                Some(funder_pubkey),
                recent_blockhash,
            ),
            vec![funder_keypair.clone()],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        assert_eq!(processed_tx.status, Status::Processed, "Create ATA failed");

        println!("ATA created for wallet {:?}: {:?}", wallet_pubkey, ata_pubkey);
        ata_pubkey
    }

    /// Mint tokens to an ATA
    fn mint_tokens(
        ctx: &TestContext,
        mint_pubkey: Pubkey,
        dest_ata: Pubkey,
        mint_authority_keypair: &UntweakedKeypair,
        mint_authority_pubkey: Pubkey,
        amount: u64,
    ) {
        let mint_to_ix = apl_token::instruction::mint_to(
            &apl_token::id(),
            &mint_pubkey,
            &dest_ata,
            &mint_authority_pubkey,
            &[&mint_authority_pubkey],
            amount,
        ).unwrap();

        let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[mint_to_ix],
                Some(mint_authority_pubkey),
                recent_blockhash,
            ),
            vec![mint_authority_keypair.clone()],
            ctx.config.network,
        ).unwrap();

        let txid = ctx.client.send_transaction(tx).unwrap();
        let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();
        assert_eq!(processed_tx.status, Status::Processed, "Mint tokens failed");

        // Verify balance
        let ata_info = ctx.client.read_account_info(dest_ata).unwrap();
        let token_account = apl_token::state::Account::unpack(&ata_info.data).unwrap();
        assert_eq!(token_account.amount, amount, "Token balance mismatch after mint");

        println!("Minted {} tokens to {:?}", amount, dest_ata);
    }

    /// Get token balance for an ATA
    fn get_token_balance(ctx: &TestContext, ata_pubkey: Pubkey) -> u64 {
        let ata_info = ctx.client.read_account_info(ata_pubkey).unwrap();
        apl_token::state::Account::unpack(&ata_info.data).unwrap().amount
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_execute_with_winternitz_apl_token_transfer() {
        println!("\n=== Test: ExecuteWithWinternitz APL Token Transfer ===\n");

        let ctx = TestContext::new();
        let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

        let creation_fee: u64 = 1000;
        let transfer_fee: u64 = 500;
        let execute_fee: u64 = 750;

        let factory_pubkey = initialize_factory(
            &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
            creation_fee, transfer_fee, execute_fee,
        );

        // Create wallet with deposit to cover execute fee
        let vault_id = [99u8; 32];
        let initial_deposit: u64 = 10_000;
        let (pq_key, private_key) = generate_wots_keypair(700);
        let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

        let wallet_pubkey = create_wallet(
            &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
            vault_id, &pq_key, initial_deposit,
        );

        // Create token mint (payer is mint authority)
        let (mint_keypair, mint_pubkey, _) = generate_new_keypair(ctx.config.network);
        create_token_mint(
            &ctx,
            &mint_keypair,
            mint_pubkey,
            payer_pubkey,
            &payer_keypair,
            9, // decimals
        );

        // Create ATA for wallet PDA (source of token transfer)
        // The wallet PDA will be the authority for this ATA
        let wallet_ata = create_ata(
            &ctx,
            &payer_keypair,
            payer_pubkey,
            wallet_pubkey, // owner of the ATA is the wallet PDA
            mint_pubkey,
        );

        // Create ATA for recipient
        let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);
        ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).unwrap();
        let recipient_ata = create_ata(
            &ctx,
            &payer_keypair,
            payer_pubkey,
            recipient_pubkey,
            mint_pubkey,
        );

        // Mint tokens to wallet's ATA
        let mint_amount: u64 = 1_000_000_000; // 1 token with 9 decimals
        mint_tokens(
            &ctx,
            mint_pubkey,
            wallet_ata,
            &payer_keypair,
            payer_pubkey,
            mint_amount,
        );

        // Verify initial balances
        assert_eq!(get_token_balance(&ctx, wallet_ata), mint_amount);
        assert_eq!(get_token_balance(&ctx, recipient_ata), 0);

        // Capture lamport balances before execute (owner pays execute fee)
        let lamport_balances_before = capture_balances(&ctx, &[factory_pubkey, wallet_pubkey]);

        // Build the token transfer CPI instruction
        // The wallet PDA will sign this transfer as the authority
        let token_transfer_amount: u64 = 500_000_000; // 0.5 tokens
        let transfer_ix = apl_token::instruction::transfer(
            &apl_token::id(),
            &wallet_ata,        // source ATA
            &recipient_ata,     // destination ATA
            &wallet_pubkey,     // authority (wallet PDA will sign)
            &[],                // no additional signers
            token_transfer_amount,
        ).unwrap();

        // Build CpiAccountMeta for the signature message
        // Order: source, dest, authority, token_program
        let cpi_account_metas = vec![
            CpiAccountMeta { is_signer: false, is_writable: true },   // source ATA
            CpiAccountMeta { is_signer: false, is_writable: true },   // dest ATA
            CpiAccountMeta { is_signer: true, is_writable: false },   // authority (wallet PDA)
            CpiAccountMeta { is_signer: false, is_writable: false },  // token program
        ];

        // Build remaining accounts for the CPI
        let remaining_accounts = vec![
            AccountMeta { pubkey: wallet_ata, is_signer: false, is_writable: true },
            AccountMeta { pubkey: recipient_ata, is_signer: false, is_writable: true },
            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: false }, // authority
            AccountMeta { pubkey: apl_token::id(), is_signer: false, is_writable: false },
        ];

        let status = execute_with_winternitz(
            &ctx,
            program_pubkey,
            factory_pubkey,
            wallet_pubkey,
            apl_token::id(), // target program is APL token
            &payer_keypair,
            payer_pubkey,
            vault_id,
            &pq_key,
            &pq_next,
            &private_key,
            transfer_ix.data.clone(),
            cpi_account_metas,
            remaining_accounts,
        );

        assert_eq!(status, Status::Processed, "APL token transfer via ExecuteWithWinternitz should succeed");

        // Verify token balances changed correctly
        let wallet_token_balance = get_token_balance(&ctx, wallet_ata);
        let recipient_token_balance = get_token_balance(&ctx, recipient_ata);

        assert_eq!(
            wallet_token_balance,
            mint_amount - token_transfer_amount,
            "Wallet ATA should have {} tokens remaining",
            mint_amount - token_transfer_amount
        );
        assert_eq!(
            recipient_token_balance,
            token_transfer_amount,
            "Recipient ATA should have {} tokens",
            token_transfer_amount
        );

        // Verify lamport balances changed correctly (owner pays execute fee)
        let lamport_balances_after = capture_balances(&ctx, &[factory_pubkey, wallet_pubkey]);

        let factory_gain = lamport_balances_after[0] - lamport_balances_before[0];
        assert_eq!(factory_gain, execute_fee, "Factory should gain execute_fee");

        // Wallet balance should be unchanged (owner pays the fee now)
        assert_eq!(lamport_balances_after[1], lamport_balances_before[1], "Wallet balance should be unchanged");

        // Verify wallet state (WOTS+ key rotated, transaction count incremented)
        verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_next, 1);

        println!("\n=== Test PASSED: ExecuteWithWinternitz APL Token Transfer ===\n");
    }
}
