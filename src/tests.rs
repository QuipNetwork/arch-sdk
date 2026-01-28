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
    use borsh::BorshDeserialize;
    use hashsigs::WOTSPlus;
    use serial_test::serial;

    use crate::instruction::QuipInstruction;
    use crate::state::{
        QuipFactory, QuipWallet,
        WinternitzPublicKey, WinternitzSignature,
    };
    use crate::utils::{
        create_btc_transfer_message, create_change_owner_message, create_transfer_message,
        derive_factory_address, derive_wallet_address,
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

    /// Generate a WOTS+ keypair with deterministic seed based on index
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
    // Factory Initialization Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_initialize_factory() {
        println!("\n=== Test: Initialize Factory ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();

        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, authority_pubkey, _) = generate_new_keypair(config.network);

        let (program_keypair, _, _) = generate_new_keypair(config.network);

        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);

        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);

        // Fund accounts
        client
            .create_and_fund_account_with_faucet(&authority_keypair)
            .expect("Failed to fund authority");

        client
            .create_and_fund_account_with_faucet(&payer_keypair)
            .expect("Failed to fund payer");

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .expect("Failed to deploy program");

        // Derive factory PDA
        let (factory_bytes, factory_bump) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        // Create UTXO for factory account
        let (factory_txid, factory_vout) = helper
            .send_utxo(factory_pubkey)
            .expect("Failed to send UTXO for factory");

        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        // Build and send InitializeFactory transaction
        let creation_fee: u64 = 1000;
        let transfer_fee: u64 = 500;
        let execute_fee: u64 = 750;

        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee,
            transfer_fee,
            execute_fee,
            factory_utxo,
        }).expect("Failed to serialize instruction");

        let accounts = vec![
            AccountMeta {
                pubkey: factory_pubkey,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: payer_pubkey,
                is_signer: true,
                is_writable: true,
            },
            AccountMeta {
                pubkey: system_program::SYSTEM_PROGRAM_ID,
                is_signer: false,
                is_writable: false,
            },
        ];

        let recent_blockhash = client
            .get_best_finalized_block_hash()
            .expect("Failed to get blockhash");

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
            vec![payer_keypair],
            config.network,
        ).expect("Failed to build transaction");

        let txid = client.send_transaction(tx).expect("Failed to send transaction");

        let processed_tx = client
            .wait_for_processed_transaction(&txid)
            .expect("Failed to wait for transaction");
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            processed_tx.status == Status::Processed,
            "Transaction failed: {:?}",
            processed_tx.status
        );

        // Verify factory state
        let factory_account = client
            .read_account_info(factory_pubkey)
            .expect("Failed to read factory account");

        let factory = QuipFactory::try_from_slice(&factory_account.data)
            .expect("Failed to deserialize factory");

        assert!(factory.is_initialized, "Factory should be initialized");

        assert_eq!(factory.admin, admin_pubkey.serialize(), "Admin mismatch");

        assert_eq!(factory.creation_fee, creation_fee, "Creation fee mismatch");

        assert_eq!(factory.transfer_fee, transfer_fee, "Transfer fee mismatch");

        assert_eq!(factory.execute_fee, execute_fee, "Execute fee mismatch");

        assert_eq!(factory.total_wallets, 0, "Total wallets should be 0");

        assert_eq!(factory.accumulated_fees, 0, "Accumulated fees should be 0");

        println!("\n=== Test PASSED: Initialize Factory ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_initialize_factory_already_initialized() {
        println!("\n=== Test: Initialize Factory Already Initialized ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, authority_pubkey, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Derive factory PDA
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        // First initialization
        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        assert!(processed_tx.status == Status::Processed);
        println!("First initialization successful");

        // Second initialization (should fail)
        let (factory_txid2, factory_vout2) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash2 = client.get_best_finalized_block_hash().unwrap();
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
            config.network,
        ).unwrap();

        let txid2 = client.send_transaction(tx2).unwrap();
        let processed_tx2 = client.wait_for_processed_transaction(&txid2).unwrap();
        println!("Second initialization status: {:?}", processed_tx2.status);

        assert!(
            matches!(processed_tx2.status, Status::Failed(_)),
            "Second initialization should fail"
        );

        println!("\n=== Test PASSED: Initialize Factory Already Initialized ===\n");
    }

    // =============================================================================
    // Wallet Creation Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_with_deposit() {
        println!("\n=== Test: DepositToWinternitz With Deposit ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, authority_pubkey, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        let creation_fee: u64 = 1000;
        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee,
            transfer_fee: 500,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        assert!(processed_tx.status == Status::Processed);
        println!("Factory initialized successfully");

        // Capture factory balance before wallet creation
        let factory_balance_before = client.read_account_info(factory_pubkey).unwrap().lamports;

        // Create wallet
        let vault_id = [1u8; 32];
        let initial_deposit: u64 = 5000;
        let (pq_key, _private_key) = generate_wots_keypair(1);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, wallet_bump) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify wallet state
        let wallet_account = client.read_account_info(wallet_pubkey).unwrap();

        let wallet = QuipWallet::try_from_slice(&wallet_account.data).unwrap();
        assert!(wallet.is_initialized);

        assert_eq!(wallet.owner, owner_bytes);

        assert_eq!(wallet.pq_owner.public_seed, pq_key.public_seed);
        assert_eq!(wallet.pq_owner.public_key_hash, pq_key.public_key_hash);

        assert_eq!(wallet.transaction_count, 0);

        // Verify wallet balance received the initial deposit + rent
        let wallet_rent = minimum_rent(QuipWallet::SPACE);
        let expected_wallet_balance = initial_deposit + wallet_rent;
        assert_eq!(
            wallet_account.lamports, expected_wallet_balance,
            "Wallet balance {} should equal initial_deposit {} + rent {}",
            wallet_account.lamports, initial_deposit, wallet_rent
        );

        // Verify factory state
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();

        assert_eq!(factory.total_wallets, 1);

        assert_eq!(factory.accumulated_fees, creation_fee);

        // Verify factory balance increased by exactly creation_fee
        let factory_balance_after = factory_account.lamports;
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

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet with no deposit
        let vault_id = [2u8; 32];
        let (pq_key, _) = generate_wots_keypair(2);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: 0, // No deposit
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify wallet
        let wallet_account = client.read_account_info(wallet_pubkey).unwrap();
        let wallet = QuipWallet::try_from_slice(&wallet_account.data).unwrap();
        assert!(wallet.is_initialized);

        println!("\n=== Test PASSED: DepositToWinternitz No Deposit ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_topup() {
        println!("\n=== Test: DepositToWinternitz Topup ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);

        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet with initial deposit
        let vault_id = [3u8; 32];
        let (pq_key, _) = generate_wots_keypair(3);
        let initial_deposit: u64 = 2000;

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        assert!(processed_tx.status == Status::Processed);
        println!("Wallet created with initial deposit: {}", initial_deposit);

        // Record state after wallet creation
        let wallet_account = client.read_account_info(wallet_pubkey).unwrap();
        let wallet_before = QuipWallet::try_from_slice(&wallet_account.data).unwrap();
        let balance_before = wallet_account.lamports;

        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory_before = QuipFactory::try_from_slice(&factory_account.data).unwrap();

        // Topup wallet
        let topup_amount: u64 = 3000;

        // For topup, we still need a UTXO but it won't be used for account creation
        let (topup_txid, topup_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let topup_utxo = UtxoMeta::from(
            hex::decode(&topup_txid).unwrap().try_into().unwrap(),
            topup_vout,
        );

        let instruction_data2 = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: topup_amount,
            wallet_utxo: topup_utxo,
        }).unwrap();

        let recent_blockhash2 = client.get_best_finalized_block_hash().unwrap();
        let tx2 = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data2,
                }],
                Some(payer_pubkey),
                recent_blockhash2,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid2 = client.send_transaction(tx2).unwrap();
        let processed_tx2 = client.wait_for_processed_transaction(&txid2).unwrap();
        println!("Topup transaction status: {:?}", processed_tx2.status);
        assert!(processed_tx2.status == Status::Processed, "Topup should succeed");

        // Verify wallet state after topup
        let wallet_account_after = client.read_account_info(wallet_pubkey).unwrap();
        let wallet_after = QuipWallet::try_from_slice(&wallet_account_after.data).unwrap();
        let balance_after = wallet_account_after.lamports;

        // Balance should increase by topup amount
        assert_eq!(
            balance_after,
            balance_before + topup_amount,
            "Wallet balance should increase by topup amount"
        );

        // Wallet state should remain unchanged
        assert_eq!(wallet_after.owner, wallet_before.owner, "Owner should remain the same");
        assert_eq!(wallet_after.pq_owner, wallet_before.pq_owner, "PQ owner should remain the same");
        assert_eq!(wallet_after.transaction_count, wallet_before.transaction_count, "Transaction count should remain the same");

        // Verify factory state after topup
        let factory_account_after = client.read_account_info(factory_pubkey).unwrap();
        let factory_after = QuipFactory::try_from_slice(&factory_account_after.data).unwrap();

        // total_wallets should remain the same (no new wallet created)
        assert_eq!(
            factory_after.total_wallets,
            factory_before.total_wallets,
            "Total wallets should remain the same (no new wallet created)"
        );

        // accumulated_fees should remain the same (no creation fee charged for topup)
        assert_eq!(
            factory_after.accumulated_fees,
            factory_before.accumulated_fees,
            "Accumulated fees should remain the same (no creation fee for topup)"
        );

        println!("\n=== Test PASSED: DepositToWinternitz Topup ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_deposit_to_winternitz_multiple_wallets_same_owner() {
        println!("\n=== Test: DepositToWinternitz Multiple Wallets Same Owner ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);

        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        let creation_fee: u64 = 1000;
        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee,
            transfer_fee: 500,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        let owner_bytes = owner_pubkey.serialize();

        // Create first wallet with vault_id_1
        let vault_id_1 = [1u8; 32];
        let (pq_key_1, _) = generate_wots_keypair(100);
        let initial_deposit_1: u64 = 5000;

        let (wallet_bytes_1, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id_1);
        let wallet_pubkey_1 = Pubkey::from_slice(&wallet_bytes_1);

        let (wallet_txid_1, wallet_vout_1) = helper.send_utxo(wallet_pubkey_1).unwrap();
        let wallet_utxo_1 = UtxoMeta::from(
            hex::decode(&wallet_txid_1).unwrap().try_into().unwrap(),
            wallet_vout_1,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id: vault_id_1,
            to: owner_bytes,
            pq_to: pq_key_1.clone(),
            initial_deposit: initial_deposit_1,
            wallet_utxo: wallet_utxo_1,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey_1, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        assert!(processed_tx.status == Status::Processed);
        println!("Wallet 1 created with deposit {}", initial_deposit_1);

        // Create second wallet with vault_id_2 for the same owner
        let vault_id_2 = [2u8; 32];
        let (pq_key_2, _) = generate_wots_keypair(200);
        let initial_deposit_2: u64 = 8000;

        let (wallet_bytes_2, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id_2);
        let wallet_pubkey_2 = Pubkey::from_slice(&wallet_bytes_2);

        // Verify the two wallet PDAs are different
        assert_ne!(
            wallet_pubkey_1, wallet_pubkey_2,
            "Different vault_ids should produce different wallet PDAs"
        );

        let (wallet_txid_2, wallet_vout_2) = helper.send_utxo(wallet_pubkey_2).unwrap();
        let wallet_utxo_2 = UtxoMeta::from(
            hex::decode(&wallet_txid_2).unwrap().try_into().unwrap(),
            wallet_vout_2,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id: vault_id_2,
            to: owner_bytes,
            pq_to: pq_key_2.clone(),
            initial_deposit: initial_deposit_2,
            wallet_utxo: wallet_utxo_2,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey_2, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        assert!(processed_tx.status == Status::Processed);
        println!("Wallet 2 created with deposit {}", initial_deposit_2);

        // Verify both wallets exist and have correct state

        let wallet_account_1 = client.read_account_info(wallet_pubkey_1).unwrap();
        let wallet_1 = QuipWallet::try_from_slice(&wallet_account_1.data).unwrap();
        assert!(wallet_1.is_initialized);
        assert_eq!(wallet_1.owner, owner_bytes);
        assert_eq!(wallet_1.pq_owner.public_seed, pq_key_1.public_seed);
        assert_eq!(wallet_1.pq_owner.public_key_hash, pq_key_1.public_key_hash);
        let wallet_rent = minimum_rent(QuipWallet::SPACE);
        let expected_balance_1 = initial_deposit_1 + wallet_rent;
        assert_eq!(
            wallet_account_1.lamports, expected_balance_1,
            "Wallet 1 balance {} should equal deposit {} + rent {}",
            wallet_account_1.lamports, initial_deposit_1, wallet_rent
        );

        let wallet_account_2 = client.read_account_info(wallet_pubkey_2).unwrap();
        let wallet_2 = QuipWallet::try_from_slice(&wallet_account_2.data).unwrap();
        assert!(wallet_2.is_initialized);
        assert_eq!(wallet_2.owner, owner_bytes);
        assert_eq!(wallet_2.pq_owner.public_seed, pq_key_2.public_seed);
        assert_eq!(wallet_2.pq_owner.public_key_hash, pq_key_2.public_key_hash);
        let expected_balance_2 = initial_deposit_2 + wallet_rent;
        assert_eq!(
            wallet_account_2.lamports, expected_balance_2,
            "Wallet 2 balance {} should equal deposit {} + rent {}",
            wallet_account_2.lamports, initial_deposit_2, wallet_rent
        );

        // Verify factory tracked both wallet creations
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(factory.total_wallets, 2, "Factory should have created 2 wallets");
        assert_eq!(
            factory.accumulated_fees, creation_fee * 2,
            "Factory accumulated_fees {} should equal creation_fee * 2 = {}",
            factory.accumulated_fees, creation_fee * 2
        );

        println!("\n=== Test PASSED: DepositToWinternitz Multiple Wallets Same Owner ===\n");
    }

    // =============================================================================
    // Transfer Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_success() {
        println!("\n=== Test: Transfer Success ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&recipient_keypair).unwrap();

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        let transfer_fee: u64 = 500;
        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee: 1000,
            transfer_fee,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet
        let vault_id = [10u8; 32];
        let initial_deposit: u64 = 10000;
        let (pq_key, private_key) = generate_wots_keypair(1);
        let (pq_next, _next_private_key) = generate_wots_keypair(2);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created with {} deposit", initial_deposit);

        // Capture balances before transfer
        let wallet_balance_before = client.read_account_info(wallet_pubkey).unwrap().lamports;
        let factory_balance_before = client.read_account_info(factory_pubkey).unwrap().lamports;
        let recipient_balance_before = client.read_account_info(recipient_pubkey).unwrap().lamports;

        // Create signature for transfer
        let transfer_amount: u64 = 2000;
        let recipient_bytes = recipient_pubkey.serialize();
        let message = create_transfer_message(&pq_key, &pq_next, &recipient_bytes, transfer_amount);
        let signature_data = sign_message(&private_key, &message);

        // Execute transfer

        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        // Request higher compute budget for WOTS+ signature verification
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
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
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify wallet state
        let wallet_account = client.read_account_info(wallet_pubkey).unwrap();
        let wallet = QuipWallet::try_from_slice(&wallet_account.data).unwrap();

        assert_eq!(wallet.pq_owner.public_seed, pq_next.public_seed);
        assert_eq!(wallet.pq_owner.public_key_hash, pq_next.public_key_hash);

        assert_eq!(wallet.transaction_count, 1);

        // Verify balance changes
        let wallet_balance_after = wallet_account.lamports;
        let factory_balance_after = client.read_account_info(factory_pubkey).unwrap().lamports;
        let recipient_balance_after = client.read_account_info(recipient_pubkey).unwrap().lamports;

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

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet
        let vault_id = [12u8; 32];
        let (pq_key, _) = generate_wots_keypair(5);
        let (pq_next, _) = generate_wots_keypair(6);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: 10000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created");

        // Create INVALID signature (random data)
        let invalid_signature = vec![0xFFu8; 2112]; // WOTS+ signature size but random data

        // Attempt transfer with invalid signature
        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: 1000,
            signature: WinternitzSignature { signature_data: invalid_signature },
        }).unwrap();

        // Request higher compute budget for WOTS+ signature verification
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
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
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transfer status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Transfer with invalid signature should fail"
        );

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

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet
        let vault_id = [20u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(10);
        let (pq_next, _) = generate_wots_keypair(11);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: 5000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created");

        // Create signature for key change
        let message = create_change_owner_message(&pq_key, &pq_next);
        let signature_data = sign_message(&private_key, &message);

        // Execute key change
        let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
            vault_id,
            pq_next: pq_next.clone(),
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        // Request higher compute budget for WOTS+ signature verification
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: false },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify wallet state
        let wallet_account = client.read_account_info(wallet_pubkey).unwrap();
        let wallet = QuipWallet::try_from_slice(&wallet_account.data).unwrap();

        assert_eq!(wallet.pq_owner.public_seed, pq_next.public_seed);
        assert_eq!(wallet.pq_owner.public_key_hash, pq_next.public_key_hash);

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

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Update fees
        let new_creation_fee: u64 = 2000;
        let new_transfer_fee: u64 = 1000;
        let new_execute_fee: u64 = 1500;

        let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
            creation_fee: new_creation_fee,
            transfer_fee: new_transfer_fee,
            execute_fee: new_execute_fee,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
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
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify factory state
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();

        assert_eq!(factory.creation_fee, new_creation_fee);

        assert_eq!(factory.transfer_fee, new_transfer_fee);

        assert_eq!(factory.execute_fee, new_execute_fee);

        println!("\n=== Test PASSED: Update Fees ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_update_fees_unauthorized() {
        println!("\n=== Test: Update Fees Unauthorized ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        let (non_admin_keypair, non_admin_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&non_admin_keypair).unwrap();

        // Deploy and initialize factory
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Attempt unauthorized fee update
        let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
            creation_fee: 9999,
            transfer_fee: 9999,
            execute_fee: 9999,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: non_admin_pubkey, is_signer: true, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(non_admin_pubkey),
                recent_blockhash,
            ),
            vec![non_admin_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Unauthorized fee update should fail"
        );

        println!("\n=== Test PASSED: Update Fees Unauthorized ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_ownership() {
        println!("\n=== Test: Transfer Ownership ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (new_admin_keypair, new_admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&new_admin_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Transfer ownership
        let instruction_data = borsh::to_vec(&QuipInstruction::TransferOwnership {
            new_admin: new_admin_pubkey.serialize(),
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
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
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify new admin
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();

        assert_eq!(factory.admin, new_admin_pubkey.serialize());

        // Verify new admin can update fees
        let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
            creation_fee: 5000,
            transfer_fee: 2500,
            execute_fee: 3000,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
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
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("New admin fee update status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify old admin cannot update fees
        let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
            creation_fee: 9999,
            transfer_fee: 9999,
            execute_fee: 9999,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
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
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Old admin fee update status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Old admin should not be able to update fees"
        );

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

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        let (_fake_system_keypair, fake_system_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Derive factory PDA
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        // Create UTXO for factory
        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        // Attempt init with fake system program
        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee: 1000,
            transfer_fee: 500,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
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
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Fake system program should be rejected"
        );

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

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet with small deposit
        let vault_id = [7u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(7);
        let (pq_next, _) = generate_wots_keypair(8);
        let initial_deposit: u64 = 100; // Very small deposit

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created with small deposit: {}", initial_deposit);

        // Attempt transfer larger than balance
        let transfer_amount: u64 = 100000; // Much larger than deposit
        let recipient_bytes = recipient_pubkey.serialize();
        let message = create_transfer_message(&pq_key, &pq_next, &recipient_bytes, transfer_amount);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        // Request higher compute budget for WOTS+ signature verification
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
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
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Transfer with insufficient balance should fail"
        );

        println!("\n=== Test PASSED: TransferWithWinternitz Insufficient Balance ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_transfer_with_winternitz_unauthorized() {
        println!("\n=== Test: TransferWithWinternitz Unauthorized ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&attacker_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet owned by owner
        let vault_id = [8u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(8);
        let (pq_next, _) = generate_wots_keypair(9);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: 10000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created");

        // Attacker attempts to transfer (with valid signature but wrong signer)
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

        // Request higher compute budget for WOTS+ signature verification
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
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
                            AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: true }, // Attacker as payer
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(attacker_pubkey),
                recent_blockhash,
            ),
            vec![attacker_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Unauthorized transfer should fail"
        );

        println!("\n=== Test PASSED: TransferWithWinternitz Unauthorized ===\n");
    }

    // =============================================================================
    // ChangePqOwner Negative Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_change_pq_owner_invalid_signature() {
        println!("\n=== Test: ChangePqOwner Invalid Signature ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet
        let vault_id = [9u8; 32];
        let (pq_key, _) = generate_wots_keypair(9);
        let (pq_next, _) = generate_wots_keypair(10);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: 5000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created");

        // Attempt key change with invalid signature
        let invalid_signature = vec![0xFFu8; 2144]; // Invalid signature data

        let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
            vault_id,
            pq_next: pq_next.clone(),
            signature: WinternitzSignature { signature_data: invalid_signature },
        }).unwrap();

        // Request higher compute budget for WOTS+ signature verification
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: false },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Key change with invalid signature should fail"
        );

        println!("\n=== Test PASSED: ChangePqOwner Invalid Signature ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_change_pq_owner_unauthorized() {
        println!("\n=== Test: ChangePqOwner Unauthorized ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&attacker_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet owned by owner
        let vault_id = [10u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(10);
        let (pq_next, _) = generate_wots_keypair(11);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: 5000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created");

        // Attacker attempts key change (even with valid signature)
        let message = create_change_owner_message(&pq_key, &pq_next);
        let signature_data = sign_message(&private_key, &message);

        let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
            vault_id,
            pq_next: pq_next.clone(),
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        // Request higher compute budget for WOTS+ signature verification
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: false },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: true }, // Attacker as payer
                        ],
                        data: instruction_data,
                    },
                ],
                Some(attacker_pubkey),
                recent_blockhash,
            ),
            vec![attacker_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Unauthorized key change should fail"
        );

        println!("\n=== Test PASSED: ChangePqOwner Unauthorized ===\n");
    }

    // =============================================================================
    // WithdrawFees Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_withdraw_fees_success() {
        println!("\n=== Test: WithdrawFees Success ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&recipient_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        let creation_fee: u64 = 1000;
        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee,
            transfer_fee: 500,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized with creation_fee: {}", creation_fee);

        // Create a wallet to accumulate fees
        let vault_id = [11u8; 32];
        let (pq_key, _) = generate_wots_keypair(11);

        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key,
            initial_deposit: 5000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created, fees accumulated");

        // Check factory state and capture balances before withdrawal
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        let factory_balance_before = factory_account.lamports;
        let recipient_balance_before = client.read_account_info(recipient_pubkey).unwrap().lamports;

        // Withdraw fees
        let withdraw_amount: u64 = 500; // Withdraw partial fees

        let instruction_data = borsh::to_vec(&QuipInstruction::WithdrawFees {
            amount: withdraw_amount,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: admin_pubkey, is_signer: true, is_writable: false },
                        AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(admin_pubkey),
                recent_blockhash,
            ),
            vec![admin_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify factory state after withdrawal
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(factory.accumulated_fees, creation_fee - withdraw_amount);

        // Verify recipient received funds
        let recipient_balance_after = client.read_account_info(recipient_pubkey).unwrap().lamports;
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

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&attacker_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create a wallet to accumulate fees
        let vault_id = [12u8; 32];
        let (pq_key, _) = generate_wots_keypair(12);
        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key,
            initial_deposit: 5000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created, fees accumulated");

        // Attacker attempts to withdraw fees
        let instruction_data = borsh::to_vec(&QuipInstruction::WithdrawFees {
            amount: 500,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: false }, // Attacker as admin
                        AccountMeta { pubkey: attacker_pubkey, is_signer: false, is_writable: true }, // Attacker as recipient
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(attacker_pubkey),
                recent_blockhash,
            ),
            vec![attacker_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Unauthorized fee withdrawal should fail"
        );

        println!("\n=== Test PASSED: WithdrawFees Unauthorized ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_withdraw_fees_insufficient() {
        println!("\n=== Test: WithdrawFees Insufficient ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
        let (admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(config.network);


        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory with small creation fee
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        let creation_fee: u64 = 100; // Small fee
        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee,
            transfer_fee: 50,
            execute_fee: 75,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized with small creation_fee: {}", creation_fee);

        // Create a wallet to accumulate some fees
        let vault_id = [13u8; 32];
        let (pq_key, _) = generate_wots_keypair(13);
        let owner_bytes = payer_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key,
            initial_deposit: 1000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(payer_pubkey),
                recent_blockhash,
            ),
            vec![payer_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created, accumulated_fees should be {}", creation_fee);

        // Attempt to withdraw more than accumulated
        let withdraw_amount: u64 = 10000; // Much more than accumulated

        let instruction_data = borsh::to_vec(&QuipInstruction::WithdrawFees {
            amount: withdraw_amount,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: admin_pubkey, is_signer: true, is_writable: false },
                        AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(admin_pubkey),
                recent_blockhash,
            ),
            vec![admin_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Withdrawing more than accumulated should fail"
        );

        println!("\n=== Test PASSED: WithdrawFees Insufficient ===\n");
    }

    // =============================================================================
    // BTC Transfer Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_partial_spend() {
        println!("\n=== Test: BTC Transfer Partial Spend ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);

        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (fee_payer_keypair, fee_payer_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&fee_payer_keypair).unwrap();

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        let transfer_fee: u64 = 500;
        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee: 1000,
            transfer_fee,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: false },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet
        let vault_id = [20u8; 32];
        let initial_deposit: u64 = 10000;
        let (pq_key, private_key) = generate_wots_keypair(30);
        let (pq_next, _next_private_key) = generate_wots_keypair(31);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: false },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created with {} lamport deposit", initial_deposit);

        // Capture balances before BTC transfer
        let wallet_balance_before = client.read_account_info(wallet_pubkey).unwrap().lamports;
        let factory_balance_before = client.read_account_info(factory_pubkey).unwrap().lamports;
        println!("Wallet lamport balance before: {}", wallet_balance_before);
        println!("Factory lamport balance before: {}", factory_balance_before);

        // Prepare fee transaction and recipient script_pubkey

        // Anchor the fee payer to a Bitcoin UTXO — Arch requires all accounts
        // in a BTC-linked transaction to be anchored, including the fee payer.
        let (fp_txid, fp_vout) = helper.send_utxo(fee_payer_pubkey).unwrap();
        let anchor_ix = system_instruction::anchor(
            &fee_payer_pubkey,
            hex::decode(&fp_txid).unwrap().try_into().unwrap(),
            fp_vout,
        );
        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(&[anchor_ix], Some(fee_payer_pubkey), recent_blockhash),
            vec![fee_payer_keypair.clone()],
            config.network,
        ).unwrap();
        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();

        let fee_tx = prepare_fees_and_wait(&helper);

        // Recipient script_pubkey: use a simple P2WPKH-style script (0x0014 + 20-byte hash)
        let recipient_script_pubkey: Vec<u8> = {
            let mut script = vec![0x00, 0x14]; // OP_0, PUSH20
            script.extend_from_slice(&[0xABu8; 20]); // dummy 20-byte pubkey hash
            script
        };

        // send_utxo creates a 3000-sat UTXO; transfer only 1500 (partial spend)
        let transfer_amount: u64 = 1500;

        // Create WOTS+ signature
        let message = create_btc_transfer_message(
            &pq_key,
            &pq_next,
            &recipient_script_pubkey,
            transfer_amount,
        );
        let signature_data = sign_message(&private_key, &message);

        // Execute BTC transfer
        let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            recipient_script_pubkey: recipient_script_pubkey.clone(),
            fee_tx,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

        // Use a separate fee_payer for the Arch transaction so the owner is NOT
        // implicitly writable (fee payers are always writable in Arch/Solana).
        // This avoids the anchoring requirement for the owner account.
        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: false },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                            AccountMeta { pubkey: fee_payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(fee_payer_pubkey),
                recent_blockhash,
            ),
            vec![fee_payer_keypair, owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(processed_tx.status == Status::Processed, "BTC transfer tx should succeed");

        // Verify lamport fee was collected from wallet to factory
        let wallet_balance_after = client.read_account_info(wallet_pubkey).unwrap().lamports;
        let factory_balance_after = client.read_account_info(factory_pubkey).unwrap().lamports;
        println!("Wallet lamport balance after: {}", wallet_balance_after);
        println!("Factory lamport balance after: {}", factory_balance_after);

        let wallet_balance_decrease = wallet_balance_before - wallet_balance_after;
        let factory_balance_increase = factory_balance_after - factory_balance_before;
        assert_eq!(
            wallet_balance_decrease, transfer_fee,
            "Wallet should have been debited exactly transfer_fee ({}) lamports",
            transfer_fee
        );
        assert_eq!(
            factory_balance_increase, transfer_fee,
            "Factory should have received exactly transfer_fee ({}) lamports",
            transfer_fee
        );

        // Verify factory accumulated_fees was updated.
        // accumulated_fees includes the creation_fee (1000) from DepositToWinternitz
        // plus the transfer_fee (500) from this BTC transfer.
        let creation_fee: u64 = 1000;
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
        assert_eq!(
            factory.accumulated_fees, creation_fee + transfer_fee,
            "Factory accumulated_fees should equal creation_fee + transfer_fee"
        );

        // Check whether the Bitcoin network accepted the transaction.
        // Partial spend has 1500 sats change — well above dust limit, should succeed.
        if let Some(ref btc_txid_hash) = processed_tx.bitcoin_txid {
            let raw_txid: arch_program::bitcoin::Txid = btc_txid_hash.into();
            let mut bytes = raw_txid.to_byte_array();
            bytes.reverse();
            let btc_txid = arch_program::bitcoin::Txid::from_byte_array(bytes);
            match helper.wait_until_titan_indexes_transaction(&btc_txid) {
                Ok(()) => {
                    println!("RESULT: Bitcoin transaction ACCEPTED (Titan indexed it)");
                }
                Err(e) => {
                    println!("RESULT: Bitcoin transaction NOT accepted: {}", e);
                }
            }
        } else {
            println!("RESULT: No bitcoin_txid — Arch did not produce a BTC transaction");
        }

        println!("\n=== Test Complete: BTC Transfer Partial Spend ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_full_spend() {
        println!("\n=== Test: BTC Transfer Full Spend ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);

        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (fee_payer_keypair, fee_payer_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&fee_payer_keypair).unwrap();

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        let transfer_fee: u64 = 500;
        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee: 1000,
            transfer_fee,
            execute_fee: 750,
            factory_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet
        let vault_id = [21u8; 32];
        let initial_deposit: u64 = 10000;
        let (pq_key, private_key) = generate_wots_keypair(40);
        let (pq_next, _next_private_key) = generate_wots_keypair(41);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created with {} lamport deposit", initial_deposit);

        // Capture balances before BTC transfer
        let wallet_balance_before = client.read_account_info(wallet_pubkey).unwrap().lamports;
        let factory_balance_before = client.read_account_info(factory_pubkey).unwrap().lamports;
        println!("Wallet lamport balance before: {}", wallet_balance_before);
        println!("Factory lamport balance before: {}", factory_balance_before);

        // Prepare fee transaction and recipient script_pubkey
        // Anchor the fee payer to a Bitcoin UTXO — Arch requires all accounts
        // in a BTC-linked transaction to be anchored, including the fee payer.
        let (fp_txid, fp_vout) = helper.send_utxo(fee_payer_pubkey).unwrap();
        let anchor_ix = system_instruction::anchor(
            &fee_payer_pubkey,
            hex::decode(&fp_txid).unwrap().try_into().unwrap(),
            fp_vout,
        );
        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(&[anchor_ix], Some(fee_payer_pubkey), recent_blockhash),
            vec![fee_payer_keypair.clone()],
            config.network,
        ).unwrap();
        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();

        let fee_tx = prepare_fees_and_wait(&helper);

        let recipient_script_pubkey: Vec<u8> = {
            let mut script = vec![0x00, 0x14]; // OP_0, PUSH20
            script.extend_from_slice(&[0xCDu8; 20]); // dummy 20-byte pubkey hash
            script
        };

        // send_utxo creates a 3000-sat UTXO; transfer the maximum allowed amount.
        // Bitcoin requires change outputs to be above the dust limit (330 sats for P2TR),
        // so the max transfer is utxo_value - 330 = 2670 sats. A 0-sat change output
        // causes the Arch runtime to silently revert all state changes.
        let dust_limit: u64 = 330;
        let utxo_sats: u64 = 3000; // from send_utxo
        let transfer_amount: u64 = utxo_sats - dust_limit; // 2670

        // Create WOTS+ signature
        let message = create_btc_transfer_message(
            &pq_key,
            &pq_next,
            &recipient_script_pubkey,
            transfer_amount,
        );
        let signature_data = sign_message(&private_key, &message);

        // Execute BTC transfer
        let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            recipient_script_pubkey: recipient_script_pubkey.clone(),
            fee_tx,
            signature: WinternitzSignature { signature_data },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: false },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                            AccountMeta { pubkey: fee_payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(fee_payer_pubkey),
                recent_blockhash,
            ),
            vec![fee_payer_keypair, owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed, "BTC max-spend tx should succeed");

        // Verify lamport fee was collected from wallet to factory
        let wallet_balance_after = client.read_account_info(wallet_pubkey).unwrap().lamports;
        let factory_balance_after = client.read_account_info(factory_pubkey).unwrap().lamports;
        println!("Wallet lamport balance after: {}", wallet_balance_after);
        println!("Factory lamport balance after: {}", factory_balance_after);

        let wallet_balance_decrease = wallet_balance_before - wallet_balance_after;
        let factory_balance_increase = factory_balance_after - factory_balance_before;
        assert_eq!(
            wallet_balance_decrease, transfer_fee,
            "Wallet should have been debited exactly transfer_fee ({}) lamports",
            transfer_fee
        );
        assert_eq!(
            factory_balance_increase, transfer_fee,
            "Factory should have received exactly transfer_fee ({}) lamports",
            transfer_fee
        );

        // Check whether the Bitcoin network accepted the transaction.
        // Change output is 330 sats (P2TR dust limit) — should be accepted.
        if let Some(ref btc_txid_hash) = processed_tx.bitcoin_txid {
            let raw_txid: arch_program::bitcoin::Txid = btc_txid_hash.into();
            let mut bytes = raw_txid.to_byte_array();
            bytes.reverse();
            let btc_txid = arch_program::bitcoin::Txid::from_byte_array(bytes);
            match helper.wait_until_titan_indexes_transaction(&btc_txid) {
                Ok(()) => {
                    println!("RESULT: Bitcoin transaction ACCEPTED (Titan indexed it)");
                }
                Err(e) => {
                    println!("RESULT: Bitcoin transaction NOT accepted: {}", e);
                }
            }
        } else {
            println!("RESULT: No bitcoin_txid — Arch did not produce a BTC transaction");
        }

        println!("\n=== Test Complete: BTC Transfer Full Spend ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_invalid_signature() {
        println!("\n=== Test: BTC Transfer Invalid Signature ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);

        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (fee_payer_keypair, fee_payer_pubkey, _) = generate_new_keypair(config.network);

        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&fee_payer_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet
        let vault_id = [22u8; 32];
        let (pq_key, _) = generate_wots_keypair(50);
        let (pq_next, _) = generate_wots_keypair(51);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: 10000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created");

        // Anchor fee payer
        let (fp_txid, fp_vout) = helper.send_utxo(fee_payer_pubkey).unwrap();
        let anchor_ix = system_instruction::anchor(
            &fee_payer_pubkey,
            hex::decode(&fp_txid).unwrap().try_into().unwrap(),
            fp_vout,
        );
        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(&[anchor_ix], Some(fee_payer_pubkey), recent_blockhash),
            vec![fee_payer_keypair.clone()],
            config.network,
        ).unwrap();
        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Fee payer anchored");

        // Attempt BTC transfer with invalid signature
        let fee_tx = prepare_fees_and_wait(&helper);

        let recipient_script_pubkey: Vec<u8> = {
            let mut script = vec![0x00, 0x14];
            script.extend_from_slice(&[0xAAu8; 20]);
            script
        };

        let invalid_signature = vec![0xFFu8; 2112]; // wrong WOTS+ signature data

        let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: 1500,
            recipient_script_pubkey,
            fee_tx,
            signature: WinternitzSignature { signature_data: invalid_signature },
        }).unwrap();

        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: false },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                            AccountMeta { pubkey: fee_payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(fee_payer_pubkey),
                recent_blockhash,
            ),
            vec![fee_payer_keypair, owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "BTC transfer with invalid signature should fail"
        );

        println!("\n=== Test PASSED: BTC Transfer Invalid Signature ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_insufficient_btc_balance() {
        println!("\n=== Test: BTC Transfer Insufficient BTC Balance ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);

        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (fee_payer_keypair, fee_payer_pubkey, _) = generate_new_keypair(config.network);

        // Fund and deploy
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&fee_payer_keypair).unwrap();

        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet
        let vault_id = [23u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(60);
        let (pq_next, _) = generate_wots_keypair(61);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: 10000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created");

        // Anchor fee payer
        let (fp_txid, fp_vout) = helper.send_utxo(fee_payer_pubkey).unwrap();
        let anchor_ix = system_instruction::anchor(
            &fee_payer_pubkey,
            hex::decode(&fp_txid).unwrap().try_into().unwrap(),
            fp_vout,
        );
        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(&[anchor_ix], Some(fee_payer_pubkey), recent_blockhash),
            vec![fee_payer_keypair.clone()],
            config.network,
        ).unwrap();
        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Fee payer anchored");

        // Attempt BTC transfer with amount > UTXO value
        // send_utxo creates 3000-sat UTXO; try to transfer 5000
        let fee_tx = prepare_fees_and_wait(&helper);

        let recipient_script_pubkey: Vec<u8> = {
            let mut script = vec![0x00, 0x14];
            script.extend_from_slice(&[0xBBu8; 20]);
            script
        };

        let transfer_amount: u64 = 5000; // exceeds 3000-sat UTXO
        let message = create_btc_transfer_message(
            &pq_key,
            &pq_next,
            &recipient_script_pubkey,
            transfer_amount,
        );
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: false },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                            AccountMeta { pubkey: fee_payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(fee_payer_pubkey),
                recent_blockhash,
            ),
            vec![fee_payer_keypair, owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "BTC transfer exceeding UTXO value should fail"
        );

        println!("\n=== Test PASSED: BTC Transfer Insufficient BTC Balance ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_btc_transfer_unauthorized() {
        println!("\n=== Test: BTC Transfer Unauthorized ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);

        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        let (owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(config.network);
        let (fee_payer_keypair, fee_payer_pubkey, _) = generate_new_keypair(config.network);


        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&attacker_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&fee_payer_keypair).unwrap();

        // Deploy program
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();

        // Initialize factory
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);

        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
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

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair.clone()],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Factory initialized");

        // Create wallet owned by `owner`
        let vault_id = [24u8; 32];
        let (pq_key, private_key) = generate_wots_keypair(70);
        let (pq_next, _) = generate_wots_keypair(71);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo = UtxoMeta::from(
            hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
            wallet_vout,
        );

        let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key.clone(),
            initial_deposit: 10000,
            wallet_utxo,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                    ],
                    data: instruction_data,
                }],
                Some(owner_pubkey),
                recent_blockhash,
            ),
            vec![owner_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Wallet created (owned by owner)");

        // Anchor fee payer
        let (fp_txid, fp_vout) = helper.send_utxo(fee_payer_pubkey).unwrap();
        let anchor_ix = system_instruction::anchor(
            &fee_payer_pubkey,
            hex::decode(&fp_txid).unwrap().try_into().unwrap(),
            fp_vout,
        );
        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(&[anchor_ix], Some(fee_payer_pubkey), recent_blockhash),
            vec![fee_payer_keypair.clone()],
            config.network,
        ).unwrap();
        let txid = client.send_transaction(tx).unwrap();
        client.wait_for_processed_transaction(&txid).unwrap();
        println!("Fee payer anchored");

        // Attacker attempts BTC transfer using their own key as payer
        let fee_tx = prepare_fees_and_wait(&helper);

        let recipient_script_pubkey: Vec<u8> = {
            let mut script = vec![0x00, 0x14];
            script.extend_from_slice(&[0xEEu8; 20]);
            script
        };

        let transfer_amount: u64 = 1500;
        let message = create_btc_transfer_message(
            &pq_key,
            &pq_next,
            &recipient_script_pubkey,
            transfer_amount,
        );
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

        // Attacker signs and submits — wallet PDA derivation will fail
        // because wallet is derived from owner's pubkey, not attacker's
        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[
                    compute_budget_ix,
                    Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                            AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: false },
                            AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                            AccountMeta { pubkey: fee_payer_pubkey, is_signer: true, is_writable: true },
                        ],
                        data: instruction_data,
                    },
                ],
                Some(fee_payer_pubkey),
                recent_blockhash,
            ),
            vec![fee_payer_keypair, attacker_keypair],
            config.network,
        ).unwrap();

        let txid = client.send_transaction(tx).unwrap();
        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "BTC transfer by non-owner should fail"
        );

        println!("\n=== Test PASSED: BTC Transfer Unauthorized ===\n");
    }
}
