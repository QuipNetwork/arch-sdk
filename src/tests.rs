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
    use borsh::BorshDeserialize;
    use hashsigs::WOTSPlus;
    use serial_test::serial;

    use crate::instruction::QuipInstruction;
    use crate::state::{
        OpdataStorage, QuipFactory, QuipWallet, SignatureStorage,
        WinternitzPublicKey,
    };
    use crate::utils::{
        create_change_owner_message, create_transfer_message,
        derive_factory_address, derive_opdata_storage_address,
        derive_signature_storage_address, derive_wallet_address,
    };

    const ELF_PATH: &str = "target/sbpf-solana-solana/release/quip_arch.so";

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
        println!("Config: network={:?}, titan_url={}", config.network, config.titan_url);

        let client = ArchRpcClient::new(&config);
        let helper = BitcoinHelper::new(&config);
        println!("Initialized ArchRpcClient and BitcoinHelper");

        // Generate keypairs
        let (authority_keypair, authority_pubkey, _) = generate_new_keypair(config.network);
        println!("Generated authority keypair: {}", authority_pubkey);

        let (program_keypair, _, _) = generate_new_keypair(config.network);
        println!("Generated program keypair");

        let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(config.network);
        println!("Generated admin keypair: {}", admin_pubkey);

        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);
        println!("Generated payer keypair: {}", payer_pubkey);

        // Fund accounts
        client
            .create_and_fund_account_with_faucet(&authority_keypair)
            .expect("Failed to fund authority");
        println!("Funded authority account");

        client
            .create_and_fund_account_with_faucet(&payer_keypair)
            .expect("Failed to fund payer");
        println!("Funded payer account");

        // Deploy program
        println!("\n--- Deploying Program ---");
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .expect("Failed to deploy program");
        println!("Program deployed at: {}", program_pubkey);

        // Derive factory PDA
        let (factory_bytes, factory_bump) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);
        println!("Factory PDA: {} (bump: {})", factory_pubkey, factory_bump);

        // Create UTXO for factory account
        println!("\n--- Creating Factory UTXO ---");
        let (factory_txid, factory_vout) = helper
            .send_utxo(factory_pubkey)
            .expect("Failed to send UTXO for factory");
        println!("Factory UTXO: {}:{}", factory_txid, factory_vout);

        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        // Build and send InitializeFactory transaction
        println!("\n--- Initializing Factory ---");
        let creation_fee: u64 = 1000;
        let transfer_fee: u64 = 500;
        let execute_fee: u64 = 750;
        println!("Fees - creation: {}, transfer: {}, execute: {}", creation_fee, transfer_fee, execute_fee);

        let instruction_data = borsh::to_vec(&QuipInstruction::InitializeFactory {
            admin: admin_pubkey.serialize(),
            creation_fee,
            transfer_fee,
            execute_fee,
            factory_utxo,
        }).expect("Failed to serialize instruction");
        println!("Instruction data serialized: {} bytes", instruction_data.len());

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
        println!("Accounts: factory={}, payer={}, system_program={}",
            factory_pubkey, payer_pubkey, system_program::SYSTEM_PROGRAM_ID);

        let recent_blockhash = client
            .get_best_finalized_block_hash()
            .expect("Failed to get blockhash");
        println!("Recent blockhash: {:?}", recent_blockhash);

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
        println!("Transaction sent: {}", txid);

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
        println!("\n--- Verifying Factory State ---");
        let factory_account = client
            .read_account_info(factory_pubkey)
            .expect("Failed to read factory account");
        println!("Factory account data: {} bytes", factory_account.data.len());

        let factory = QuipFactory::try_from_slice(&factory_account.data)
            .expect("Failed to deserialize factory");

        assert!(factory.is_initialized, "Factory should be initialized");
        println!("is_initialized: {}", factory.is_initialized);

        assert_eq!(factory.admin, admin_pubkey.serialize(), "Admin mismatch");
        println!("admin: {} (matches)", admin_pubkey);

        assert_eq!(factory.creation_fee, creation_fee, "Creation fee mismatch");
        println!("creation_fee: {}", factory.creation_fee);

        assert_eq!(factory.transfer_fee, transfer_fee, "Transfer fee mismatch");
        println!("transfer_fee: {}", factory.transfer_fee);

        assert_eq!(factory.execute_fee, execute_fee, "Execute fee mismatch");
        println!("execute_fee: {}", factory.execute_fee);

        assert_eq!(factory.total_wallets, 0, "Total wallets should be 0");
        println!("total_wallets: {}", factory.total_wallets);

        assert_eq!(factory.accumulated_fees, 0, "Accumulated fees should be 0");
        println!("accumulated_fees: {}", factory.accumulated_fees);

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

        println!("Authority: {}", authority_pubkey);
        println!("Admin: {}", admin_pubkey);
        println!("Payer: {}", payer_pubkey);

        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();
        println!("Funded authority and payer accounts");

        // Deploy program
        println!("\n--- Deploying Program ---");
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();
        println!("Program deployed at: {}", program_pubkey);

        // Derive factory PDA
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);
        println!("Factory PDA: {}", factory_pubkey);

        // First initialization
        println!("\n--- First Initialization ---");
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
        println!("\n--- Second Initialization (should fail) ---");
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
    fn test_create_wallet_with_deposit() {
        println!("\n=== Test: Create Wallet With Deposit ===\n");

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

        println!("Authority: {}", authority_pubkey);
        println!("Admin: {}", admin_pubkey);
        println!("Payer: {}", payer_pubkey);
        println!("Owner: {}", owner_pubkey);

        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&payer_keypair).unwrap();
        println!("Funded authority and payer accounts");

        // Deploy program
        println!("\n--- Deploying Program ---");
        let deployer = ProgramDeployer::new(&config);
        let program_pubkey = deployer
            .try_deploy_program(
                "quip-arch".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .unwrap();
        println!("Program deployed at: {}", program_pubkey);

        // Initialize factory
        println!("\n--- Initializing Factory ---");
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);
        println!("Factory PDA: {}", factory_pubkey);

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

        // Create wallet
        println!("\n--- Creating Wallet ---");
        let vault_id = [1u8; 32];
        let initial_deposit: u64 = 5000;
        let (pq_key, _private_key) = generate_wots_keypair(1);
        println!("Vault ID: {:?}", &vault_id[..4]);
        println!("Initial deposit: {}", initial_deposit);
        println!("PQ key public_seed: {:?}", &pq_key.public_seed[..8]);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, wallet_bump) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);
        println!("Wallet PDA: {} (bump: {})", wallet_pubkey, wallet_bump);

        let (wallet_txid, wallet_vout) = helper.send_utxo(wallet_pubkey).unwrap();
        println!("Wallet UTXO: {}:{}", wallet_txid, wallet_vout);
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
            tx_hex: vec![],
        }).unwrap();
        println!("Instruction data: {} bytes", instruction_data.len());

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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify wallet state
        println!("\n--- Verifying Wallet State ---");
        let wallet_account = client.read_account_info(wallet_pubkey).unwrap();
        println!("Wallet account data: {} bytes", wallet_account.data.len());

        let wallet = QuipWallet::try_from_slice(&wallet_account.data).unwrap();
        assert!(wallet.is_initialized);
        println!("is_initialized: {}", wallet.is_initialized);

        assert_eq!(wallet.owner, owner_bytes);
        println!("owner: {} (matches)", owner_pubkey);

        assert_eq!(wallet.pq_owner.public_seed, pq_key.public_seed);
        assert_eq!(wallet.pq_owner.public_key_hash, pq_key.public_key_hash);
        println!("pq_owner: matches");

        assert_eq!(wallet.transaction_count, 0);
        println!("transaction_count: {}", wallet.transaction_count);

        // Verify factory state
        println!("\n--- Verifying Factory State ---");
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();

        assert_eq!(factory.total_wallets, 1);
        println!("total_wallets: {}", factory.total_wallets);

        assert_eq!(factory.accumulated_fees, creation_fee);
        println!("accumulated_fees: {}", factory.accumulated_fees);

        println!("\n=== Test PASSED: Create Wallet With Deposit ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_create_wallet_no_deposit() {
        println!("\n=== Test: Create Wallet No Deposit ===\n");

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

        println!("Payer: {}", payer_pubkey);
        println!("Owner: {}", owner_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

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
        println!("\n--- Creating Wallet (no deposit) ---");
        let vault_id = [2u8; 32];
        let (pq_key, _) = generate_wots_keypair(2);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);
        println!("Wallet PDA: {}", wallet_pubkey);

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
            tx_hex: vec![],
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
        println!("Wallet initialized: {}", wallet.is_initialized);

        println!("\n=== Test PASSED: Create Wallet No Deposit ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_create_wallet_duplicate() {
        println!("\n=== Test: Create Wallet Duplicate ===\n");

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

        println!("Payer: {}", payer_pubkey);
        println!("Owner: {}", owner_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

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

        // Create first wallet
        println!("\n--- Creating First Wallet ---");
        let vault_id = [3u8; 32];
        let (pq_key, _) = generate_wots_keypair(3);

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
            initial_deposit: 1000,
            wallet_utxo,
            tx_hex: vec![],
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
        println!("First wallet created");

        // Attempt duplicate wallet creation
        println!("\n--- Creating Duplicate Wallet (should fail) ---");
        let (wallet_txid2, wallet_vout2) = helper.send_utxo(wallet_pubkey).unwrap();
        let wallet_utxo2 = UtxoMeta::from(
            hex::decode(&wallet_txid2).unwrap().try_into().unwrap(),
            wallet_vout2,
        );

        let instruction_data2 = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
            vault_id,
            to: owner_bytes,
            pq_to: pq_key,
            initial_deposit: 1000,
            wallet_utxo: wallet_utxo2,
            tx_hex: vec![],
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
        println!("Duplicate wallet status: {:?}", processed_tx2.status);

        assert!(
            matches!(processed_tx2.status, Status::Failed(_)),
            "Duplicate wallet creation should fail"
        );

        println!("\n=== Test PASSED: Create Wallet Duplicate ===\n");
    }

    // =============================================================================
    // Storage Tests
    // =============================================================================

    #[test]
    #[serial]
    #[ignore]
    fn test_store_signature_single_chunk() {
        println!("\n=== Test: Store Signature Single Chunk ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);

        println!("Owner: {}", owner_pubkey);
        println!("Payer: {}", payer_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

        // Derive signature storage PDA
        let owner_bytes = owner_pubkey.serialize();
        let (storage_bytes, storage_bump) = derive_signature_storage_address(&program_pubkey, &owner_bytes);
        let storage_pubkey = Pubkey::from_slice(&storage_bytes);
        println!("Signature storage PDA: {} (bump: {})", storage_pubkey, storage_bump);

        // Store signature (single chunk)
        println!("\n--- Storing Signature ---");
        let signature_data = vec![0xABu8; 500];
        println!("Signature data size: {} bytes", signature_data.len());

        let instruction_data = borsh::to_vec(&QuipInstruction::StoreSignature {
            chunk_data: signature_data.clone(),
            is_first_chunk: true,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: storage_pubkey, is_signer: false, is_writable: true },
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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify storage state
        println!("\n--- Verifying Storage State ---");
        let storage_account = client.read_account_info(storage_pubkey).unwrap();
        println!("Storage account data: {} bytes", storage_account.data.len());

        let storage = SignatureStorage::try_from_slice(&storage_account.data).unwrap();
        assert!(storage.is_initialized);
        println!("is_initialized: {}", storage.is_initialized);

        assert_eq!(storage.signature_data, signature_data);
        println!("signature_data: matches ({} bytes)", storage.signature_data.len());

        println!("\n=== Test PASSED: Store Signature Single Chunk ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_store_signature_multiple_chunks() {
        println!("\n=== Test: Store Signature Multiple Chunks ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);

        println!("Owner: {}", owner_pubkey);
        println!("Payer: {}", payer_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

        // Derive signature storage PDA
        let owner_bytes = owner_pubkey.serialize();
        let (storage_bytes, _) = derive_signature_storage_address(&program_pubkey, &owner_bytes);
        let storage_pubkey = Pubkey::from_slice(&storage_bytes);
        println!("Signature storage PDA: {}", storage_pubkey);

        // Store signature in multiple chunks
        println!("\n--- Storing Signature (multiple chunks) ---");
        let signature_data = vec![0xCDu8; 2000];
        println!("Total signature data size: {} bytes", signature_data.len());

        const MAX_CHUNK_SIZE: usize = 900;
        let chunks: Vec<&[u8]> = signature_data.chunks(MAX_CHUNK_SIZE).collect();
        println!("Number of chunks: {}", chunks.len());

        for (i, chunk) in chunks.iter().enumerate() {
            let is_first_chunk = i == 0;
            println!("Sending chunk {} ({} bytes, is_first: {})", i, chunk.len(), is_first_chunk);

            let instruction_data = borsh::to_vec(&QuipInstruction::StoreSignature {
                chunk_data: chunk.to_vec(),
                is_first_chunk,
            }).unwrap();

            let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
            let tx = build_and_sign_transaction(
                ArchMessage::new(
                    &[Instruction {
                        program_id: program_pubkey,
                        accounts: vec![
                            AccountMeta { pubkey: storage_pubkey, is_signer: false, is_writable: true },
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
            println!("Chunk {} status: {:?}", i, processed_tx.status);
            assert!(processed_tx.status == Status::Processed);
        }

        // Verify storage state
        println!("\n--- Verifying Storage State ---");
        let storage_account = client.read_account_info(storage_pubkey).unwrap();
        let storage = SignatureStorage::try_from_slice(&storage_account.data).unwrap();

        assert!(storage.is_initialized);
        println!("is_initialized: {}", storage.is_initialized);

        assert_eq!(storage.signature_data, signature_data);
        println!("signature_data: matches ({} bytes)", storage.signature_data.len());

        println!("\n=== Test PASSED: Store Signature Multiple Chunks ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_store_signature_too_large() {
        println!("\n=== Test: Store Signature Too Large ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);

        println!("Owner: {}", owner_pubkey);
        println!("Payer: {}", payer_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

        // Derive signature storage PDA
        let owner_bytes = owner_pubkey.serialize();
        let (storage_bytes, _) = derive_signature_storage_address(&program_pubkey, &owner_bytes);
        let storage_pubkey = Pubkey::from_slice(&storage_bytes);
        println!("Signature storage PDA: {}", storage_pubkey);

        // Attempt to store oversized signature
        println!("\n--- Attempting to Store Oversized Signature ---");
        let oversized_data = vec![0xEFu8; SignatureStorage::MAX_SIGNATURE_SIZE + 100];
        println!("Oversized data size: {} bytes (max: {})",
            oversized_data.len(), SignatureStorage::MAX_SIGNATURE_SIZE);

        let instruction_data = borsh::to_vec(&QuipInstruction::StoreSignature {
            chunk_data: oversized_data,
            is_first_chunk: true,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: storage_pubkey, is_signer: false, is_writable: true },
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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Oversized signature should be rejected"
        );

        println!("\n=== Test PASSED: Store Signature Too Large ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_store_opdata_single_chunk() {
        println!("\n=== Test: Store Opdata Single Chunk ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);

        println!("Owner: {}", owner_pubkey);
        println!("Payer: {}", payer_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

        // Derive opdata storage PDA
        let owner_bytes = owner_pubkey.serialize();
        let (storage_bytes, storage_bump) = derive_opdata_storage_address(&program_pubkey, &owner_bytes);
        let storage_pubkey = Pubkey::from_slice(&storage_bytes);
        println!("Opdata storage PDA: {} (bump: {})", storage_pubkey, storage_bump);

        // Store opdata
        println!("\n--- Storing Opdata ---");
        let opdata = vec![0x12u8; 500];
        println!("Opdata size: {} bytes", opdata.len());

        let instruction_data = borsh::to_vec(&QuipInstruction::StoreOpdata {
            opdata_chunk: opdata.clone(),
            is_first_chunk: true,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: storage_pubkey, is_signer: false, is_writable: true },
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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify storage state
        println!("\n--- Verifying Storage State ---");
        let storage_account = client.read_account_info(storage_pubkey).unwrap();
        let storage = OpdataStorage::try_from_slice(&storage_account.data).unwrap();

        assert!(storage.is_initialized);
        println!("is_initialized: {}", storage.is_initialized);

        assert_eq!(storage.opdata, opdata);
        println!("opdata: matches ({} bytes)", storage.opdata.len());

        println!("\n=== Test PASSED: Store Opdata Single Chunk ===\n");
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_store_opdata_too_large() {
        println!("\n=== Test: Store Opdata Too Large ===\n");

        // Setup
        let mut config = Config::localnet();
        config.titan_url = "http://127.0.0.1:8080".to_string();
        let client = ArchRpcClient::new(&config);

        // Generate keypairs
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
            
        let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(config.network);
        let (payer_keypair, payer_pubkey, _) = generate_new_keypair(config.network);

        println!("Owner: {}", owner_pubkey);
        println!("Payer: {}", payer_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

        // Derive opdata storage PDA
        let owner_bytes = owner_pubkey.serialize();
        let (storage_bytes, _) = derive_opdata_storage_address(&program_pubkey, &owner_bytes);
        let storage_pubkey = Pubkey::from_slice(&storage_bytes);
        println!("Opdata storage PDA: {}", storage_pubkey);

        // Attempt to store oversized opdata
        println!("\n--- Attempting to Store Oversized Opdata ---");
        let oversized_data = vec![0x34u8; OpdataStorage::MAX_OPDATA_SIZE + 100];
        println!("Oversized data size: {} bytes (max: {})",
            oversized_data.len(), OpdataStorage::MAX_OPDATA_SIZE);

        let instruction_data = borsh::to_vec(&QuipInstruction::StoreOpdata {
            opdata_chunk: oversized_data,
            is_first_chunk: true,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: storage_pubkey, is_signer: false, is_writable: true },
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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Oversized opdata should be rejected"
        );

        println!("\n=== Test PASSED: Store Opdata Too Large ===\n");
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
        let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(config.network);

        println!("Owner: {}", owner_pubkey);
        println!("Recipient: {}", recipient_pubkey);

        // Fund accounts
        client.create_and_fund_account_with_faucet(&authority_keypair).unwrap();
        client.create_and_fund_account_with_faucet(&owner_keypair).unwrap();
        println!("Funded authority and owner accounts");

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
        println!("Program deployed at: {}", program_pubkey);

        // Initialize factory
        println!("\n--- Initializing Factory ---");
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
        println!("\n--- Creating Wallet ---");
        let vault_id = [10u8; 32];
        let initial_deposit: u64 = 10000;
        let (pq_key, private_key) = generate_wots_keypair(1);
        let (pq_next, _next_private_key) = generate_wots_keypair(2);

        let owner_bytes = owner_pubkey.serialize();
        let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
        let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);
        println!("Wallet PDA: {}", wallet_pubkey);

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
            tx_hex: vec![],
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

        // Create and store signature
        println!("\n--- Storing Signature ---");
        let transfer_amount: u64 = 2000;
        let recipient_bytes = recipient_pubkey.serialize();
        let message = create_transfer_message(&pq_key, &pq_next, &recipient_bytes, transfer_amount);
        let signature_data = sign_message(&private_key, &message);
        println!("Signature created: {} bytes", signature_data.len());

        let (sig_storage_bytes, _) = derive_signature_storage_address(&program_pubkey, &owner_bytes);
        let signature_storage_pubkey = Pubkey::from_slice(&sig_storage_bytes);

        let instruction_data = borsh::to_vec(&QuipInstruction::StoreSignature {
            chunk_data: signature_data,
            is_first_chunk: true,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: signature_storage_pubkey, is_signer: false, is_writable: true },
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
        println!("Signature stored at: {}", signature_storage_pubkey);

        // Execute transfer
        println!("\n--- Executing Transfer ---");
        println!("Transfer amount: {}", transfer_amount);
        println!("Recipient: {}", recipient_pubkey);

        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: transfer_amount,
            tx_hex: vec![],
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: signature_storage_pubkey, is_signer: false, is_writable: false },
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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify wallet state
        println!("\n--- Verifying Wallet State ---");
        let wallet_account = client.read_account_info(wallet_pubkey).unwrap();
        let wallet = QuipWallet::try_from_slice(&wallet_account.data).unwrap();

        assert_eq!(wallet.pq_owner.public_seed, pq_next.public_seed);
        assert_eq!(wallet.pq_owner.public_key_hash, pq_next.public_key_hash);
        println!("pq_owner: rotated to next key");

        assert_eq!(wallet.transaction_count, 1);
        println!("transaction_count: {}", wallet.transaction_count);

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

        println!("Owner: {}", owner_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

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
            tx_hex: vec![],
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

        // Store INVALID signature (random data)
        println!("\n--- Storing Invalid Signature ---");
        let invalid_signature = vec![0xFFu8; 2112]; // WOTS+ signature size but random data
        println!("Invalid signature size: {} bytes", invalid_signature.len());

        let (sig_storage_bytes, _) = derive_signature_storage_address(&program_pubkey, &owner_bytes);
        let signature_storage_pubkey = Pubkey::from_slice(&sig_storage_bytes);

        let instruction_data = borsh::to_vec(&QuipInstruction::StoreSignature {
            chunk_data: invalid_signature,
            is_first_chunk: true,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: signature_storage_pubkey, is_signer: false, is_writable: true },
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
        println!("Invalid signature stored");

        // Attempt transfer with invalid signature
        println!("\n--- Attempting Transfer (should fail) ---");
        let instruction_data = borsh::to_vec(&QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next: pq_next.clone(),
            amount: 1000,
            tx_hex: vec![],
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: signature_storage_pubkey, is_signer: false, is_writable: false },
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

        println!("Owner: {}", owner_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

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
        println!("\n--- Creating Wallet ---");
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
            tx_hex: vec![],
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

        // Create and store signature for key change
        println!("\n--- Storing Signature for Key Change ---");
        let message = create_change_owner_message(&pq_key, &pq_next);
        let signature_data = sign_message(&private_key, &message);
        println!("Signature created: {} bytes", signature_data.len());

        let (sig_storage_bytes, _) = derive_signature_storage_address(&program_pubkey, &owner_bytes);
        let signature_storage_pubkey = Pubkey::from_slice(&sig_storage_bytes);

        let instruction_data = borsh::to_vec(&QuipInstruction::StoreSignature {
            chunk_data: signature_data,
            is_first_chunk: true,
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: signature_storage_pubkey, is_signer: false, is_writable: true },
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
        println!("Signature stored");

        // Execute key change
        println!("\n--- Changing PQ Owner ---");
        let instruction_data = borsh::to_vec(&QuipInstruction::ChangePqOwner {
            vault_id,
            pq_next: pq_next.clone(),
        }).unwrap();

        let recent_blockhash = client.get_best_finalized_block_hash().unwrap();
        let tx = build_and_sign_transaction(
            ArchMessage::new(
                &[Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: owner_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: signature_storage_pubkey, is_signer: false, is_writable: false },
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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify wallet state
        println!("\n--- Verifying Wallet State ---");
        let wallet_account = client.read_account_info(wallet_pubkey).unwrap();
        let wallet = QuipWallet::try_from_slice(&wallet_account.data).unwrap();

        assert_eq!(wallet.pq_owner.public_seed, pq_next.public_seed);
        assert_eq!(wallet.pq_owner.public_key_hash, pq_next.public_key_hash);
        println!("pq_owner: rotated to next key");

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

        println!("Admin: {}", admin_pubkey);
        println!("Payer: {}", payer_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

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
        println!("\n--- Updating Fees ---");
        let new_creation_fee: u64 = 2000;
        let new_transfer_fee: u64 = 1000;
        let new_execute_fee: u64 = 1500;
        println!("New fees - creation: {}, transfer: {}, execute: {}",
            new_creation_fee, new_transfer_fee, new_execute_fee);

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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify factory state
        println!("\n--- Verifying Factory State ---");
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();

        assert_eq!(factory.creation_fee, new_creation_fee);
        println!("creation_fee: {}", factory.creation_fee);

        assert_eq!(factory.transfer_fee, new_transfer_fee);
        println!("transfer_fee: {}", factory.transfer_fee);

        assert_eq!(factory.execute_fee, new_execute_fee);
        println!("execute_fee: {}", factory.execute_fee);

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

        println!("Admin: {}", admin_pubkey);
        println!("Non-admin: {}", non_admin_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

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
        println!("\n--- Attempting Unauthorized Fee Update ---");
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

        println!("Admin: {}", admin_pubkey);
        println!("New Admin: {}", new_admin_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

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
        println!("\n--- Transferring Ownership ---");
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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);
        assert!(processed_tx.status == Status::Processed);

        // Verify new admin
        println!("\n--- Verifying New Admin ---");
        let factory_account = client.read_account_info(factory_pubkey).unwrap();
        let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();

        assert_eq!(factory.admin, new_admin_pubkey.serialize());
        println!("admin: {} (new admin)", new_admin_pubkey);

        // Verify new admin can update fees
        println!("\n--- New Admin Updating Fees ---");
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
        println!("\n--- Old Admin Attempting Fee Update (should fail) ---");
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

        println!("Payer: {}", payer_pubkey);
        println!("Fake system program: {}", fake_system_pubkey);

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
        println!("Program deployed at: {}", program_pubkey);

        // Derive factory PDA
        let (factory_bytes, _) = derive_factory_address(&program_pubkey);
        let factory_pubkey = Pubkey::from_slice(&factory_bytes);
        println!("Factory PDA: {}", factory_pubkey);

        // Create UTXO for factory
        let (factory_txid, factory_vout) = helper.send_utxo(factory_pubkey).unwrap();
        let factory_utxo = UtxoMeta::from(
            hex::decode(&factory_txid).unwrap().try_into().unwrap(),
            factory_vout,
        );

        // Attempt init with fake system program
        println!("\n--- Attempting Init with Fake System Program ---");
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
        println!("Transaction sent: {}", txid);

        let processed_tx = client.wait_for_processed_transaction(&txid).unwrap();
        println!("Transaction status: {:?}", processed_tx.status);

        assert!(
            matches!(processed_tx.status, Status::Failed(_)),
            "Fake system program should be rejected"
        );

        println!("\n=== Test PASSED: Fake System Program Rejected ===\n");
    }
}
