// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for DepositToWinternitz instruction

use arch_program::rent::minimum_rent;
use super::*;

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_with_deposit() {
    println!("\n=== Test: DepositToWinternitz With Deposit ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let creation_fee: u64 = 1000;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, creation_fee, 500, 750,
    ).await;

    // Capture factory balance before wallet creation
    let factory_balance_before = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;

    // Create wallet (owner is the payer)
    let vault_id = [1u8; 32];
    let initial_deposit: u64 = 5000;
    let (pq_key, _private_key) = generate_wots_keypair(1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, initial_deposit,
    ).await;

    // Verify wallet state
    verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_key, 0).await;

    // Verify wallet balance received the initial deposit + rent
    let wallet_account = ctx.client.read_account_info(wallet_pubkey).await.unwrap();
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
    ).await;

    // Verify factory balance increased by exactly creation_fee
    let factory_balance_after = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;
    let factory_balance_increase = factory_balance_after - factory_balance_before;
    assert_eq!(
        factory_balance_increase, creation_fee,
        "Factory balance increase {} should equal creation_fee {}",
        factory_balance_increase, creation_fee
    );

    println!("\n=== Test PASSED: DepositToWinternitz With Deposit ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_no_deposit() {
    println!("\n=== Test: DepositToWinternitz No Deposit ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
    ).await;

    // Create wallet with no deposit (owner is the payer)
    let vault_id = [2u8; 32];
    let (pq_key, _) = generate_wots_keypair(2);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 0, // No deposit
    ).await;

    // Verify wallet
    verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_key, 0).await;

    println!("\n=== Test PASSED: DepositToWinternitz No Deposit ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_multiple_wallets_same_owner() {
    println!("\n=== Test: DepositToWinternitz Multiple Wallets Same Owner ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let creation_fee: u64 = 1000;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, creation_fee, 500, 750,
    ).await;

    // Create first wallet with vault_id_1 (owner is the payer)
    let vault_id_1 = [1u8; 32];
    let (pq_key_1, _) = generate_wots_keypair(100);
    let initial_deposit_1: u64 = 5000;

    let (wallet_pubkey_1, _wallet_utxo_1) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id_1, &pq_key_1, initial_deposit_1,
    ).await;
    println!("Wallet 1 created with deposit {}", initial_deposit_1);

    // Create second wallet with vault_id_2 for the same owner
    let vault_id_2 = [2u8; 32];
    let (pq_key_2, _) = generate_wots_keypair(200);
    let initial_deposit_2: u64 = 8000;

    let (wallet_pubkey_2, _wallet_utxo_2) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id_2, &pq_key_2, initial_deposit_2,
    ).await;
    println!("Wallet 2 created with deposit {}", initial_deposit_2);

    // Verify the two wallet PDAs are different
    assert_ne!(
        wallet_pubkey_1, wallet_pubkey_2,
        "Different vault_ids should produce different wallet PDAs"
    );

    // Verify both wallets exist and have correct state
    let owner_bytes = payer_pubkey.serialize();
    verify_wallet_state(&ctx, wallet_pubkey_1, owner_bytes, &pq_key_1, 0).await;
    verify_wallet_state(&ctx, wallet_pubkey_2, owner_bytes, &pq_key_2, 0).await;

    let wallet_rent = minimum_rent(QuipWallet::SPACE);
    let wallet_account_1 = ctx.client.read_account_info(wallet_pubkey_1).await.unwrap();
    let expected_balance_1 = initial_deposit_1 + wallet_rent;
    assert_eq!(
        wallet_account_1.lamports, expected_balance_1,
        "Wallet 1 balance {} should equal deposit {} + rent {}",
        wallet_account_1.lamports, initial_deposit_1, wallet_rent
    );

    let wallet_account_2 = ctx.client.read_account_info(wallet_pubkey_2).await.unwrap();
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
    ).await;

    println!("\n=== Test PASSED: DepositToWinternitz Multiple Wallets Same Owner ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_wrong_system_program() {
    println!("\n=== Test: DepositToWinternitz Wrong System Program ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
    ).await;

    // Create a fake system program account
    let (_fake_system_keypair, fake_system_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Derive wallet PDA
    let vault_id = [42u8; 32];
    let owner_bytes = payer_pubkey.serialize();
    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).await.unwrap();
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

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
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

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_owner_not_signer() {
    println!("\n=== Test: DepositToWinternitz Owner Not Signer ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
    ).await;

    // Create a separate owner account that we won't sign with
    let (_owner_keypair, owner_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Derive wallet PDA for the non-signing owner
    let vault_id = [43u8; 32];
    let owner_bytes = owner_pubkey.serialize();
    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).await.unwrap();
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

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Owner not signer status: {:?}", processed_tx.status);

    assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

    println!("\n=== Test PASSED: DepositToWinternitz Owner Not Signer ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_uninitialized_factory() {
    println!("\n=== Test: DepositToWinternitz Uninitialized Factory ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;

    // Derive factory PDA but don't initialize it
    let (factory_bytes, _) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    // Derive wallet PDA
    let vault_id = [44u8; 32];
    let owner_bytes = payer_pubkey.serialize();
    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).await.unwrap();
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

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Uninitialized factory status: {:?}", processed_tx.status);

    // Factory not initialized = invalid account data
    assert_invalid_account_data(&processed_tx.status);

    println!("\n=== Test PASSED: DepositToWinternitz Uninitialized Factory ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_wrong_factory_pda() {
    println!("\n=== Test: DepositToWinternitz Wrong Factory PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Initialize the real factory
    let _factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
    ).await;

    // Create a wrong/random account to use as factory
    let (_wrong_keypair, wrong_factory_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Derive wallet PDA
    let vault_id = [45u8; 32];
    let owner_bytes = payer_pubkey.serialize();
    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).await.unwrap();
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

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Wrong factory PDA status: {:?}", processed_tx.status);

    // Wrong factory fails PDA derivation check
    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: DepositToWinternitz Wrong Factory PDA ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_wrong_wallet_pda() {
    println!("\n=== Test: DepositToWinternitz Wrong Wallet PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
    ).await;

    // Derive wallet with WRONG vault_id, but pass different vault_id in instruction
    let correct_vault_id = [46u8; 32];
    let wrong_vault_id = [99u8; 32];
    let owner_bytes = payer_pubkey.serialize();

    // Derive wallet using wrong_vault_id
    let (wrong_wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &wrong_vault_id);
    let wrong_wallet_pubkey = Pubkey::from_slice(&wrong_wallet_bytes);

    let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wrong_wallet_pubkey).await.unwrap();
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

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Wrong wallet PDA status: {:?}", processed_tx.status);

    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: DepositToWinternitz Wrong Wallet PDA ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_already_exists() {
    println!("\n=== Test: DepositToWinternitz Already Exists ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
    ).await;

    // Create wallet first time
    let vault_id = [47u8; 32];
    let (pq_key, _) = generate_wots_keypair(47);
    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 1000,
    ).await;
    println!("Wallet created successfully: {:?}", wallet_pubkey);

    // Try to create the same wallet again (same vault_id, same owner)
    let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).await.unwrap();
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

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
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

#[tokio::test]
#[serial]
#[ignore]
async fn test_deposit_to_winternitz_insufficient_balance_for_fee() {
    println!("\n=== Test: DepositToWinternitz Insufficient Balance For Fee ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Set a very high creation fee
    let high_creation_fee: u64 = 1_000_000_000_000; // 1 trillion lamports
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        high_creation_fee, 500, 750,
    ).await;

    // Create a new owner with limited funds
    let (poor_owner_keypair, poor_owner_pubkey, _) = generate_new_keypair(ctx.config.network);
    ctx.client.create_and_fund_account_with_faucet(&poor_owner_keypair).await.unwrap();

    // Derive wallet PDA
    let vault_id = [38u8; 32];
    let owner_bytes = poor_owner_pubkey.serialize();
    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    let (wallet_txid, wallet_vout) = ctx.helper.send_utxo(wallet_pubkey).await.unwrap();
    let wallet_utxo = UtxoMeta::from(
        hex::decode(&wallet_txid).unwrap().try_into().unwrap(),
        wallet_vout,
    );

    let (pq_key, _) = generate_wots_keypair(200);
    let instruction_data = borsh::to_vec(&QuipInstruction::DepositToWinternitz {
        vault_id,
        pq_owner: pq_key,
        deposit: 0, // No deposit, just trying to pay creation fee
        wallet_utxo,
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                    AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                    AccountMeta { pubkey: poor_owner_pubkey, is_signer: true, is_writable: true },
                    AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                ],
                data: instruction_data,
            }],
            Some(poor_owner_pubkey),
            recent_blockhash,
        ),
        vec![poor_owner_keypair],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();

    // Should fail because owner can't afford the creation fee
    // The pre-check with check_sufficient_balance returns InsufficientWalletBalance
    assert_error(&processed_tx.status, QuipError::InsufficientWalletBalance);

    println!("\n=== Test PASSED: DepositToWinternitz Insufficient Balance For Fee ===\n");
}
