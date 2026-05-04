// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for TransferWithWinternitz instruction

use super::*;

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_success() {
    println!("\n=== Test: Transfer Success ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, _payer_keypair, _payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (owner_keypair, owner_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&owner_keypair).await.unwrap();
    ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).await.unwrap();

    let transfer_fee: u64 = 500;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &owner_keypair, owner_pubkey, admin_pubkey, 1000, transfer_fee, 750,
    ).await;

    // Create wallet
    let vault_id = [10u8; 32];
    let initial_deposit: u64 = 10000;
    let (pq_key, private_key) = generate_wots_keypair(1);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &owner_keypair, owner_pubkey,
        vault_id, &pq_key, initial_deposit,
    ).await;
    println!("Wallet created with {} deposit", initial_deposit);

    // Capture balances before transfer
    let balances_before = capture_balances(&ctx, &[wallet_pubkey, factory_pubkey, recipient_pubkey]).await;
    let wallet_balance_before = balances_before[0];
    let factory_balance_before = balances_before[1];
    let recipient_balance_before = balances_before[2];

    // Execute transfer
    let transfer_amount: u64 = 2000;
    let status = execute_transfer(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey, recipient_pubkey,
        &owner_keypair, owner_pubkey, vault_id, &pq_key, &pq_next, &private_key, transfer_amount,
    ).await;
    assert!(status == Status::Processed);

    // Verify wallet state
    verify_wallet_state(&ctx, wallet_pubkey, owner_pubkey.serialize(), &pq_next, 1).await;

    // Verify balance changes
    let balances_after = capture_balances(&ctx, &[wallet_pubkey, factory_pubkey, recipient_pubkey]).await;
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

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_invalid_signature() {
    println!("\n=== Test: Transfer Invalid Signature ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, _payer_keypair, _payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (owner_keypair, owner_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&owner_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &owner_keypair, owner_pubkey, admin_pubkey, 1000, 500, 750,
    ).await;

    // Create wallet
    let vault_id = [12u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(5);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &owner_keypair, owner_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

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
        vec![owner_keypair],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Transfer status: {:?}", processed_tx.status);

    assert_error(&processed_tx.status, QuipError::InvalidWotsSignature);

    println!("\n=== Test PASSED: Transfer Invalid Signature ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_with_winternitz_insufficient_balance() {
    println!("\n=== Test: TransferWithWinternitz Insufficient Balance ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet with very small deposit
    let vault_id = [7u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(7);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);
    let initial_deposit: u64 = 100; // Very small deposit

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, initial_deposit,
    ).await;

    // Attempt transfer larger than balance (should fail)
    let transfer_amount: u64 = 100000; // Much larger than deposit
    let status = execute_transfer(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey, recipient_pubkey,
        &payer_keypair, payer_pubkey, vault_id, &pq_key, &pq_next, &private_key, transfer_amount,
    ).await;

    assert_error(&status, QuipError::InsufficientWalletBalance);

    println!("\n=== Test PASSED: TransferWithWinternitz Insufficient Balance ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_with_winternitz_wrong_wallet_pda() {
    println!("\n=== Test: TransferWithWinternitz Wrong Wallet PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet owned by payer
    let vault_id = [8u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(8);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();

    // After refactor: fails at verify_wallet_address because wallet PDA
    // was derived from original owner, not attacker
    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: TransferWithWinternitz Wrong Wallet PDA ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_with_winternitz_owner_not_signer() {
    println!("\n=== Test: TransferWithWinternitz Owner Not Signer ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (other_keypair, other_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&other_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [80u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(80);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();

    assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

    println!("\n=== Test PASSED: TransferWithWinternitz Owner Not Signer ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_with_winternitz_uninitialized_factory() {
    println!("\n=== Test: TransferWithWinternitz Uninitialized Factory ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();

    // Factory not initialized = invalid account data
    assert_invalid_account_data(&processed_tx.status);

    println!("\n=== Test PASSED: TransferWithWinternitz Uninitialized Factory ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_with_winternitz_uninitialized_wallet() {
    println!("\n=== Test: TransferWithWinternitz Uninitialized Wallet ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();

    // Wallet not created = invalid account data
    assert_invalid_account_data(&processed_tx.status);

    println!("\n=== Test PASSED: TransferWithWinternitz Uninitialized Wallet ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_with_winternitz_wrong_factory_pda() {
    println!("\n=== Test: TransferWithWinternitz Wrong Factory PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (random_keypair, random_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&random_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [83u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(83);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

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
    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();

    // Random account fails PDA derivation check
    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: TransferWithWinternitz Wrong Factory PDA ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_with_winternitz_zero_amount() {
    println!("\n=== Test: Transfer With Winternitz Zero Amount ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet
    let vault_id = [36u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(180);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Execute transfer with zero amount (should succeed as a no-op for lamports)
    let transfer_amount: u64 = 0;
    let status = execute_transfer(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey, recipient_pubkey,
        &payer_keypair, payer_pubkey, vault_id, &pq_key, &pq_next, &private_key, transfer_amount,
    ).await;

    // Zero lamport transfer should succeed (fee is still paid, key is rotated)
    assert!(status == Status::Processed, "Zero amount transfer should succeed");

    // Verify wallet state was updated (key rotated)
    verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_next, 1).await;

    println!("\n=== Test PASSED: Transfer With Winternitz Zero Amount ===\n");
}
