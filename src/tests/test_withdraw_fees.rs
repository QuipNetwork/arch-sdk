// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for WithdrawFees instruction

use super::*;

#[tokio::test]
#[serial]
#[ignore]
async fn test_withdraw_fees_success() {
    println!("\n=== Test: WithdrawFees Success ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&admin_keypair).await.unwrap();
    ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).await.unwrap();

    let creation_fee: u64 = 1000;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        creation_fee, 500, 750,
    ).await;

    // Create a wallet to accumulate fees
    let vault_id = [11u8; 32];
    let (pq_key, _) = generate_wots_keypair(11);

    let (_wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 5000,
    ).await;

    // Capture recipient balance before withdrawal
    let recipient_balance_before = ctx.client.read_account_info(recipient_pubkey).await.unwrap().lamports;

    // Withdraw fees
    let withdraw_amount: u64 = 500;
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &admin_keypair, admin_pubkey, recipient_pubkey, withdraw_amount,
    ).await;

    assert!(status == Status::Processed, "WithdrawFees should succeed");

    // Verify factory state after withdrawal
    let factory_account = ctx.client.read_account_info(factory_pubkey).await.unwrap();
    let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
    assert_eq!(factory.accumulated_fees, creation_fee - withdraw_amount);

    // Verify recipient received funds
    let recipient_balance_after = ctx.client.read_account_info(recipient_pubkey).await.unwrap().lamports;
    let recipient_balance_increase = recipient_balance_after - recipient_balance_before;
    assert_eq!(
        recipient_balance_increase, withdraw_amount,
        "Recipient balance increase {} should equal withdraw_amount {}",
        recipient_balance_increase, withdraw_amount
    );

    println!("\n=== Test PASSED: WithdrawFees Success ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_withdraw_fees_unauthorized() {
    println!("\n=== Test: WithdrawFees Unauthorized ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create a wallet to accumulate fees
    let vault_id = [12u8; 32];
    let (pq_key, _) = generate_wots_keypair(12);

    let (_wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 5000,
    ).await;

    // Attacker attempts to withdraw fees (should fail)
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &attacker_keypair, attacker_pubkey, attacker_pubkey, 500,
    ).await;

    assert_error(&status, QuipError::UnauthorizedSigner);

    println!("\n=== Test PASSED: WithdrawFees Unauthorized ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_withdraw_fees_insufficient() {
    println!("\n=== Test: WithdrawFees Insufficient ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&admin_keypair).await.unwrap();

    let creation_fee: u64 = 100; // Small fee
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        creation_fee, 50, 75,
    ).await;

    // Create a wallet to accumulate some fees
    let vault_id = [13u8; 32];
    let (pq_key, _) = generate_wots_keypair(13);

    let (_wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 1000,
    ).await;

    // Attempt to withdraw more than accumulated (should fail)
    let withdraw_amount: u64 = 10000; // Much more than accumulated
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &admin_keypair, admin_pubkey, recipient_pubkey, withdraw_amount,
    ).await;

    assert_error(&status, QuipError::InsufficientFunds);

    println!("\n=== Test PASSED: WithdrawFees Insufficient ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_withdraw_fees_wrong_factory() {
    println!("\n=== Test: WithdrawFees Wrong Factory ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&admin_keypair).await.unwrap();

    let creation_fee: u64 = 1000;
    let _factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        creation_fee, 500, 750,
    ).await;

    // Create a wrong/random account to use as factory
    let (_wrong_keypair, wrong_factory_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Attempt to withdraw with wrong factory (should fail)
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, wrong_factory_pubkey,
        &admin_keypair, admin_pubkey, recipient_pubkey, 500,
    ).await;

    assert_error(&status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: WithdrawFees Wrong Factory ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_withdraw_fees_zero_amount() {
    println!("\n=== Test: WithdrawFees Zero Amount ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&admin_keypair).await.unwrap();
    ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).await.unwrap();

    let creation_fee: u64 = 1000;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        creation_fee, 500, 750,
    ).await;

    // Create a wallet to accumulate fees
    let vault_id = [14u8; 32];
    let (pq_key, _) = generate_wots_keypair(14);

    let (_wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 5000,
    ).await;

    // Capture recipient balance before withdrawal
    let recipient_balance_before = ctx.client.read_account_info(recipient_pubkey).await.unwrap().lamports;

    // Withdraw zero fees (should succeed as no-op)
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &admin_keypair, admin_pubkey, recipient_pubkey, 0,
    ).await;

    assert!(status == Status::Processed, "WithdrawFees with zero amount should succeed");

    // Verify factory state unchanged
    let factory_account = ctx.client.read_account_info(factory_pubkey).await.unwrap();
    let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
    assert_eq!(factory.accumulated_fees, creation_fee);

    // Verify recipient balance unchanged
    let recipient_balance_after = ctx.client.read_account_info(recipient_pubkey).await.unwrap().lamports;
    assert_eq!(recipient_balance_before, recipient_balance_after);

    println!("\n=== Test PASSED: WithdrawFees Zero Amount ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_withdraw_fees_exact_accumulated() {
    println!("\n=== Test: WithdrawFees Exact Accumulated ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&admin_keypair).await.unwrap();
    ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).await.unwrap();

    let creation_fee: u64 = 1000;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        creation_fee, 500, 750,
    ).await;

    // Create a wallet to accumulate fees
    let vault_id = [15u8; 32];
    let (pq_key, _) = generate_wots_keypair(15);

    let (_wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 5000,
    ).await;

    // Capture recipient balance before withdrawal
    let recipient_balance_before = ctx.client.read_account_info(recipient_pubkey).await.unwrap().lamports;

    // Withdraw exactly accumulated fees (should drain to 0)
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &admin_keypair, admin_pubkey, recipient_pubkey, creation_fee,
    ).await;

    assert!(status == Status::Processed, "WithdrawFees exact accumulated should succeed");

    // Verify factory accumulated_fees is now 0
    let factory_account = ctx.client.read_account_info(factory_pubkey).await.unwrap();
    let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
    assert_eq!(factory.accumulated_fees, 0);

    // Verify recipient received funds
    let recipient_balance_after = ctx.client.read_account_info(recipient_pubkey).await.unwrap().lamports;
    let recipient_balance_increase = recipient_balance_after - recipient_balance_before;
    assert_eq!(recipient_balance_increase, creation_fee);

    println!("\n=== Test PASSED: WithdrawFees Exact Accumulated ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_withdraw_fees_multiple_sequential() {
    println!("\n=== Test: WithdrawFees Multiple Sequential ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&admin_keypair).await.unwrap();
    ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).await.unwrap();

    let creation_fee: u64 = 1000;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        creation_fee, 500, 750,
    ).await;

    // Create a wallet to accumulate fees
    let vault_id = [16u8; 32];
    let (pq_key, _) = generate_wots_keypair(16);

    let (_wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 5000,
    ).await;

    // Capture recipient balance before withdrawals
    let recipient_balance_before = ctx.client.read_account_info(recipient_pubkey).await.unwrap().lamports;

    // First withdrawal: 300
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &admin_keypair, admin_pubkey, recipient_pubkey, 300,
    ).await;
    assert!(status == Status::Processed, "First withdrawal should succeed");

    // Verify factory state after first withdrawal
    let factory_account = ctx.client.read_account_info(factory_pubkey).await.unwrap();
    let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
    assert_eq!(factory.accumulated_fees, creation_fee - 300);

    // Second withdrawal: 400
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &admin_keypair, admin_pubkey, recipient_pubkey, 400,
    ).await;
    assert!(status == Status::Processed, "Second withdrawal should succeed");

    // Verify factory state after second withdrawal
    let factory_account = ctx.client.read_account_info(factory_pubkey).await.unwrap();
    let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
    assert_eq!(factory.accumulated_fees, creation_fee - 300 - 400);

    // Third withdrawal: 300 (remaining)
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &admin_keypair, admin_pubkey, recipient_pubkey, 300,
    ).await;
    assert!(status == Status::Processed, "Third withdrawal should succeed");

    // Verify factory state after third withdrawal (should be 0)
    let factory_account = ctx.client.read_account_info(factory_pubkey).await.unwrap();
    let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
    assert_eq!(factory.accumulated_fees, 0);

    // Verify recipient received total funds
    let recipient_balance_after = ctx.client.read_account_info(recipient_pubkey).await.unwrap().lamports;
    let recipient_balance_increase = recipient_balance_after - recipient_balance_before;
    assert_eq!(recipient_balance_increase, creation_fee);

    // Fourth withdrawal should fail (no more fees)
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &admin_keypair, admin_pubkey, recipient_pubkey, 1,
    ).await;
    assert_error(&status, QuipError::InsufficientFunds);

    println!("\n=== Test PASSED: WithdrawFees Multiple Sequential ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_withdraw_fees_admin_not_signer() {
    println!("\n=== Test: Withdraw Fees Admin Not Signer ===\n");

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

    // Create a wallet to accumulate fees
    let vault_id = [35u8; 32];
    let (pq_key, _) = generate_wots_keypair(170);
    let (_wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 5000,
    ).await;

    // Attempt withdrawal with admin NOT as signer
    let instruction_data = borsh::to_vec(&QuipInstruction::WithdrawFees {
        amount: 500,
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                    AccountMeta { pubkey: admin_pubkey, is_signer: false, is_writable: false }, // NOT a signer!
                    AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
                ],
                data: instruction_data,
            }],
            Some(other_pubkey),
            recent_blockhash,
        ),
        vec![other_keypair],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();

    assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

    println!("\n=== Test PASSED: Withdraw Fees Admin Not Signer ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_withdraw_fees_uninitialized_factory() {
    println!("\n=== Test: Withdraw Fees Uninitialized Factory ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Derive factory PDA but don't initialize it
    let (factory_bytes, _) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    // Attempt withdrawal on uninitialized factory
    let status = execute_withdraw_fees(
        &ctx, program_pubkey, factory_pubkey,
        &payer_keypair, payer_pubkey, recipient_pubkey, 500,
    ).await;

    // Factory not initialized = invalid account data
    assert_invalid_account_data(&status);

    println!("\n=== Test PASSED: Withdraw Fees Uninitialized Factory ===\n");
}
