// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for TransferOwnership instruction

use super::*;

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_ownership() {
    println!("\n=== Test: Transfer Ownership ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (new_admin_keypair, new_admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&admin_keypair).await.unwrap();
    ctx.client.create_and_fund_account_with_faucet(&new_admin_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
    ).await;

    // Transfer ownership
    let instruction_data = borsh::to_vec(&QuipInstruction::TransferOwnership {
        new_admin: new_admin_pubkey.serialize(),
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
    println!("Transaction status: {:?}", processed_tx.status);
    assert!(processed_tx.status == Status::Processed);

    // Verify new admin
    verify_factory_state(
        &ctx, factory_pubkey, new_admin_pubkey.serialize(), 1000, 500, 750, 0, 0,
    ).await;

    // Verify new admin can update fees
    let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
        creation_fee: 5000,
        transfer_fee: 2500,
        execute_fee: 3000,
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("New admin fee update status: {:?}", processed_tx.status);
    assert!(processed_tx.status == Status::Processed);

    // Verify old admin cannot update fees
    let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
        creation_fee: 9999,
        transfer_fee: 9999,
        execute_fee: 9999,
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
        vec![admin_keypair],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Old admin fee update status: {:?}", processed_tx.status);

    assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

    println!("\n=== Test PASSED: Transfer Ownership ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_ownership_unauthorized() {
    println!("\n=== Test: Transfer Ownership Unauthorized ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Attacker attempts ownership transfer (should fail)
    let instruction_data = borsh::to_vec(&QuipInstruction::TransferOwnership {
        new_admin: attacker_pubkey.serialize(),
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                    AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: false },
                ],
                data: instruction_data,
            }],
            Some(attacker_pubkey),
            recent_blockhash,
        ),
        vec![attacker_keypair],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();

    assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

    println!("\n=== Test PASSED: Transfer Ownership Unauthorized ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_ownership_wrong_factory_pda() {
    println!("\n=== Test: Transfer Ownership Wrong Factory PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_new_admin_keypair, new_admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&admin_keypair).await.unwrap();

    let _factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wrong/random factory account
    let (_wrong_keypair, wrong_factory_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Attempt transfer ownership with wrong factory
    let instruction_data = borsh::to_vec(&QuipInstruction::TransferOwnership {
        new_admin: new_admin_pubkey.serialize(),
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta { pubkey: wrong_factory_pubkey, is_signer: false, is_writable: true },
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();

    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: Transfer Ownership Wrong Factory PDA ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_ownership_admin_not_signer() {
    println!("\n=== Test: Transfer Ownership Admin Not Signer ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (other_keypair, other_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (_new_admin_keypair, new_admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&other_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Attempt transfer ownership with admin NOT as signer
    let instruction_data = borsh::to_vec(&QuipInstruction::TransferOwnership {
        new_admin: new_admin_pubkey.serialize(),
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                    AccountMeta { pubkey: admin_pubkey, is_signer: false, is_writable: false }, // NOT a signer!
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

    println!("\n=== Test PASSED: Transfer Ownership Admin Not Signer ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_transfer_ownership_uninitialized_factory() {
    println!("\n=== Test: Transfer Ownership Uninitialized Factory ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_new_admin_keypair, new_admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Derive factory PDA but don't initialize it
    let (factory_bytes, _) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    // Attempt transfer ownership on uninitialized factory
    let instruction_data = borsh::to_vec(&QuipInstruction::TransferOwnership {
        new_admin: new_admin_pubkey.serialize(),
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
                    AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: false },
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

    // Factory not initialized = invalid account data
    assert_invalid_account_data(&processed_tx.status);

    println!("\n=== Test PASSED: Transfer Ownership Uninitialized Factory ===\n");
}
