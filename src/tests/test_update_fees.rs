// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for UpdateFees instruction

use super::*;

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
fn test_update_fees_wrong_factory_pda() {
    println!("\n=== Test: Update Fees Wrong Factory PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
    let (admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&admin_keypair).unwrap();

    let _factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    );

    // Create wrong/random factory account
    let (_wrong_keypair, wrong_factory_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Attempt update with wrong factory
    let status = execute_update_fees(
        &ctx, program_pubkey, wrong_factory_pubkey,
        &admin_keypair, admin_pubkey,
        2000, 1000, 1500,
    );

    assert_error(&status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: Update Fees Wrong Factory PDA ===\n");
}

#[test]
#[serial]
#[ignore]
fn test_update_fees_admin_not_signer() {
    println!("\n=== Test: Update Fees Admin Not Signer ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (other_keypair, other_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&other_keypair).unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    );

    // Attempt update with admin account NOT as signer
    let instruction_data = borsh::to_vec(&QuipInstruction::UpdateFees {
        creation_fee: 2000,
        transfer_fee: 1000,
        execute_fee: 1500,
    }).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
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

    let txid = ctx.client.send_transaction(tx).unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

    assert_error(&processed_tx.status, QuipError::UnauthorizedSigner);

    println!("\n=== Test PASSED: Update Fees Admin Not Signer ===\n");
}

#[test]
#[serial]
#[ignore]
fn test_update_fees_uninitialized_factory() {
    println!("\n=== Test: Update Fees Uninitialized Factory ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);

    // Derive factory PDA but don't initialize it
    let (factory_bytes, _) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    // Attempt update on uninitialized factory
    let status = execute_update_fees(
        &ctx, program_pubkey, factory_pubkey,
        &payer_keypair, payer_pubkey,
        2000, 1000, 1500,
    );

    // Factory not initialized = invalid account data
    assert_invalid_account_data(&status);

    println!("\n=== Test PASSED: Update Fees Uninitialized Factory ===\n");
}
