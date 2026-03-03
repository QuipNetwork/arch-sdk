// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for ChangePqOwner instruction

use super::*;

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

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
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

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
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

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
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

    // Wallet not created = invalid account data
    assert_invalid_account_data(&processed_tx.status);

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

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
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

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
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
