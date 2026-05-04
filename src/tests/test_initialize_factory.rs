// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for InitializeFactory instruction

use super::*;

#[tokio::test]
#[serial]
#[ignore]
async fn test_initialize_factory() {
    println!("\n=== Test: Initialize Factory ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
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
    ).await;

    verify_factory_state(
        &ctx,
        factory_pubkey,
        admin_pubkey.serialize(),
        creation_fee,
        transfer_fee,
        execute_fee,
        0, // total_wallets
        0, // accumulated_fees
    ).await;

    println!("\n=== Test PASSED: Initialize Factory ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_initialize_factory_already_initialized() {
    println!("\n=== Test: Initialize Factory Already Initialized ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // First initialization
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey, 1000, 500, 750,
    ).await;
    println!("First initialization successful");

    // Second initialization (should fail)
    let (factory_txid2, factory_vout2) = ctx.helper.send_utxo(factory_pubkey).await.unwrap();
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

    let recent_blockhash2 = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid2 = ctx.client.send_transaction(tx2).await.unwrap();
    let processed_tx2 = ctx.client.wait_for_processed_transaction(&txid2).await.unwrap();
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

#[tokio::test]
#[serial]
#[ignore]
async fn test_initialize_factory_wrong_pda() {
    println!("\n=== Test: Initialize Factory Wrong PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Create a random account instead of the derived factory PDA
    let (_wrong_keypair, wrong_pubkey, _) = generate_new_keypair(ctx.config.network);

    let (factory_txid, factory_vout) = ctx.helper.send_utxo(wrong_pubkey).await.unwrap();
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

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("Wrong PDA initialization status: {:?}", processed_tx.status);

    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: Initialize Factory Wrong PDA ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_initialize_factory_wrong_system_program() {
    println!("\n=== Test: Initialize Factory Wrong System Program ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Create a fake system program account
    let (_fake_system_keypair, fake_system_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Derive correct factory PDA
    let (factory_bytes, _) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    let (factory_txid, factory_vout) = ctx.helper.send_utxo(factory_pubkey).await.unwrap();
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

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
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

    println!("\n=== Test PASSED: Initialize Factory Wrong System Program ===\n");
}
