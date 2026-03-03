// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Miscellaneous tests

use super::*;

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

    // The Arch runtime rejects the fake system program before our code runs
    match &processed_tx.status {
        Status::Failed(err) => {
            assert!(
                err.contains("incorrect program id"),
                "Expected runtime 'incorrect program id' error, got: {}",
                err
            );
        }
        _ => panic!("Expected failure, got: {:?}", processed_tx.status),
    }

    println!("\n=== Test PASSED: Fake System Program Rejected ===\n");
}

#[test]
#[serial]
#[ignore]
fn test_invalid_instruction_data() {
    println!("\n=== Test: Invalid Instruction Data ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx);

    // Send garbage bytes that fail borsh deserialization
    let garbage_data = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xAA, 0xBB];

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                ],
                data: garbage_data,
            }],
            Some(payer_pubkey),
            recent_blockhash,
        ),
        vec![payer_keypair],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).unwrap();

    // Should fail with InvalidInstructionData (borsh deserialization error)
    match &processed_tx.status {
        Status::Failed(err) => {
            assert!(
                err.contains("invalid instruction data"),
                "Expected 'invalid instruction data' error, got: {}",
                err
            );
        }
        other => panic!("Expected Status::Failed, got: {:?}", other),
    }

    println!("\n=== Test PASSED: Invalid Instruction Data ===\n");
}
