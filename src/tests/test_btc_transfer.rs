// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for BtcTransferWithWinternitz instruction

use super::*;

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_partial_spend() {
    println!("\n=== Test: BTC Transfer Partial Spend ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let creation_fee: u64 = 1000;
    let transfer_fee: u64 = 500;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        creation_fee, transfer_fee, 750,
    ).await;

    let vault_id = [20u8; 32];
    let initial_deposit: u64 = 10000;
    let (pq_key, private_key) = generate_wots_keypair(30);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, initial_deposit,
    ).await;

    // Anchor owner and capture balances before BTC transfer
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    let wallet_balance_before = ctx.client.read_account_info(wallet_pubkey).await.unwrap().lamports;
    let factory_balance_before = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;
    let owner_balance_before = ctx.client.read_account_info(payer_pubkey).await.unwrap().lamports;

    // Execute BTC transfer (partial spend: 1500 of 3000 sats)
    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xABu8; 20]);

    let (status, bitcoin_txid) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey, fee_tx,
        &wallet_utxo,
    ).await;

    assert!(status == Status::Processed, "BTC transfer tx should succeed");

    // Verify lamport fee was collected from owner to factory
    let wallet_balance_after = ctx.client.read_account_info(wallet_pubkey).await.unwrap().lamports;
    let factory_balance_after = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;
    let owner_balance_after = ctx.client.read_account_info(payer_pubkey).await.unwrap().lamports;

    let wallet_balance_decrease = wallet_balance_before - wallet_balance_after;
    let factory_balance_increase = factory_balance_after - factory_balance_before;
    let owner_balance_decrease = owner_balance_before - owner_balance_after;

    assert_eq!(wallet_balance_decrease, 0, "Wallet balance should be unchanged");
    assert_eq!(factory_balance_increase, transfer_fee, "Factory should have received exactly transfer_fee");
    assert!(owner_balance_decrease >= transfer_fee, "Owner should have paid transfer_fee + Arch tx fees");

    // Verify factory accumulated_fees
    let factory_account = ctx.client.read_account_info(factory_pubkey).await.unwrap();
    let factory = QuipFactory::try_from_slice(&factory_account.data).unwrap();
    assert_eq!(factory.accumulated_fees, creation_fee + transfer_fee);

    // Check Bitcoin transaction acceptance
    if let Some(ref btc_txid_hash) = bitcoin_txid {
        let raw_txid: arch_program::bitcoin::Txid = btc_txid_hash.into();
        let mut bytes = raw_txid.to_byte_array();
        bytes.reverse();
        let btc_txid = arch_program::bitcoin::Txid::from_byte_array(bytes);
        match ctx.helper.wait_until_titan_indexes_transaction(&btc_txid).await {
            Ok(()) => println!("RESULT: Bitcoin transaction ACCEPTED"),
            Err(e) => println!("RESULT: Bitcoin transaction NOT accepted: {}", e),
        }
    }

    println!("\n=== Test Complete: BTC Transfer Partial Spend ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_full_spend() {
    println!("\n=== Test: BTC Transfer Full Spend ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let transfer_fee: u64 = 500;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, transfer_fee, 750,
    ).await;

    let vault_id = [21u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(40);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor owner and capture balances
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    let wallet_balance_before = ctx.client.read_account_info(wallet_pubkey).await.unwrap().lamports;
    let factory_balance_before = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;
    let owner_balance_before = ctx.client.read_account_info(payer_pubkey).await.unwrap().lamports;

    // Full spend: 3000 - 330 (dust limit) = 2670 sats
    let transfer_amount: u64 = 2670;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xCDu8; 20]);

    let (status, bitcoin_txid) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey, fee_tx,
        &wallet_utxo,
    ).await;

    assert!(status == Status::Processed, "BTC max-spend tx should succeed");

    // Verify lamport fee was collected from owner
    let wallet_balance_after = ctx.client.read_account_info(wallet_pubkey).await.unwrap().lamports;
    let factory_balance_after = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;
    let owner_balance_after = ctx.client.read_account_info(payer_pubkey).await.unwrap().lamports;

    assert_eq!(wallet_balance_before - wallet_balance_after, 0, "Wallet balance should be unchanged");
    assert_eq!(factory_balance_after - factory_balance_before, transfer_fee);
    assert!(owner_balance_before - owner_balance_after >= transfer_fee, "Owner should have paid transfer_fee + Arch tx fees");

    // Check Bitcoin transaction acceptance
    if let Some(ref btc_txid_hash) = bitcoin_txid {
        let raw_txid: arch_program::bitcoin::Txid = btc_txid_hash.into();
        let mut bytes = raw_txid.to_byte_array();
        bytes.reverse();
        let btc_txid = arch_program::bitcoin::Txid::from_byte_array(bytes);
        match ctx.helper.wait_until_titan_indexes_transaction(&btc_txid).await {
            Ok(()) => println!("RESULT: Bitcoin transaction ACCEPTED"),
            Err(e) => println!("RESULT: Bitcoin transaction NOT accepted: {}", e),
        }
    }

    println!("\n=== Test Complete: BTC Transfer Full Spend ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_invalid_signature() {
    println!("\n=== Test: BTC Transfer Invalid Signature ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [22u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(50);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Attempt BTC transfer with invalid signature (should fail)
    let recipient_script_pubkey = create_p2wpkh_script(&[0xAAu8; 20]);
    let invalid_signature = vec![0xFFu8; 2112];

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount: 1500,
        recipient_script_pubkey,
        fee_tx,
        source_utxo: wallet_utxo,
        signature: WinternitzSignature { signature_data: invalid_signature },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

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
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    assert_error(&processed_tx.status, QuipError::InvalidWotsSignature);

    println!("\n=== Test PASSED: BTC Transfer Invalid Signature ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_insufficient_btc_balance() {
    println!("\n=== Test: BTC Transfer Insufficient BTC Balance ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [23u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(60);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Attempt BTC transfer with amount > UTXO value (3000 sats)
    let transfer_amount: u64 = 5000; // exceeds 3000-sat UTXO
    let recipient_script_pubkey = create_p2wpkh_script(&[0xBBu8; 20]);

    let (status, _) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey, fee_tx,
        &wallet_utxo,
    ).await;

    assert_error(&status, QuipError::InsufficientBtcBalance);

    println!("\n=== Test PASSED: BTC Transfer Insufficient BTC Balance ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_unauthorized() {
    println!("\n=== Test: BTC Transfer Unauthorized ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);
    let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);

    ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).await.unwrap();

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet owned by payer
    let vault_id = [24u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(70);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor attacker (they will try to be the signer)
    anchor_account(&ctx, &attacker_keypair, attacker_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Attacker attempts BTC transfer using their own key as owner (should fail)
    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xEEu8; 20]);

    let message = create_btc_transfer_message(&pq_key, &pq_next, &recipient_script_pubkey, transfer_amount, &wallet_utxo);
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount: transfer_amount,
        recipient_script_pubkey,
        fee_tx,
        source_utxo: wallet_utxo,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

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
                        AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    // PDA derivation check catches the unauthorized caller (attacker's pubkey
    // doesn't match the wallet owner used in PDA derivation)
    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: BTC Transfer Unauthorized ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_non_anchor_utxo_full_spend() {
    println!("\n=== Test: BTC Transfer Non-Anchor UTXO Full Spend ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let transfer_fee: u64 = 500;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, transfer_fee, 750,
    ).await;

    let vault_id = [25u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(80);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    // Create wallet with anchor UTXO
    let (wallet_pubkey, _anchor_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Send a second UTXO to the wallet (non-anchor) and wait for Titan to index it
    let (non_anchor_txid, non_anchor_vout) = ctx.helper
        .send_utxo(wallet_pubkey).await
        .expect("Failed to send non-anchor UTXO");
    let non_anchor_utxo = UtxoMeta::from(
        hex::decode(&non_anchor_txid).unwrap().try_into().unwrap(),
        non_anchor_vout,
    );
    println!("Non-anchor UTXO sent: {}:{}", non_anchor_txid, non_anchor_vout);

    // Wait for Titan to index the non-anchor UTXO
    let mut non_anchor_txid_bytes: [u8; 32] = hex::decode(&non_anchor_txid).unwrap().try_into().unwrap();
    non_anchor_txid_bytes.reverse();
    let non_anchor_bitcoin_txid = arch_program::bitcoin::Txid::from_byte_array(non_anchor_txid_bytes);
    ctx.helper.wait_until_titan_indexes_transaction(&non_anchor_bitcoin_txid).await
        .expect("Failed to wait for non-anchor UTXO indexing");
    println!("Non-anchor UTXO indexed by Titan");

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    let wallet_balance_before = ctx.client.read_account_info(wallet_pubkey).await.unwrap().lamports;
    let factory_balance_before = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;
    let owner_balance_before = ctx.client.read_account_info(payer_pubkey).await.unwrap().lamports;

    // Full spend of non-anchor UTXO (3000 sats, change = 0)
    let transfer_amount: u64 = 3000;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF0u8; 20]);

    let (status, bitcoin_txid) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey, fee_tx,
        &non_anchor_utxo,
    ).await;

    assert!(status == Status::Processed, "Non-anchor full spend should succeed");

    // Verify lamport fee was collected from owner
    let wallet_balance_after = ctx.client.read_account_info(wallet_pubkey).await.unwrap().lamports;
    let factory_balance_after = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;
    let owner_balance_after = ctx.client.read_account_info(payer_pubkey).await.unwrap().lamports;

    // Verify lamport fees
    assert_eq!(wallet_balance_before - wallet_balance_after, 0, "Wallet balance should be unchanged");
    assert_eq!(factory_balance_after - factory_balance_before, transfer_fee);
    assert!(owner_balance_before - owner_balance_after >= transfer_fee, "Owner should have paid transfer_fee + Arch tx fees");

    // Verify wallet state updated
    verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_next, 1).await;

    // Check Bitcoin transaction acceptance
    if let Some(ref btc_txid_hash) = bitcoin_txid {
        let raw_txid: arch_program::bitcoin::Txid = btc_txid_hash.into();
        let mut bytes = raw_txid.to_byte_array();
        bytes.reverse();
        let btc_txid = arch_program::bitcoin::Txid::from_byte_array(bytes);
        ctx.helper.wait_until_titan_indexes_transaction(&btc_txid).await
            .expect("Bitcoin transaction must be accepted for full spend");
    }

    println!("\n=== Test PASSED: BTC Transfer Non-Anchor UTXO Full Spend ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_non_anchor_utxo_with_change() {
    println!("\n=== Test: BTC Transfer Non-Anchor UTXO With Change ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let transfer_fee: u64 = 500;
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, transfer_fee, 750,
    ).await;

    let vault_id = [26u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(90);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    // Create wallet with anchor UTXO
    let (wallet_pubkey, _anchor_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Send a second UTXO to the wallet (non-anchor) and wait for Titan to index it
    let (non_anchor_txid, non_anchor_vout) = ctx.helper
        .send_utxo(wallet_pubkey).await
        .expect("Failed to send non-anchor UTXO");
    let non_anchor_utxo = UtxoMeta::from(
        hex::decode(&non_anchor_txid).unwrap().try_into().unwrap(),
        non_anchor_vout,
    );
    println!("Non-anchor UTXO sent: {}:{}", non_anchor_txid, non_anchor_vout);

    // Wait for Titan to index the non-anchor UTXO
    let mut non_anchor_txid_bytes: [u8; 32] = hex::decode(&non_anchor_txid).unwrap().try_into().unwrap();
    non_anchor_txid_bytes.reverse();
    let non_anchor_bitcoin_txid = arch_program::bitcoin::Txid::from_byte_array(non_anchor_txid_bytes);
    ctx.helper.wait_until_titan_indexes_transaction(&non_anchor_bitcoin_txid).await
        .expect("Failed to wait for non-anchor UTXO indexing");
    println!("Non-anchor UTXO indexed by Titan");

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    let wallet_balance_before = ctx.client.read_account_info(wallet_pubkey).await.unwrap().lamports;
    let factory_balance_before = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;
    let owner_balance_before = ctx.client.read_account_info(payer_pubkey).await.unwrap().lamports;

    // Partial spend of non-anchor UTXO (3000 sats total, transfer 2000, change = 1000)
    let transfer_amount: u64 = 2000;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF1u8; 20]);

    let (status, bitcoin_txid) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey.clone(), fee_tx,
        &non_anchor_utxo,
    ).await;

    assert!(status == Status::Processed, "Non-anchor with change should succeed");

    // Verify lamport fee was collected from owner
    let wallet_balance_after = ctx.client.read_account_info(wallet_pubkey).await.unwrap().lamports;
    let factory_balance_after = ctx.client.read_account_info(factory_pubkey).await.unwrap().lamports;
    let owner_balance_after = ctx.client.read_account_info(payer_pubkey).await.unwrap().lamports;

    assert_eq!(wallet_balance_before - wallet_balance_after, 0, "Wallet balance should be unchanged");
    assert_eq!(factory_balance_after - factory_balance_before, transfer_fee);
    assert!(owner_balance_before - owner_balance_after >= transfer_fee, "Owner should have paid transfer_fee + Arch tx fees");

    // Verify wallet state updated
    verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_next, 1).await;

    // Check Bitcoin transaction acceptance
    if let Some(ref btc_txid_hash) = bitcoin_txid {
        let raw_txid: arch_program::bitcoin::Txid = btc_txid_hash.into();
        let mut bytes = raw_txid.to_byte_array();
        bytes.reverse();
        let btc_txid = arch_program::bitcoin::Txid::from_byte_array(bytes);
        ctx.helper.wait_until_titan_indexes_transaction(&btc_txid).await
            .expect("Bitcoin transaction must be accepted");
        println!("RESULT: Bitcoin transaction ACCEPTED - {}", btc_txid);
    } else {
        panic!("Bitcoin transaction should have been created");
    }

    println!("\n=== Test PASSED: BTC Transfer Non-Anchor UTXO With Change ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_utxo_not_owned_by_wallet() {
    println!("\n=== Test: BTC Transfer UTXO Not Owned By Wallet ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [26u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(90);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    // Create wallet
    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Create a different account and send a UTXO to it
    let (other_keypair, other_pubkey, _) = generate_new_keypair(ctx.config.network);
    ctx.client.create_and_fund_account_with_faucet(&other_keypair).await.unwrap();
    let (other_txid, other_vout) = ctx.helper
        .send_utxo(other_pubkey).await
        .expect("Failed to send UTXO to other account");
    let other_utxo = UtxoMeta::from(
        hex::decode(&other_txid).unwrap().try_into().unwrap(),
        other_vout,
    );

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Attempt BTC transfer with UTXO that belongs to other_pubkey (not wallet)
    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF1u8; 20]);

    let (status, _) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey, fee_tx,
        &other_utxo,
    ).await;

    assert_error(&status, QuipError::UtxoNotOwnedByWallet);

    println!("\n=== Test PASSED: BTC Transfer UTXO Not Owned By Wallet ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_non_anchor_dust_change() {
    println!("\n=== Test: BTC Transfer Non-Anchor Dust Change ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [27u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(100);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    // Create wallet with anchor UTXO
    let (wallet_pubkey, _anchor_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Send a second UTXO to the wallet (non-anchor) and wait for Titan to index it
    let (non_anchor_txid, non_anchor_vout) = ctx.helper
        .send_utxo(wallet_pubkey).await
        .expect("Failed to send non-anchor UTXO");
    let non_anchor_utxo = UtxoMeta::from(
        hex::decode(&non_anchor_txid).unwrap().try_into().unwrap(),
        non_anchor_vout,
    );

    // Wait for Titan to index the non-anchor UTXO
    let mut non_anchor_txid_bytes: [u8; 32] = hex::decode(&non_anchor_txid).unwrap().try_into().unwrap();
    non_anchor_txid_bytes.reverse();
    let non_anchor_bitcoin_txid = arch_program::bitcoin::Txid::from_byte_array(non_anchor_txid_bytes);
    ctx.helper.wait_until_titan_indexes_transaction(&non_anchor_bitcoin_txid).await
        .expect("Failed to wait for non-anchor UTXO indexing");
    println!("Non-anchor UTXO indexed by Titan");

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Attempt transfer leaving change > 0 but < 330 sats (dust limit)
    // UTXO is 3000 sats, transfer 2800 leaves 200 sats change (dust)
    let transfer_amount: u64 = 2800;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF2u8; 20]);

    let (status, _) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey, fee_tx,
        &non_anchor_utxo,
    ).await;

    assert_error(&status, QuipError::ChangeBelowDustLimit);

    println!("\n=== Test PASSED: BTC Transfer Non-Anchor Dust Change ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_anchor_dust_change() {
    println!("\n=== Test: BTC Transfer Anchor Dust Change ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [28u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(110);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    // Create wallet - anchor UTXO has 3000 sats
    let (wallet_pubkey, anchor_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Attempt transfer on anchor UTXO leaving change > 0 but < 330 sats (dust limit)
    // UTXO is 3000 sats, transfer 2800 leaves 200 sats change (dust)
    let transfer_amount: u64 = 2800;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF3u8; 20]);

    let (status, _) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey, fee_tx,
        &anchor_utxo,
    ).await;

    assert_error(&status, QuipError::AnchorChangeBelowDustLimit);

    println!("\n=== Test PASSED: BTC Transfer Anchor Dust Change ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_rejects_zero_amount() {
    println!("\n=== Test: BTC Transfer Rejects Zero Amount ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [29u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(120);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Attempt BTC transfer with amount = 0
    let transfer_amount: u64 = 0;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF4u8; 20]);

    let (status, _) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey, fee_tx,
        &wallet_utxo,
    ).await;

    // Zero-amount transfers are rejected early as semantically invalid
    assert_error(&status, QuipError::ZeroAmountTransfer);

    println!("\n=== Test PASSED: BTC Transfer Rejects Zero Amount ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_wrong_factory_pda() {
    println!("\n=== Test: BTC Transfer Wrong Factory PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [30u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(130);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Create wrong/random factory account
    let (_wrong_keypair, wrong_factory_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Build valid signature
    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF5u8; 20]);
    let message = create_btc_transfer_message(&pq_key, &pq_next, &recipient_script_pubkey, transfer_amount, &wallet_utxo);
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount: transfer_amount,
        recipient_script_pubkey,
        fee_tx,
        source_utxo: wallet_utxo,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[
                compute_budget_ix,
                Instruction {
                    program_id: program_pubkey,
                    accounts: vec![
                        AccountMeta { pubkey: wrong_factory_pubkey, is_signer: false, is_writable: true }, // Wrong!
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: BTC Transfer Wrong Factory PDA ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_wrong_wallet_pda() {
    println!("\n=== Test: BTC Transfer Wrong Wallet PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet with vault_id_1
    let vault_id_1 = [31u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(140);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id_1, &pq_key, 10000,
    ).await;

    // Use wrong vault_id in instruction
    let wrong_vault_id = [32u8; 32];

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Build signature (with wrong vault_id committed to message doesn't matter,
    // the PDA derivation will fail first)
    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF6u8; 20]);
    let message = create_btc_transfer_message(&pq_key, &pq_next, &recipient_script_pubkey, transfer_amount, &wallet_utxo);
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id: wrong_vault_id, // Wrong vault_id
        pq_next: pq_next.clone(),
        amount: transfer_amount,
        recipient_script_pubkey,
        fee_tx,
        source_utxo: wallet_utxo,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

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
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: BTC Transfer Wrong Wallet PDA ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_uninitialized_factory() {
    println!("\n=== Test: BTC Transfer Uninitialized Factory ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;

    // Derive factory address but don't initialize it
    let (factory_bytes, _) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    // Derive wallet address
    let vault_id = [33u8; 32];
    let owner_bytes = payer_pubkey.serialize();
    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    // Generate keys and sign
    let (pq_key, private_key) = generate_wots_keypair(150);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Create a dummy UTXO for the instruction
    let dummy_utxo = arch_program::utxo::UtxoMeta::from([0u8; 32], 0);

    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF7u8; 20]);
    let message = create_btc_transfer_message(&pq_key, &pq_next, &recipient_script_pubkey, transfer_amount, &dummy_utxo);
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount: transfer_amount,
        recipient_script_pubkey,
        fee_tx,
        source_utxo: dummy_utxo,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

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
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    println!("\n=== Test PASSED: BTC Transfer Uninitialized Factory ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_uninitialized_wallet() {
    println!("\n=== Test: BTC Transfer Uninitialized Wallet ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Derive wallet address but don't create it
    let vault_id = [34u8; 32];
    let owner_bytes = payer_pubkey.serialize();
    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    let (pq_key, private_key) = generate_wots_keypair(160);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Create a dummy UTXO for the instruction
    let dummy_utxo = arch_program::utxo::UtxoMeta::from([0u8; 32], 0);

    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF8u8; 20]);
    let message = create_btc_transfer_message(&pq_key, &pq_next, &recipient_script_pubkey, transfer_amount, &dummy_utxo);
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount: transfer_amount,
        recipient_script_pubkey,
        fee_tx,
        source_utxo: dummy_utxo,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

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
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    println!("\n=== Test PASSED: BTC Transfer Uninitialized Wallet ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_wrong_system_program() {
    println!("\n=== Test: BTC Transfer Wrong System Program ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [37u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(190);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Create fake system program
    let (_fake_system_keypair, fake_system_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Build valid signature
    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xF9u8; 20]);
    let message = create_btc_transfer_message(&pq_key, &pq_next, &recipient_script_pubkey, transfer_amount, &wallet_utxo);
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount: transfer_amount,
        recipient_script_pubkey,
        fee_tx,
        source_utxo: wallet_utxo,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

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
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: fake_system_pubkey, is_signer: false, is_writable: false }, // Wrong!
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

    // Should fail because wrong system program is passed for fee transfer
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

    println!("\n=== Test PASSED: BTC Transfer Wrong System Program ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_empty_recipient_script() {
    println!("\n=== Test: BTC Transfer Empty Recipient Script ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [40u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(220);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    // Attempt BTC transfer with empty recipient script pubkey
    let transfer_amount: u64 = 1500;
    let empty_recipient_script: Vec<u8> = vec![]; // Empty!

    let (status, _) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, empty_recipient_script, fee_tx,
        &wallet_utxo,
    ).await;

    // Empty script is rejected early with explicit error
    assert_error(&status, QuipError::EmptyRecipientScript);

    println!("\n=== Test PASSED: BTC Transfer Empty Recipient Script ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_invalid_fee_tx() {
    println!("\n=== Test: BTC Transfer Invalid Fee Tx ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [41u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(230);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor owner but use garbage bytes for fee_tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let invalid_fee_tx = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xAA]; // Garbage bytes

    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xFAu8; 20]);

    // Build signature with invalid fee_tx
    let message = create_btc_transfer_message(&pq_key, &pq_next, &recipient_script_pubkey, transfer_amount, &wallet_utxo);
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount: transfer_amount,
        recipient_script_pubkey,
        fee_tx: invalid_fee_tx,
        source_utxo: wallet_utxo,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

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
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    // Should fail because fee_tx can't be deserialized
    match &processed_tx.status {
        Status::Failed(err) => {
            // Deserialization failure expected
            println!("Failed as expected with: {}", err);
        }
        other => panic!("Expected Status::Failed, got: {:?}", other),
    }

    println!("\n=== Test PASSED: BTC Transfer Invalid Fee Tx ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_insufficient_lamport_fee() {
    println!("\n=== Test: BTC Transfer Insufficient Lamport Fee ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Set a very high transfer fee
    let high_transfer_fee: u64 = 1_000_000_000_000; // 1 trillion lamports
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, high_transfer_fee, 750,
    ).await;

    let vault_id = [42u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(240);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor owner and prepare fee tx
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;
    let fee_tx = prepare_fees_and_wait(&ctx.helper).await;

    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xFBu8; 20]);

    let (status, _) = execute_btc_transfer_raw(
        &ctx, program_pubkey, factory_pubkey, wallet_pubkey,
        &payer_keypair, payer_pubkey,
        vault_id, &pq_key, &pq_next, &private_key,
        transfer_amount, recipient_script_pubkey, fee_tx,
        &wallet_utxo,
    ).await;

    // Should fail because owner can't afford the lamport transfer fee
    // Note: check_sufficient_balance returns InsufficientWalletBalance for all balance checks
    assert_error(&status, QuipError::InsufficientWalletBalance);

    println!("\n=== Test PASSED: BTC Transfer Insufficient Lamport Fee ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_btc_transfer_fee_tx_no_inputs() {
    println!("\n=== Test: BTC Transfer Fee Tx No Inputs ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    let vault_id = [43u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(250);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10000,
    ).await;

    // Anchor owner
    anchor_account(&ctx, &payer_keypair, payer_pubkey).await;

    // Create a minimal valid Bitcoin transaction with NO inputs
    use arch_program::bitcoin::{
        Transaction, TxOut,
        absolute::LockTime, transaction::Version,
    };

    let empty_inputs_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![], // No inputs!
        output: vec![TxOut {
            value: arch_program::bitcoin::Amount::from_sat(1000),
            script_pubkey: arch_program::bitcoin::ScriptBuf::new(),
        }],
    };

    let fee_tx = arch_program::bitcoin::consensus::serialize(&empty_inputs_tx);

    let transfer_amount: u64 = 1500;
    let recipient_script_pubkey = create_p2wpkh_script(&[0xFCu8; 20]);

    // Build signature
    let message = create_btc_transfer_message(&pq_key, &pq_next, &recipient_script_pubkey, transfer_amount, &wallet_utxo);
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::BtcTransferWithWinternitz {
        vault_id,
        pq_next: pq_next.clone(),
        amount: transfer_amount,
        recipient_script_pubkey,
        fee_tx,
        source_utxo: wallet_utxo,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(BTC_TRANSFER_COMPUTE_BUDGET);

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
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    // Should fail because fee_tx has no inputs (can't extract funding UTXO)
    match &processed_tx.status {
        Status::Failed(err) => {
            // Index out of bounds or validation failure expected
            println!("Failed as expected with: {}", err);
        }
        other => panic!("Expected Status::Failed, got: {:?}", other),
    }

    println!("\n=== Test PASSED: BTC Transfer Fee Tx No Inputs ===\n");
}
