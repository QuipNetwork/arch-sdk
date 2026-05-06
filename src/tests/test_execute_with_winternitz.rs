// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for ExecuteWithWinternitz instruction

use super::*;

/// Helper function to execute an ExecuteWithWinternitz instruction
async fn execute_with_winternitz(
    ctx: &TestContext,
    program_pubkey: Pubkey,
    factory_pubkey: Pubkey,
    wallet_pubkey: Pubkey,
    target_program_pubkey: Pubkey,
    signer_keypair: &UntweakedKeypair,
    signer_pubkey: Pubkey,
    vault_id: [u8; 32],
    pq_key: &WinternitzPublicKey,
    pq_next: &WinternitzPublicKey,
    private_key: &[u8; 32],
    instruction_data: Vec<u8>,
    account_metas: Vec<CpiAccountMeta>,
    remaining_accounts: Vec<AccountMeta>,
) -> Status {
    // Build account pubkeys for the message
    let account_pubkeys: Vec<[u8; 32]> = remaining_accounts
        .iter()
        .map(|a| a.pubkey.serialize())
        .collect();

    let target_bytes = target_program_pubkey.serialize();
    let message = create_execute_message(
        pq_key,
        pq_next,
        &target_bytes,
        &instruction_data,
        &account_pubkeys,
        &account_metas,
    );
    let signature_data = sign_message(private_key, &message);

    let cpi_instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id,
        instruction_data,
        account_metas,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

    // Build accounts: factory, wallet, target_program, owner, system_program, then remaining accounts
    let mut accounts = vec![
        AccountMeta { pubkey: factory_pubkey, is_signer: false, is_writable: true },
        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
        AccountMeta { pubkey: target_program_pubkey, is_signer: false, is_writable: false },
        AccountMeta { pubkey: signer_pubkey, is_signer: true, is_writable: true },
        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
    ];
    accounts.extend(remaining_accounts);

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[
                compute_budget_ix,
                Instruction {
                    program_id: program_pubkey,
                    accounts,
                    data: cpi_instruction_data,
                },
            ],
            Some(signer_pubkey),
            recent_blockhash,
        ),
        vec![signer_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    println!("ExecuteWithWinternitz status: {:?}", processed_tx.status);
    processed_tx.status
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_success() {
    println!("\n=== Test: ExecuteWithWinternitz Success ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let creation_fee: u64 = 1000;
    let transfer_fee: u64 = 500;
    let execute_fee: u64 = 750;

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        creation_fee, transfer_fee, execute_fee,
    ).await;

    // Create wallet with deposit to cover execute fee
    let vault_id = [42u8; 32];
    let initial_deposit: u64 = 10_000;
    let (pq_key, private_key) = generate_wots_keypair(100);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, initial_deposit,
    ).await;

    // Create a recipient account that will receive lamports via the CPI
    let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);
    ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).await.unwrap();

    // Capture balances before execute
    let balances_before = capture_balances(&ctx, &[factory_pubkey, wallet_pubkey, recipient_pubkey]).await;

    // Execute a CPI: system transfer from owner (payer) to recipient
    // The owner is a signer in the transaction, so it can authorize this transfer
    let cpi_transfer_amount: u64 = 1000;
    let transfer_ix = system_instruction::transfer(&payer_pubkey, &recipient_pubkey, cpi_transfer_amount);

    // Build CpiAccountMeta for the signature message
    let cpi_account_metas = vec![
        CpiAccountMeta { is_signer: true, is_writable: true },   // owner (source)
        CpiAccountMeta { is_signer: false, is_writable: true },  // recipient (dest)
    ];

    // Build remaining accounts for the CPI (these will be passed to invoke_signed)
    let remaining_accounts = vec![
        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
        AccountMeta { pubkey: recipient_pubkey, is_signer: false, is_writable: true },
    ];

    let status = execute_with_winternitz(
        &ctx,
        program_pubkey,
        factory_pubkey,
        wallet_pubkey,
        system_program::SYSTEM_PROGRAM_ID, // target program
        &payer_keypair,
        payer_pubkey,
        vault_id,
        &pq_key,
        &pq_next,
        &private_key,
        transfer_ix.data.clone(), // system transfer instruction data
        cpi_account_metas,
        remaining_accounts,
    ).await;

    assert_eq!(status, Status::Processed, "ExecuteWithWinternitz should succeed");

    // Verify balances changed correctly
    let balances_after = capture_balances(&ctx, &[factory_pubkey, wallet_pubkey, recipient_pubkey]).await;

    // Factory should have gained execute_fee
    let factory_gain = balances_after[0] - balances_before[0];
    assert_eq!(factory_gain, execute_fee, "Factory should gain execute_fee");

    // Wallet balance should have decreased by exactly execute_fee
    assert_eq!(
        balances_before[1] - balances_after[1],
        execute_fee,
        "Wallet should have paid exactly execute_fee"
    );

    // Recipient should have gained the CPI transfer amount
    let recipient_gain = balances_after[2] - balances_before[2];
    assert_eq!(recipient_gain, cpi_transfer_amount, "Recipient should gain CPI transfer amount");

    // Verify wallet state (WOTS+ key rotated, transaction count incremented)
    verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_next, 1).await;

    // Verify factory accumulated fees
    verify_factory_state(
        &ctx, factory_pubkey, admin_pubkey.serialize(),
        creation_fee, transfer_fee, execute_fee,
        1, // total_wallets
        creation_fee + execute_fee, // accumulated_fees
    ).await;

    println!("\n=== Test PASSED: ExecuteWithWinternitz Success ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_owner_not_signer() {
    println!("\n=== Test: ExecuteWithWinternitz Owner Not Signer ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet
    let vault_id = [43u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(200);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10_000,
    ).await;

    // Create a different signer (attacker) who will sign but is not the owner
    let (attacker_keypair, attacker_pubkey, _) = generate_new_keypair(ctx.config.network);
    ctx.client.create_and_fund_account_with_faucet(&attacker_keypair).await.unwrap();

    // Build message with owner's pubkey but sign with attacker
    let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
    let message = create_execute_message(
        &pq_key,
        &pq_next,
        &target_bytes,
        &[],
        &[],
        &[],
    );
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id,
        instruction_data: vec![],
        account_metas: vec![],
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

    // Use attacker as signer but they're not the wallet owner
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
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                        AccountMeta { pubkey: attacker_pubkey, is_signer: true, is_writable: true }, // owner (attacker, not real owner)
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
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

    // Should fail because attacker's pubkey doesn't derive the wallet PDA
    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: ExecuteWithWinternitz Owner Not Signer ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_uninitialized_factory() {
    println!("\n=== Test: ExecuteWithWinternitz Uninitialized Factory ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;

    // Derive factory address but don't initialize it
    let (factory_bytes, _) = derive_factory_address(&program_pubkey);
    let factory_pubkey = Pubkey::from_slice(&factory_bytes);

    // Create a random wallet address (won't actually exist)
    let vault_id = [44u8; 32];
    let owner_bytes = payer_pubkey.serialize();
    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    let (pq_key, private_key) = generate_wots_keypair(300);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    // Build signature
    let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
    let message = create_execute_message(
        &pq_key,
        &pq_next,
        &target_bytes,
        &[],
        &[],
        &[],
    );
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id,
        instruction_data: vec![],
        account_metas: vec![],
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
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true }, // owner
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
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

    // Should fail because factory is not initialized = invalid account data
    assert_invalid_account_data(&processed_tx.status);

    println!("\n=== Test PASSED: ExecuteWithWinternitz Uninitialized Factory ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_uninitialized_wallet() {
    println!("\n=== Test: ExecuteWithWinternitz Uninitialized Wallet ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Initialize factory but don't create wallet
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Derive wallet address but don't create it
    let vault_id = [45u8; 32];
    let owner_bytes = payer_pubkey.serialize();
    let (wallet_bytes, _) = derive_wallet_address(&program_pubkey, &owner_bytes, &vault_id);
    let wallet_pubkey = Pubkey::from_slice(&wallet_bytes);

    let (pq_key, private_key) = generate_wots_keypair(400);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    // Build signature
    let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
    let message = create_execute_message(
        &pq_key,
        &pq_next,
        &target_bytes,
        &[],
        &[],
        &[],
    );
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id,
        instruction_data: vec![],
        account_metas: vec![],
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
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true }, // owner
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
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

    // Should fail because wallet is not created = invalid account data
    assert_invalid_account_data(&processed_tx.status);

    println!("\n=== Test PASSED: ExecuteWithWinternitz Uninitialized Wallet ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_wrong_factory_pda() {
    println!("\n=== Test: ExecuteWithWinternitz Wrong Factory PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Initialize factory
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet
    let vault_id = [46u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(500);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10_000,
    ).await;

    // Create a fake factory account (random address)
    let (_fake_factory_keypair, fake_factory_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Build signature
    let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
    let message = create_execute_message(
        &pq_key,
        &pq_next,
        &target_bytes,
        &[],
        &[],
        &[],
    );
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id,
        instruction_data: vec![],
        account_metas: vec![],
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
                        // Use fake factory instead of real one
                        AccountMeta { pubkey: fake_factory_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true }, // owner
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
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

    // Should fail because fake factory fails PDA derivation check
    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: ExecuteWithWinternitz Wrong Factory PDA ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_wrong_wallet_pda() {
    println!("\n=== Test: ExecuteWithWinternitz Wrong Wallet PDA ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Initialize factory
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet with vault_id_1
    let vault_id_1 = [47u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(600);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id_1, &pq_key, 10_000,
    ).await;

    // Use a different vault_id in the instruction
    let wrong_vault_id = [48u8; 32];

    // Build signature with wrong vault_id
    let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
    let message = create_execute_message(
        &pq_key,
        &pq_next,
        &target_bytes,
        &[],
        &[],
        &[],
    );
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id: wrong_vault_id, // Wrong vault_id
        instruction_data: vec![],
        account_metas: vec![],
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
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // target program
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true }, // owner
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false }, // system program for fee transfer
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

    // Should fail because wallet PDA doesn't match with wrong_vault_id
    assert_error(&processed_tx.status, QuipError::InvalidAccountDerivation);

    println!("\n=== Test PASSED: ExecuteWithWinternitz Wrong Wallet PDA ===\n");
}

// =============================================================================
// APL Token Transfer via ExecuteWithWinternitz Tests
// =============================================================================

/// Create a token mint account
async fn create_token_mint(
    ctx: &TestContext,
    mint_keypair: &UntweakedKeypair,
    mint_pubkey: Pubkey,
    mint_authority_pubkey: Pubkey,
    mint_authority_keypair: &UntweakedKeypair,
    decimals: u8,
) {
    // Send UTXO to mint account
    let (mint_txid, mint_vout) = ctx.helper.send_utxo(mint_pubkey).await.unwrap();

    // Create mint account with anchor
    let create_mint_ix = system_instruction::create_account_with_anchor(
        &mint_authority_pubkey,
        &mint_pubkey,
        minimum_rent(apl_token::state::Mint::LEN),
        apl_token::state::Mint::LEN as u64,
        &apl_token::id(),
        hex::decode(&mint_txid).unwrap().try_into().unwrap(),
        mint_vout,
    );

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[create_mint_ix],
            Some(mint_authority_pubkey),
            recent_blockhash,
        ),
        vec![mint_authority_keypair.clone(), mint_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    assert_eq!(processed_tx.status, Status::Processed, "Create mint account failed");

    // Initialize mint
    let init_mint_ix = apl_token::instruction::initialize_mint(
        &apl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        Some(&mint_authority_pubkey),
        decimals,
    ).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[init_mint_ix],
            Some(mint_authority_pubkey),
            recent_blockhash,
        ),
        vec![mint_authority_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    assert_eq!(processed_tx.status, Status::Processed, "Initialize mint failed");

    println!("Token mint created: {:?}", mint_pubkey);
}

/// Create an Associated Token Account (ATA)
async fn create_ata(
    ctx: &TestContext,
    funder_keypair: &UntweakedKeypair,
    funder_pubkey: Pubkey,
    wallet_pubkey: Pubkey,
    mint_pubkey: Pubkey,
) -> Pubkey {
    let (ata_pubkey, _) = apl_associated_token_account::get_associated_token_address_and_bump_seed(
        &wallet_pubkey,
        &mint_pubkey,
        &apl_associated_token_account::id(),
    );

    // Send UTXO to ATA
    let (ata_txid, ata_vout) = ctx.helper.send_utxo(ata_pubkey).await.unwrap();

    // Build ATA creation instruction data (txid + vout)
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(ata_txid.as_bytes());
    data.extend_from_slice(&ata_vout.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(funder_pubkey, true),
        AccountMeta::new(ata_pubkey, false),
        AccountMeta::new(wallet_pubkey, false),
        AccountMeta::new(mint_pubkey, false),
        AccountMeta::new(Pubkey::system_program(), false),
        AccountMeta::new(apl_token::id(), false),
    ];

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[Instruction {
                program_id: apl_associated_token_account::id(),
                accounts,
                data,
            }],
            Some(funder_pubkey),
            recent_blockhash,
        ),
        vec![funder_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    assert_eq!(processed_tx.status, Status::Processed, "Create ATA failed");

    println!("ATA created for wallet {:?}: {:?}", wallet_pubkey, ata_pubkey);
    ata_pubkey
}

/// Mint tokens to an ATA
async fn mint_tokens(
    ctx: &TestContext,
    mint_pubkey: Pubkey,
    dest_ata: Pubkey,
    mint_authority_keypair: &UntweakedKeypair,
    mint_authority_pubkey: Pubkey,
    amount: u64,
) {
    let mint_to_ix = apl_token::instruction::mint_to(
        &apl_token::id(),
        &mint_pubkey,
        &dest_ata,
        &mint_authority_pubkey,
        &[&mint_authority_pubkey],
        amount,
    ).unwrap();

    let recent_blockhash = ctx.client.get_best_finalized_block_hash().await.unwrap();
    let tx = build_and_sign_transaction(
        ArchMessage::new(
            &[mint_to_ix],
            Some(mint_authority_pubkey),
            recent_blockhash,
        ),
        vec![mint_authority_keypair.clone()],
        ctx.config.network,
    ).unwrap();

    let txid = ctx.client.send_transaction(tx).await.unwrap();
    let processed_tx = ctx.client.wait_for_processed_transaction(&txid).await.unwrap();
    assert_eq!(processed_tx.status, Status::Processed, "Mint tokens failed");

    // Verify balance
    let ata_info = ctx.client.read_account_info(dest_ata).await.unwrap();
    let token_account = apl_token::state::Account::unpack(&ata_info.data).unwrap();
    assert_eq!(token_account.amount, amount, "Token balance mismatch after mint");

    println!("Minted {} tokens to {:?}", amount, dest_ata);
}

/// Get token balance for an ATA
async fn get_token_balance(ctx: &TestContext, ata_pubkey: Pubkey) -> u64 {
    let ata_info = ctx.client.read_account_info(ata_pubkey).await.unwrap();
    apl_token::state::Account::unpack(&ata_info.data).unwrap().amount
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_apl_token_transfer() {
    println!("\n=== Test: ExecuteWithWinternitz APL Token Transfer ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let creation_fee: u64 = 1000;
    let transfer_fee: u64 = 500;
    let execute_fee: u64 = 750;

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        creation_fee, transfer_fee, execute_fee,
    ).await;

    // Create wallet with deposit to cover execute fee
    let vault_id = [99u8; 32];
    let initial_deposit: u64 = 10_000;
    let (pq_key, private_key) = generate_wots_keypair(700);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, initial_deposit,
    ).await;

    // Create token mint (payer is mint authority)
    let (mint_keypair, mint_pubkey, _) = generate_new_keypair(ctx.config.network);
    create_token_mint(
        &ctx,
        &mint_keypair,
        mint_pubkey,
        payer_pubkey,
        &payer_keypair,
        9, // decimals
    ).await;

    // Create ATA for wallet PDA (source of token transfer)
    // The wallet PDA will be the authority for this ATA
    let wallet_ata = create_ata(
        &ctx,
        &payer_keypair,
        payer_pubkey,
        wallet_pubkey, // owner of the ATA is the wallet PDA
        mint_pubkey,
    ).await;

    // Create ATA for recipient
    let (recipient_keypair, recipient_pubkey, _) = generate_new_keypair(ctx.config.network);
    ctx.client.create_and_fund_account_with_faucet(&recipient_keypair).await.unwrap();
    let recipient_ata = create_ata(
        &ctx,
        &payer_keypair,
        payer_pubkey,
        recipient_pubkey,
        mint_pubkey,
    ).await;

    // Mint tokens to wallet's ATA
    let mint_amount: u64 = 1_000_000_000; // 1 token with 9 decimals
    mint_tokens(
        &ctx,
        mint_pubkey,
        wallet_ata,
        &payer_keypair,
        payer_pubkey,
        mint_amount,
    ).await;

    // Verify initial balances
    assert_eq!(get_token_balance(&ctx, wallet_ata).await, mint_amount);
    assert_eq!(get_token_balance(&ctx, recipient_ata).await, 0);

    // Capture lamport balances before execute (wallet pays execute fee)
    let lamport_balances_before = capture_balances(&ctx, &[factory_pubkey, wallet_pubkey]).await;

    // Build the token transfer CPI instruction
    // The wallet PDA will sign this transfer as the authority
    let token_transfer_amount: u64 = 500_000_000; // 0.5 tokens
    let transfer_ix = apl_token::instruction::transfer(
        &apl_token::id(),
        &wallet_ata,        // source ATA
        &recipient_ata,     // destination ATA
        &wallet_pubkey,     // authority (wallet PDA will sign)
        &[],                // no additional signers
        token_transfer_amount,
    ).unwrap();

    // Build CpiAccountMeta for the signature message
    // Order: source, dest, authority, token_program
    let cpi_account_metas = vec![
        CpiAccountMeta { is_signer: false, is_writable: true },   // source ATA
        CpiAccountMeta { is_signer: false, is_writable: true },   // dest ATA
        CpiAccountMeta { is_signer: true, is_writable: false },   // authority (wallet PDA)
        CpiAccountMeta { is_signer: false, is_writable: false },  // token program
    ];

    // Build remaining accounts for the CPI
    let remaining_accounts = vec![
        AccountMeta { pubkey: wallet_ata, is_signer: false, is_writable: true },
        AccountMeta { pubkey: recipient_ata, is_signer: false, is_writable: true },
        AccountMeta { pubkey: wallet_pubkey, is_signer: false, is_writable: false }, // authority
        AccountMeta { pubkey: apl_token::id(), is_signer: false, is_writable: false },
    ];

    let status = execute_with_winternitz(
        &ctx,
        program_pubkey,
        factory_pubkey,
        wallet_pubkey,
        apl_token::id(), // target program is APL token
        &payer_keypair,
        payer_pubkey,
        vault_id,
        &pq_key,
        &pq_next,
        &private_key,
        transfer_ix.data.clone(),
        cpi_account_metas,
        remaining_accounts,
    ).await;

    assert_eq!(status, Status::Processed, "APL token transfer via ExecuteWithWinternitz should succeed");

    // Verify token balances changed correctly
    let wallet_token_balance = get_token_balance(&ctx, wallet_ata).await;
    let recipient_token_balance = get_token_balance(&ctx, recipient_ata).await;

    assert_eq!(
        wallet_token_balance,
        mint_amount - token_transfer_amount,
        "Wallet ATA should have {} tokens remaining",
        mint_amount - token_transfer_amount
    );
    assert_eq!(
        recipient_token_balance,
        token_transfer_amount,
        "Recipient ATA should have {} tokens",
        token_transfer_amount
    );

    // Verify lamport balances changed correctly (wallet pays execute fee)
    let lamport_balances_after = capture_balances(&ctx, &[factory_pubkey, wallet_pubkey]).await;

    let factory_gain = lamport_balances_after[0] - lamport_balances_before[0];
    assert_eq!(factory_gain, execute_fee, "Factory should gain execute_fee");

    // Wallet balance should have decreased by exactly execute_fee
    assert_eq!(
        lamport_balances_before[1] - lamport_balances_after[1],
        execute_fee,
        "Wallet should have paid exactly execute_fee"
    );

    // Verify wallet state (WOTS+ key rotated, transaction count incremented)
    verify_wallet_state(&ctx, wallet_pubkey, payer_pubkey.serialize(), &pq_next, 1).await;

    println!("\n=== Test PASSED: ExecuteWithWinternitz APL Token Transfer ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_invalid_signature() {
    println!("\n=== Test: ExecuteWithWinternitz Invalid Signature ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet
    let vault_id = [50u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(800);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10_000,
    ).await;

    // Build instruction with INVALID signature (random data)
    let invalid_signature = vec![0xFFu8; 2112];

    let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id,
        instruction_data: vec![],
        account_metas: vec![],
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
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    println!("\n=== Test PASSED: ExecuteWithWinternitz Invalid Signature ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_account_metas_mismatch() {
    println!("\n=== Test: ExecuteWithWinternitz Account Metas Mismatch ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet
    let vault_id = [51u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(810);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10_000,
    ).await;

    // Build signature with 2 account_metas but only 1 remaining account
    let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
    let cpi_account_metas = vec![
        CpiAccountMeta { is_signer: false, is_writable: true },
        CpiAccountMeta { is_signer: false, is_writable: true }, // Mismatch: 2 metas
    ];
    let account_pubkeys: Vec<[u8; 32]> = vec![payer_pubkey.serialize()]; // Only 1 pubkey

    let message = create_execute_message(
        &pq_key,
        &pq_next,
        &target_bytes,
        &[],
        &account_pubkeys,
        &cpi_account_metas,
    );
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id,
        instruction_data: vec![],
        account_metas: cpi_account_metas,
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

    // Pass only 1 remaining account but 2 account_metas
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
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        AccountMeta { pubkey: payer_pubkey, is_signer: true, is_writable: true },
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
                        // Only 1 remaining account
                        AccountMeta { pubkey: payer_pubkey, is_signer: false, is_writable: true },
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

    assert_error(&processed_tx.status, QuipError::AccountMetasMismatch);

    println!("\n=== Test PASSED: ExecuteWithWinternitz Account Metas Mismatch ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_wrong_system_program() {
    println!("\n=== Test: ExecuteWithWinternitz Wrong System Program ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, 750,
    ).await;

    // Create wallet
    let vault_id = [52u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(820);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10_000,
    ).await;

    // Create fake system program
    let (_fake_system_keypair, fake_system_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Build valid signature
    let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
    let message = create_execute_message(
        &pq_key,
        &pq_next,
        &target_bytes,
        &[],
        &[],
        &[],
    );
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id,
        instruction_data: vec![],
        account_metas: vec![],
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
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    println!("\n=== Test PASSED: ExecuteWithWinternitz Wrong System Program ===\n");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_execute_with_winternitz_insufficient_fee() {
    println!("\n=== Test: ExecuteWithWinternitz Insufficient Fee ===\n");

    let ctx = TestContext::new();
    let (program_pubkey, payer_keypair, payer_pubkey) = deploy_program(&ctx).await;
    let (_admin_keypair, admin_pubkey, _) = generate_new_keypair(ctx.config.network);

    // Set a very high execute fee
    let high_execute_fee: u64 = 1_000_000_000_000; // 1 trillion lamports
    let factory_pubkey = initialize_factory(
        &ctx, program_pubkey, &payer_keypair, payer_pubkey, admin_pubkey,
        1000, 500, high_execute_fee,
    ).await;

    // Create wallet with small deposit
    let vault_id = [39u8; 32];
    let (pq_key, private_key) = generate_wots_keypair(210);
    let pq_next = derive_wots_pubkey_at_index(&private_key, 1);

    let (wallet_pubkey, _wallet_utxo) = create_wallet(
        &ctx, program_pubkey, factory_pubkey, &payer_keypair, payer_pubkey,
        vault_id, &pq_key, 10_000,
    ).await;

    // Create a poor owner who can't afford execute fee
    let (poor_owner_keypair, _poor_owner_pubkey, _) = generate_new_keypair(ctx.config.network);
    ctx.client.create_and_fund_account_with_faucet(&poor_owner_keypair).await.unwrap();

    // Build signature
    let target_bytes = system_program::SYSTEM_PROGRAM_ID.serialize();
    let message = create_execute_message(
        &pq_key,
        &pq_next,
        &target_bytes,
        &[],
        &[],
        &[],
    );
    let signature_data = sign_message(&private_key, &message);

    let instruction_data = borsh::to_vec(&QuipInstruction::ExecuteWithWinternitz {
        pq_next: pq_next.clone(),
        vault_id,
        instruction_data: vec![],
        account_metas: vec![],
        signature: WinternitzSignature { signature_data },
    }).unwrap();

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(WOTS_COMPUTE_BUDGET);

    // Note: The original owner (payer) owns the wallet PDA derivation, so using
    // poor_owner will fail at PDA derivation. Instead, we need to update fees
    // AFTER wallet creation. Let's test by making payer have insufficient funds.
    // Actually for this test, we'll use a different approach - we need the actual
    // owner to not have funds. Let's simulate by draining the owner.

    // For simplicity, we'll just verify the factory has high execute_fee and
    // the transfer will fail. The original owner (payer) still has faucet funds,
    // so let's just verify the fee amount is set correctly and proceed.
    // In a real scenario, the owner would be drained of funds.

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
                        AccountMeta { pubkey: system_program::SYSTEM_PROGRAM_ID, is_signer: false, is_writable: false },
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

    // Should fail because owner can't afford the execute fee
    // The pre-check with check_sufficient_balance returns InsufficientWalletBalance
    assert_error(&processed_tx.status, QuipError::InsufficientWalletBalance);

    println!("\n=== Test PASSED: ExecuteWithWinternitz Insufficient Fee ===\n");
}
