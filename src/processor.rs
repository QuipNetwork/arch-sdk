// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use arch_program::{
    account::{AccountInfo, AccountMeta, next_account_info},
    bitcoin::{
        self, absolute::LockTime, transaction::Version,
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    },
    helper::add_state_transition,
    input_to_sign::InputToSign,
    instruction::Instruction,
    msg,
    program::{
        get_account_script_pubkey, get_bitcoin_block_height, get_bitcoin_tx_output_value,
        invoke, invoke_signed, set_transaction_to_sign, validate_utxo_ownership,
    },
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction::sign_input,
};
use borsh::BorshDeserialize;

use crate::error::QuipError;
use crate::instruction::QuipInstruction;
use crate::state::{VERSION, *};
use crate::utils::{load_state, require_admin, require_signer, require_valid_signature, save_state};

/// Program result type
pub type ProgramResult = Result<(), ProgramError>;

/// Bitcoin dust limit for P2TR (Taproot) outputs.
/// Outputs below this value are rejected by Bitcoin nodes as non-standard.
/// Confirmed via integration tests: 0-sat change outputs cause the Arch
/// runtime to silently revert all program state changes.
const BTC_DUST_LIMIT: u64 = 330;

/// Helper to convert Pubkey to bytes
fn pubkey_to_bytes(pubkey: &Pubkey) -> [u8; 32] {
    pubkey.serialize()
}

/// Main instruction processor - routes to specific handlers
pub fn process_instruction<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = QuipInstruction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match instruction {
        QuipInstruction::InitializeFactory {
            admin,
            creation_fee,
            transfer_fee,
            execute_fee,
            factory_utxo,
        } => {
            msg!("Instruction: InitializeFactory");
            process_initialize_factory(
                program_id,
                accounts,
                admin,
                creation_fee,
                transfer_fee,
                execute_fee,
                factory_utxo,
            )
        }

        QuipInstruction::DepositToWinternitz {
            vault_id,
            pq_owner,
            deposit,
            wallet_utxo,
        } => {
            msg!("Instruction: DepositToWinternitz");
            process_deposit_to_winternitz(
                program_id,
                accounts,
                vault_id,
                pq_owner,
                deposit,
                wallet_utxo,
            )
        }

        QuipInstruction::TransferWithWinternitz {
            vault_id,
            pq_next,
            amount,
            signature,
        } => {
            msg!("Instruction: TransferWithWinternitz");
            process_transfer_with_winternitz(program_id, accounts, vault_id, pq_next, amount, signature)
        }

        QuipInstruction::ExecuteWithWinternitz {
            pq_next,
            vault_id,
            instruction_data,
            account_metas,
            signature,
        } => {
            msg!("Instruction: ExecuteWithWinternitz");
            process_execute_with_winternitz(program_id, accounts, pq_next, vault_id, instruction_data, account_metas, signature)
        }

        QuipInstruction::ChangePqOwner { vault_id, pq_next, signature } => {
            msg!("Instruction: ChangePqOwner");
            process_change_pq_owner(program_id, accounts, vault_id, pq_next, signature)
        }

        QuipInstruction::UpdateFees {
            creation_fee,
            transfer_fee,
            execute_fee,
        } => {
            msg!("Instruction: UpdateFees");
            process_update_fees(program_id, accounts, creation_fee, transfer_fee, execute_fee)
        }

        QuipInstruction::WithdrawFees { amount } => {
            msg!("Instruction: WithdrawFees");
            process_withdraw_fees(program_id, accounts, amount)
        }

        QuipInstruction::TransferOwnership { new_admin } => {
            msg!("Instruction: TransferOwnership");
            process_transfer_ownership(program_id, accounts, new_admin)
        }

        QuipInstruction::BtcTransferWithWinternitz {
            vault_id,
            pq_next,
            amount,
            recipient_script_pubkey,
            fee_tx,
            source_utxo,
            signature,
        } => {
            msg!("Instruction: BtcTransferWithWinternitz");
            process_btc_transfer_with_winternitz(
                program_id,
                accounts,
                vault_id,
                pq_next,
                amount,
                recipient_script_pubkey,
                fee_tx,
                source_utxo,
                signature,
            )
        }
    }
}

// =============================================================================
// Instruction Handlers
// =============================================================================

fn process_initialize_factory<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    admin: [u8; 32],
    creation_fee: u64,
    transfer_fee: u64,
    execute_fee: u64,
    factory_utxo: arch_program::utxo::UtxoMeta,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify factory account derivation and get bump
    let factory_bump = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;

    // Create PDA account (will fail naturally if called a second time)
    // This makes `is_initialized` implicit - account existence implies initialization since
    // factories can only be created via initialize instruction, and creation + initialization are atomic.
    let factory_seeds: &[&[u8]] = &[b"factory", &[factory_bump]];
    crate::utils::create_pda_account(
        payer_info,
        factory_info,
        QuipFactory::SPACE,
        program_id,
        &factory_utxo,
        factory_seeds,
    )?;

    // Create factory state
    let factory = QuipFactory {
        admin,
        creation_fee,
        transfer_fee,
        execute_fee,
        total_wallets: 0,
        accumulated_fees: 0,
        bump: factory_bump, // PDA bump seed for invoke_signed
    };

    // Serialize and write to account
    save_state(&factory, factory_info)?;

    msg!("Factory initialized with admin: {}", hex::encode(admin));
    Ok(())
}

fn process_deposit_to_winternitz<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    vault_id: [u8; 32],
    pq_owner: WinternitzPublicKey,
    deposit: u64,
    wallet_utxo: arch_program::utxo::UtxoMeta,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    // Owner pays for wallet creation and deposit
    let owner_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify owner is signer
    require_signer(owner_info).map_err(|_| QuipError::UnauthorizedSigner)?;

    // Derive owner bytes from signer
    let owner = pubkey_to_bytes(owner_info.key);

    // Verify account derivations and get bumps (implies program ownership for PDAs)
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;
    let wallet_bump = crate::utils::verify_wallet_address(program_id, &owner, &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Load factory early for balance check
    let mut factory: QuipFactory = load_state(factory_info)?;

    // Pre-check owner balance for creation fee + deposit (fail-fast)
    let total_required = factory.creation_fee
        .checked_add(deposit)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    crate::utils::check_sufficient_balance(owner_info, total_required)?;

    // Create wallet PDA account (will fail if wallet already exists via system program CPI)
    let wallet_seeds: &[&[u8]] = &[b"wallet", owner.as_ref(), vault_id.as_ref(), &[wallet_bump]];
    crate::utils::create_pda_account(
        owner_info,
        wallet_info,
        QuipWallet::SPACE,
        program_id,
        &wallet_utxo,
        wallet_seeds,
    )?;

    // Transfer creation fee from owner to factory
    crate::utils::transfer_value_from_signer(owner_info, factory_info, factory.creation_fee)?;

    // Transfer deposit from owner to wallet
    if deposit > 0 {
        crate::utils::transfer_value_from_signer(owner_info, wallet_info, deposit)?;
    }

    // Update factory counters
    factory.accumulate_fee(factory.creation_fee);
    factory.total_wallets = factory
        .total_wallets
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Create wallet state
    let current_block = get_bitcoin_block_height() as i64;
    let wallet = QuipWallet {
        version: VERSION,
        owner,
        pq_owner,
        created_at: current_block,
        last_activity: current_block,
        transaction_count: 0,
        bump: wallet_bump,
    };

    // Serialize wallet and factory state
    save_state(&wallet, wallet_info)?;
    save_state(&factory, factory_info)?;

    msg!(
        "Wallet created with vault_id: {}, deposit: {}",
        hex::encode(vault_id),
        deposit
    );

    Ok(())
}

fn process_transfer_with_winternitz<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    vault_id: [u8; 32],
    pq_next: WinternitzPublicKey,
    amount: u64,
    signature: WinternitzSignature,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    let recipient_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    // Verify owner is signer
    require_signer(owner_info).map_err(|_| QuipError::UnauthorizedSigner)?;

    let owner = pubkey_to_bytes(owner_info.key);

    // Verify account derivations (implies program ownership for PDAs)
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;
    let _ = crate::utils::verify_wallet_address(program_id, &owner, &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Load states
    let mut factory: QuipFactory = load_state(factory_info)?;
    let mut wallet: QuipWallet = load_state(wallet_info)?;

    // Pre-check wallet balance: fee + transfer amount
    let total_required = factory.transfer_fee
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    crate::utils::check_sufficient_balance(wallet_info, total_required)?;

    // Verify signature
    let recipient_bytes = pubkey_to_bytes(recipient_info.key);
    let message = crate::utils::create_transfer_message(
        &wallet.pq_owner,
        &pq_next,
        &recipient_bytes,
        amount,
    );
    require_valid_signature(&wallet.pq_owner, &message, &signature)?;

    // Transfer fee from wallet to factory
    crate::utils::transfer_value(wallet_info, factory_info, factory.transfer_fee)?;

    // Transfer the amount from wallet to recipient
    crate::utils::transfer_value(wallet_info, recipient_info, amount)?;

    // Update factory fees
    factory.accumulate_fee(factory.transfer_fee);

    // Update wallet state
    wallet.rotate_key(pq_next);
    wallet.increment_transaction_count();
    wallet.last_activity = get_bitcoin_block_height() as i64;

    // Serialize updated states
    save_state(&factory, factory_info)?;
    save_state(&wallet, wallet_info)?;

    msg!(
        "Transfer of {} to {} executed with vault_id: {}",
        amount,
        hex::encode(recipient_bytes),
        hex::encode(vault_id)
    );
    Ok(())
}

fn process_execute_with_winternitz<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    pq_next: WinternitzPublicKey,
    vault_id: [u8; 32],
    instruction_data: Vec<u8>,
    account_metas: Vec<CpiAccountMeta>,
    signature: WinternitzSignature,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    let target_program_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify owner is signer
    require_signer(owner_info).map_err(|_| QuipError::UnauthorizedSigner)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    let owner = pubkey_to_bytes(owner_info.key);

    // Verify account derivations (implies program ownership for PDAs)
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;
    let _ = crate::utils::verify_wallet_address(program_id, &owner, &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Load states
    let mut factory: QuipFactory = load_state(factory_info)?;
    let mut wallet: QuipWallet = load_state(wallet_info)?;

    // Pre-check owner balance for execute fee (owner pays, not wallet)
    crate::utils::check_sufficient_balance(owner_info, factory.execute_fee)?;

    // Collect remaining accounts for CPI
    let remaining_accounts: Vec<&AccountInfo> = account_info_iter.collect();

    // Verify account metas match remaining accounts
    if account_metas.len() != remaining_accounts.len() {
        return Err(QuipError::AccountMetasMismatch.into());
    }

    // Get account pubkeys for message
    let account_pubkeys: Vec<[u8; 32]> = remaining_accounts
        .iter()
        .map(|a| pubkey_to_bytes(a.key))
        .collect();

    // Verify signature
    let target_bytes = pubkey_to_bytes(target_program_info.key);
    let message = crate::utils::create_execute_message(
        &wallet.pq_owner,
        &pq_next,
        &target_bytes,
        &instruction_data,
        &account_pubkeys,
        &account_metas,
    );
    require_valid_signature(&wallet.pq_owner, &message, &signature)?;

    // Copy values needed for wallet_seeds before mutating wallet
    let wallet_owner = wallet.owner;
    let wallet_bump = wallet.bump;

    // Transfer execute fee from owner to factory
    crate::utils::transfer_value_from_signer(owner_info, factory_info, factory.execute_fee)?;

    // Update factory fees
    factory.accumulate_fee(factory.execute_fee);

    // Update wallet state
    wallet.rotate_key(pq_next);
    wallet.increment_transaction_count();
    wallet.last_activity = get_bitcoin_block_height() as i64;

    // Serialize updated states
    save_state(&factory, factory_info)?;
    save_state(&wallet, wallet_info)?;

    // Build wallet PDA seeds for signing (uses copied values)
    let wallet_seeds: &[&[u8]] = &[
        b"wallet",
        wallet_owner.as_ref(),
        vault_id.as_ref(),
        &[wallet_bump],
    ];

    // Build the CPI instruction
    let cpi_account_metas: Vec<AccountMeta> = remaining_accounts
        .iter()
        .zip(account_metas.iter())
        .map(|(account, meta)| AccountMeta {
            pubkey: account.key.clone(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    let cpi_instruction = Instruction {
        program_id: target_program_info.key.clone(),
        accounts: cpi_account_metas,
        data: instruction_data,
    };

    // Execute CPI using ArchVM's invoke_signed mechanism
    // The wallet PDA must sign for this CPI (using wallet_seeds defined above)
    let cpi_account_infos: Vec<AccountInfo> = remaining_accounts
        .iter()
        .map(|a| (*a).clone())
        .collect();
    invoke_signed(&cpi_instruction, &cpi_account_infos, &[wallet_seeds])?;

    msg!(
        "Execute CPI to {} with vault_id: {}",
        hex::encode(target_bytes),
        hex::encode(vault_id)
    );
    Ok(())
}

fn process_change_pq_owner<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    vault_id: [u8; 32],
    pq_next: WinternitzPublicKey,
    signature: WinternitzSignature,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let wallet_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    // Verify owner is signer
    require_signer(owner_info).map_err(|_| QuipError::UnauthorizedSigner)?;

    // Verify wallet address derivation (implies program ownership for PDAs)
    let _ = crate::utils::verify_wallet_address(program_id, &pubkey_to_bytes(owner_info.key), &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Load wallet state
    let mut wallet: QuipWallet = load_state(wallet_info)?;

    // Verify signature
    let message = crate::utils::create_change_owner_message(&wallet.pq_owner, &pq_next);
    require_valid_signature(&wallet.pq_owner, &message, &signature)?;

    // Update wallet state
    wallet.rotate_key(pq_next);
    wallet.last_activity = get_bitcoin_block_height() as i64;

    // Serialize updated state
    save_state(&wallet, wallet_info)?;

    msg!("Post-quantum owner changed");
    Ok(())
}

fn process_update_fees<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    creation_fee: u64,
    transfer_fee: u64,
    execute_fee: u64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let admin_info = next_account_info(account_info_iter)?;

    // Verify factory account derivation (implies program ownership for PDAs)
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;

    // Verify admin is signer
    require_signer(admin_info).map_err(|_| QuipError::UnauthorizedSigner)?;

    // Load factory and verify admin
    let mut factory: QuipFactory = load_state(factory_info)?;
    require_admin(&factory, &pubkey_to_bytes(admin_info.key))?;

    // Update fees
    factory.creation_fee = creation_fee;
    factory.transfer_fee = transfer_fee;
    factory.execute_fee = execute_fee;

    // Serialize updated factory
    save_state(&factory, factory_info)?;

    msg!(
        "Fees updated: creation={}, transfer={}, execute={}",
        creation_fee,
        transfer_fee,
        execute_fee
    );
    Ok(())
}

fn process_withdraw_fees<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    amount: u64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let admin_info = next_account_info(account_info_iter)?;
    let recipient_info = next_account_info(account_info_iter)?;

    // Verify factory account derivation
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;

    // Verify admin is signer
    require_signer(admin_info).map_err(|_| QuipError::UnauthorizedSigner)?;

    // Load factory and verify admin
    let mut factory: QuipFactory = load_state(factory_info)?;
    require_admin(&factory, &pubkey_to_bytes(admin_info.key))?;

    // Verify sufficient fees (both tracked and actual balance)
    if factory.accumulated_fees < amount {
        return Err(QuipError::InsufficientFunds.into());
    }
    crate::utils::check_sufficient_balance(factory_info, amount)?;

    // Deduct fees
    factory.accumulated_fees = factory
        .accumulated_fees
        .checked_sub(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Transfer the fees from factory to recipient
    crate::utils::transfer_value(factory_info, recipient_info, amount)?;

    // Serialize updated factory (after transfer to ensure state consistency)
    save_state(&factory, factory_info)?;

    msg!("Withdrew {} fees", amount);
    Ok(())
}

fn process_transfer_ownership<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    new_admin: [u8; 32],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let admin_info = next_account_info(account_info_iter)?;

    // Verify factory account derivation
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;

    // Verify admin is signer
    require_signer(admin_info).map_err(|_| QuipError::UnauthorizedSigner)?;

    // Load factory and verify admin
    let mut factory: QuipFactory = load_state(factory_info)?;
    require_admin(&factory, &pubkey_to_bytes(admin_info.key))?;

    // Update admin
    let old_admin = factory.admin;
    factory.admin = new_admin;

    // Serialize updated factory
    save_state(&factory, factory_info)?;

    msg!(
        "Ownership transferred from {} to {}",
        hex::encode(old_admin),
        hex::encode(new_admin)
    );
    Ok(())
}

/// Process a BTC transfer from a Quip wallet using WOTS+ signature authorization.
///
/// This function builds and signs a Bitcoin transaction that transfers funds from
/// the wallet to a recipient. The wallet can spend either its anchor UTXO or any
/// non-anchor UTXO it owns.
///
/// # Key Constraints
///
/// - **Anchor UTXO**: Must always leave >= dust (330 sats) as change to keep the
///   wallet account anchored.
/// - **Non-anchor UTXO**: Can be fully spent (change = 0) since the wallet remains
///   anchored to its primary UTXO.
/// - **WOTS+ Key Rotation**: The signing key is rotated after each transaction for
///   quantum resistance. Each key can only be used once.
///
/// # Accounts
///
/// 0. `[writable]` Factory - Program state, receives transfer fee
/// 1. `[writable]` Wallet - The wallet PDA being spent from
/// 2. `[writable, signer]` Owner - Pays Arch tx fees and lamport transfer fee
/// 3. `[]` System Program
fn process_btc_transfer_with_winternitz<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    vault_id: [u8; 32],
    pq_next: WinternitzPublicKey,
    amount: u64,
    recipient_script_pubkey: Vec<u8>,
    fee_tx: Vec<u8>,
    source_utxo: arch_program::utxo::UtxoMeta,
    signature: WinternitzSignature,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    // The owner is also the Arch tx fee payer. Since fee payers are implicitly
    // writable in Arch, the owner must be anchored to a UTXO and included in
    // the BTC transaction. Signed via sign_input + invoke (system-owned).
    let owner_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    let owner_bytes = pubkey_to_bytes(owner_info.key);

    // Verify account derivations (implies program ownership and wallet belongs to owner_bytes)
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;
    let _ = crate::utils::verify_wallet_address(program_id, &owner_bytes, &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Load states
    let mut factory: QuipFactory = load_state(factory_info)?;
    let mut wallet: QuipWallet = load_state(wallet_info)?;

    // Pre-check owner lamport balance for transfer fee (owner pays, not wallet)
    crate::utils::check_sufficient_balance(owner_info, factory.transfer_fee)?;

    // Validate inputs
    if amount == 0 {
        return Err(QuipError::ZeroAmountTransfer.into());
    }
    if recipient_script_pubkey.is_empty() {
        return Err(QuipError::EmptyRecipientScript.into());
    }

    // Validate UTXO ownership - the source UTXO must belong to the wallet
    if !validate_utxo_ownership(&source_utxo, wallet_info.key) {
        return Err(QuipError::UtxoNotOwnedByWallet.into());
    }

    // Determine if this is the anchor UTXO (the UTXO that anchors the wallet account)
    let is_anchor_utxo = source_utxo.txid() == wallet_info.utxo.txid()
        && source_utxo.vout() == wallet_info.utxo.vout();

    // Verify WOTS+ signature (includes source_utxo for replay protection)
    let message = crate::utils::create_btc_transfer_message(
        &wallet.pq_owner,
        &pq_next,
        &recipient_script_pubkey,
        amount,
        &source_utxo,
    );
    require_valid_signature(&wallet.pq_owner, &message, &signature)?;

    // Get source UTXO value
    let utxo_value = get_bitcoin_tx_output_value(
        source_utxo.txid_big_endian(),
        source_utxo.vout(),
    )
    .ok_or::<ProgramError>(QuipError::InsufficientBtcBalance.into())?;

    // Calculate change and validate based on UTXO type
    let change = utxo_value
        .checked_sub(amount)
        .ok_or::<ProgramError>(QuipError::InsufficientBtcBalance.into())?;

    // Anchor UTXO: must keep >= dust limit (cannot close account)
    let anchor_insufficient = is_anchor_utxo && change < BTC_DUST_LIMIT;
    if anchor_insufficient {
        return Err(QuipError::AnchorChangeBelowDustLimit.into());
    }

    // Non-anchor UTXO: full spend OK (change=0), otherwise change >= dust limit
    let non_anchor_dust = !is_anchor_utxo && change > 0 && change < BTC_DUST_LIMIT;
    if non_anchor_dust {
        return Err(QuipError::ChangeBelowDustLimit.into());
    }

    // Deserialize the fee transaction and extract its first input as the fee input
    let fee_transaction: Transaction = bitcoin::consensus::deserialize(&fee_tx)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let fee_input = fee_transaction.input.first()
        .ok_or(ProgramError::InvalidInstructionData)?
        .clone();

    // --- State mutations (must happen BEFORE add_state_transition) ---

    // Charge lamport transfer fee from owner to factory.
    // Owner is a system-owned signer, so we use the system program transfer.
    crate::utils::transfer_value_from_signer(owner_info, factory_info, factory.transfer_fee)?;

    // Update factory accumulated fees
    factory.accumulate_fee(factory.transfer_fee);

    // Rotate WOTS+ key (critical: each key must only be used once)
    wallet.rotate_key(pq_next);
    wallet.increment_transaction_count();
    wallet.last_activity = get_bitcoin_block_height() as i64;

    // Serialize updated states
    save_state(&factory, factory_info)?;
    save_state(&wallet, wallet_info)?;

    // --- Build Bitcoin transaction ---
    //
    // TRANSACTION LAYOUT
    // ==================
    //
    // The Arch runtime requires that each account's input and output are at matching
    // indices (Input N / Output N) for UTXO tracking. We place account pass-through
    // outputs first, then variable outputs (change/recipient) last.
    //
    // Case 1: ANCHOR UTXO spending
    //   Input 0 / Output 0 : wallet (change = utxo_value - amount, must be >= dust)
    //   Input 1 / Output 1 : factory (pass-through)
    //   Input 2 / Output 2 : owner (pass-through)
    //   Input 3            : fee input (unsigned)
    //   Output 3           : recipient
    //
    // Case 2: NON-ANCHOR UTXO with change (change > 0)
    //   Input 0 / Output 0 : wallet anchor (pass-through, unchanged)
    //   Input 1 / Output 1 : factory (pass-through)
    //   Input 2 / Output 2 : owner (pass-through)
    //   Input 3            : non-anchor UTXO (fully consumed)
    //   Input 4            : fee input (unsigned)
    //   Output 3           : wallet change
    //   Output 4           : recipient
    //
    // Case 3: NON-ANCHOR UTXO full spend (change = 0)
    //   Input 0 / Output 0 : wallet anchor (pass-through, unchanged)
    //   Input 1 / Output 1 : factory (pass-through)
    //   Input 2 / Output 2 : owner (pass-through)
    //   Input 3            : non-anchor UTXO (fully consumed)
    //   Input 4            : fee input (unsigned)
    //   Output 3           : recipient (no change output)

    let wallet_script_bytes = get_account_script_pubkey(wallet_info.key);
    let wallet_script = ScriptBuf::from_bytes(wallet_script_bytes.to_vec());

    // Get anchor UTXO value (needed for both layouts)
    // Reuse already-fetched value when spending the anchor UTXO
    let anchor_utxo_value = if is_anchor_utxo {
        utxo_value
    } else {
        get_bitcoin_tx_output_value(
            wallet_info.utxo.txid_big_endian(),
            wallet_info.utxo.vout(),
        )
        .ok_or::<ProgramError>(QuipError::InsufficientBtcBalance.into())?
    };

    // Determine wallet anchor output value
    let wallet_anchor_output_value = if is_anchor_utxo {
        // Spending the anchor UTXO: change goes to anchor output
        change
    } else {
        // Not spending anchor: anchor passes through unchanged
        anchor_utxo_value
    };

    let mut btc_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            // Input 0: wallet's anchor UTXO
            TxIn {
                previous_output: OutPoint {
                    txid: wallet_info.utxo.to_txid(),
                    vout: wallet_info.utxo.vout(),
                },
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
        ],
        output: vec![
            // Output 0: wallet anchor (change if spending anchor, pass-through otherwise)
            TxOut {
                value: Amount::from_sat(wallet_anchor_output_value),
                script_pubkey: wallet_script.clone(),
            },
        ],
    };

    // Input 1 + Output 1: factory state transition (pass-through)
    add_state_transition(&mut btc_tx, factory_info)?;

    // Input 2 + Output 2: owner pass-through (signed via sign_input)
    let owner_utxo_value = get_bitcoin_tx_output_value(
        owner_info.utxo.txid_big_endian(),
        owner_info.utxo.vout(),
    )
    .ok_or::<ProgramError>(QuipError::InsufficientBtcBalance.into())?;
    btc_tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: owner_info.utxo.to_txid(),
            vout: owner_info.utxo.vout(),
        },
        script_sig: ScriptBuf::default(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });
    btc_tx.output.push(TxOut {
        value: Amount::from_sat(owner_utxo_value),
        script_pubkey: ScriptBuf::from_bytes(
            get_account_script_pubkey(owner_info.key).to_vec(),
        ),
    });

    // For non-anchor UTXO: add source_utxo as Input 3
    if !is_anchor_utxo {
        btc_tx.input.push(TxIn {
            previous_output: OutPoint {
                txid: source_utxo.to_txid(),
                vout: source_utxo.vout(),
            },
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        });
    }

    // For non-anchor UTXO with change: add wallet change output at index 3
    if !is_anchor_utxo && change > 0 {
        btc_tx.output.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: wallet_script.clone(),
        });
    }

    // Recipient output
    btc_tx.output.push(TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: ScriptBuf::from_bytes(recipient_script_pubkey.clone()),
    });

    // Fee input: Input 3 for anchor, Input 4 for non-anchor
    btc_tx.input.push(fee_input);

    // Threshold-sign program-owned PDA inputs (wallet + factory)
    let inputs_to_sign = build_inputs_to_sign(wallet_info.key, factory_info.key, is_anchor_utxo);
    set_transaction_to_sign(accounts, &btc_tx, &inputs_to_sign)?;

    // Sign the owner's BTC input (index 2). The owner is system-owned,
    // not a program PDA, so it can't be included in InputToSign. Instead we use
    // sign_input + invoke, which delegates signing to the system program using
    // the owner's signer authority from the Arch transaction.
    let ix = sign_input(2, owner_info.key);
    invoke(&ix, &[owner_info.clone()])?;

    msg!(
        "BTC transfer of {} sats with vault_id: {}",
        amount,
        hex::encode(vault_id)
    );
    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Build the InputToSign array for BTC transfer transactions.
///
/// CRITICAL - InputToSign Ordering:
/// The Arch runtime updates account.utxo to (txid, index) for EACH InputToSign entry,
/// meaning the LAST entry for a given signer determines the account's final UTXO.
///
/// For non-anchor spending, the wallet signs TWO inputs (index 0 and index 3).
/// We must order them so index 0 (anchor) is signed LAST, ensuring wallet.utxo
/// points to Output 0 (the anchor pass-through) rather than Output 3 (recipient).
///
/// This allows full spending of non-anchor UTXOs while preserving the wallet's anchor.
fn build_inputs_to_sign(
    wallet_key: &Pubkey,
    factory_key: &Pubkey,
    is_anchor_utxo: bool,
) -> Vec<InputToSign> {
    if is_anchor_utxo {
        vec![
            InputToSign { index: 0, signer: wallet_key.clone() },
            InputToSign { index: 1, signer: factory_key.clone() },
        ]
    } else {
        vec![
            InputToSign { index: 3, signer: wallet_key.clone() }, // non-anchor (first)
            InputToSign { index: 1, signer: factory_key.clone() },
            InputToSign { index: 0, signer: wallet_key.clone() }, // anchor (last)
        ]
    }
}
