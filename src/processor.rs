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
        invoke, invoke_signed, set_transaction_to_sign,
    },
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction::sign_input,
};
use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::QuipError;
use crate::instruction::QuipInstruction;
use crate::state::*;

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
            to,
            pq_to,
            initial_deposit,
            wallet_utxo,
        } => {
            msg!("Instruction: DepositToWinternitz");
            process_deposit_to_winternitz(
                program_id,
                accounts,
                vault_id,
                to,
                pq_to,
                initial_deposit,
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

    // Verify writable
    if !factory_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify factory account derivation and get bump
    let factory_bump = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;

    // Check if factory account needs to be created
    if factory_info.data_len() == 0 {
        // Create PDA account
        let factory_seeds: &[&[u8]] = &[b"factory", &[factory_bump]];
        crate::utils::create_pda_account(
            payer_info,
            factory_info,
            QuipFactory::SPACE,
            program_id,
            &factory_utxo,
            factory_seeds,
        )?;
    }

    // Verify ownership
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }

    // Check if factory is already initialized
    let factory_data = factory_info.try_borrow_data()?;
    if !factory_data.is_empty() {
        // Try to deserialize to check is_initialized flag
        if let Ok(existing_factory) = QuipFactory::try_from_slice(&factory_data) {
            if existing_factory.is_initialized {
                return Err(QuipError::FactoryAlreadyInitialized.into());
            }
        }
    }
    drop(factory_data);

    // Create factory state
    let factory = QuipFactory {
        is_initialized: true,
        admin,
        creation_fee,
        transfer_fee,
        execute_fee,
        total_wallets: 0,
        accumulated_fees: 0,
        bump: factory_bump, // PDA bump seed for invoke_signed
    };

    // Serialize and write to account
    let mut data = factory_info.try_borrow_mut_data()?;
    factory.serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Factory initialized with admin: {}", hex::encode(admin));
    Ok(())
}

fn process_deposit_to_winternitz<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    vault_id: [u8; 32],
    to: [u8; 32],
    pq_to: WinternitzPublicKey,
    initial_deposit: u64,
    wallet_utxo: arch_program::utxo::UtxoMeta,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    let _owner_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify writable permissions
    if !factory_info.is_writable || !wallet_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify payer is signer
    if !payer_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Verify account derivations and get bumps
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;
    let wallet_bump = crate::utils::verify_wallet_address(program_id, &to, &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Check if this is a new wallet creation or a topup
    let is_new_wallet = wallet_info.data_len() == 0;

    // Create wallet PDA account if it doesn't exist
    if is_new_wallet {
        let wallet_seeds: &[&[u8]] = &[b"wallet", to.as_ref(), vault_id.as_ref(), &[wallet_bump]];
        crate::utils::create_pda_account(
            payer_info,
            wallet_info,
            QuipWallet::SPACE,
            program_id,
            &wallet_utxo,
            wallet_seeds,
        )?;
    }

    // Verify ownership (factory must already exist, wallet was just created or exists)
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if wallet_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }

    // Load factory
    let factory_data = factory_info.try_borrow_data()?;
    let mut factory = QuipFactory::try_from_slice(&factory_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    // Verify factory is initialized
    if !factory.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    if is_new_wallet {
        // NEW WALLET: charge creation fee, initialize wallet state

        // Transfer creation fee from payer (signer) to factory
        crate::utils::transfer_value_from_signer(payer_info, factory_info, factory.creation_fee)?;

        // Transfer initial deposit from payer (signer) to wallet
        if initial_deposit > 0 {
            crate::utils::transfer_value_from_signer(payer_info, wallet_info, initial_deposit)?;
        }

        // Update factory counters
        factory.accumulated_fees = factory
            .accumulated_fees
            .checked_add(factory.creation_fee)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        factory.total_wallets = factory
            .total_wallets
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        // Create wallet state
        let current_block = get_bitcoin_block_height() as i64;
        let wallet = QuipWallet {
            is_initialized: true,
            factory: pubkey_to_bytes(factory_info.key),
            owner: to,
            pq_owner: pq_to,
            created_at: current_block,
            last_activity: current_block,
            transaction_count: 0,
            bump: wallet_bump,
        };

        // Serialize wallet state
        let mut wallet_data = wallet_info.try_borrow_mut_data()?;
        wallet.serialize(&mut &mut wallet_data[..])
            .map_err(|_| ProgramError::InvalidAccountData)?;

        // Serialize factory state
        let mut factory_data = factory_info.try_borrow_mut_data()?;
        factory.serialize(&mut &mut factory_data[..])
            .map_err(|_| ProgramError::InvalidAccountData)?;

        msg!(
            "Wallet created with vault_id: {}, deposit: {}",
            hex::encode(vault_id),
            initial_deposit
        );
    } else {
        // TOPUP: just transfer deposit, no creation fee, no state changes

        // Verify wallet is initialized
        let wallet_data = wallet_info.try_borrow_data()?;
        let wallet = QuipWallet::try_from_slice(&wallet_data)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        drop(wallet_data);

        if !wallet.is_initialized {
            return Err(QuipError::AccountNotInitialized.into());
        }

        // Transfer deposit from payer (signer) to wallet
        if initial_deposit > 0 {
            crate::utils::transfer_value_from_signer(payer_info, wallet_info, initial_deposit)?;
        }

        msg!(
            "Wallet topped up with vault_id: {}, deposit: {}",
            hex::encode(vault_id),
            initial_deposit
        );
    }

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
    let payer_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify account ownership and permissions
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if wallet_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if !factory_info.is_writable || !wallet_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify payer is signer
    if !payer_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    let payer_bytes = pubkey_to_bytes(payer_info.key);

    // Verify account derivations
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;
    let _ = crate::utils::verify_wallet_address(program_id, &payer_bytes, &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Load states
    let factory_data = factory_info.try_borrow_data()?;
    let mut factory = QuipFactory::try_from_slice(&factory_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    // Verify factory is initialized
    if !factory.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    let wallet_data = wallet_info.try_borrow_data()?;
    let mut wallet = QuipWallet::try_from_slice(&wallet_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(wallet_data);

    // Verify wallet is initialized
    if !wallet.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    // Verify payer is wallet owner
    if pubkey_to_bytes(payer_info.key) != wallet.owner {
        return Err(QuipError::UnauthorizedSigner.into());
    }

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

    let is_valid = crate::utils::verify_winternitz_signature(&wallet.pq_owner, &message, &signature)?;
    if !is_valid {
        return Err(QuipError::InvalidWotsSignature.into());
    }

    // Transfer fee from wallet to factory
    crate::utils::transfer_value(wallet_info, factory_info, factory.transfer_fee)?;

    // Transfer the amount from wallet to recipient
    crate::utils::transfer_value(wallet_info, recipient_info, amount)?;

    // Update accumulated fees counter
    factory.accumulated_fees = factory
        .accumulated_fees
        .checked_add(factory.transfer_fee)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Update wallet state
    wallet.pq_owner = pq_next;
    wallet.transaction_count = wallet
        .transaction_count
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    wallet.last_activity = get_bitcoin_block_height() as i64;

    // Serialize updated states
    let mut factory_data = factory_info.try_borrow_mut_data()?;
    factory.serialize(&mut &mut factory_data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    let mut wallet_data = wallet_info.try_borrow_mut_data()?;
    wallet.serialize(&mut &mut wallet_data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

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
    let payer_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify account ownership and permissions
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if wallet_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if !factory_info.is_writable || !wallet_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify payer is signer
    if !payer_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    let payer_bytes = pubkey_to_bytes(payer_info.key);

    // Verify account derivations
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;
    let _ = crate::utils::verify_wallet_address(program_id, &payer_bytes, &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Load states
    let factory_data = factory_info.try_borrow_data()?;
    let mut factory = QuipFactory::try_from_slice(&factory_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    // Verify factory is initialized
    if !factory.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    let wallet_data = wallet_info.try_borrow_data()?;
    let mut wallet = QuipWallet::try_from_slice(&wallet_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(wallet_data);

    // Verify wallet is initialized
    if !wallet.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    // Verify payer is wallet owner
    if pubkey_to_bytes(payer_info.key) != wallet.owner {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Pre-check wallet balance for execute fee
    crate::utils::check_sufficient_balance(wallet_info, factory.execute_fee)?;

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

    let is_valid = crate::utils::verify_winternitz_signature(&wallet.pq_owner, &message, &signature)?;
    if !is_valid {
        return Err(QuipError::InvalidWotsSignature.into());
    }

    // Build wallet PDA seeds for signing
    let wallet_seeds: &[&[u8]] = &[
        b"wallet",
        wallet.owner.as_ref(),
        vault_id.as_ref(),
        &[wallet.bump],
    ];

    // Transfer execute fee from wallet to factory
    crate::utils::transfer_value(wallet_info, factory_info, factory.execute_fee)?;

    // Update accumulated fees counter
    factory.accumulated_fees = factory
        .accumulated_fees
        .checked_add(factory.execute_fee)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Update wallet state
    wallet.pq_owner = pq_next;
    wallet.transaction_count = wallet
        .transaction_count
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    wallet.last_activity = get_bitcoin_block_height() as i64;

    // Serialize updated states
    let mut factory_data = factory_info.try_borrow_mut_data()?;
    factory.serialize(&mut &mut factory_data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    let mut wallet_data = wallet_info.try_borrow_mut_data()?;
    wallet.serialize(&mut &mut wallet_data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

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
    // Convert Vec<&AccountInfo> to Vec<AccountInfo> for invoke_signed
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
    let _factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;

    // Verify account ownership and permissions
    if wallet_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if !wallet_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify payer is signer
    if !payer_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    let payer_bytes = pubkey_to_bytes(payer_info.key);

    // Verify account derivations
    let _ = crate::utils::verify_wallet_address(program_id, &payer_bytes, &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Load states
    let wallet_data = wallet_info.try_borrow_data()?;
    let mut wallet = QuipWallet::try_from_slice(&wallet_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(wallet_data);

    // Verify wallet is initialized
    if !wallet.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    // Verify payer is wallet owner
    if pubkey_to_bytes(payer_info.key) != wallet.owner {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Verify signature
    let message = crate::utils::create_change_owner_message(&wallet.pq_owner, &pq_next);

    let is_valid = crate::utils::verify_winternitz_signature(&wallet.pq_owner, &message, &signature)?;
    if !is_valid {
        return Err(QuipError::InvalidWotsSignature.into());
    }

    // Update wallet state
    wallet.pq_owner = pq_next;
    wallet.last_activity = get_bitcoin_block_height() as i64;

    // Serialize updated state
    let mut wallet_data = wallet_info.try_borrow_mut_data()?;
    wallet.serialize(&mut &mut wallet_data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

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

    // Verify account ownership and permissions
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if !factory_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify factory account derivation
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;

    // Verify admin is signer
    if !admin_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Load factory
    let factory_data = factory_info.try_borrow_data()?;
    let mut factory = QuipFactory::try_from_slice(&factory_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    // Verify factory is initialized
    if !factory.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    // Verify admin matches
    if pubkey_to_bytes(admin_info.key) != factory.admin {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Update fees
    factory.creation_fee = creation_fee;
    factory.transfer_fee = transfer_fee;
    factory.execute_fee = execute_fee;

    // Serialize updated factory
    let mut data = factory_info.try_borrow_mut_data()?;
    factory.serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

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
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify account ownership and permissions
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if !factory_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify factory account derivation
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;

    // Verify admin is signer
    if !admin_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Load factory
    let factory_data = factory_info.try_borrow_data()?;
    let mut factory = QuipFactory::try_from_slice(&factory_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    // Verify factory is initialized
    if !factory.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    // Verify admin matches
    if pubkey_to_bytes(admin_info.key) != factory.admin {
        return Err(QuipError::UnauthorizedSigner.into());
    }

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
    let mut data = factory_info.try_borrow_mut_data()?;
    factory.serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

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

    // Verify account ownership and permissions
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if !factory_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify factory account derivation
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;

    // Verify admin is signer
    if !admin_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Load factory
    let factory_data = factory_info.try_borrow_data()?;
    let mut factory = QuipFactory::try_from_slice(&factory_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    // Verify factory is initialized
    if !factory.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    // Verify admin matches
    if pubkey_to_bytes(admin_info.key) != factory.admin {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Update admin
    let old_admin = factory.admin;
    factory.admin = new_admin;

    // Serialize updated factory
    let mut data = factory_info.try_borrow_mut_data()?;
    factory.serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!(
        "Ownership transferred from {} to {}",
        hex::encode(old_admin),
        hex::encode(new_admin)
    );
    Ok(())
}

fn process_btc_transfer_with_winternitz<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    vault_id: [u8; 32],
    pq_next: WinternitzPublicKey,
    amount: u64,
    recipient_script_pubkey: Vec<u8>,
    fee_tx: Vec<u8>,
    signature: WinternitzSignature,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    // Fee payer for the Arch transaction — must be anchored and included in the
    // BTC transaction so the validator accepts it. System-owned, so it is signed
    // via sign_input + invoke (not InputToSign, which is for program-owned PDAs).
    let fee_payer_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify account ownership and permissions
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if wallet_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    // Both wallet and factory must be writable: wallet for state + UTXO update,
    // factory for lamport fee collection. Both are program-owned PDAs, so
    // set_transaction_to_sign can update their UTXOs. They are included in the
    // BTC transaction to satisfy Arch's anchoring requirement.
    if !factory_info.is_writable || !wallet_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify payer is signer
    if !payer_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    let payer_bytes = pubkey_to_bytes(payer_info.key);

    // Verify account derivations
    let _ = crate::utils::verify_factory_address(program_id, &pubkey_to_bytes(factory_info.key))?;
    let _ = crate::utils::verify_wallet_address(program_id, &payer_bytes, &vault_id, &pubkey_to_bytes(wallet_info.key))?;

    // Load states
    let factory_data = factory_info.try_borrow_data()?;
    let mut factory = QuipFactory::try_from_slice(&factory_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    if !factory.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    let wallet_data = wallet_info.try_borrow_data()?;
    let mut wallet = QuipWallet::try_from_slice(&wallet_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(wallet_data);

    if !wallet.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    // Verify payer is wallet owner
    if payer_bytes != wallet.owner {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Pre-check wallet lamport balance for transfer fee
    crate::utils::check_sufficient_balance(wallet_info, factory.transfer_fee)?;

    // Validate inputs
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    if recipient_script_pubkey.is_empty() {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify WOTS+ signature
    let message = crate::utils::create_btc_transfer_message(
        &wallet.pq_owner,
        &pq_next,
        &recipient_script_pubkey,
        amount,
    );
    let is_valid = crate::utils::verify_winternitz_signature(&wallet.pq_owner, &message, &signature)?;
    if !is_valid {
        return Err(QuipError::InvalidWotsSignature.into());
    }

    // Get wallet's current UTXO value
    let utxo_value = get_bitcoin_tx_output_value(
        wallet_info.utxo.txid_big_endian(),
        wallet_info.utxo.vout(),
    )
    .ok_or::<ProgramError>(QuipError::InsufficientBtcBalance.into())?;

    // Verify sufficient BTC balance.
    // The change output must stay above the Bitcoin dust limit (330 sats for P2TR)
    // because Bitcoin nodes reject transactions with sub-dust outputs as non-standard.
    // This means the maximum transferable amount is (utxo_value - BTC_DUST_LIMIT).
    let max_transfer = utxo_value
        .checked_sub(BTC_DUST_LIMIT)
        .ok_or::<ProgramError>(QuipError::InsufficientBtcBalance.into())?;
    if amount > max_transfer {
        return Err(QuipError::InsufficientBtcBalance.into());
    }

    // Compute wallet change (guaranteed >= BTC_DUST_LIMIT by the check above)
    let wallet_change = utxo_value
        .checked_sub(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Deserialize the fee transaction and extract its first input as the fee input
    let fee_transaction: Transaction = bitcoin::consensus::deserialize(&fee_tx)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let fee_input = fee_transaction.input.first()
        .ok_or(ProgramError::InvalidInstructionData)?
        .clone();

    // --- State mutations (must happen BEFORE add_state_transition) ---

    // Charge lamport transfer fee from wallet to factory.
    // Both are program-owned PDAs, so direct lamport manipulation works.
    crate::utils::transfer_value(wallet_info, factory_info, factory.transfer_fee)?;

    // Update factory accumulated fees
    factory.accumulated_fees = factory
        .accumulated_fees
        .checked_add(factory.transfer_fee)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Rotate WOTS+ key (critical: each key must only be used once)
    wallet.pq_owner = pq_next;
    wallet.transaction_count = wallet
        .transaction_count
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    wallet.last_activity = get_bitcoin_block_height() as i64;

    // Serialize updated states
    let mut factory_data = factory_info.try_borrow_mut_data()?;
    factory.serialize(&mut &mut factory_data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    let mut wallet_data = wallet_info.try_borrow_mut_data()?;
    wallet.serialize(&mut &mut wallet_data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(wallet_data);

    // --- Build Bitcoin transaction ---
    //
    // CRITICAL LAYOUT CONSTRAINT: set_transaction_to_sign uses InputToSign.index
    // as BOTH the input index to sign AND the output vout for the account's new
    // UTXO. Therefore, each signed account's input and output MUST be at the same
    // index. We achieve this by placing account pass-through outputs first, then
    // the recipient output last.
    //
    // Layout:
    //   Input 0 / Output 0 : wallet   (manual — custom change)
    //   Input 1 / Output 1 : factory  (add_state_transition — pass-through)
    //   Input 2 / Output 2 : fee_payer (manual — pass-through, signed via sign_input)
    //   Input 3 / ---      : fee input (pre-signed by client)
    //   ---     / Output 3 : recipient (BTC transfer destination)

    let wallet_script_bytes = get_account_script_pubkey(wallet_info.key);
    let wallet_script = ScriptBuf::from_bytes(wallet_script_bytes.to_vec());

    let mut btc_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            // Input 0: wallet's current UTXO (manual — custom change amount)
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
            // Output 0: wallet change (must be at same index as wallet input)
            TxOut {
                value: Amount::from_sat(wallet_change),
                script_pubkey: wallet_script,
            },
        ],
    };

    // Input 1 + Output 1: factory state transition (pass-through)
    add_state_transition(&mut btc_tx, factory_info)?;

    // Input 2 + Output 2: fee payer pass-through (signed via sign_input)
    let fp_utxo_value = get_bitcoin_tx_output_value(
        fee_payer_info.utxo.txid_big_endian(),
        fee_payer_info.utxo.vout(),
    )
    .ok_or::<ProgramError>(QuipError::InsufficientBtcBalance.into())?;
    btc_tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: fee_payer_info.utxo.to_txid(),
            vout: fee_payer_info.utxo.vout(),
        },
        script_sig: ScriptBuf::default(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });
    btc_tx.output.push(TxOut {
        value: Amount::from_sat(fp_utxo_value),
        script_pubkey: ScriptBuf::from_bytes(
            get_account_script_pubkey(fee_payer_info.key).to_vec(),
        ),
    });

    // Output 3: recipient (placed after all account outputs to preserve index alignment)
    btc_tx.output.push(TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: ScriptBuf::from_bytes(recipient_script_pubkey.clone()),
    });

    // Input 3: fee input (pre-signed by client, covers BTC mining fee)
    btc_tx.input.push(fee_input);

    // Threshold-sign program-owned PDA inputs (wallet + factory).
    let inputs_to_sign = vec![
        InputToSign {
            index: 0,
            signer: wallet_info.key.clone(),
        },
        InputToSign {
            index: 1,
            signer: factory_info.key.clone(),
        },
    ];
    set_transaction_to_sign(accounts, &btc_tx, &inputs_to_sign)?;

    // Sign the fee payer's BTC input (index 2). The fee payer is system-owned,
    // not a program PDA, so it can't be included in InputToSign. Instead we use
    // sign_input + invoke, which delegates signing to the system program using
    // the fee payer's signer authority from the Arch transaction.
    let ix = sign_input(2, fee_payer_info.key);
    invoke(&ix, &[fee_payer_info.clone()])?;

    msg!(
        "BTC transfer of {} sats with vault_id: {}",
        amount,
        hex::encode(vault_id)
    );
    Ok(())
}
