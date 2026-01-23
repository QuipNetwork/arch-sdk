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
    instruction::Instruction,
    msg,
    program::{get_bitcoin_block_height, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
};
use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::QuipError;
use crate::instruction::QuipInstruction;
use crate::state::*;

/// Program result type
pub type ProgramResult = Result<(), ProgramError>;

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
        } => {
            msg!("Instruction: TransferWithWinternitz");
            process_transfer_with_winternitz(program_id, accounts, vault_id, pq_next, amount)
        }

        QuipInstruction::ExecuteWithWinternitz {
            pq_next,
            vault_id,
            account_metas,
        } => {
            msg!("Instruction: ExecuteWithWinternitz");
            process_execute_with_winternitz(program_id, accounts, pq_next, vault_id, account_metas)
        }

        QuipInstruction::ChangePqOwner { vault_id, pq_next } => {
            msg!("Instruction: ChangePqOwner");
            process_change_pq_owner(program_id, accounts, vault_id, pq_next)
        }

        QuipInstruction::StoreSignature {
            chunk_data,
            is_first_chunk,
        } => {
            msg!("Instruction: StoreSignature");
            process_store_signature(program_id, accounts, chunk_data, is_first_chunk)
        }

        QuipInstruction::StoreOpdata {
            opdata_chunk,
            is_first_chunk,
        } => {
            msg!("Instruction: StoreOpdata");
            process_store_opdata(program_id, accounts, opdata_chunk, is_first_chunk)
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

    // Create wallet PDA account if it doesn't exist
    if wallet_info.data_len() == 0 {
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

    // Verify ownership (factory must already exist, wallet was just created)
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if wallet_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }

    // Check if wallet already exists
    let wallet_data = wallet_info.try_borrow_data()?;
    if !wallet_data.is_empty() {
        if let Ok(existing_wallet) = QuipWallet::try_from_slice(&wallet_data) {
            if existing_wallet.is_initialized {
                return Err(QuipError::WalletAlreadyExists.into());
            }
        }
    }
    drop(wallet_data);

    // Load and update factory
    let factory_data = factory_info.try_borrow_data()?;
    let mut factory = QuipFactory::try_from_slice(&factory_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    // Verify factory is initialized
    if !factory.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    // Transfer creation fee from payer (signer) to factory
    crate::utils::transfer_value_from_signer(payer_info, factory_info, factory.creation_fee)?;

    // Transfer initial deposit from payer (signer) to wallet
    if initial_deposit > 0 {
        crate::utils::transfer_value_from_signer(payer_info, wallet_info, initial_deposit)?;
    }

    // Update accumulated fees counter
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
        bump: wallet_bump, // PDA bump seed for invoke_signed
    };

    // Serialize states
    let mut factory_data = factory_info.try_borrow_mut_data()?;
    factory.serialize(&mut &mut factory_data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(factory_data);

    let mut wallet_data = wallet_info.try_borrow_mut_data()?;
    wallet.serialize(&mut &mut wallet_data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!(
        "Wallet created with vault_id: {}, deposit: {}",
        hex::encode(vault_id),
        initial_deposit
    );
    Ok(())
}

fn process_transfer_with_winternitz<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    vault_id: [u8; 32],
    pq_next: WinternitzPublicKey,
    amount: u64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    let recipient_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    let signature_storage_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify account ownership and permissions
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if wallet_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if signature_storage_info.owner != program_id {
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
    let _ = crate::utils::verify_signature_storage_address(program_id, &payer_bytes, &pubkey_to_bytes(signature_storage_info.key))?;

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

    let sig_data = signature_storage_info.try_borrow_data()?;
    let signature_storage = SignatureStorage::try_from_slice(&sig_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(sig_data);

    // Verify payer is wallet owner
    if pubkey_to_bytes(payer_info.key) != wallet.owner {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Verify signature storage is initialized
    if !signature_storage.is_initialized {
        return Err(QuipError::SignatureStorageNotInitialized.into());
    }

    // Pre-check wallet balance: fee + transfer amount
    let total_required = factory.transfer_fee
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    crate::utils::check_sufficient_balance(wallet_info, total_required)?;

    // Create and verify signature
    let signature = WinternitzSignature {
        signature_data: signature_storage.signature_data.clone(),
    };
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

    // Build wallet PDA seeds for signing transfers
    let wallet_seeds: &[&[u8]] = &[
        b"wallet",
        wallet.owner.as_ref(),
        vault_id.as_ref(),
        &[wallet.bump],
    ];

    // Transfer fee from wallet to factory
    crate::utils::transfer_value(wallet_info, factory_info, factory.transfer_fee, wallet_seeds)?;

    // Transfer the amount from wallet to recipient
    crate::utils::transfer_value(wallet_info, recipient_info, amount, wallet_seeds)?;

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
    account_metas: Vec<CpiAccountMeta>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    let target_program_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    let signature_storage_info = next_account_info(account_info_iter)?;
    let opdata_storage_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify account ownership and permissions
    if factory_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if wallet_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if signature_storage_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if opdata_storage_info.owner != program_id {
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
    let _ = crate::utils::verify_signature_storage_address(program_id, &payer_bytes, &pubkey_to_bytes(signature_storage_info.key))?;
    let _ = crate::utils::verify_opdata_storage_address(program_id, &payer_bytes, &pubkey_to_bytes(opdata_storage_info.key))?;

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

    let sig_data = signature_storage_info.try_borrow_data()?;
    let signature_storage = SignatureStorage::try_from_slice(&sig_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(sig_data);

    let op_data = opdata_storage_info.try_borrow_data()?;
    let opdata_storage = OpdataStorage::try_from_slice(&op_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(op_data);

    // Verify payer is wallet owner
    if pubkey_to_bytes(payer_info.key) != wallet.owner {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Verify storages are initialized
    if !signature_storage.is_initialized {
        return Err(QuipError::SignatureStorageNotInitialized.into());
    }
    if !opdata_storage.is_initialized {
        return Err(QuipError::OpdataStorageNotInitialized.into());
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

    // Create and verify signature
    let signature = WinternitzSignature {
        signature_data: signature_storage.signature_data.clone(),
    };
    let target_bytes = pubkey_to_bytes(target_program_info.key);
    let message = crate::utils::create_execute_message(
        &wallet.pq_owner,
        &pq_next,
        &target_bytes,
        &opdata_storage.opdata,
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
    crate::utils::transfer_value(wallet_info, factory_info, factory.execute_fee, wallet_seeds)?;

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
        data: opdata_storage.opdata.clone(),
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
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let _factory_info = next_account_info(account_info_iter)?;
    let wallet_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;
    let signature_storage_info = next_account_info(account_info_iter)?;

    // Verify account ownership and permissions
    if wallet_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if signature_storage_info.owner != program_id {
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
    let _ = crate::utils::verify_signature_storage_address(program_id, &payer_bytes, &pubkey_to_bytes(signature_storage_info.key))?;

    // Load states
    let wallet_data = wallet_info.try_borrow_data()?;
    let mut wallet = QuipWallet::try_from_slice(&wallet_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(wallet_data);

    // Verify wallet is initialized
    if !wallet.is_initialized {
        return Err(QuipError::AccountNotInitialized.into());
    }

    let sig_data = signature_storage_info.try_borrow_data()?;
    let signature_storage = SignatureStorage::try_from_slice(&sig_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(sig_data);

    // Verify payer is wallet owner
    if pubkey_to_bytes(payer_info.key) != wallet.owner {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Verify signature storage is initialized
    if !signature_storage.is_initialized {
        return Err(QuipError::SignatureStorageNotInitialized.into());
    }

    // Create and verify signature
    let signature = WinternitzSignature {
        signature_data: signature_storage.signature_data.clone(),
    };
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

fn process_store_signature<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    chunk_data: Vec<u8>,
    is_first_chunk: bool,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let signature_storage_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify account ownership and permissions
    if signature_storage_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if !signature_storage_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify payer is signer
    if !payer_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Verify signature storage derivation
    let payer_bytes = pubkey_to_bytes(payer_info.key);
    let _ = crate::utils::verify_signature_storage_address(program_id, &payer_bytes, &pubkey_to_bytes(signature_storage_info.key))?;

    let mut storage = if is_first_chunk {
        // Initialize new storage
        SignatureStorage {
            is_initialized: true,
            signature_data: Vec::new(),
        }
    } else {
        // Load existing storage
        let data = signature_storage_info.try_borrow_data()?;
        let storage = SignatureStorage::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        drop(data);
        if !storage.is_initialized {
            return Err(QuipError::SignatureStorageNotInitialized.into());
        }
        storage
    };

    // Append chunk data
    storage.signature_data.extend_from_slice(&chunk_data);

    // Validate size
    if storage.signature_data.len() > SignatureStorage::MAX_SIGNATURE_SIZE {
        return Err(QuipError::SignatureDataTooLarge.into());
    }

    // Serialize updated storage
    let mut data = signature_storage_info.try_borrow_mut_data()?;
    storage.serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!(
        "Stored signature chunk, total size: {}",
        storage.signature_data.len()
    );
    Ok(())
}

fn process_store_opdata<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    opdata_chunk: Vec<u8>,
    is_first_chunk: bool,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let opdata_storage_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Verify system program
    crate::utils::verify_system_program(system_program_info)?;

    // Verify account ownership and permissions
    if opdata_storage_info.owner != program_id {
        return Err(QuipError::IncorrectProgramOwner.into());
    }
    if !opdata_storage_info.is_writable {
        return Err(QuipError::AccountNotWritable.into());
    }

    // Verify payer is signer
    if !payer_info.is_signer {
        return Err(QuipError::UnauthorizedSigner.into());
    }

    // Verify opdata storage derivation
    let payer_bytes = pubkey_to_bytes(payer_info.key);
    let _ = crate::utils::verify_opdata_storage_address(program_id, &payer_bytes, &pubkey_to_bytes(opdata_storage_info.key))?;

    let mut storage = if is_first_chunk {
        // Initialize new storage
        OpdataStorage {
            is_initialized: true,
            opdata: Vec::new(),
        }
    } else {
        // Load existing storage
        let data = opdata_storage_info.try_borrow_data()?;
        let storage = OpdataStorage::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        drop(data);
        if !storage.is_initialized {
            return Err(QuipError::OpdataStorageNotInitialized.into());
        }
        storage
    };

    // Append chunk data
    storage.opdata.extend_from_slice(&opdata_chunk);

    // Validate size
    if storage.opdata.len() > OpdataStorage::MAX_OPDATA_SIZE {
        return Err(QuipError::ChunkDataTooLarge.into());
    }

    // Serialize updated storage
    let mut data = opdata_storage_info.try_borrow_mut_data()?;
    storage.serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Stored opdata chunk, total size: {}", storage.opdata.len());
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

    // Build factory PDA seeds for signing
    let factory_seeds: &[&[u8]] = &[
        b"factory",
        &[factory.bump],
    ];

    // Transfer the fees from factory to recipient
    crate::utils::transfer_value(factory_info, recipient_info, amount, factory_seeds)?;

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
