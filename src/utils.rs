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
    account::AccountInfo,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
    system_program,
};
#[cfg(feature = "debug")]
use arch_program::msg;
use hashsigs::{PublicKey, WOTSPlus};

use crate::error::QuipError;
use crate::state::{CpiAccountMeta, WinternitzPublicKey, WinternitzSignature};

// =============================================================================
// PDA Address Derivation
// =============================================================================

/// Derive factory PDA address using Arch's native PDA mechanism
/// Returns (pubkey_bytes, bump)
pub fn derive_factory_address(program_id: &Pubkey) -> ([u8; 32], u8) {
    let (pda, bump) = Pubkey::find_program_address(&[b"factory"], program_id);
    (pda.serialize(), bump)
}

/// Derive wallet PDA address using Arch's native PDA mechanism
/// Returns (pubkey_bytes, bump)
pub fn derive_wallet_address(
    program_id: &Pubkey,
    owner: &[u8; 32],
    vault_id: &[u8; 32],
) -> ([u8; 32], u8) {
    let (pda, bump) = Pubkey::find_program_address(
        &[b"wallet", owner.as_ref(), vault_id.as_ref()],
        program_id,
    );
    (pda.serialize(), bump)
}

// =============================================================================
// Account Derivation Verification
// =============================================================================

/// Verify that an account key matches the expected factory address and return bump
pub fn verify_factory_address(
    program_id: &Pubkey,
    account_key: &[u8; 32],
) -> Result<u8, ProgramError> {
    let (expected, bump) = derive_factory_address(program_id);
    if *account_key != expected {
        return Err(QuipError::InvalidAccountDerivation.into());
    }
    Ok(bump)
}

/// Verify that an account key matches the expected wallet address and return bump
pub fn verify_wallet_address(
    program_id: &Pubkey,
    owner: &[u8; 32],
    vault_id: &[u8; 32],
    account_key: &[u8; 32],
) -> Result<u8, ProgramError> {
    let (expected, bump) = derive_wallet_address(program_id, owner, vault_id);
    if *account_key != expected {
        return Err(QuipError::InvalidAccountDerivation.into());
    }
    Ok(bump)
}

// =============================================================================
// Keccak256 Hash Function (for WOTS+ signatures)
// =============================================================================

/// Compute Keccak256 hash for WOTS+ signature verification
fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    arch_program::hashing_functions::keccak256(data).0
}

// =============================================================================
// WOTS+ Signature Verification
// =============================================================================

/// Verify a WOTS+ signature against a message
pub fn verify_winternitz_signature(
    public_key: &WinternitzPublicKey,
    message: &[u8],
    signature: &WinternitzSignature,
) -> Result<bool, ProgramError> {
    // Debug logging (only when 'debug' feature is enabled)
    #[cfg(feature = "debug")]
    {
        msg!("WOTS+ Verification Debug:");
        msg!(
            "Public seed: {}",
            hex::encode(public_key.public_seed)
        );
        msg!(
            "Public key hash: {}",
            hex::encode(public_key.public_key_hash)
        );
        msg!("Message length: {}", message.len());
        msg!("Message: {}", hex::encode(message));
        msg!(
            "Signature data length: {}",
            signature.signature_data.len()
        );
    }

    // Create hashsigs PublicKey from our structure
    let hashsigs_pubkey = PublicKey {
        public_seed: public_key.public_seed,
        public_key_hash: public_key.public_key_hash,
    };

    // Hash the message using Keccak256
    let message_hash = keccak256_hash(message);

    #[cfg(feature = "debug")]
    msg!("Message hash: {}", hex::encode(message_hash));

    // Convert signature data to expected format (array of 32-byte chunks)
    let signature_vec: Vec<[u8; 32]> = signature
        .signature_data
        .chunks_exact(32)
        .map(|chunk| {
            let mut array = [0u8; 32];
            array.copy_from_slice(chunk);
            array
        })
        .collect();

    #[cfg(feature = "debug")]
    msg!("Signature elements count: {}", signature_vec.len());

    // Create WOTS+ instance with Keccak256 hash function and verify
    let winternitz = WOTSPlus::new(keccak256_hash);
    let is_valid = winternitz.verify(&hashsigs_pubkey, &message_hash, &signature_vec);

    #[cfg(feature = "debug")]
    msg!("WOTS+ Verification result: {}", is_valid);

    Ok(is_valid)
}

// =============================================================================
// Message Construction
// =============================================================================

/// Create a message for transfer operations
/// Message format: current_key || next_key || recipient || amount
pub fn create_transfer_message(
    current_key: &WinternitzPublicKey,
    next_key: &WinternitzPublicKey,
    recipient: &[u8; 32],
    amount: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&current_key.public_seed);
    message.extend_from_slice(&current_key.public_key_hash);
    message.extend_from_slice(&next_key.public_seed);
    message.extend_from_slice(&next_key.public_key_hash);
    message.extend_from_slice(recipient);
    message.extend_from_slice(&amount.to_le_bytes());
    message
}

/// Create a message for execute operations (CPI)
/// Message format: current_key || next_key || target_program || instruction_data || accounts
pub fn create_execute_message(
    current_key: &WinternitzPublicKey,
    next_key: &WinternitzPublicKey,
    target_program: &[u8; 32],
    instruction_data: &[u8],
    account_pubkeys: &[[u8; 32]],
    account_metas: &[CpiAccountMeta],
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&current_key.public_seed);
    message.extend_from_slice(&current_key.public_key_hash);
    message.extend_from_slice(&next_key.public_seed);
    message.extend_from_slice(&next_key.public_key_hash);
    message.extend_from_slice(target_program);
    message.extend_from_slice(instruction_data);

    // Include account pubkeys and metas in the signed message for security
    // This prevents attackers from swapping accounts after signing
    for (pubkey, meta) in account_pubkeys.iter().zip(account_metas.iter()) {
        message.extend_from_slice(pubkey);
        message.push(if meta.is_signer { 1 } else { 0 });
        message.push(if meta.is_writable { 1 } else { 0 });
    }

    message
}

/// Create a message for changing the post-quantum owner
/// Message format: current_key || next_key || "change_owner"
pub fn create_change_owner_message(
    current_key: &WinternitzPublicKey,
    next_key: &WinternitzPublicKey,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&current_key.public_seed);
    message.extend_from_slice(&current_key.public_key_hash);
    message.extend_from_slice(&next_key.public_seed);
    message.extend_from_slice(&next_key.public_key_hash);
    message.extend_from_slice(b"change_owner"); // Operation identifier
    message
}

/// Create a message for BTC transfer operations
/// Message format: current_key || next_key || len(script_pubkey) as u32 LE || script_pubkey || amount
pub fn create_btc_transfer_message(
    current_key: &WinternitzPublicKey,
    next_key: &WinternitzPublicKey,
    recipient_script_pubkey: &[u8],
    amount: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&current_key.public_seed);
    message.extend_from_slice(&current_key.public_key_hash);
    message.extend_from_slice(&next_key.public_seed);
    message.extend_from_slice(&next_key.public_key_hash);
    message.extend_from_slice(&(recipient_script_pubkey.len() as u32).to_le_bytes());
    message.extend_from_slice(recipient_script_pubkey);
    message.extend_from_slice(&amount.to_le_bytes());
    message
}

// =============================================================================
// Value Transfer (Lamports/ARCH tokens)
// =============================================================================

/// Transfer lamports (ARCH tokens) from a PDA to another account.
///
/// This function transfers the native ARCH token (lamports) between accounts
/// by directly manipulating lamport balances. This approach is required because
/// the system program's transfer instruction does not allow transfers FROM accounts
/// that have data (like our wallet/factory PDAs).
///
/// The system program can only transfer from accounts it owns. Once an account
/// stores custom data, its ownership transfers to the program, and the System
/// Program cannot transfer SOL from accounts it doesn't own.
///
/// ## Parameters
///
/// - `from`: Source account (must be a PDA owned by this program)
/// - `to`: Destination account
/// - `amount`: Amount of lamports to transfer
///
/// ## Returns
///
/// Returns `Ok(())` on successful transfer, or a `ProgramError` if the
/// transfer fails (e.g., insufficient funds).
pub fn transfer_value<'a>(
    from: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    amount: u64,
) -> Result<(), ProgramError> {
    // Skip zero-amount transfers
    if amount == 0 {
        return Ok(());
    }

    // Verify sufficient balance
    if from.lamports() < amount {
        return Err(ProgramError::InsufficientFunds);
    }

    // Direct lamport manipulation - required for PDAs with data
    // (system_instruction::transfer fails with "invalid program argument")
    **from.try_borrow_mut_lamports()? -= amount;
    **to.try_borrow_mut_lamports()? += amount;

    Ok(())
}

/// Transfer lamports (ARCH tokens) from a signer account to another account.
///
/// This function is used when the source account is a regular signer (not a PDA),
/// such as when a user pays the wallet creation fee during deposit.
///
/// ## Parameters
///
/// - `from`: Source account (must be a signer)
/// - `to`: Destination account
/// - `amount`: Amount of lamports to transfer
///
/// ## Returns
///
/// Returns `Ok(())` on successful transfer, or a `ProgramError` if the
/// transfer fails (e.g., insufficient funds, invalid accounts).
pub fn transfer_value_from_signer<'a>(
    from: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    amount: u64,
) -> Result<(), ProgramError> {
    use arch_program::program::invoke;

    // Skip zero-amount transfers
    if amount == 0 {
        return Ok(());
    }

    // Create the system instruction for transferring lamports
    let ix = system_instruction::transfer(from.key, to.key, amount);

    // Execute the transfer using invoke since 'from' is a signer
    invoke(&ix, &[from.clone(), to.clone()])
}

// =============================================================================
// System Program Verification
// =============================================================================

/// Verify that the provided account is the system program
pub fn verify_system_program(account: &AccountInfo) -> Result<(), ProgramError> {
    if account.key != &system_program::SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

// =============================================================================
// PDA Account Creation
// =============================================================================

/// Create a PDA account using Arch Network's anchoring mechanism.
///
/// This function creates a new PDA account by anchoring it to a Bitcoin UTXO.
/// The account will be owned by the specified program after creation.
///
/// ## Parameters
///
/// - `payer`: Account paying for the creation (must be signer)
/// - `pda_account`: The PDA account to create
/// - `space`: Size of the account data in bytes
/// - `owner_program`: The program that will own this account
/// - `utxo`: The Bitcoin UTXO to anchor the account creation to
/// - `signer_seeds`: Seeds for signing the creation (including bump)
///
/// ## Returns
///
/// Returns `Ok(())` on success, or a `ProgramError` if creation fails.
pub fn create_pda_account<'a>(
    payer: &AccountInfo<'a>,
    pda_account: &AccountInfo<'a>,
    space: usize,
    owner_program: &Pubkey,
    utxo: &arch_program::utxo::UtxoMeta,
    signer_seeds: &[&[u8]],
) -> Result<(), ProgramError> {
    use arch_program::system_instruction::create_account_with_anchor;
    use arch_program::rent::minimum_rent;

    let ix = create_account_with_anchor(
        payer.key,
        pda_account.key,
        minimum_rent(space),
        space as u64,
        owner_program,
        utxo.txid().try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
        utxo.vout(),
    );

    invoke_signed(&ix, &[pda_account.clone(), payer.clone()], &[signer_seeds])
}

// =============================================================================
// Balance Checks
// =============================================================================

/// Check if an account has sufficient balance for an operation
pub fn check_sufficient_balance(
    account: &AccountInfo,
    required_amount: u64,
) -> Result<(), ProgramError> {
    if account.lamports() < required_amount {
        return Err(QuipError::InsufficientWalletBalance.into());
    }
    Ok(())
}

