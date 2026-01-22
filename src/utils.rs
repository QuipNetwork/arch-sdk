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

use arch_program::{account::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
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

/// Derive signature storage PDA address
/// Returns (pubkey_bytes, bump)
pub fn derive_signature_storage_address(program_id: &Pubkey, owner: &[u8; 32]) -> ([u8; 32], u8) {
    let (pda, bump) = Pubkey::find_program_address(
        &[b"signature", owner.as_ref()],
        program_id,
    );
    (pda.serialize(), bump)
}

/// Derive opdata storage PDA address
/// Returns (pubkey_bytes, bump)
pub fn derive_opdata_storage_address(program_id: &Pubkey, owner: &[u8; 32]) -> ([u8; 32], u8) {
    let (pda, bump) = Pubkey::find_program_address(
        &[b"opdata", owner.as_ref()],
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

/// Verify that an account key matches the expected signature storage address and return bump
pub fn verify_signature_storage_address(
    program_id: &Pubkey,
    owner: &[u8; 32],
    account_key: &[u8; 32],
) -> Result<u8, ProgramError> {
    let (expected, bump) = derive_signature_storage_address(program_id, owner);
    if *account_key != expected {
        return Err(QuipError::InvalidAccountDerivation.into());
    }
    Ok(bump)
}

/// Verify that an account key matches the expected opdata storage address and return bump
pub fn verify_opdata_storage_address(
    program_id: &Pubkey,
    owner: &[u8; 32],
    account_key: &[u8; 32],
) -> Result<u8, ProgramError> {
    let (expected, bump) = derive_opdata_storage_address(program_id, owner);
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

// =============================================================================
// Value Transfer (Authorization Only)
// =============================================================================

/// Authorize a value transfer (satoshis) from one account to another.
///
/// # Important: Authorization Only
///
/// In Arch Network's UTXO model, this function does NOT perform actual Bitcoin
/// value transfers. The program's role is to **authorize** transfers through
/// WOTS+ signature verification - the actual UTXO manipulation happens at the
/// transaction level, constructed by the client.
///
/// ## How Value Transfers Work in Arch Network
///
/// 1. **Client constructs transaction**: The client builds a Bitcoin transaction
///    with inputs (source UTXOs) and outputs (destination amounts)
/// 2. **Program authorizes**: This program verifies the WOTS+ signature, confirming
///    the wallet owner approved the transfer
/// 3. **Network signs**: The Arch Network's distributed key signs the transaction
/// 4. **Bitcoin broadcast**: The signed transaction is broadcast to Bitcoin
///
/// ## What This Function Does
///
/// - Validates the transfer is authorized (caller must verify WOTS+ signature first)
/// - Returns success to indicate the authorization is valid
/// - Does NOT move actual Bitcoin - that's handled by the transaction structure
///
/// ## Parameters
///
/// - `_from`: Source account (UTXO owner) - unused, authorization done via WOTS+
/// - `_to`: Destination account - unused, specified in transaction outputs
/// - `_amount`: Transfer amount in satoshis - unused, specified in transaction outputs
///
/// ## Returns
///
/// Always returns `Ok(())` if called after successful WOTS+ verification.
/// The actual transfer validity is ensured by:
/// 1. WOTS+ signature verification (caller's responsibility)
/// 2. Transaction construction (client's responsibility)
/// 3. Network validation (Arch Network's responsibility)
pub fn transfer_value(
    _from: &AccountInfo,
    _to: &AccountInfo,
    _amount: u64,
) -> Result<(), ProgramError> {
    // Authorization-only: The WOTS+ signature verification in the caller
    // confirms the wallet owner approved this transfer. The actual Bitcoin
    // UTXO manipulation is specified in the client-constructed transaction
    // and executed by the Arch Network after signing.
    Ok(())
}
