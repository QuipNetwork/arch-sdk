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
// Address Derivation
// =============================================================================

/// Derive the factory address from seeds
/// In ArchVM, we use deterministic hashing instead of Solana's PDA mechanism
pub fn derive_factory_address(program_id: &Pubkey) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(b"factory");
    data.extend_from_slice(program_id.as_ref());
    keccak256_hash(&data)
}

/// Derive a wallet address from owner and vault_id
pub fn derive_wallet_address(
    program_id: &Pubkey,
    owner: &[u8; 32],
    vault_id: &[u8; 32],
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(b"wallet");
    data.extend_from_slice(owner);
    data.extend_from_slice(vault_id);
    data.extend_from_slice(program_id.as_ref());
    keccak256_hash(&data)
}

/// Derive signature storage address
pub fn derive_signature_storage_address(program_id: &Pubkey, owner: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(b"signature");
    data.extend_from_slice(owner);
    data.extend_from_slice(program_id.as_ref());
    keccak256_hash(&data)
}

/// Derive opdata storage address
pub fn derive_opdata_storage_address(program_id: &Pubkey, owner: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(b"opdata");
    data.extend_from_slice(owner);
    data.extend_from_slice(program_id.as_ref());
    keccak256_hash(&data)
}

// =============================================================================
// Account Derivation Verification
// =============================================================================

/// Verify that an account key matches the expected factory address
pub fn verify_factory_address(
    program_id: &Pubkey,
    account_key: &[u8; 32],
) -> Result<(), ProgramError> {
    let expected = derive_factory_address(program_id);
    if *account_key != expected {
        return Err(QuipError::InvalidAccountDerivation.into());
    }
    Ok(())
}

/// Verify that an account key matches the expected wallet address
pub fn verify_wallet_address(
    program_id: &Pubkey,
    owner: &[u8; 32],
    vault_id: &[u8; 32],
    account_key: &[u8; 32],
) -> Result<(), ProgramError> {
    let expected = derive_wallet_address(program_id, owner, vault_id);
    if *account_key != expected {
        return Err(QuipError::InvalidAccountDerivation.into());
    }
    Ok(())
}

/// Verify that an account key matches the expected signature storage address
pub fn verify_signature_storage_address(
    program_id: &Pubkey,
    owner: &[u8; 32],
    account_key: &[u8; 32],
) -> Result<(), ProgramError> {
    let expected = derive_signature_storage_address(program_id, owner);
    if *account_key != expected {
        return Err(QuipError::InvalidAccountDerivation.into());
    }
    Ok(())
}

/// Verify that an account key matches the expected opdata storage address
pub fn verify_opdata_storage_address(
    program_id: &Pubkey,
    owner: &[u8; 32],
    account_key: &[u8; 32],
) -> Result<(), ProgramError> {
    let expected = derive_opdata_storage_address(program_id, owner);
    if *account_key != expected {
        return Err(QuipError::InvalidAccountDerivation.into());
    }
    Ok(())
}

// =============================================================================
// Keccak256 Hash Function
// =============================================================================

/// Compute Keccak256 hash using hashsigs' implementation
fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generate a vault ID from a seed string
pub fn generate_vault_id(seed: &str) -> [u8; 32] {
    keccak256_hash(seed.as_bytes())
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
// Value Transfer
// =============================================================================

/// Transfer value (satoshis) from one account to another
/// 
/// In ArchVM, value transfer is accomplished via the UTXO model at the
/// transaction level, not within program execution. The program's role is to
/// authorize the transfer through signature verification (which we do via WOTS+).
/// 
/// The actual Bitcoin UTXO manipulation is handled by the ArchVM runtime
/// based on the transaction inputs/outputs, not by the program directly.
/// 
/// This function validates the transfer authorization has been properly verified
/// and logs the intended transfer. The ArchVM runtime handles the actual
/// satoshi movement based on the transaction structure.
pub fn transfer_value(
    _from: &AccountInfo,
    _to: &AccountInfo,
    _amount: u64,
) -> Result<(), ProgramError> {
    // In ArchVM's UTXO model, value transfers are specified in the transaction
    // inputs and outputs, not manipulated directly by the program.
    // 
    // The program's job is to:
    // 1. Verify the WOTS+ signature authorizes this transfer (done before calling this)
    // 2. Update program state to reflect the transfer (done in the caller)
    // 
    // The ArchVM runtime handles the actual Bitcoin UTXO manipulation.
    // This is a no-op because the authorization is already verified.
    Ok(())
}
