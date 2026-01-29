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

use borsh::{BorshDeserialize, BorshSerialize};

/// Hash length constant (32 bytes for Keccak256)
pub const HASH_LEN: usize = 32;

// =============================================================================
// WOTS+ Data Structures (matching hashsigs-rs format)
// =============================================================================

/// Winternitz One-Time Signature Plus public key
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct WinternitzPublicKey {
    /// Public seed (HASH_LEN bytes)
    pub public_seed: [u8; HASH_LEN],
    /// Public key hash (HASH_LEN bytes)
    pub public_key_hash: [u8; HASH_LEN],
}

impl WinternitzPublicKey {
    pub const SPACE: usize = HASH_LEN + HASH_LEN; // 64 bytes
}

/// Winternitz signature (variable length)
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct WinternitzSignature {
    /// WOTS+ signature data
    pub signature_data: Vec<u8>,
}

// =============================================================================
// Factory Account
// =============================================================================

/// Global factory configuration - singleton account
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct QuipFactory {
    /// Factory administrator (32-byte pubkey)
    pub admin: [u8; 32],
    /// Fee for creating new wallets (in satoshis)
    pub creation_fee: u64,
    /// Fee for transfers (in satoshis)
    pub transfer_fee: u64,
    /// Fee for executing instructions (in satoshis)
    pub execute_fee: u64,
    /// Total wallets created
    pub total_wallets: u64,
    /// Accumulated fees ready for withdrawal
    pub accumulated_fees: u64,
    /// PDA bump seed (required for invoke_signed in CPIs)
    pub bump: u8,
}

impl QuipFactory {
    pub const SPACE: usize = 32 + // admin
        8 + // creation_fee
        8 + // transfer_fee
        8 + // execute_fee
        8 + // total_wallets
        8 + // accumulated_fees
        1; // bump
    // = 73 bytes (no discriminator in arch-program)
}

// =============================================================================
// Wallet Account
// =============================================================================

/// Per-user Quip wallet with post-quantum security
// TODO: Remove is_initialized - account existence implies initialization since
// wallets can only be created via deposit instruction, and creation + initialization are atomic
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct QuipWallet {
    /// Whether this wallet is initialized
    pub is_initialized: bool,
    /// Factory that created this wallet
    pub factory: [u8; 32],
    /// Classical key owner
    pub owner: [u8; 32],
    /// Current WOTS+ public key (post-quantum owner)
    pub pq_owner: WinternitzPublicKey,
    /// Wallet creation timestamp
    pub created_at: i64,
    /// Last transaction timestamp
    pub last_activity: i64,
    /// Number of transactions performed
    pub transaction_count: u64,
    /// PDA bump seed (required for invoke_signed in CPIs)
    pub bump: u8,
}

impl QuipWallet {
    pub const SPACE: usize = 1 + // is_initialized
        32 + // factory
        32 + // owner
        64 + // pq_owner (WinternitzPublicKey)
        8 + // created_at
        8 + // last_activity
        8 + // transaction_count
        1; // bump
    // = 154 bytes
}

// =============================================================================
// CPI Account Meta (for execute_with_winternitz)
// =============================================================================

/// Account metadata for CPI calls
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct CpiAccountMeta {
    /// Whether this account is a signer in the CPI
    pub is_signer: bool,
    /// Whether this account is writable in the CPI
    pub is_writable: bool,
}
