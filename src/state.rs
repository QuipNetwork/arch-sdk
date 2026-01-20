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
    /// Whether this factory is initialized
    pub is_initialized: bool,
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
    /// Factory bump seed (for address derivation verification)
    pub bump: u8,
}

impl QuipFactory {
    pub const SPACE: usize = 1 + // is_initialized
        32 + // admin
        8 + // creation_fee
        8 + // transfer_fee
        8 + // execute_fee
        8 + // total_wallets
        8 + // accumulated_fees
        1; // bump
    // = 74 bytes (no discriminator in arch-program)
}

// =============================================================================
// Wallet Account
// =============================================================================

/// Per-user Quip wallet with post-quantum security
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
    /// Wallet bump seed (for address derivation verification)
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
// Storage Accounts (for chunked data uploads)
// =============================================================================

/// Temporary storage for WOTS+ signatures
/// Used to upload large signatures across multiple transactions
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct SignatureStorage {
    /// Whether this storage is initialized
    pub is_initialized: bool,
    /// Signature data (up to 2200 bytes)
    pub signature_data: Vec<u8>,
}

impl SignatureStorage {
    pub const MAX_SIGNATURE_SIZE: usize = 2200;
    pub const SPACE: usize = 1 + // is_initialized
        4 + // Vec length prefix (Borsh uses u32)
        Self::MAX_SIGNATURE_SIZE;
    // = 2205 bytes
}

/// Temporary storage for instruction operation data
/// Used to upload instruction data across multiple transactions
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct OpdataStorage {
    /// Whether this storage is initialized
    pub is_initialized: bool,
    /// Operation data (up to 1024 bytes)
    pub opdata: Vec<u8>,
}

impl OpdataStorage {
    pub const MAX_OPDATA_SIZE: usize = 1024;
    pub const SPACE: usize = 1 + // is_initialized
        4 + // Vec length prefix (Borsh uses u32)
        Self::MAX_OPDATA_SIZE;
    // = 1029 bytes
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
