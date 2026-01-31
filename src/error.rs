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

use thiserror::Error;
use arch_program::program_error::ProgramError;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum QuipError {
    #[error("Insufficient funds for operation")]
    InsufficientFunds,

    #[error("Invalid WOTS+ signature")]
    InvalidWotsSignature,

    #[error("Unauthorized signer")]
    UnauthorizedSigner,

    #[error("Insufficient transfer fee")]
    InsufficientTransferFee,

    #[error("Insufficient execute fee")]
    InsufficientExecuteFee,

    #[error("Insufficient wallet balance")]
    InsufficientWalletBalance,

    #[error("Invalid vault ID")]
    InvalidVaultId,

    #[error("Wallet already exists")]
    WalletAlreadyExists,

    #[error("WOTS+ key already used")]
    WotsKeyAlreadyUsed,

    #[error("Invalid instruction data format")]
    InvalidInstructionData,

    #[error("Unsupported recipient account type")]
    UnsupportedRecipientType,

    #[error("Account metas length does not match remaining accounts")]
    AccountMetasMismatch,

    #[error("Invalid account data")]
    InvalidAccountData,

    #[error("Account not initialized")]
    AccountNotInitialized,

    #[error("Factory already initialized")]
    FactoryAlreadyInitialized,

    #[error("Invalid account derivation")]
    InvalidAccountDerivation,

    #[error("Account not owned by program")]
    IncorrectProgramOwner,

    #[error("Account not writable")]
    AccountNotWritable,

    #[error("Insufficient BTC balance in wallet UTXO")]
    InsufficientBtcBalance,

    #[error("UTXO is not owned by wallet account")]
    UtxoNotOwnedByWallet,

    #[error("Change amount is below dust limit (must be >= 330 sats or 0)")]
    ChangeBelowDustLimit,
}

impl From<QuipError> for ProgramError {
    fn from(e: QuipError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
