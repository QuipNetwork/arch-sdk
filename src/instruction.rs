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

use arch_program::utxo::UtxoMeta;
use borsh::{BorshDeserialize, BorshSerialize};
use crate::state::{CpiAccountMeta, WinternitzPublicKey, WinternitzSignature};

/// All instructions supported by the Quip program
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum QuipInstruction {
    /// Initialize the global factory
    ///
    /// Accounts:
    /// 0. `[writable]` Factory account (to be created)
    /// 1. `[signer, writable]` Payer
    /// 2. `[]` System program
    InitializeFactory {
        admin: [u8; 32],
        creation_fee: u64,
        transfer_fee: u64,
        execute_fee: u64,
        /// UTXO for anchoring factory account creation
        factory_utxo: UtxoMeta,
    },

    /// Create a new wallet with WOTS+ key and optional deposit
    ///
    /// Accounts:
    /// 0. `[writable]` Factory
    /// 1. `[writable]` Wallet account (to be created)
    /// 2. `[signer, writable]` Owner (pays for creation and deposit)
    /// 3. `[]` System program
    DepositToWinternitz {
        vault_id: [u8; 32],
        pq_owner: WinternitzPublicKey,
        deposit: u64,
        /// UTXO for anchoring wallet account creation
        wallet_utxo: UtxoMeta,
    },

    /// Transfer funds using WOTS+ signature
    ///
    /// Accounts:
    /// 0. `[writable]` Factory
    /// 1. `[writable]` Wallet
    /// 2. `[writable]` Recipient
    /// 3. `[signer, writable]` Owner (must be wallet owner)
    TransferWithWinternitz {
        vault_id: [u8; 32],
        pq_next: WinternitzPublicKey,
        amount: u64,
        /// WOTS+ signature
        signature: WinternitzSignature,
    },

    /// Execute arbitrary CPI using WOTS+ signature
    ///
    /// Accounts:
    /// 0. `[writable]` Factory
    /// 1. `[writable]` Wallet
    /// 2. `[]` Target program
    /// 3. `[signer, writable]` Payer (must be wallet owner)
    /// 4. `[]` System program
    /// 5+ `[]` Remaining accounts for CPI
    ExecuteWithWinternitz {
        pq_next: WinternitzPublicKey,
        vault_id: [u8; 32],
        /// Instruction data to pass to the target program
        instruction_data: Vec<u8>,
        account_metas: Vec<CpiAccountMeta>,
        /// WOTS+ signature
        signature: WinternitzSignature,
    },

    /// Change the post-quantum owner (rotate WOTS+ key)
    ///
    /// Accounts:
    /// 0. `[writable]` Factory
    /// 1. `[writable]` Wallet
    /// 2. `[signer, writable]` Payer (must be wallet owner)
    ChangePqOwner {
        vault_id: [u8; 32],
        pq_next: WinternitzPublicKey,
        /// WOTS+ signature
        signature: WinternitzSignature,
    },

    /// Update factory fees (admin only)
    ///
    /// Accounts:
    /// 0. `[writable]` Factory
    /// 1. `[signer]` Admin
    UpdateFees {
        creation_fee: u64,
        transfer_fee: u64,
        execute_fee: u64,
    },

    /// Withdraw accumulated fees (admin only)
    ///
    /// Accounts:
    /// 0. `[writable]` Factory
    /// 1. `[signer]` Admin
    /// 2. `[writable]` Recipient
    WithdrawFees {
        amount: u64,
    },

    /// Transfer factory ownership (admin only)
    ///
    /// Accounts:
    /// 0. `[writable]` Factory
    /// 1. `[signer]` Current admin
    TransferOwnership {
        new_admin: [u8; 32],
    },

    /// Transfer BTC (satoshis) on the Bitcoin network using WOTS+ signature
    ///
    /// Builds a Bitcoin transaction that spends the wallet PDA's UTXO,
    /// sends `amount` satoshis to `recipient_script_pubkey`, and returns
    /// change to the wallet. The Arch validator network threshold-signs
    /// the transaction. Charges `transfer_fee` in lamports.
    ///
    /// Accounts:
    /// 0. `[writable]` Factory
    /// 1. `[writable]` Wallet
    /// 2. `[signer, writable]` Payer (must be wallet owner)
    /// 3. `[]` System program
    BtcTransferWithWinternitz {
        vault_id: [u8; 32],
        pq_next: WinternitzPublicKey,
        /// Satoshis to send to recipient
        amount: u64,
        /// Recipient's Bitcoin script_pubkey (supports any address type)
        recipient_script_pubkey: Vec<u8>,
        /// Serialized Bitcoin transaction providing the fee input
        fee_tx: Vec<u8>,
        /// WOTS+ signature
        signature: WinternitzSignature,
    },
}
