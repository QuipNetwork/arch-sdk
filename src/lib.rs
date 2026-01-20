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

//! Quip Arch - Post-quantum secure wallets for ArchVM (Bitcoin)
//!
//! This program provides WOTS+ (Winternitz One-Time Signature Plus) secured
//! wallets on the Arch Network, enabling quantum-resistant transactions
//! that settle on Bitcoin.

#[cfg(not(feature = "no-entrypoint"))]
pub mod entrypoint;

pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
pub mod utils;

// Re-exports for convenience
pub use error::QuipError;
pub use instruction::QuipInstruction;
pub use state::*;
