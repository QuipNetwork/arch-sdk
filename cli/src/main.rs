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

//! quip-cli: CLI tools for quip-arch deployment and wallet management.
//!
//! Usage:
//! ```bash
//! # Deploy program and initialize factory
//! quip-cli deploy --deployer-keypair keys/testnet_deployer.json
//!
//! # Create a new wallet
//! quip-cli create-wallet --vault-id 1
//!
//! # Show help
//! quip-cli --help
//! ```

mod btc_helper;
mod commands;
mod common;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "quip-cli")]
#[command(about = "CLI tools for quip-arch deployment and wallet management")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Deploy quip-arch program to Arch Network and initialize factory
    Deploy(commands::deploy::Args),

    /// Create a new quip-arch wallet with WOTS+ post-quantum security
    CreateWallet(commands::create_wallet::Args),

    /// Generate a fresh WOTS+ keypair (Rust-compat) as JSON on stdout
    WotsGen(commands::wots_gen::Args),

    /// Derive a WOTS+ public key at a given rotation index from a private key
    WotsDerive(commands::wots_derive::Args),

    /// Sign a message with a WOTS+ private key (keccak256-then-sign)
    WotsSign(commands::wots_sign::Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Deploy(args) => commands::deploy::run(args).await,
        Commands::CreateWallet(args) => commands::create_wallet::run(args).await,
        Commands::WotsGen(args) => commands::wots_gen::run(args),
        Commands::WotsDerive(args) => commands::wots_derive::run(args),
        Commands::WotsSign(args) => commands::wots_sign::run(args),
    }
}
