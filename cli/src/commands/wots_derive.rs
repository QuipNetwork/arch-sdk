// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Derive a WOTS+ public key at a given rotation index from an existing
//! private key. Mirrors `derive_wots_pubkey_at_index` from the in-tree test
//! helpers (`src/tests/mod.rs`) so TS tooling can compute `pq_next` without
//! re-implementing the algorithm.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use hashsigs::WOTSPlus;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// 32-byte WOTS+ private key, hex-encoded (as emitted by `wots-gen`).
    #[arg(long)]
    private_key: String,

    /// Rotation index. The on-chain wallet's first key is at index 0; after
    /// the first WOTS+-signed action the wallet rotates to index 1, etc.
    #[arg(long)]
    index: u64,
}

fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    use arch_program::hashing_functions::keccak256;
    keccak256(data).0
}

pub fn run(args: Args) -> Result<()> {
    let private_key_bytes = hex::decode(&args.private_key)
        .context("--private-key must be valid hex")?;
    let private_key: [u8; 32] = private_key_bytes
        .as_slice()
        .try_into()
        .context("--private-key must be 32 bytes")?;

    // Match `derive_wots_pubkey_at_index` in src/tests/mod.rs: derive a unique
    // public_seed by hashing private_key || index_le, then compute the public
    // key under that seed.
    let mut seed_input = Vec::with_capacity(40);
    seed_input.extend_from_slice(&private_key);
    seed_input.extend_from_slice(&args.index.to_le_bytes());
    let public_seed = keccak256_hash(&seed_input);

    let winternitz = WOTSPlus::new(keccak256_hash);
    let public_key = winternitz.get_public_key_with_public_seed(&private_key, &public_seed);

    let out = serde_json::json!({
        "index": args.index,
        "public_seed": hex::encode(public_key.public_seed),
        "public_key_hash": hex::encode(public_key.public_key_hash),
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
