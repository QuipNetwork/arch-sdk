// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generate a fresh WOTS+ keypair using hashsigs-rs (the same library the
//! on-chain verifier uses). Emits JSON on stdout so TS/other tooling can
//! consume a Rust-compatible keypair without re-implementing the algorithm.

use anyhow::Result;
use clap::Args as ClapArgs;
use hashsigs::WOTSPlus;
use rand::RngCore;

#[derive(ClapArgs, Debug)]
pub struct Args {}

fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    use arch_program::hashing_functions::keccak256;
    keccak256(data).0
}

pub fn run(_args: Args) -> Result<()> {
    let winternitz = WOTSPlus::new(keccak256_hash);

    let mut private_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut private_seed);

    let (public_key, private_key) = winternitz.generate_key_pair(&private_seed);

    let out = serde_json::json!({
        "private_seed": hex::encode(private_seed),
        "private_key": hex::encode(private_key),
        "public_seed": hex::encode(public_key.public_seed),
        "public_key_hash": hex::encode(public_key.public_key_hash),
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
