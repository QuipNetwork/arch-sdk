// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sign an arbitrary message with a WOTS+ private key using hashsigs-rs (the
//! same library the on-chain verifier uses). The CLI accepts the raw message
//! bytes (hex-encoded) and hashes them with keccak256 internally — matching
//! the on-chain `require_valid_signature` path. Emits JSON on stdout so
//! TS/other tooling can consume the signature without re-implementing WOTS+.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use hashsigs::WOTSPlus;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// 32-byte WOTS+ private key, hex-encoded (as emitted by `wots-gen`).
    #[arg(long)]
    private_key: String,

    /// Message bytes to sign, hex-encoded. Hashed with keccak256 internally
    /// before being passed to WOTS+, matching on-chain verification.
    #[arg(long)]
    message: String,
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

    let message = hex::decode(&args.message).context("--message must be valid hex")?;

    let winternitz = WOTSPlus::new(keccak256_hash);
    let message_hash = keccak256_hash(&message);
    let signature = winternitz.sign(&private_key, &message_hash);

    // Flatten Vec<[u8; 32]> -> contiguous bytes, matching the on-chain
    // serialization in `WinternitzSignature::signature_data`.
    let signature_bytes: Vec<u8> = signature.iter().flat_map(|c| c.iter().copied()).collect();

    let out = serde_json::json!({
        "message_hash": hex::encode(message_hash),
        "signature_data": hex::encode(signature_bytes),
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
