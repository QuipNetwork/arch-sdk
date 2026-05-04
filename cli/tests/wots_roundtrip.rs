// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Integration test: invoke the built `quip-cli` binary via `wots-gen`,
// `wots-sign`, and `wots-derive`, then verify the produced signature with
// hashsigs. This proves the CLI's JSON I/O matches the on-chain verifier's
// expectations without needing a live Arch validator.

use std::process::Command;

use hashsigs::{PublicKey, WOTSPlus};
use serde_json::Value;

fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    use arch_program::hashing_functions::keccak256;
    keccak256(data).0
}

fn cli_path() -> String {
    // Cargo runs integration tests with CARGO_BIN_EXE_<name> set to the binary path.
    env!("CARGO_BIN_EXE_quip-cli").to_string()
}

fn run_cli(args: &[&str]) -> Value {
    let out = Command::new(cli_path())
        .args(args)
        .output()
        .expect("spawn quip-cli");
    assert!(
        out.status.success(),
        "cli {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8(out.stdout).expect("utf8 stdout");
    serde_json::from_str(s.trim()).expect("valid json")
}

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn wots_gen_and_sign_roundtrip() {
    // 1. Generate a fresh keypair via the CLI.
    let gen = run_cli(&["wots-gen"]);
    let private_key_hex = gen["private_key"].as_str().unwrap();
    let public_seed = from_hex(gen["public_seed"].as_str().unwrap());
    let public_key_hash = from_hex(gen["public_key_hash"].as_str().unwrap());

    // 2. Sign an arbitrary message via the CLI.
    let message = b"hello quip-arch from the wots-sign CLI";
    let message_hex = hex::encode(message);
    let signed = run_cli(&[
        "wots-sign",
        "--private-key",
        private_key_hex,
        "--message",
        &message_hex,
    ]);
    let signature_data = from_hex(signed["signature_data"].as_str().unwrap());

    // 3. Verify with hashsigs the same way the on-chain program does
    //    (keccak256(message) -> 32 chunks of 32 bytes -> verify).
    let pubkey = PublicKey {
        public_seed: public_seed.as_slice().try_into().unwrap(),
        public_key_hash: public_key_hash.as_slice().try_into().unwrap(),
    };
    let message_hash = keccak256_hash(message);
    let signature_chunks: Vec<[u8; 32]> = signature_data
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect();

    let winternitz = WOTSPlus::new(keccak256_hash);
    assert!(
        winternitz.verify(&pubkey, &message_hash, &signature_chunks),
        "signature from wots-sign must verify against the wots-gen public key"
    );
}

#[test]
fn wots_derive_matches_in_tree_helper() {
    let gen = run_cli(&["wots-gen"]);
    let private_key_hex = gen["private_key"].as_str().unwrap();
    let private_key: [u8; 32] = from_hex(private_key_hex).as_slice().try_into().unwrap();

    // Derive index 1 via the CLI.
    let derived = run_cli(&[
        "wots-derive",
        "--private-key",
        private_key_hex,
        "--index",
        "1",
    ]);
    let cli_public_seed = from_hex(derived["public_seed"].as_str().unwrap());
    let cli_public_key_hash = from_hex(derived["public_key_hash"].as_str().unwrap());

    // Replicate the in-tree `derive_wots_pubkey_at_index` (src/tests/mod.rs)
    // and confirm byte-for-byte equality.
    let mut seed_input = Vec::with_capacity(40);
    seed_input.extend_from_slice(&private_key);
    seed_input.extend_from_slice(&1u64.to_le_bytes());
    let expected_public_seed = keccak256_hash(&seed_input);

    let winternitz = WOTSPlus::new(keccak256_hash);
    let expected_pubkey =
        winternitz.get_public_key_with_public_seed(&private_key, &expected_public_seed);

    assert_eq!(cli_public_seed.as_slice(), expected_public_seed.as_slice());
    assert_eq!(
        cli_public_key_hash.as_slice(),
        expected_pubkey.public_key_hash.as_slice()
    );
}
