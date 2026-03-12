// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared utilities for quip-cli commands.

use anyhow::{Context, Result};
use arch_program::pubkey::Pubkey;
use arch_sdk::arch_program::bitcoin::key::UntweakedKeypair;
use bitcoin::Network;
use std::path::Path;

/// Base58 alphabet (Bitcoin/Solana style)
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes to base58 string
pub fn base58_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let zeros = bytes.iter().take_while(|&&b| b == 0).count();

    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        result.push('1');
    }
    for digit in digits.iter().rev() {
        result.push(BASE58_ALPHABET[*digit as usize] as char);
    }
    result
}

/// Convert Pubkey to base58 string
pub fn pubkey_to_base58(pubkey: &Pubkey) -> String {
    base58_encode(&pubkey.serialize())
}

/// Load a keypair from a JSON file (arch-cli format)
pub fn load_keypair(path: &Path) -> Result<UntweakedKeypair> {
    let json_str = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read keypair file: {}", path.display()))?;

    let bytes: Vec<u8> = serde_json::from_str(&json_str)
        .with_context(|| "Failed to parse keypair JSON")?;

    // Support both 32-byte (arch-cli) and 64-byte (Solana) formats
    let secret_bytes: [u8; 32] = match bytes.len() {
        32 => bytes.try_into().expect("checked length is 32"),
        64 => bytes[..32].try_into().expect("slice is 32 bytes"),
        n => anyhow::bail!("Invalid keypair length: expected 32 or 64 bytes, got {}", n),
    };

    let keypair = UntweakedKeypair::from_seckey_slice(
        &arch_program::bitcoin::secp256k1::Secp256k1::new(),
        &secret_bytes,
    ).with_context(|| "Failed to create keypair from secret key")?;

    Ok(keypair)
}

/// Parse network string to Bitcoin Network enum
pub fn parse_network(s: &str) -> Result<Network> {
    match s {
        "testnet4" => Ok(Network::Testnet4),
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "regtest" => Ok(Network::Regtest),
        _ => anyhow::bail!("Unknown network: {} (expected testnet4, bitcoin, regtest)", s),
    }
}

/// Parse a hex string into a 32-byte array
pub fn parse_hex_32(hex_str: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .with_context(|| format!("Invalid hex for {}", label))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must be 32 bytes (64 hex chars)", label))
}

/// Parse a hex program ID string into a Pubkey
pub fn parse_program_id(hex_str: &str) -> Result<Pubkey> {
    let bytes = parse_hex_32(hex_str, "program ID")?;
    Ok(Pubkey::from_slice(&bytes))
}

/// Load deployment.json for a given network
pub fn load_deployment(network: &str) -> Result<Option<serde_json::Value>> {
    let deployment_file = std::path::PathBuf::from(format!("deployments/{}/deployment.json", network));

    if deployment_file.exists() {
        let content = std::fs::read_to_string(&deployment_file)
            .with_context(|| format!("Failed to read {}", deployment_file.display()))?;
        Ok(Some(serde_json::from_str(&content)?))
    } else {
        Ok(None)
    }
}
