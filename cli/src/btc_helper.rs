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

//! Bitcoin P2TR transaction construction, signing, and broadcast via mempool.space.

use anyhow::{Context, Result};
use arch_program::pubkey::Pubkey;
use bitcoin::{
    absolute::LockTime,
    address::Address,
    key::{TapTweak, UntweakedKeypair},
    secp256k1::{self, Secp256k1},
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    Txid, Witness, XOnlyPublicKey,
};
use serde::Deserialize;
use std::str::FromStr;

const SEND_AMOUNT: u64 = 3000;
const FEE: u64 = 200;

fn mempool_base_url(network: Network) -> &'static str {
    match network {
        Network::Testnet4 => "https://mempool.space/testnet4/api",
        Network::Bitcoin => "https://mempool.space/api",
        _ => "https://mempool.space/testnet4/api",
    }
}

/// UTXO as returned by mempool.space API.
#[derive(Debug, Deserialize)]
struct Utxo {
    txid: String,
    vout: u32,
    value: u64,
    status: UtxoStatus,
}

#[derive(Debug, Deserialize)]
struct UtxoStatus {
    confirmed: bool,
}

/// Derive the deployer's P2TR Bitcoin address from keypair.
fn deployer_address(keypair: &UntweakedKeypair, network: Network) -> Address {
    let secp = Secp256k1::new();
    let (xonly, _) = XOnlyPublicKey::from_keypair(keypair);
    Address::p2tr(&secp, xonly, None, network)
}

/// Fetch UTXOs for an address from mempool.space.
/// Prefers confirmed UTXOs, but falls back to unconfirmed if none are available
/// (allows chaining off unconfirmed change outputs).
fn fetch_utxos(address: &str, network: Network) -> Result<Vec<Utxo>> {
    let url = format!("{}/address/{}/utxo", mempool_base_url(network), address);
    let resp = reqwest::blocking::get(&url)
        .with_context(|| format!("Failed to fetch UTXOs from {}", url))?;
    let utxos: Vec<Utxo> = resp
        .json()
        .context("Failed to parse UTXO response")?;
    let confirmed: Vec<Utxo> = utxos.into_iter().collect::<Vec<_>>();
    let (conf, unconf): (Vec<_>, Vec<_>) = confirmed.into_iter().partition(|u| u.status.confirmed);
    if conf.is_empty() {
        println!("No confirmed UTXOs, using unconfirmed");
        Ok(unconf)
    } else {
        Ok(conf)
    }
}

/// Get an Arch account's Bitcoin address via RPC get_account_address.
fn get_account_btc_address(arch_rpc_url: &str, pubkey: &Pubkey, network: Network) -> Result<Address> {
    let config = arch_sdk::Config {
        arch_node_url: arch_rpc_url.to_string(),
        node_endpoint: String::new(),
        node_username: String::new(),
        node_password: String::new(),
        network,
        titan_url: String::new(),
    };
    let client = arch_sdk::ArchRpcClient::new(&config);
    let addr_str = client
        .get_account_address(pubkey)
        .map_err(|e| anyhow::anyhow!("get_account_address RPC failed: {:?}", e))?;
    let addr = Address::from_str(&addr_str)
        .context("Failed to parse account BTC address")?
        .require_network(network)
        .map_err(|e| anyhow::anyhow!("Network mismatch for account address: {}", e))?;
    Ok(addr)
}

/// Build and sign a P2TR key-path spend tx: deployer UTXO -> target + change.
fn build_and_sign_p2tr_tx(
    keypair: &UntweakedKeypair,
    utxo: &Utxo,
    target_address: &Address,
    change_address: &Address,
) -> Result<Transaction> {
    let txid = Txid::from_str(&utxo.txid).context("Invalid UTXO txid")?;

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: utxo.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(SEND_AMOUNT),
                script_pubkey: target_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(utxo.value - SEND_AMOUNT - FEE),
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    };

    let prevout = TxOut {
        value: Amount::from_sat(utxo.value),
        script_pubkey: change_address.script_pubkey(),
    };
    let prevouts = [prevout];

    let sighash_type = TapSighashType::Default;
    let sighash = {
        let mut sighasher = SighashCache::new(&mut tx);
        sighasher
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), sighash_type)
            .context("Failed to compute taproot sighash")?
    };

    let secp = Secp256k1::new();
    let tweaked = keypair.tap_tweak(&secp, None);
    let msg = secp256k1::Message::from(sighash);
    let sig = secp.sign_schnorr(&msg, &tweaked.to_inner());

    let signature = bitcoin::taproot::Signature {
        signature: sig,
        sighash_type,
    };
    tx.input[0].witness.push(signature.to_vec());

    Ok(tx)
}

/// Broadcast a raw transaction via mempool.space POST /api/tx.
fn broadcast(tx: &Transaction, network: Network) -> Result<String> {
    let raw_hex = bitcoin::consensus::encode::serialize_hex(tx);
    let url = format!("{}/tx", mempool_base_url(network));
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .body(raw_hex)
        .send()
        .context("Failed to broadcast transaction")?;
    let status = resp.status();
    let body = resp.text().context("Failed to read broadcast response")?;
    if !status.is_success() {
        anyhow::bail!("Broadcast failed (HTTP {}): {}", status, body);
    }
    Ok(body.trim().to_string())
}

/// Poll Titan's `/tx/{txid}` endpoint until indexed (up to 60s).
fn wait_for_titan(titan_url: &str, txid: &str) -> Result<()> {
    let url = format!("{}/tx/{}", titan_url.trim_end_matches('/'), txid);
    let client = reqwest::blocking::Client::new();
    for elapsed in 0..60 {
        if elapsed > 0 {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => {}
        }
    }
    anyhow::bail!("Titan did not index transaction {} within 60 seconds", txid)
}

/// Fetch the deployer's largest confirmed UTXO, build a P2TR tx sending 3000 sats
/// to the target Arch account's Bitcoin address, sign, broadcast, wait for Titan
/// indexing, and return (txid_hex, vout).
pub fn send_utxo(
    keypair: &UntweakedKeypair,
    target_pubkey: &Pubkey,
    arch_rpc_url: &str,
    titan_url: &str,
    network: Network,
) -> Result<(String, u32)> {
    let change_addr = deployer_address(keypair, network);
    let deployer_addr_str = change_addr.to_string();
    println!("Deployer BTC address: {}", deployer_addr_str);

    let target_addr = get_account_btc_address(arch_rpc_url, target_pubkey, network)?;
    println!("Target BTC address: {}", target_addr);

    let utxos = fetch_utxos(&deployer_addr_str, network)?;
    let utxo = utxos
        .iter()
        .max_by_key(|u| u.value)
        .ok_or_else(|| anyhow::anyhow!(
            "No confirmed UTXOs found for deployer address {}",
            deployer_addr_str
        ))?;

    if utxo.value < SEND_AMOUNT + FEE {
        anyhow::bail!(
            "Largest UTXO ({} sats) is too small; need at least {} sats",
            utxo.value,
            SEND_AMOUNT + FEE,
        );
    }
    println!(
        "Using UTXO {}:{} ({} sats)",
        utxo.txid, utxo.vout, utxo.value,
    );

    let tx = build_and_sign_p2tr_tx(keypair, utxo, &target_addr, &change_addr)?;
    let txid = broadcast(&tx, network)?;
    println!("Broadcast txid: {}", txid);

    println!("Waiting for Titan to index transaction...");
    wait_for_titan(titan_url, &txid)?;
    println!("Transaction indexed by Titan.");

    Ok((txid, 0))
}
