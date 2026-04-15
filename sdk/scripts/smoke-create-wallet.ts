// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase 2 live smoke test: create a wallet on testnet using the TS SDK.
// Exercises: blockhash fetch -> sanitize -> BIP-322 sign -> sendTransaction,
// plus the BTC UTXO ceremony replicated from cli/src/btc_helper.rs::send_utxo.
//
// Run: npx tsx scripts/smoke-create-wallet.ts [--vault-id N]

import { readFileSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { RpcConnection, type Pubkey } from '@arch-network/arch-sdk'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base58check as mkBase58check } from '@scure/base'
import * as btc from '@scure/btc-signer'
import { Signer as Bip322Signer } from 'bip322-js'
import { QuipArchClient, programIdFor, createVaultId } from '../src'
import type { ClassicalSigner } from '../src/client'

const KEYPAIR_PATH = '/Users/quark/quip/quip-arch/keys/testnet_deployer.json'
const ARCH_RPC = 'https://rpc.testnet.arch.network'
const MEMPOOL_BASE = 'https://mempool.space/testnet4/api'
const SEND_AMOUNT = 3000n
const FEE = 500n
const CLI_BIN = '/Users/quark/quip/quip-arch/target/debug/quip-cli'

function toHex(u8: Uint8Array): string {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')
}
function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function loadDeployerSecret(): Uint8Array {
  const raw = JSON.parse(readFileSync(KEYPAIR_PATH, 'utf8')) as number[]
  return new Uint8Array(raw)
}

async function fetchUtxos(address: string) {
  const res = await fetch(`${MEMPOOL_BASE}/address/${address}/utxo`)
  if (!res.ok) throw new Error(`utxo fetch HTTP ${res.status}`)
  return (await res.json()) as Array<{
    txid: string
    vout: number
    value: number
    status: { confirmed: boolean }
  }>
}

async function broadcastTx(rawHex: string): Promise<string> {
  const res = await fetch(`${MEMPOOL_BASE}/tx`, {
    method: 'POST',
    body: rawHex,
    headers: { 'content-type': 'text/plain' },
  })
  const body = await res.text()
  if (!res.ok) throw new Error(`broadcast HTTP ${res.status}: ${body}`)
  return body
}

async function waitForMempool(txid: string, maxMs = 60_000): Promise<void> {
  // Titan is unreachable from some networks; poll mempool.space/api/tx/{id}
  // for visibility instead (Arch queries bitcoin-rpc directly, not Titan).
  const start = Date.now()
  while (Date.now() - start < maxMs) {
    try {
      const res = await fetch(`${MEMPOOL_BASE}/tx/${txid}`)
      if (res.ok) return
    } catch {}
    await new Promise((r) => setTimeout(r, 2000))
  }
  throw new Error(`mempool did not surface ${txid} within ${maxMs}ms`)
}

function genWotsKeypair(): { publicSeed: Uint8Array; publicKeyHash: Uint8Array } {
  const out = execSync(`${CLI_BIN} wots-gen`).toString('utf8').trim()
  const j = JSON.parse(out)
  return {
    publicSeed: fromHex(j.public_seed),
    publicKeyHash: fromHex(j.public_key_hash),
  }
}

async function main() {
  const vaultIdArg = process.argv.includes('--vault-id')
    ? BigInt(process.argv[process.argv.indexOf('--vault-id') + 1])
    : BigInt(Date.now()) // unique vault id
  console.log('vault id:', vaultIdArg.toString())

  const secret = loadDeployerSecret()
  const xOnly = secp256k1.getPublicKey(secret, true).slice(1)
  console.log('deployer pubkey (x-only hex):', toHex(xOnly))

  const rpc = new RpcConnection(ARCH_RPC)
  const client = new QuipArchClient({ rpc, programId: programIdFor('testnet') })

  const vaultId = createVaultId(vaultIdArg)
  const walletPDA = client.walletAddress(xOnly, vaultId)
  console.log('wallet PDA (hex):', toHex(walletPDA))

  // --- Step 1: get wallet's Bitcoin address via Arch RPC ---
  const walletBtcAddr = await rpc.getAccountAddress(walletPDA as Pubkey)
  console.log('wallet BTC address:', walletBtcAddr)

  // --- Step 2: build & broadcast BTC UTXO ceremony ---
  const deployerP2tr = btc.p2tr(xOnly, undefined, btc.TEST_NETWORK)
  console.log('deployer P2TR:', deployerP2tr.address)

  const utxos = await fetchUtxos(deployerP2tr.address!)
  // Allow unconfirmed (our own change) to chain broadcasts in a single session.
  const sorted = [...utxos].sort((a, b) => b.value - a.value)
  if (sorted.length === 0) throw new Error('no deployer UTXOs')
  const pick = sorted[0]
  console.log(`picked UTXO ${pick.txid}:${pick.vout} (${pick.value} sats)`)

  const inputValue = BigInt(pick.value)
  if (inputValue < SEND_AMOUNT + FEE) throw new Error('UTXO too small')
  const changeValue = inputValue - SEND_AMOUNT - FEE

  const tx = new btc.Transaction()
  tx.addInput({
    txid: pick.txid,
    index: pick.vout,
    witnessUtxo: { script: deployerP2tr.script, amount: inputValue },
    tapInternalKey: xOnly,
  })
  tx.addOutputAddress(walletBtcAddr, SEND_AMOUNT, btc.TEST_NETWORK)
  if (changeValue > 546n) {
    tx.addOutputAddress(deployerP2tr.address!, changeValue, btc.TEST_NETWORK)
  }
  tx.sign(secret)
  tx.finalize()
  const rawHex = tx.hex
  const localTxid = tx.id
  console.log('local txid:', localTxid, 'size:', rawHex.length / 2, 'bytes')
  const broadcastId = await broadcastTx(rawHex)
  console.log('broadcast txid:', broadcastId)
  if (broadcastId !== localTxid) console.warn('WARN: txid mismatch')

  console.log('confirming mempool visibility...')
  await waitForMempool(broadcastId)
  console.log('mempool OK; sleeping 15s before Arch submit')
  await new Promise((r) => setTimeout(r, 15_000))

  // --- Step 3: WOTS+ keypair via Rust CLI ---
  console.log('generating WOTS+ keypair via quip-cli wots-gen...')
  const pqOwner = genWotsKeypair()
  console.log('  public_seed:', toHex(pqOwner.publicSeed))
  console.log('  public_key_hash:', toHex(pqOwner.publicKeyHash))

  // --- Step 4: ClassicalSigner (BIP-322 simple, via bip322-js) ---
  // Arch expects a BIP-322 simple signature over the UTF-8-decoded message
  // hash, signed by the BTC address corresponding to the transaction payer.
  // bip322-js wants a WIF private key; derive one for testnet compressed.
  const base58check = mkBase58check(sha256)
  const wifPayload = new Uint8Array(34)
  wifPayload[0] = 0xef // testnet
  wifPayload.set(secret, 1)
  wifPayload[33] = 0x01 // compressed
  const wif = base58check.encode(wifPayload)
  const deployerAddr = deployerP2tr.address!
  const signer: ClassicalSigner = {
    pubkey: xOnly,
    sign(messageHashUtf8) {
      const sigB64 = Bip322Signer.sign(wif, deployerAddr, messageHashUtf8)
      return Uint8Array.from(Buffer.from(sigB64 as string, 'base64'))
    },
  }

  // --- Step 5: call client.createWallet ---
  const walletUtxo = { txid: fromHex(broadcastId), vout: 0 }
  console.log('submitting createWallet...')
  const result = await client.createWallet({
    owner: signer,
    vaultId,
    pqOwner,
    deposit: 0n,
    walletUtxo,
  })
  console.log('  tx signature:', result.signature)
  console.log('  wallet address:', toHex(result.walletAddress))

  // --- Step 6: verify via getWallet ---
  console.log('waiting for Arch tx processing...')
  await new Promise((r) => setTimeout(r, 5000))
  const readback = await client.getWallet(xOnly, vaultId)
  if (!readback) {
    console.error('FAIL: getWallet returned null')
    process.exit(1)
  }
  console.log('readback:', {
    owner: toHex(readback.owner),
    pqOwnerSeed: toHex(readback.pqOwner.publicSeed),
    pqOwnerHash: toHex(readback.pqOwner.publicKeyHash),
    transactionCount: readback.transactionCount.toString(),
    bump: readback.bump,
  })

  // sanity: pqOwner matches what we sent
  if (toHex(readback.pqOwner.publicSeed) !== toHex(pqOwner.publicSeed))
    throw new Error('pqOwner.publicSeed mismatch')
  if (toHex(readback.pqOwner.publicKeyHash) !== toHex(pqOwner.publicKeyHash))
    throw new Error('pqOwner.publicKeyHash mismatch')

  console.log('\nPHASE 2 PASS: createWallet end-to-end works, readback matches.')
}

main().catch((err) => {
  console.error('SMOKE TEST FAILED:', err)
  process.exit(1)
})
