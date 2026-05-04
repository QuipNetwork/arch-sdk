// Anchor the deployer's Arch account to a fresh BTC UTXO on testnet4.
//
// Standalone extract of `ensureOwnerAnchored()` from smoke-btc-transfer.ts.
// Idempotent: exits early if the deployer is already anchored.
//
// Run: npx tsx scripts/anchor-deployer.ts

import { readFileSync } from 'node:fs'
import {
  RpcConnection,
  SystemInstruction,
  type Pubkey,
} from '@arch-network/arch-sdk'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base58check as mkBase58check } from '@scure/base'
import * as btc from '@scure/btc-signer'
import { Signer as Bip322Signer } from 'bip322-js'
import { QuipArchClient, programIdFor, type Instruction } from '../src'
import type { ClassicalSigner } from '../src/client'

const KEYPAIR_PATH = '/Users/quark/quip/quip-arch/keys/testnet_deployer.json'
const ARCH_RPC = 'https://rpc.testnet.arch.network'
const MEMPOOL_BASE = 'https://mempool.space/testnet4/api'
const ANCHOR_AMOUNT = 3000n
const TX_FEE = 500n

function toHex(u8: Uint8Array): string {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')
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

async function waitForMempool(txid: string, maxMs = 120_000): Promise<void> {
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

function makeBip322Signer(
  secret: Uint8Array,
  p2trAddress: string,
  xOnly: Uint8Array
): ClassicalSigner {
  const base58check = mkBase58check(sha256)
  const wifPayload = new Uint8Array(34)
  wifPayload[0] = 0xef
  wifPayload.set(secret, 1)
  wifPayload[33] = 0x01
  const wif = base58check.encode(wifPayload)
  return {
    pubkey: xOnly,
    sign(messageHashUtf8) {
      const sigB64 = Bip322Signer.sign(wif, p2trAddress, messageHashUtf8)
      return Uint8Array.from(Buffer.from(sigB64 as string, 'base64'))
    },
  }
}

function archIxToQuipIx(archIx: {
  program_id: Uint8Array
  accounts: Array<{ pubkey: Uint8Array; is_signer: boolean; is_writable: boolean }>
  data: Uint8Array
}): Instruction {
  return {
    programId: archIx.program_id,
    accounts: archIx.accounts.map((a) => ({
      pubkey: a.pubkey,
      isSigner: a.is_signer,
      isWritable: a.is_writable,
    })),
    data: archIx.data,
  }
}

async function main() {
  const secret = new Uint8Array(JSON.parse(readFileSync(KEYPAIR_PATH, 'utf8')))
  const xOnly = secp256k1.getPublicKey(secret, true).slice(1)
  const deployerP2tr = btc.p2tr(xOnly, undefined, btc.TEST_NETWORK)
  console.log('deployer x-only :', toHex(xOnly))
  console.log('deployer P2TR   :', deployerP2tr.address)

  const rpc = new RpcConnection(ARCH_RPC)
  const client = new QuipArchClient({ rpc, programId: programIdFor('testnet') })

  const info = await rpc.readAccountInfo(xOnly as Pubkey)
  const utxoRef = (info as any).utxo as string | undefined
  const isAnchored =
    !!utxoRef && !/^0+:0$/.test(utxoRef) && utxoRef.length > 0
  if (isAnchored) {
    console.log('already anchored at', utxoRef)
    return
  }
  console.log('not anchored — proceeding')

  const ownerBtcAddr = await rpc.getAccountAddress(xOnly as Pubkey)
  console.log('owner BTC addr  :', ownerBtcAddr)

  // Check if a previous run already funded ownerBtcAddr — if so, reuse it
  // (script idempotency: avoids double-spending BTC if Anchor ix needs retry).
  const ownerUtxos = await fetchUtxos(ownerBtcAddr)
  const existing = ownerUtxos.find((u) => BigInt(u.value) === ANCHOR_AMOUNT)
  let anchorTxid: string
  let anchorVout: number
  if (existing) {
    anchorTxid = existing.txid
    anchorVout = existing.vout
    console.log(`reusing existing funding UTXO ${anchorTxid}:${anchorVout} (${existing.value} sats, ${existing.status.confirmed ? 'confirmed' : 'unconfirmed'})`)
  } else {
    const utxos = await fetchUtxos(deployerP2tr.address!)
    const sorted = [...utxos].sort((a, b) => b.value - a.value)
    const pick = sorted.find(
      (u) => BigInt(u.value) >= ANCHOR_AMOUNT + TX_FEE
    )
    if (!pick) {
      throw new Error(
        `no deployer UTXO >= ${ANCHOR_AMOUNT + TX_FEE} sats (need ${ANCHOR_AMOUNT} + ${TX_FEE} fee)`
      )
    }
    console.log(`picked input UTXO ${pick.txid}:${pick.vout} (${pick.value} sats)`)

    const inputValue = BigInt(pick.value)
    const change = inputValue - ANCHOR_AMOUNT - TX_FEE
    const tx = new btc.Transaction()
    tx.addInput({
      txid: pick.txid,
      index: pick.vout,
      witnessUtxo: { script: deployerP2tr.script, amount: inputValue },
      tapInternalKey: xOnly,
    })
    tx.addOutputAddress(ownerBtcAddr, ANCHOR_AMOUNT, btc.TEST_NETWORK)
    if (change > 546n) {
      tx.addOutputAddress(deployerP2tr.address!, change, btc.TEST_NETWORK)
    }
    tx.sign(secret)
    tx.finalize()

    anchorTxid = await broadcastTx(tx.hex)
    anchorVout = 0
    console.log('anchor BTC tx broadcast:', anchorTxid)
    await waitForMempool(anchorTxid)
    console.log('mempool OK; sleeping 30s for Arch bitcoin-rpc to ingest')
    await new Promise((r) => setTimeout(r, 30_000))
  }

  const bip322 = makeBip322Signer(secret, deployerP2tr.address!, xOnly)
  const archIx = SystemInstruction.anchor(xOnly as Pubkey, anchorTxid, anchorVout)
  const quipIx = archIxToQuipIx({
    program_id: archIx.program_id,
    accounts: archIx.accounts,
    data: archIx.data,
  })
  const rt = await client.buildTransaction(quipIx, [bip322])
  const archTxid = await rpc.sendTransaction(rt)
  console.log('Anchor ix submitted:', archTxid)

  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 2000))
    let refreshed
    try {
      refreshed = await rpc.readAccountInfo(xOnly as Pubkey)
    } catch {
      continue
    }
    const u = (refreshed as any).utxo as string | undefined
    if (u && !/^0+:0$/.test(u)) {
      console.log('owner now anchored at', u)
      return
    }
  }
  throw new Error('owner anchor did not finalize within 60s')
}

main().catch((err) => {
  console.error('ANCHOR FAILED:', err)
  process.exit(1)
})
