// Read-only preflight checks for smoke-btc-transfer.ts. No broadcasts.
//
// Confirms:
//   - keypair file is loadable
//   - deployer P2TR has enough UTXO inventory (>= 12500 sats in one output)
//   - the wallet's "owner BTC address" per Arch RPC matches the deployer P2TR
//     (so anchor & funding hit the same address)
//   - the deployer's Arch account is anchored
//   - the QuipFactory PDA exists and is initialized
//
// Run: npx tsx scripts/preflight-btc-transfer.ts

import { readFileSync } from 'node:fs'
import { RpcConnection, type Pubkey } from '@arch-network/arch-sdk'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import * as btc from '@scure/btc-signer'
import { QuipArchClient, programIdFor } from '../src'

const KEYPAIR = '/Users/quark/quip/quip-arch/keys/testnet_deployer.json'
const ARCH_RPC = 'https://rpc.testnet.arch.network'
const MEMPOOL_BASE = 'https://mempool.space/testnet4/api'
const NEEDED = 12500

function toHex(u8: Uint8Array) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')
}

async function main() {
  const secret = new Uint8Array(JSON.parse(readFileSync(KEYPAIR, 'utf8')))
  const xOnly = secp256k1.getPublicKey(secret, true).slice(1)
  const p2tr = btc.p2tr(xOnly, undefined, btc.TEST_NETWORK)
  console.log('deployer x-only :', toHex(xOnly))
  console.log('deployer P2TR   :', p2tr.address)

  const rpc = new RpcConnection(ARCH_RPC)
  const client = new QuipArchClient({ rpc, programId: programIdFor('testnet') })
  console.log('program id      :', toHex(programIdFor('testnet')))
  console.log('factory addr    :', toHex(client.factoryAddress))

  // 1. Owner Arch account
  const info = await rpc.readAccountInfo(xOnly as Pubkey)
  console.log('owner Arch utxo :', JSON.stringify(info.utxo))
  console.log('owner lamports  :', info.lamports)

  // 2. Owner BTC address per Arch RPC
  const ownerBtcAddr = await rpc.getAccountAddress(xOnly as Pubkey)
  console.log('owner BTC addr  :', ownerBtcAddr)
  console.log('matches P2TR?   :', ownerBtcAddr === p2tr.address)

  // 3. UTXO inventory
  const res = await fetch(`${MEMPOOL_BASE}/address/${p2tr.address}/utxo`)
  const utxos = (await res.json()) as Array<{
    txid: string
    vout: number
    value: number
    status: { confirmed: boolean }
  }>
  const sorted = [...utxos].sort((a, b) => b.value - a.value)
  console.log(`deployer P2TR has ${utxos.length} UTXOs:`)
  for (const u of sorted.slice(0, 10)) {
    console.log(`  ${u.txid}:${u.vout} = ${u.value} sats (confirmed=${u.status.confirmed})`)
  }
  const total = sorted.reduce((s, u) => s + u.value, 0)
  console.log(`total: ${total} sats`)
  console.log(`largest UTXO >= ${NEEDED}?`, (sorted[0]?.value ?? 0) >= NEEDED)

  // 4. Factory state
  try {
    const factory = await client.getFactory()
    console.log(
      'factory: admin=%s creationFee=%s transferFee=%s executeFee=%s',
      toHex(factory.admin),
      factory.creationFee.toString(),
      factory.transferFee.toString(),
      factory.executeFee.toString()
    )
  } catch (e) {
    console.log('factory ERROR:', (e as Error).message)
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
