// Dev-only: derive deployer pubkeys (Arch x-only + BTC P2TR address) and
// report current funding state on testnet.
//
// Run: npx tsx scripts/deployer-info.ts

import { readFileSync } from 'node:fs'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import * as btc from '@scure/btc-signer'
import { RpcConnection, type Pubkey } from '@arch-network/arch-sdk'

const KEYPAIR_PATH = '/Users/quark/quip/quip-arch/keys/testnet_deployer.json'
const ARCH_RPC = 'https://rpc.testnet.arch.network'
const MEMPOOL_BASE = 'https://mempool.space/testnet4/api'

function toHex(u8: Uint8Array): string {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')
}

function loadDeployerSecret(): Uint8Array {
  const raw = JSON.parse(readFileSync(KEYPAIR_PATH, 'utf8')) as number[]
  if (raw.length !== 32) throw new Error(`expected 32-byte secret, got ${raw.length}`)
  return new Uint8Array(raw)
}

async function main() {
  const secret = loadDeployerSecret()

  // Compressed pubkey (33 bytes: 0x02/0x03 | x)
  const compressed = secp256k1.getPublicKey(secret, true)
  const xOnly = compressed.slice(1) // 32 bytes — this is the Arch pubkey AND the BIP-340 pubkey
  console.log('deployer secret (hex):', toHex(secret))
  console.log('deployer x-only pubkey (hex):', toHex(xOnly))

  // Derive testnet P2TR address (key-path spend, no script tree)
  const p2tr = btc.p2tr(xOnly, undefined, btc.TEST_NETWORK)
  console.log('deployer BTC address (testnet P2TR):', p2tr.address)

  // Arch balance
  const rpc = new RpcConnection(ARCH_RPC)
  try {
    const info = await rpc.readAccountInfo(xOnly as Pubkey)
    console.log('\n--- Arch account ---')
    console.log('  exists:', !!info)
    if (info) {
      console.log('  lamports:', info.lamports)
      console.log('  owner (hex):', toHex(info.owner as unknown as Uint8Array))
      console.log('  data.length:', info.data?.length ?? 0)
    }
  } catch (e) {
    console.log('\n--- Arch account ---')
    console.log('  read error:', (e as Error).message)
  }

  // Bitcoin UTXOs
  console.log('\n--- BTC UTXOs (mempool.space testnet4) ---')
  const url = `${MEMPOOL_BASE}/address/${p2tr.address}/utxo`
  try {
    const res = await fetch(url)
    if (!res.ok) {
      console.log('  HTTP', res.status, await res.text())
      return
    }
    const utxos = (await res.json()) as Array<{
      txid: string
      vout: number
      value: number
      status: { confirmed: boolean; block_height?: number }
    }>
    console.log(`  found ${utxos.length} UTXO(s)`)
    for (const u of utxos) {
      console.log(
        `    ${u.txid}:${u.vout}  ${u.value} sats  ${u.status.confirmed ? `confirmed @ ${u.status.block_height}` : 'unconfirmed'}`
      )
    }
    const total = utxos.reduce((a, u) => a + u.value, 0)
    console.log(`  total: ${total} sats`)
  } catch (e) {
    console.log('  fetch error:', (e as Error).message)
  }
}

main().catch((err) => {
  console.error('FAIL:', err)
  process.exit(1)
})
