// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase 1 read-only smoke test: verify the SDK can talk to Arch testnet.
// Do NOT commit this under dist/; it's a dev-only validation harness.
//
// Run: npx tsx scripts/smoke-testnet.ts

import { RpcConnection } from '@arch-network/arch-sdk'
import { QuipArchClient, programIdFor } from '../src'

const RPC_URL = 'https://rpc.testnet.arch.network'

function toHex(u8: Uint8Array): string {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')
}

async function main() {
  const rpc = new RpcConnection(RPC_URL)
  const client = new QuipArchClient({
    rpc,
    programId: programIdFor('testnet'),
  })

  console.log('programId (hex):', toHex(client.programId))
  console.log('factory PDA (hex):', toHex(client.factoryAddress))

  const blockhashRaw = await rpc.getBestBlockHash()
  console.log('\n--- blockhash inspection ---')
  console.log('typeof:', typeof blockhashRaw)
  console.log('raw:', JSON.stringify(blockhashRaw))
  if (typeof blockhashRaw === 'string') {
    console.log('length:', blockhashRaw.length)
    console.log('startsWith 0x:', blockhashRaw.startsWith('0x'))
    const clean = blockhashRaw.startsWith('0x') ? blockhashRaw.slice(2) : blockhashRaw
    console.log('hex-clean length:', clean.length, '(expect 64)')
    console.log('is all hex chars:', /^[0-9a-fA-F]+$/.test(clean))
  }

  console.log('\n--- factory read ---')
  const factory = await client.getFactory()
  if (!factory) {
    console.error('FAIL: getFactory() returned null')
    process.exit(1)
  }
  console.log('factory:', {
    admin: toHex(factory.admin),
    creationFee: factory.creationFee.toString(),
    transferFee: factory.transferFee.toString(),
    executeFee: factory.executeFee.toString(),
    totalWallets: factory.totalWallets.toString(),
    accumulatedFees: factory.accumulatedFees.toString(),
    bump: factory.bump,
  })
  console.log('\nOK: read path works against testnet.')
}

main().catch((err) => {
  console.error('SMOKE TEST FAILED:', err)
  process.exit(1)
})
