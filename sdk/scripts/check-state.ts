import { RpcConnection, type Pubkey } from '@arch-network/arch-sdk'
import { QuipArchClient, programIdFor } from '../src'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { readFileSync } from 'node:fs'

const rpc = new RpcConnection('https://rpc.testnet.arch.network')
const client = new QuipArchClient({ rpc, programId: programIdFor('testnet') })
const secret = new Uint8Array(JSON.parse(readFileSync('/Users/quark/quip/quip-arch/keys/testnet_deployer.json','utf8')))
const xOnly = secp256k1.getPublicKey(secret, true).slice(1)

function hex(u: Uint8Array) { return Array.from(u, b => b.toString(16).padStart(2,'0')).join('') }

console.log('best block hash:', await rpc.getBestBlockHash())

console.log('\n--- deployer account ---')
try {
  const info = await rpc.readAccountInfo(xOnly as Pubkey)
  console.log('  lamports:', info.lamports, 'utxo:', info.utxo)
} catch (e: any) {
  console.log('  ERROR:', e.error?.message ?? e.message)
}

console.log('\n--- program account ---')
try {
  const info = await rpc.readAccountInfo(programIdFor('testnet') as Pubkey)
  console.log('  lamports:', info.lamports, 'executable:', info.is_executable)
} catch (e: any) {
  console.log('  ERROR:', e.error?.message ?? e.message)
}

console.log('\n--- factory PDA ---')
console.log('  addr:', hex(client.factoryAddress))
try {
  const f = await client.getFactory()
  console.log('  admin:', hex(f.admin), 'creationFee:', f.creationFee.toString())
} catch (e: any) {
  console.log('  ERROR:', e.message)
}
