// One-off inspector: print everything we can about an Arch processed tx.
// Usage: npx tsx scripts/inspect-tx.ts <arch_txid>

import { RpcConnection } from '@arch-network/arch-sdk'

const ARCH_RPC = 'https://rpc.testnet.arch.network'
const txid = process.argv[2]
if (!txid) {
  console.error('usage: inspect-tx.ts <arch_txid>')
  process.exit(1)
}

const rpc = new RpcConnection(ARCH_RPC)
const proc = await rpc.getProcessedTransaction(txid)
if (!proc) {
  console.log('processed tx not found (still pending?)')
  process.exit(0)
}
console.log('status        :', JSON.stringify(proc.status))
console.log('bitcoin_txid  :', proc.bitcoin_txid)
console.log('rollback      :', JSON.stringify(proc.rollback_status))
console.log('logs:')
for (const l of proc.logs) console.log('  ', l)
console.log('inner instructions:', JSON.stringify(proc.inner_instructions_list, null, 2))
