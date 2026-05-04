import { readFileSync } from 'node:fs'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import * as btc from '@scure/btc-signer'

const MEMPOOL_BASE = 'https://mempool.space/testnet4/api'

const secret = new Uint8Array(JSON.parse(readFileSync('/Users/quark/quip/quip-arch/keys/testnet_deployer.json','utf8')))
const xOnly = secp256k1.getPublicKey(secret, true).slice(1)

// run 6 TX-A
const txa = process.argv[2] || 'd5747ab7179c199e7be194f6d91402d3fe3a0c5a95457cc8a05c10ec0b7e4d0d'
const res = await fetch(`${MEMPOOL_BASE}/tx/${txa}/status`)
console.log('TX-A status:', await res.text())
const out = await fetch(`${MEMPOOL_BASE}/tx/${txa}/outspends`)
const spends = await out.json() as Array<{spent: boolean, txid?: string, vin?: number}>
console.log('TX-A outspends:')
spends.forEach((s, i) => console.log(`  out[${i}] spent=${s.spent}${s.txid ? ' by ' + s.txid : ''}`))

const deployerAddr = btc.p2tr(xOnly, undefined, btc.TEST_NETWORK).address!
const utxoRes = await fetch(`${MEMPOOL_BASE}/address/${deployerAddr}/utxo`)
const utxos = await utxoRes.json() as Array<{txid: string, vout: number, value: number}>
console.log(`deployer P2TR has ${utxos.length} current UTXOs:`)
const sorted = [...utxos].sort((a,b) => b.value - a.value)
for (const u of sorted) console.log(`  ${u.txid}:${u.vout} = ${u.value} sats`)
