import { RpcConnection, type Pubkey } from '@arch-network/arch-sdk'
import { QuipArchClient, programIdFor } from '../src'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { readFileSync } from 'node:fs'

const rpc = new RpcConnection('https://rpc.testnet.arch.network')
const client = new QuipArchClient({ rpc, programId: programIdFor('testnet') })
const secret = new Uint8Array(JSON.parse(readFileSync('/Users/quark/quip/quip-arch/keys/testnet_deployer.json','utf8')))
const xOnly = secp256k1.getPublicKey(secret, true).slice(1)

function hex(u: Uint8Array) { return Array.from(u, b => b.toString(16).padStart(2,'0')).join('') }
function fromHex(s: string): Uint8Array {
  const o = new Uint8Array(s.length / 2)
  for (let i=0; i<o.length; i++) o[i] = parseInt(s.slice(i*2,i*2+2), 16)
  return o
}

console.log('best block hash:', await rpc.getBestBlockHash())

// Try multiple times in case it's flaky
async function tryReadAccount(label: string, pk: Uint8Array) {
  for (let i = 0; i < 3; i++) {
    try {
      const info = await rpc.readAccountInfo(pk as Pubkey)
      console.log(`  ${label}: lamports=${info.lamports} executable=${info.is_executable} dataLen=${info.data.length} utxo=${info.utxo}`)
      return
    } catch (e: any) {
      const msg = e.error?.message ?? e.message
      if (msg?.includes('account is not in database') || msg?.includes('404')) {
        console.log(`  ${label}: NOT FOUND (${msg})`)
        return
      }
      if (i === 2) console.log(`  ${label}: RPC ERROR after 3 retries: ${msg}`)
      await new Promise(r => setTimeout(r, 2000 * (i+1)))
    }
  }
}

// 1. System program — should ALWAYS exist on any healthy Arch chain
await tryReadAccount('system program (32 zero bytes)', new Uint8Array(32))

// 2. ComputeBudget program — also a system fixture
await tryReadAccount('ComputeBudget111... (base58-decoded)',
  fromHex('0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000'))

// 3. Our quip-arch program
await tryReadAccount('quip-arch program', programIdFor('testnet'))

// 4. Deployer
await tryReadAccount('deployer', xOnly)

// 5. Factory PDA
await tryReadAccount('factory PDA', client.factoryAddress)

// 6. A known historical tx from yesterday's run 6 — createWallet that succeeded
console.log('\n--- historical tx lookups (yesterday) ---')
const histTxids = [
  '84775629b5617b1c894c9ec8bb9d66aa790244bea256d7986b27547fa4b0d227', // run 6 createWallet
  '15dd1f863b5868e3a2e0aef9006b16e258083caac54ff733296a5ca2085d13a3', // owner-anchor Bitcoin txid (also Arch reference)
]
for (const t of histTxids) {
  try {
    const proc = await rpc.getProcessedTransaction(t)
    if (!proc) console.log(`  ${t}: not found in processed-tx store`)
    else console.log(`  ${t}: status=${JSON.stringify(proc.status)}`)
  } catch (e: any) {
    console.log(`  ${t}: ERROR ${e.message}`)
  }
}
