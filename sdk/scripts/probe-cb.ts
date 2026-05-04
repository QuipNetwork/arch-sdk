// Probe: send a no-op compute-budget instruction alone to see whether Arch
// recognizes the program ID. If the tx processes (success or fail), our base58
// decoded program ID is right. If it's silently dropped, the program ID is
// wrong for this Arch testnet.

import { readFileSync } from 'node:fs'
import {
  RpcConnection,
  SanitizedMessageUtil,
  SignatureUtil,
  SystemInstruction,
  type Instruction as ArchInstruction,
  type Pubkey,
  type SanitizedMessage,
} from '@arch-network/arch-sdk'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base58check as mkBase58check } from '@scure/base'
import * as btc from '@scure/btc-signer'
import { Signer as Bip322Signer } from 'bip322-js'

const KEYPAIR = '/Users/quark/quip/quip-arch/keys/testnet_deployer.json'
const ARCH_RPC = 'https://rpc.testnet.arch.network'

function fromHex(s: string): Uint8Array {
  const o = new Uint8Array(s.length / 2)
  for (let i = 0; i < o.length; i++) o[i] = parseInt(s.slice(i*2, i*2+2), 16)
  return o
}

const candidates: Record<string, string> = {
  'base58-decoded (Solana canonical)': '0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000',
  'raw ASCII (arch-sdk-ts default)':   '436f6d70757465427564676574313131313131313131313131313131313131',
}

const which = process.argv[2] || 'base58-decoded (Solana canonical)'
const pidHex = candidates[which]
if (!pidHex) {
  console.error('candidates:', Object.keys(candidates))
  process.exit(1)
}
console.log('using program id:', which, '=', pidHex)

const secret = new Uint8Array(JSON.parse(readFileSync(KEYPAIR,'utf8')))
const xOnly = secp256k1.getPublicKey(secret, true).slice(1)
const p2tr = btc.p2tr(xOnly, undefined, btc.TEST_NETWORK)

const base58check = mkBase58check(sha256)
const wifPayload = new Uint8Array(34)
wifPayload[0] = 0xef
wifPayload.set(secret, 1)
wifPayload[33] = 0x01
const wif = base58check.encode(wifPayload)

const cuData = new Uint8Array(8)
new DataView(cuData.buffer).setUint32(0, 1, true)
new DataView(cuData.buffer).setUint32(4, 3000000, true)
const ix: ArchInstruction = {
  program_id: fromHex(pidHex) as Pubkey,
  accounts: [],
  data: cuData,
}

const rpc = new RpcConnection(ARCH_RPC)
const blockhashHex = await rpc.getBestBlockHash()
const clean = blockhashHex.startsWith('0x') ? blockhashHex.slice(2) : blockhashHex
const blockhash = SystemInstruction.hexStringToUint8Array(clean)
const msg = SanitizedMessageUtil.createSanitizedMessage([ix], xOnly as Pubkey, blockhash)
if (typeof msg === 'number') {
  console.error('CompileError:', msg)
  process.exit(1)
}
const hash = SanitizedMessageUtil.hash(msg as SanitizedMessage)
const hashUtf8 = new TextDecoder().decode(hash)
const sigB64 = Bip322Signer.sign(wif, p2tr.address!, hashUtf8)
const sigBytes = Uint8Array.from(Buffer.from(sigB64 as string, 'base64'))
const adjusted = SignatureUtil.adjustSignature(sigBytes)
const txid = await rpc.sendTransaction({ version: 0, signatures: [adjusted], message: msg as SanitizedMessage })
console.log('submitted txid:', txid)

for (let i = 0; i < 60; i++) {
  await new Promise(r => setTimeout(r, 5000))
  const proc = await rpc.getProcessedTransaction(txid)
  if (proc) {
    console.log('status:', JSON.stringify(proc.status))
    for (const l of proc.logs) console.log('  ', l)
    process.exit(0)
  }
  console.log(`  not yet processed (${5*(i+1)}s)`)
}
console.log('TIMEOUT — tx silently dropped')
