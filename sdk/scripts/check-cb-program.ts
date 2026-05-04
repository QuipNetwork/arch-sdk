import { RpcConnection, type Pubkey } from '@arch-network/arch-sdk'
const rpc = new RpcConnection('https://rpc.testnet.arch.network')
function fromHex(s: string): Uint8Array {
  const o = new Uint8Array(s.length / 2)
  for (let i = 0; i < o.length; i++) o[i] = parseInt(s.slice(i*2, i*2+2), 16)
  return o
}
const ids: Record<string, string> = {
  'base58-decoded': '0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000',
  'raw ASCII (padded to 32)': '436f6d70757465427564676574313131313131313131313131313131313131' + '31',
  'system program (sanity)': '0000000000000000000000000000000000000000000000000000000000000000',
}
for (const [name, hex] of Object.entries(ids)) {
  try {
    const info = await rpc.readAccountInfo(fromHex(hex) as Pubkey)
    console.log(`${name}: lamports=${info.lamports} executable=${info.is_executable} owner=${info.owner instanceof Uint8Array ? Buffer.from(info.owner).toString('hex') : info.owner}`)
  } catch (e) {
    console.log(`${name}: ERROR ${(e as Error).message}`)
  }
}
