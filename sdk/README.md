# @quip.network/arch-sdk

TypeScript SDK for interacting with quip-arch post-quantum wallets on Arch Network.

## Installation

```bash
npm install @quip.network/arch-sdk @arch-network/arch-sdk @quip.network/hashsigs
```

`@arch-network/arch-sdk` is a required peer dependency. `@quip.network/hashsigs`
is an optional peer for signing WOTS+ messages in JavaScript. See
[WOTS+ key generation](#wots-key-generation) for an important compatibility
caveat about minting keypairs in TS.

You also need a BIP-322 signer for the outer transaction envelope — the SDK
does not bundle one. See [Classical signer (BIP-322)](#classical-signer-bip-322).

## Features

- **`QuipArchClient`** - High-level client: build, sign, and submit transactions
- **PDA Derivation** - Derive factory and wallet addresses
- **Message Builders** - Construct the exact byte payloads that WOTS+ signs
- **Instruction Builders** - All 9 quip-arch program instructions (low-level)
- **Account Parsers** - Deserialize on-chain wallet and factory state
- **Known Program IDs** - `programIdFor('testnet')` etc.
- **Key-rotation helpers** - `assertValidRotation` to catch WOTS+ key reuse
- **TypeScript Types** - Full type definitions for all structures

## Quick Start (high-level client)

```typescript
import { RpcConnection } from '@arch-network/arch-sdk'
import {
  QuipArchClient,
  type ClassicalSigner,
  programIdFor,
  createVaultId,
  buildTransferMessage,
  assertValidRotation,
} from '@quip.network/arch-sdk'
import { WOTSPlus } from '@quip.network/hashsigs'

const client = new QuipArchClient({
  rpc: new RpcConnection('https://rpc.testnet.arch.network'),
  programId: programIdFor('testnet'),
})

// Classical signer for the outer transaction envelope. `sign` receives the
// UTF-8-decoded form of the sanitized-message hash and must return a BIP-322
// simple signature. See "Classical signer (BIP-322)" below for Node + browser
// examples.
const owner: ClassicalSigner = {
  pubkey: ownerXOnlyPubkey, // 32 bytes
  sign: (messageHashUtf8) => myBip322Sign(messageHashUtf8),
}

const vaultId = createVaultId(1)

// 1. Build the message and sign it with WOTS+ (one-time key!)
const msg = buildTransferMessage(currentPqKey, nextPqKey, recipient, 1000n)
assertValidRotation(currentPqKey, nextPqKey)
const wots = new WOTSPlus(/* hash */)
const signatureData = wots.sign(currentPqPrivateKey, msg)

// 2. Submit in one call
const txid = await client.transfer({
  owner,
  vaultId,
  recipient,
  amount: 1000n,
  pqNext: nextPqKey,
  signature: { signatureData },
})
```

The client also exposes `createWallet`, `changePqOwner`, `execute`,
`btcTransfer`, `updateFees`, `withdrawFees`, `transferOwnership`,
`getFactory`, `getWallet`, and `buildTransaction` (for simulation / batching).

## Lower-level API

If you need to assemble transactions yourself, the underlying builders and
parsers are all exported:

```typescript
import {
  deriveWalletAddress,
  deriveFactoryAddress,
  buildTransferWithWinternitzInstruction,
  parseWalletAccount,
} from '@quip.network/arch-sdk'
```

## API Reference

### Address Derivation

```typescript
// Derive factory PDA
deriveFactoryAddress(programId: Uint8Array): { address: Uint8Array; bump: number }

// Derive wallet PDA
deriveWalletAddress(
  programId: Uint8Array,
  owner: Uint8Array,
  vaultId: Uint8Array
): { address: Uint8Array; bump: number }

// Create vault ID from number
createVaultId(id: number | bigint): Uint8Array
```

### Message Builders

These build the byte arrays that get signed with WOTS+:

```typescript
buildTransferMessage(currentKey, nextKey, recipient, amount): Uint8Array
buildChangePqOwnerMessage(currentKey, nextKey): Uint8Array
buildExecuteMessage(currentKey, nextKey, targetProgram, instructionData, accounts): Uint8Array
buildBtcTransferMessage(currentKey, nextKey, scriptPubkey, amount, sourceUtxo): Uint8Array
```

### Instruction Builders

All return `{ programId, accounts, data }`:

```typescript
buildInitializeFactoryInstruction(params)
buildDepositToWinternitzInstruction(params)
buildTransferWithWinternitzInstruction(params)
buildChangePqOwnerInstruction(params)  // Note: no factory account needed
buildExecuteWithWinternitzInstruction(params)  // cpiAccounts: ExecuteCpiAccount[]
buildBtcTransferWithWinternitzInstruction(params)
buildUpdateFeesInstruction(params)
buildWithdrawFeesInstruction(params)
buildTransferOwnershipInstruction(params)
```

> **Note on `ExecuteWithWinternitz`:** the single `cpiAccounts` array carries
> both the account pubkey and the `isSigner` / `isWritable` flags. These flags
> are applied both to the CPI's `AccountMeta` AND to the outer transaction's
> account list — this is required because ArchVM only grants the inner CPI
> access it already has on the outer instruction.

### Account Parsers

```typescript
parseWalletAccount(data: Uint8Array): QuipWallet
parseFactoryAccount(data: Uint8Array): QuipFactory
```

## Types

```typescript
interface WinternitzPublicKey {
  publicSeed: Uint8Array    // 32 bytes
  publicKeyHash: Uint8Array // 32 bytes
}

interface QuipWallet {
  version: number
  owner: Uint8Array
  pqOwner: WinternitzPublicKey
  createdAt: bigint
  lastActivity: bigint
  transactionCount: bigint
  bump: number
}

interface QuipFactory {
  admin: Uint8Array
  creationFee: bigint
  transferFee: bigint
  executeFee: bigint
  totalWallets: bigint
  accumulatedFees: bigint
  bump: number
}

interface UtxoMeta {
  txid: Uint8Array  // 32 bytes
  vout: number
}
```

## Classical signer (BIP-322)

The outer transaction envelope is authenticated with a BIP-322 simple
signature over the sanitized-message hash. The SDK does not bundle a BIP-322
implementation — consumers plug in their own signer through the
`ClassicalSigner` interface:

```typescript
interface ClassicalSigner {
  pubkey: Uint8Array                              // 32-byte x-only pubkey
  sign(messageHashUtf8: string): Uint8Array | Promise<Uint8Array>
}
```

Contract:

- **Input** is the `TextDecoder().decode(...)` of the sanitized-message hash
  — a string, not raw bytes. This matches the `arch-typescript-sdk`
  convention and is what BIP-322 signers expect as the "message" argument.
- **Output** is a BIP-322 simple signature (the witness bytes). The SDK
  normalizes it via `SignatureUtil.adjustSignature` before submission, so
  either a raw `Uint8Array` or the base64-decoded output of a browser
  wallet's `signMessage` call will work.

### Node.js (bip322-js)

```typescript
import { Signer as Bip322Signer, Verifier } from 'bip322-js'
import type { ClassicalSigner } from '@quip.network/arch-sdk'

// WIF-encoded taproot key for the classical signer
const signerWIF = '...'
const signerAddress = 'tb1p...'   // taproot address for that key
const ownerXOnly = /* 32 bytes */

const owner: ClassicalSigner = {
  pubkey: ownerXOnly,
  sign: (messageHashUtf8) => {
    const sigBase64 = Bip322Signer.sign(signerWIF, signerAddress, messageHashUtf8)
    return Buffer.from(sigBase64 as string, 'base64')
  },
}
```

`bip322-js` is used by `sdk/scripts/smoke-create-wallet.ts` as a working
end-to-end reference. It is a devDependency of this SDK — consumers must
install it themselves if they want to use it in production.

### Browser (Unisat / Xverse / etc.)

```typescript
const owner: ClassicalSigner = {
  pubkey: ownerXOnly,
  sign: async (messageHashUtf8) => {
    // Unisat-style API; Xverse exposes an equivalent method.
    const sigBase64 = await window.unisat.signMessage(messageHashUtf8, 'bip322-simple')
    return Uint8Array.from(atob(sigBase64), (c) => c.charCodeAt(0))
  },
}
```

Hardware wallets work the same way — wrap the vendor SDK's BIP-322 signing
call in a `ClassicalSigner`.

## WOTS+ key generation

`@quip.network/hashsigs` (JS) and `hashsigs-rs` (Rust, used by the on-chain
verifier) derive the WOTS+ private key from the seed differently:

- Rust `0.0.2`: `private_key = keccak256(private_seed)`
- TypeScript: `private_key = keccak256(privateSeed || publicSeed)`

As a result, **keypairs minted by `WOTSPlus.generateKeyPair` in TypeScript
cannot be verified on-chain** — the pubkey hash a TS-minted key produces
does not match what the verifier reconstructs. The lower-level `sign` /
`verify` primitives do interop if you pass `privateKey` and `publicSeed`
manually, but whole-keypair generation is not byte-compatible.

Until the JS library is republished to match, **generate WOTS+ keypairs
with the Rust CLI** shipped alongside this SDK:

```bash
cargo build -p quip-cli
./target/debug/quip-cli wots-gen
# { "private_seed": "...", "private_key": "...",
#   "public_seed": "...", "public_key_hash": "..." }
```

`sdk/scripts/smoke-create-wallet.ts` demonstrates the end-to-end flow,
invoking `quip-cli wots-gen` as a subprocess and feeding the hex fields
back into the SDK.

## Important: WOTS+ Key Safety

**WOTS+ keys are ONE-TIME USE.** After signing a single message, the key must be rotated to a new key. Reusing a key compromises security.

The SDK does not manage keys - you are responsible for:
1. Generating WOTS+ keypairs externally
2. Tracking which keys have been used
3. Rotating to a new key after each transaction

## License

AGPL-3.0-or-later
