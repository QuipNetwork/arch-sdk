# @quip-network/sdk

TypeScript SDK for interacting with quip-arch post-quantum wallets on Arch Network.

## Installation

```bash
npm install @quip-network/sdk @arch-network/arch-sdk
```

## Features

- **PDA Derivation** - Derive factory and wallet addresses
- **Message Builders** - Construct messages for WOTS+ signing
- **Instruction Builders** - Build all 9 quip-arch program instructions
- **Account Parsers** - Deserialize on-chain wallet and factory state
- **TypeScript Types** - Full type definitions for all structures

## Quick Start

```typescript
import {
  deriveWalletAddress,
  deriveFactoryAddress,
  createVaultId,
  buildTransferMessage,
  buildTransferWithWinternitzInstruction,
  parseWalletAccount,
} from '@quip-network/sdk'

// Your program ID
const programId = new Uint8Array(32) // ... your program ID bytes

// Derive addresses
const { address: factoryAddress } = deriveFactoryAddress(programId)
const vaultId = createVaultId(1)
const { address: walletAddress } = deriveWalletAddress(programId, ownerPubkey, vaultId)

// Build message for signing
const message = buildTransferMessage(currentKey, nextKey, recipientPubkey, 1000n)

// Sign with your WOTS+ library (external)
const signature = myWotsLibrary.sign(privateKey, message)

// Build the instruction
const instruction = buildTransferWithWinternitzInstruction({
  programId,
  factoryAddress,
  walletAddress,
  recipient: recipientPubkey,
  owner: ownerPubkey,
  vaultId,
  pqNext: nextKey,
  amount: 1000n,
  signature: { signatureData: signature },
})

// Use with @arch-network/arch-sdk to build and send transaction
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
buildExecuteWithWinternitzInstruction(params)
buildBtcTransferWithWinternitzInstruction(params)
buildUpdateFeesInstruction(params)
buildWithdrawFeesInstruction(params)
buildTransferOwnershipInstruction(params)
```

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

## Important: WOTS+ Key Safety

**WOTS+ keys are ONE-TIME USE.** After signing a single message, the key must be rotated to a new key. Reusing a key compromises security.

The SDK does not manage keys - you are responsible for:
1. Generating WOTS+ keypairs externally
2. Tracking which keys have been used
3. Rotating to a new key after each transaction

## License

AGPL-3.0-or-later
