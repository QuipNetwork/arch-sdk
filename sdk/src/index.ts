// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @quip-network/sdk
 *
 * TypeScript SDK for interacting with quip-arch post-quantum wallets on Arch Network.
 *
 * This SDK provides:
 * - PDA derivation for factory and wallet addresses
 * - Message builders for WOTS+ signing
 * - Instruction builders for all quip-arch program instructions
 * - Account parsers for reading on-chain state
 *
 * @example
 * ```typescript
 * import {
 *   deriveWalletAddress,
 *   buildTransferMessage,
 *   buildTransferWithWinternitzInstruction,
 *   parseWalletAccount,
 * } from '@quip-network/sdk'
 *
 * // Derive wallet address
 * const { address, bump } = deriveWalletAddress(programId, owner, vaultId)
 *
 * // Build message for signing
 * const message = buildTransferMessage(currentKey, nextKey, recipient, amount)
 *
 * // Sign externally with your WOTS+ library
 * const signature = myWotsLib.sign(privateKey, message)
 *
 * // Build instruction
 * const ix = buildTransferWithWinternitzInstruction({
 *   programId,
 *   factoryAddress,
 *   walletAddress,
 *   recipient,
 *   owner,
 *   vaultId,
 *   pqNext: nextKey,
 *   amount,
 *   signature: { signatureData: signature },
 * })
 * ```
 */

// Types
export type {
  WinternitzPublicKey,
  WinternitzSignature,
  QuipWallet,
  QuipFactory,
  UtxoMeta,
  AccountMeta,
  Instruction,
  CpiAccountMeta,
} from './types'

// Address derivation (uses @arch-network/arch-sdk PubkeyUtil)
export {
  findProgramAddress,
  deriveFactoryAddress,
  deriveWalletAddress,
  createVaultId,
  fromHex,
  toHex,
} from './addresses'

// Message builders (for external signing)
export {
  buildTransferMessage,
  buildChangePqOwnerMessage,
  buildExecuteMessage,
  buildBtcTransferMessage,
} from './messages'

// Instruction builders
export {
  buildInitializeFactoryInstruction,
  buildDepositToWinternitzInstruction,
  buildTransferWithWinternitzInstruction,
  buildExecuteWithWinternitzInstruction,
  buildChangePqOwnerInstruction,
  buildUpdateFeesInstruction,
  buildWithdrawFeesInstruction,
  buildTransferOwnershipInstruction,
  buildBtcTransferWithWinternitzInstruction,
} from './instructions'

// Instruction param types
export type {
  InitializeFactoryParams,
  DepositToWinternitzParams,
  TransferWithWinternitzParams,
  ExecuteWithWinternitzParams,
  ChangePqOwnerParams,
  UpdateFeesParams,
  WithdrawFeesParams,
  TransferOwnershipParams,
  BtcTransferWithWinternitzParams,
} from './instructions'

// Parsers
export { parseWalletAccount, parseFactoryAccount } from './parsers'

// Errors
export {
  QuipError,
  InvalidAccountDataError,
  InvalidParamsError,
  PdaDerivationError,
} from './errors'

// Schemas (for advanced use cases)
export {
  QuipWalletSchema,
  QuipFactorySchema,
  WinternitzPublicKeySchema,
  WinternitzSignatureSchema,
  UtxoMetaSchema,
  InstructionType,
} from './schemas'
