// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { SystemInstruction } from '@arch-network/arch-sdk'
import type { WinternitzPublicKey, CpiAccountMeta, UtxoMeta } from './types'

/**
 * Serialize a WinternitzPublicKey to bytes.
 * Format: publicSeed (32) || publicKeyHash (32)
 */
function serializeWinternitzPublicKey(key: WinternitzPublicKey): Uint8Array {
  const result = new Uint8Array(64)
  result.set(key.publicSeed, 0)
  result.set(key.publicKeyHash, 32)
  return result
}

/**
 * Build message for TransferWithWinternitz instruction.
 *
 * Format: currentKey || nextKey || recipient || amount
 *
 * @param currentKey - Current WOTS+ public key
 * @param nextKey - Next WOTS+ public key (for rotation)
 * @param recipient - Recipient address (32 bytes)
 * @param amount - Amount to transfer (lamports)
 * @returns Message bytes to sign
 */
export function buildTransferMessage(
  currentKey: WinternitzPublicKey,
  nextKey: WinternitzPublicKey,
  recipient: Uint8Array,
  amount: bigint
): Uint8Array {
  const currentKeyBytes = serializeWinternitzPublicKey(currentKey)
  const nextKeyBytes = serializeWinternitzPublicKey(nextKey)
  const amountBytes = SystemInstruction.u64ToLeBytes(amount)

  const message = new Uint8Array(64 + 64 + 32 + 8)
  let offset = 0

  message.set(currentKeyBytes, offset)
  offset += 64

  message.set(nextKeyBytes, offset)
  offset += 64

  message.set(recipient, offset)
  offset += 32

  message.set(amountBytes, offset)

  return message
}

/**
 * Build message for ChangePqOwner instruction.
 *
 * Format: currentKey || nextKey || "change_owner"
 *
 * @param currentKey - Current WOTS+ public key
 * @param nextKey - New WOTS+ public key
 * @returns Message bytes to sign
 */
export function buildChangePqOwnerMessage(
  currentKey: WinternitzPublicKey,
  nextKey: WinternitzPublicKey
): Uint8Array {
  const currentKeyBytes = serializeWinternitzPublicKey(currentKey)
  const nextKeyBytes = serializeWinternitzPublicKey(nextKey)
  const suffix = new TextEncoder().encode('change_owner')

  const message = new Uint8Array(64 + 64 + suffix.length)
  let offset = 0

  message.set(currentKeyBytes, offset)
  offset += 64

  message.set(nextKeyBytes, offset)
  offset += 64

  message.set(suffix, offset)

  return message
}

/**
 * Build message for ExecuteWithWinternitz instruction (CPI).
 *
 * Format: currentKey || nextKey || targetProgram || instructionData || accounts
 *
 * @param currentKey - Current WOTS+ public key
 * @param nextKey - Next WOTS+ public key (for rotation)
 * @param targetProgram - Target program ID (32 bytes)
 * @param instructionData - Instruction data to pass to target program
 * @param accounts - Account pubkeys and metas for CPI
 * @returns Message bytes to sign
 */
export function buildExecuteMessage(
  currentKey: WinternitzPublicKey,
  nextKey: WinternitzPublicKey,
  targetProgram: Uint8Array,
  instructionData: Uint8Array,
  accounts: { pubkey: Uint8Array; meta: CpiAccountMeta }[]
): Uint8Array {
  const currentKeyBytes = serializeWinternitzPublicKey(currentKey)
  const nextKeyBytes = serializeWinternitzPublicKey(nextKey)

  // Calculate total size
  // 64 (current) + 64 (next) + 32 (program) + instructionData.length + accounts * 34
  const accountsSize = accounts.length * (32 + 2) // pubkey + 2 flags
  const totalSize = 64 + 64 + 32 + instructionData.length + accountsSize

  const message = new Uint8Array(totalSize)
  let offset = 0

  message.set(currentKeyBytes, offset)
  offset += 64

  message.set(nextKeyBytes, offset)
  offset += 64

  message.set(targetProgram, offset)
  offset += 32

  message.set(instructionData, offset)
  offset += instructionData.length

  // Include account pubkeys and metas
  for (const account of accounts) {
    message.set(account.pubkey, offset)
    offset += 32
    message[offset++] = account.meta.isSigner ? 1 : 0
    message[offset++] = account.meta.isWritable ? 1 : 0
  }

  return message
}

/**
 * Build message for BtcTransferWithWinternitz instruction.
 *
 * Format: currentKey || nextKey || len(scriptPubkey) as u32 LE || scriptPubkey || amount || utxoTxid || utxoVout
 *
 * @param currentKey - Current WOTS+ public key
 * @param nextKey - Next WOTS+ public key (for rotation)
 * @param recipientScriptPubkey - Recipient's Bitcoin script_pubkey
 * @param amount - Amount in satoshis
 * @param sourceUtxo - Source UTXO to spend
 * @returns Message bytes to sign
 */
export function buildBtcTransferMessage(
  currentKey: WinternitzPublicKey,
  nextKey: WinternitzPublicKey,
  recipientScriptPubkey: Uint8Array,
  amount: bigint,
  sourceUtxo: UtxoMeta
): Uint8Array {
  const currentKeyBytes = serializeWinternitzPublicKey(currentKey)
  const nextKeyBytes = serializeWinternitzPublicKey(nextKey)
  const scriptLenBytes = SystemInstruction.u32ToLeBytes(recipientScriptPubkey.length)
  const amountBytes = SystemInstruction.u64ToLeBytes(amount)
  const voutBytes = SystemInstruction.u32ToLeBytes(sourceUtxo.vout)

  // 64 + 64 + 4 + scriptPubkey.length + 8 + 32 + 4
  const totalSize = 64 + 64 + 4 + recipientScriptPubkey.length + 8 + 32 + 4

  const message = new Uint8Array(totalSize)
  let offset = 0

  message.set(currentKeyBytes, offset)
  offset += 64

  message.set(nextKeyBytes, offset)
  offset += 64

  message.set(scriptLenBytes, offset)
  offset += 4

  message.set(recipientScriptPubkey, offset)
  offset += recipientScriptPubkey.length

  message.set(amountBytes, offset)
  offset += 8

  message.set(sourceUtxo.txid, offset)
  offset += 32

  message.set(voutBytes, offset)

  return message
}
