// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { serialize } from 'borsh'
import { PubkeyUtil } from '@arch-network/arch-sdk'
import type {
  Instruction,
  AccountMeta,
  WinternitzPublicKey,
  WinternitzSignature,
  UtxoMeta,
  CpiAccountMeta,
} from './types'
import {
  InstructionType,
  InitializeFactoryDataSchema,
  DepositToWinternitzDataSchema,
  TransferWithWinternitzDataSchema,
  ExecuteWithWinternitzDataSchema,
  ChangePqOwnerDataSchema,
  UpdateFeesDataSchema,
  WithdrawFeesDataSchema,
  TransferOwnershipDataSchema,
  BtcTransferWithWinternitzDataSchema,
} from './schemas'

const SYSTEM_PROGRAM_ID: Uint8Array = PubkeyUtil.systemProgram()

// =============================================================================
// InitializeFactory
// =============================================================================

export interface InitializeFactoryParams {
  programId: Uint8Array
  factoryAddress: Uint8Array
  payer: Uint8Array
  admin: Uint8Array
  creationFee: bigint
  transferFee: bigint
  executeFee: bigint
  factoryUtxo: UtxoMeta
}

/**
 * Build InitializeFactory instruction.
 *
 * Accounts:
 * 0. [writable] Factory account (to be created)
 * 1. [signer, writable] Payer
 * 2. [] System program
 */
export function buildInitializeFactoryInstruction(
  params: InitializeFactoryParams
): Instruction {
  const data = serialize(InitializeFactoryDataSchema, {
    discriminant: InstructionType.InitializeFactory,
    admin: params.admin,
    creationFee: params.creationFee,
    transferFee: params.transferFee,
    executeFee: params.executeFee,
    factoryUtxo: params.factoryUtxo,
  })

  const accounts: AccountMeta[] = [
    { pubkey: params.factoryAddress, isSigner: false, isWritable: true },
    { pubkey: params.payer, isSigner: true, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ]

  return { programId: params.programId, accounts, data }
}

// =============================================================================
// DepositToWinternitz
// =============================================================================

export interface DepositToWinternitzParams {
  programId: Uint8Array
  factoryAddress: Uint8Array
  walletAddress: Uint8Array
  owner: Uint8Array
  vaultId: Uint8Array
  pqOwner: WinternitzPublicKey
  deposit: bigint
  walletUtxo: UtxoMeta
}

/**
 * Build DepositToWinternitz instruction (create wallet).
 *
 * Accounts:
 * 0. [writable] Factory
 * 1. [writable] Wallet account (to be created)
 * 2. [signer, writable] Owner (pays for creation and deposit)
 * 3. [] System program
 */
export function buildDepositToWinternitzInstruction(
  params: DepositToWinternitzParams
): Instruction {
  const data = serialize(DepositToWinternitzDataSchema, {
    discriminant: InstructionType.DepositToWinternitz,
    vaultId: params.vaultId,
    pqOwner: params.pqOwner,
    deposit: params.deposit,
    walletUtxo: params.walletUtxo,
  })

  const accounts: AccountMeta[] = [
    { pubkey: params.factoryAddress, isSigner: false, isWritable: true },
    { pubkey: params.walletAddress, isSigner: false, isWritable: true },
    { pubkey: params.owner, isSigner: true, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ]

  return { programId: params.programId, accounts, data }
}

// =============================================================================
// TransferWithWinternitz
// =============================================================================

export interface TransferWithWinternitzParams {
  programId: Uint8Array
  factoryAddress: Uint8Array
  walletAddress: Uint8Array
  recipient: Uint8Array
  owner: Uint8Array
  vaultId: Uint8Array
  pqNext: WinternitzPublicKey
  amount: bigint
  signature: WinternitzSignature
}

/**
 * Build TransferWithWinternitz instruction.
 *
 * Accounts:
 * 0. [writable] Factory
 * 1. [writable] Wallet
 * 2. [writable] Recipient
 * 3. [signer, writable] Owner (must be wallet owner)
 */
export function buildTransferWithWinternitzInstruction(
  params: TransferWithWinternitzParams
): Instruction {
  const data = serialize(TransferWithWinternitzDataSchema, {
    discriminant: InstructionType.TransferWithWinternitz,
    vaultId: params.vaultId,
    pqNext: params.pqNext,
    amount: params.amount,
    signature: params.signature,
  })

  const accounts: AccountMeta[] = [
    { pubkey: params.factoryAddress, isSigner: false, isWritable: true },
    { pubkey: params.walletAddress, isSigner: false, isWritable: true },
    { pubkey: params.recipient, isSigner: false, isWritable: true },
    { pubkey: params.owner, isSigner: true, isWritable: true },
  ]

  return { programId: params.programId, accounts, data }
}

// =============================================================================
// ExecuteWithWinternitz
// =============================================================================

/**
 * Account passed through to the inner CPI call.
 *
 * The `isSigner` / `isWritable` flags are used both for the CPI's `AccountMeta`
 * AND for the outer transaction's account list, because ArchVM only loads an
 * account as writable (or as a signer) at CPI time if the outer instruction
 * already marked it that way.
 */
export interface ExecuteCpiAccount {
  pubkey: Uint8Array
  isSigner: boolean
  isWritable: boolean
}

export interface ExecuteWithWinternitzParams {
  programId: Uint8Array
  factoryAddress: Uint8Array
  walletAddress: Uint8Array
  targetProgram: Uint8Array
  owner: Uint8Array
  vaultId: Uint8Array
  pqNext: WinternitzPublicKey
  instructionData: Uint8Array
  cpiAccounts: ExecuteCpiAccount[]
  signature: WinternitzSignature
}

/**
 * Build ExecuteWithWinternitz instruction (arbitrary CPI).
 *
 * Accounts:
 * 0. [writable] Factory
 * 1. [writable] Wallet
 * 2. [] Target program
 * 3. [signer, writable] Owner (must be wallet owner)
 * 4. [] System program
 * 5+ [per cpiAccounts flags] Remaining accounts for CPI
 */
export function buildExecuteWithWinternitzInstruction(
  params: ExecuteWithWinternitzParams
): Instruction {
  const cpiMetas: CpiAccountMeta[] = params.cpiAccounts.map((a) => ({
    isSigner: a.isSigner,
    isWritable: a.isWritable,
  }))

  const data = serialize(ExecuteWithWinternitzDataSchema, {
    discriminant: InstructionType.ExecuteWithWinternitz,
    pqNext: params.pqNext,
    vaultId: params.vaultId,
    instructionData: Array.from(params.instructionData),
    accountMetas: cpiMetas,
    signature: params.signature,
  })

  const accounts: AccountMeta[] = [
    { pubkey: params.factoryAddress, isSigner: false, isWritable: true },
    { pubkey: params.walletAddress, isSigner: false, isWritable: true },
    { pubkey: params.targetProgram, isSigner: false, isWritable: false },
    { pubkey: params.owner, isSigner: true, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ...params.cpiAccounts.map((a) => ({
      pubkey: a.pubkey,
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
  ]

  return { programId: params.programId, accounts, data }
}

// =============================================================================
// ChangePqOwner
// =============================================================================

export interface ChangePqOwnerParams {
  programId: Uint8Array
  walletAddress: Uint8Array
  owner: Uint8Array
  vaultId: Uint8Array
  pqNext: WinternitzPublicKey
  signature: WinternitzSignature
}

/**
 * Build ChangePqOwner instruction (key rotation).
 *
 * Accounts:
 * 0. [writable] Wallet
 * 1. [signer, writable] Owner (must be wallet owner)
 */
export function buildChangePqOwnerInstruction(
  params: ChangePqOwnerParams
): Instruction {
  const data = serialize(ChangePqOwnerDataSchema, {
    discriminant: InstructionType.ChangePqOwner,
    vaultId: params.vaultId,
    pqNext: params.pqNext,
    signature: params.signature,
  })

  const accounts: AccountMeta[] = [
    { pubkey: params.walletAddress, isSigner: false, isWritable: true },
    { pubkey: params.owner, isSigner: true, isWritable: true },
  ]

  return { programId: params.programId, accounts, data }
}

// =============================================================================
// UpdateFees (admin only)
// =============================================================================

export interface UpdateFeesParams {
  programId: Uint8Array
  factoryAddress: Uint8Array
  admin: Uint8Array
  creationFee: bigint
  transferFee: bigint
  executeFee: bigint
}

/**
 * Build UpdateFees instruction (admin only).
 *
 * Accounts:
 * 0. [writable] Factory
 * 1. [signer] Admin
 */
export function buildUpdateFeesInstruction(
  params: UpdateFeesParams
): Instruction {
  const data = serialize(UpdateFeesDataSchema, {
    discriminant: InstructionType.UpdateFees,
    creationFee: params.creationFee,
    transferFee: params.transferFee,
    executeFee: params.executeFee,
  })

  const accounts: AccountMeta[] = [
    { pubkey: params.factoryAddress, isSigner: false, isWritable: true },
    { pubkey: params.admin, isSigner: true, isWritable: false },
  ]

  return { programId: params.programId, accounts, data }
}

// =============================================================================
// WithdrawFees (admin only)
// =============================================================================

export interface WithdrawFeesParams {
  programId: Uint8Array
  factoryAddress: Uint8Array
  admin: Uint8Array
  recipient: Uint8Array
  amount: bigint
}

/**
 * Build WithdrawFees instruction (admin only).
 *
 * Accounts:
 * 0. [writable] Factory
 * 1. [signer] Admin
 * 2. [writable] Recipient
 */
export function buildWithdrawFeesInstruction(
  params: WithdrawFeesParams
): Instruction {
  const data = serialize(WithdrawFeesDataSchema, {
    discriminant: InstructionType.WithdrawFees,
    amount: params.amount,
  })

  const accounts: AccountMeta[] = [
    { pubkey: params.factoryAddress, isSigner: false, isWritable: true },
    { pubkey: params.admin, isSigner: true, isWritable: false },
    { pubkey: params.recipient, isSigner: false, isWritable: true },
  ]

  return { programId: params.programId, accounts, data }
}

// =============================================================================
// TransferOwnership (admin only)
// =============================================================================

export interface TransferOwnershipParams {
  programId: Uint8Array
  factoryAddress: Uint8Array
  currentAdmin: Uint8Array
  newAdmin: Uint8Array
}

/**
 * Build TransferOwnership instruction (admin only).
 *
 * Accounts:
 * 0. [writable] Factory
 * 1. [signer] Current admin
 */
export function buildTransferOwnershipInstruction(
  params: TransferOwnershipParams
): Instruction {
  const data = serialize(TransferOwnershipDataSchema, {
    discriminant: InstructionType.TransferOwnership,
    newAdmin: params.newAdmin,
  })

  const accounts: AccountMeta[] = [
    { pubkey: params.factoryAddress, isSigner: false, isWritable: true },
    { pubkey: params.currentAdmin, isSigner: true, isWritable: false },
  ]

  return { programId: params.programId, accounts, data }
}

// =============================================================================
// BtcTransferWithWinternitz
// =============================================================================

export interface BtcTransferWithWinternitzParams {
  programId: Uint8Array
  factoryAddress: Uint8Array
  walletAddress: Uint8Array
  payer: Uint8Array
  vaultId: Uint8Array
  pqNext: WinternitzPublicKey
  amount: bigint
  recipientScriptPubkey: Uint8Array
  feeTx: Uint8Array
  sourceUtxo: UtxoMeta
  signature: WinternitzSignature
}

/**
 * Build BtcTransferWithWinternitz instruction.
 *
 * Accounts:
 * 0. [writable] Factory
 * 1. [writable] Wallet
 * 2. [signer, writable] Payer (must be wallet owner)
 * 3. [] System program
 */
export function buildBtcTransferWithWinternitzInstruction(
  params: BtcTransferWithWinternitzParams
): Instruction {
  const data = serialize(BtcTransferWithWinternitzDataSchema, {
    discriminant: InstructionType.BtcTransferWithWinternitz,
    vaultId: params.vaultId,
    pqNext: params.pqNext,
    amount: params.amount,
    recipientScriptPubkey: Array.from(params.recipientScriptPubkey),
    feeTx: Array.from(params.feeTx),
    sourceUtxo: params.sourceUtxo,
    signature: params.signature,
  })

  const accounts: AccountMeta[] = [
    { pubkey: params.factoryAddress, isSigner: false, isWritable: true },
    { pubkey: params.walletAddress, isSigner: false, isWritable: true },
    { pubkey: params.payer, isSigner: true, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ]

  return { programId: params.programId, accounts, data }
}
