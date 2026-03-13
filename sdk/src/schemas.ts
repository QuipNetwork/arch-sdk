// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Borsh schemas matching the on-chain Rust structs.
 * These schemas are the source of truth for serialization format.
 */

import type { Schema } from 'borsh'

// =============================================================================
// Primitive Schemas
// =============================================================================

/** 32-byte fixed array (pubkeys, hashes) */
export const Bytes32Schema: Schema = { array: { type: 'u8', len: 32 } }

// =============================================================================
// WOTS+ Schemas
// =============================================================================

/** WinternitzPublicKey: publicSeed (32) + publicKeyHash (32) */
export const WinternitzPublicKeySchema: Schema = {
  struct: {
    publicSeed: Bytes32Schema,
    publicKeyHash: Bytes32Schema,
  },
}

/** WinternitzSignature: Vec<u8> */
export const WinternitzSignatureSchema: Schema = {
  struct: {
    signatureData: { array: { type: 'u8' } },
  },
}

// =============================================================================
// UTXO Schema
// =============================================================================

/** UtxoMeta: txid (32) + vout (u32) */
export const UtxoMetaSchema: Schema = {
  struct: {
    txid: Bytes32Schema,
    vout: 'u32',
  },
}

// =============================================================================
// Account State Schemas
// =============================================================================

/** QuipFactory account state */
export const QuipFactorySchema: Schema = {
  struct: {
    admin: Bytes32Schema,
    creationFee: 'u64',
    transferFee: 'u64',
    executeFee: 'u64',
    totalWallets: 'u64',
    accumulatedFees: 'u64',
    bump: 'u8',
  },
}

/** QuipWallet account state */
export const QuipWalletSchema: Schema = {
  struct: {
    version: 'u8',
    owner: Bytes32Schema,
    pqOwner: WinternitzPublicKeySchema,
    createdAt: 'i64',
    lastActivity: 'i64',
    transactionCount: 'u64',
    bump: 'u8',
  },
}

/** CpiAccountMeta for ExecuteWithWinternitz */
export const CpiAccountMetaSchema: Schema = {
  struct: {
    isSigner: 'bool',
    isWritable: 'bool',
  },
}

// =============================================================================
// Instruction Data Schemas (enum variants)
// =============================================================================

/** InitializeFactory instruction data */
export const InitializeFactoryDataSchema: Schema = {
  struct: {
    discriminant: 'u8',
    admin: Bytes32Schema,
    creationFee: 'u64',
    transferFee: 'u64',
    executeFee: 'u64',
    factoryUtxo: UtxoMetaSchema,
  },
}

/** DepositToWinternitz instruction data */
export const DepositToWinternitzDataSchema: Schema = {
  struct: {
    discriminant: 'u8',
    vaultId: Bytes32Schema,
    pqOwner: WinternitzPublicKeySchema,
    deposit: 'u64',
    walletUtxo: UtxoMetaSchema,
  },
}

/** TransferWithWinternitz instruction data */
export const TransferWithWinternitzDataSchema: Schema = {
  struct: {
    discriminant: 'u8',
    vaultId: Bytes32Schema,
    pqNext: WinternitzPublicKeySchema,
    amount: 'u64',
    signature: WinternitzSignatureSchema,
  },
}

/** ExecuteWithWinternitz instruction data */
export const ExecuteWithWinternitzDataSchema: Schema = {
  struct: {
    discriminant: 'u8',
    pqNext: WinternitzPublicKeySchema,
    vaultId: Bytes32Schema,
    instructionData: { array: { type: 'u8' } },
    accountMetas: { array: { type: CpiAccountMetaSchema } },
    signature: WinternitzSignatureSchema,
  },
}

/** ChangePqOwner instruction data */
export const ChangePqOwnerDataSchema: Schema = {
  struct: {
    discriminant: 'u8',
    vaultId: Bytes32Schema,
    pqNext: WinternitzPublicKeySchema,
    signature: WinternitzSignatureSchema,
  },
}

/** UpdateFees instruction data */
export const UpdateFeesDataSchema: Schema = {
  struct: {
    discriminant: 'u8',
    creationFee: 'u64',
    transferFee: 'u64',
    executeFee: 'u64',
  },
}

/** WithdrawFees instruction data */
export const WithdrawFeesDataSchema: Schema = {
  struct: {
    discriminant: 'u8',
    amount: 'u64',
  },
}

/** TransferOwnership instruction data */
export const TransferOwnershipDataSchema: Schema = {
  struct: {
    discriminant: 'u8',
    newAdmin: Bytes32Schema,
  },
}

/** BtcTransferWithWinternitz instruction data */
export const BtcTransferWithWinternitzDataSchema: Schema = {
  struct: {
    discriminant: 'u8',
    vaultId: Bytes32Schema,
    pqNext: WinternitzPublicKeySchema,
    amount: 'u64',
    recipientScriptPubkey: { array: { type: 'u8' } },
    feeTx: { array: { type: 'u8' } },
    sourceUtxo: UtxoMetaSchema,
    signature: WinternitzSignatureSchema,
  },
}

// =============================================================================
// Instruction Discriminants
// =============================================================================

export const InstructionType = {
  InitializeFactory: 0,
  DepositToWinternitz: 1,
  TransferWithWinternitz: 2,
  ExecuteWithWinternitz: 3,
  ChangePqOwner: 4,
  UpdateFees: 5,
  WithdrawFees: 6,
  TransferOwnership: 7,
  BtcTransferWithWinternitz: 8,
} as const
