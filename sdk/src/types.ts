// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Winternitz One-Time Signature Plus public key.
 *
 * IMPORTANT: WOTS+ keys are ONE-TIME USE. After signing a single message,
 * the key must be rotated to a new key. Reusing a key compromises security.
 */
export interface WinternitzPublicKey {
  /** Public seed (32 bytes) */
  publicSeed: Uint8Array
  /** Public key hash (32 bytes) */
  publicKeyHash: Uint8Array
}

/**
 * Winternitz signature data.
 */
export interface WinternitzSignature {
  /** Raw signature bytes */
  signatureData: Uint8Array
}

/**
 * Quip wallet account state.
 */
export interface QuipWallet {
  /** Wallet state version (for migrations) */
  version: number
  /** Classical key owner (32 bytes) */
  owner: Uint8Array
  /** Current WOTS+ public key (post-quantum owner) */
  pqOwner: WinternitzPublicKey
  /** Wallet creation timestamp (Unix seconds) */
  createdAt: bigint
  /** Last transaction timestamp (Unix seconds) */
  lastActivity: bigint
  /** Number of transactions performed */
  transactionCount: bigint
  /** PDA bump seed */
  bump: number
}

/**
 * Quip factory account state (singleton).
 */
export interface QuipFactory {
  /** Factory administrator (32 bytes) */
  admin: Uint8Array
  /** Fee for creating new wallets (in lamports) */
  creationFee: bigint
  /** Fee for transfers (in lamports) */
  transferFee: bigint
  /** Fee for executing instructions (in lamports) */
  executeFee: bigint
  /** Total wallets created */
  totalWallets: bigint
  /** Accumulated fees ready for withdrawal */
  accumulatedFees: bigint
  /** PDA bump seed */
  bump: number
}

/**
 * UTXO reference for Bitcoin transactions.
 */
export interface UtxoMeta {
  /** Transaction ID (32 bytes, reversed) */
  txid: Uint8Array
  /** Output index */
  vout: number
}

/**
 * Account metadata for instructions.
 */
export interface AccountMeta {
  /** Account public key (32 bytes) */
  pubkey: Uint8Array
  /** Whether this account is a signer */
  isSigner: boolean
  /** Whether this account is writable */
  isWritable: boolean
}

/**
 * A complete instruction ready for transaction building.
 */
export interface Instruction {
  /** Program ID (32 bytes) */
  programId: Uint8Array
  /** Account metas */
  accounts: AccountMeta[]
  /** Serialized instruction data */
  data: Uint8Array
}

/**
 * CPI account metadata (for ExecuteWithWinternitz).
 */
export interface CpiAccountMeta {
  /** Whether this account is a signer in the CPI */
  isSigner: boolean
  /** Whether this account is writable in the CPI */
  isWritable: boolean
}
