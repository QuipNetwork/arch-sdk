// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  WinternitzPublicKey,
  WinternitzSignature,
  UtxoMeta,
  CpiAccountMeta,
} from '../types'

// =============================================================================
// Known Test Vectors (deterministic 32-byte arrays)
// =============================================================================

/** Test program ID: 0x01 repeated */
export const TEST_PROGRAM_ID = new Uint8Array(32).fill(0x01)

/** Test owner pubkey: 0x02 repeated */
export const TEST_OWNER = new Uint8Array(32).fill(0x02)

/** Test recipient pubkey: 0x03 repeated */
export const TEST_RECIPIENT = new Uint8Array(32).fill(0x03)

/** Test admin pubkey: 0x04 repeated */
export const TEST_ADMIN = new Uint8Array(32).fill(0x04)

/** Test factory address: 0x05 repeated */
export const TEST_FACTORY = new Uint8Array(32).fill(0x05)

/** Test wallet address: 0x06 repeated */
export const TEST_WALLET = new Uint8Array(32).fill(0x06)

/** Test target program: 0x07 repeated */
export const TEST_TARGET_PROGRAM = new Uint8Array(32).fill(0x07)

/** Test vault ID: 0x08 repeated */
export const TEST_VAULT_ID = new Uint8Array(32).fill(0x08)

/** System program ID (all zeros) */
export const SYSTEM_PROGRAM_ID = new Uint8Array(32)

// =============================================================================
// Mock Factories
// =============================================================================

/**
 * Create a mock WinternitzPublicKey.
 */
export function getMockWinternitzPublicKey(
  overrides?: Partial<WinternitzPublicKey>
): WinternitzPublicKey {
  return {
    publicSeed: new Uint8Array(32).fill(0xaa),
    publicKeyHash: new Uint8Array(32).fill(0xbb),
    ...overrides,
  }
}

/**
 * Create a "next" WinternitzPublicKey (different from default).
 */
export function getMockNextWinternitzPublicKey(
  overrides?: Partial<WinternitzPublicKey>
): WinternitzPublicKey {
  return {
    publicSeed: new Uint8Array(32).fill(0xcc),
    publicKeyHash: new Uint8Array(32).fill(0xdd),
    ...overrides,
  }
}

/**
 * Create a mock WinternitzSignature.
 */
export function getMockWinternitzSignature(
  length = 2144
): WinternitzSignature {
  return {
    signatureData: new Uint8Array(length).fill(0xee),
  }
}

/**
 * Create a mock UtxoMeta.
 */
export function getMockUtxoMeta(overrides?: Partial<UtxoMeta>): UtxoMeta {
  return {
    txid: new Uint8Array(32).fill(0xff),
    vout: 0,
    ...overrides,
  }
}

/**
 * Create a mock CpiAccountMeta.
 */
export function getMockCpiAccountMeta(
  overrides?: Partial<CpiAccountMeta>
): CpiAccountMeta {
  return {
    isSigner: false,
    isWritable: false,
    ...overrides,
  }
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Create a Uint8Array filled with a specific byte value.
 */
export function filledBytes(length: number, fill: number): Uint8Array {
  return new Uint8Array(length).fill(fill)
}

/**
 * Create a Uint8Array with sequential bytes (0, 1, 2, ...).
 */
export function sequentialBytes(length: number): Uint8Array {
  return new Uint8Array(Array.from({ length }, (_, i) => i % 256))
}
