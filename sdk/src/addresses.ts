// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  PubkeyUtil,
  SystemInstruction,
  type Pubkey,
} from '@arch-network/arch-sdk'

/**
 * Derive the factory PDA address.
 * Seeds: ["factory"]
 *
 * @param programId - Program ID (32 bytes)
 * @returns Object with address and bump
 */
export function deriveFactoryAddress(
  programId: Uint8Array
): { address: Uint8Array; bump: number } {
  const [address, bump] = PubkeyUtil.findProgramAddress(
    [new TextEncoder().encode('factory')],
    programId as Pubkey
  )
  return { address, bump }
}

/**
 * Derive a wallet PDA address.
 * Seeds: ["wallet", owner, vaultId]
 *
 * @param programId - Program ID (32 bytes)
 * @param owner - Owner public key (32 bytes)
 * @param vaultId - Vault ID (32 bytes)
 * @returns Object with address and bump
 */
export function deriveWalletAddress(
  programId: Uint8Array,
  owner: Uint8Array,
  vaultId: Uint8Array
): { address: Uint8Array; bump: number } {
  const [address, bump] = PubkeyUtil.findProgramAddress(
    [new TextEncoder().encode('wallet'), owner, vaultId],
    programId as Pubkey
  )
  return { address, bump }
}

/**
 * Create a vault ID from a number.
 * Converts to 32-byte little-endian padded array.
 *
 * @param id - Vault ID as number or bigint
 * @returns 32-byte Uint8Array
 */
export function createVaultId(id: number | bigint): Uint8Array {
  const vaultId = new Uint8Array(32)
  vaultId.set(SystemInstruction.u64ToLeBytes(BigInt(id)))
  return vaultId
}

