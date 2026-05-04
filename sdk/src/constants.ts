// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { SystemInstruction } from '@arch-network/arch-sdk'

/**
 * Known quip-arch program IDs per network.
 *
 * Hex strings map to the deployed program accounts. Use `programIdFor(network)`
 * to get a 32-byte Uint8Array ready to pass into instruction builders or
 * `QuipArchClient`.
 */
export const KNOWN_PROGRAM_IDS = {
  testnet: '993e88bbb8e9c6bf39408905230a70a9986413ed84d964bf20b7b402796ebcc9',
} as const satisfies Record<string, string>

export type QuipNetwork = keyof typeof KNOWN_PROGRAM_IDS

/**
 * Resolve a known program ID for the given network as a 32-byte array.
 */
export function programIdFor(network: QuipNetwork): Uint8Array {
  return SystemInstruction.hexStringToUint8Array(KNOWN_PROGRAM_IDS[network])
}
