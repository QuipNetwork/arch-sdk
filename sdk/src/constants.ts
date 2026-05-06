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
  testnet: '8e41ed4f9f278cd8ebafc6d873803774abd8457b7fb3eb693f23f8e0caa1889b',
} as const satisfies Record<string, string>

export type QuipNetwork = keyof typeof KNOWN_PROGRAM_IDS

/**
 * Resolve a known program ID for the given network as a 32-byte array.
 */
export function programIdFor(network: QuipNetwork): Uint8Array {
  return SystemInstruction.hexStringToUint8Array(KNOWN_PROGRAM_IDS[network])
}
