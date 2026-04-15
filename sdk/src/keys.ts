// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { WinternitzPublicKey } from './types'
import { InvalidParamsError } from './errors'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/**
 * True if two WinternitzPublicKeys are byte-for-byte equal.
 */
export function pqKeysEqual(
  a: WinternitzPublicKey,
  b: WinternitzPublicKey
): boolean {
  return (
    bytesEqual(a.publicSeed, b.publicSeed) &&
    bytesEqual(a.publicKeyHash, b.publicKeyHash)
  )
}

/**
 * Assert that a key rotation is valid (next key differs from current) and
 * that both keys have the expected 32/32 byte layout.
 *
 * WOTS+ keys are strictly one-time use — signing twice with the same key
 * leaks private key material. Reusing a key as its own "next" key is the
 * most obvious form of this mistake and this helper exists to catch it
 * before a signature is produced.
 *
 * @throws InvalidParamsError if the keys are malformed or identical.
 */
export function assertValidRotation(
  current: WinternitzPublicKey,
  next: WinternitzPublicKey
): void {
  for (const [label, key] of [
    ['current', current],
    ['next', next],
  ] as const) {
    if (key.publicSeed.length !== 32) {
      throw new InvalidParamsError(
        `${label}.publicSeed must be 32 bytes, got ${key.publicSeed.length}`
      )
    }
    if (key.publicKeyHash.length !== 32) {
      throw new InvalidParamsError(
        `${label}.publicKeyHash must be 32 bytes, got ${key.publicKeyHash.length}`
      )
    }
  }
  if (pqKeysEqual(current, next)) {
    throw new InvalidParamsError(
      'WOTS+ key rotation invalid: next key equals current key. ' +
        'Reusing a WOTS+ key leaks private material — generate a fresh next key.'
    )
  }
}
