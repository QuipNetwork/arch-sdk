// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { deserialize } from 'borsh'
import type { QuipWallet, QuipFactory } from './types'
import { QuipWalletSchema, QuipFactorySchema } from './schemas'
import { InvalidAccountDataError } from './errors'

/** Expected size of QuipWallet account data */
const WALLET_SIZE = 122

/** Expected size of QuipFactory account data */
const FACTORY_SIZE = 73

/**
 * Parse QuipWallet account data.
 *
 * @param data - Raw account data bytes
 * @returns Parsed QuipWallet
 * @throws InvalidAccountDataError if data is malformed
 */
export function parseWalletAccount(data: Uint8Array): QuipWallet {
  if (data.length < WALLET_SIZE) {
    throw new InvalidAccountDataError(
      `Wallet data too short: ${data.length} < ${WALLET_SIZE}`
    )
  }

  try {
    return deserialize(QuipWalletSchema, data) as QuipWallet
  } catch (e) {
    throw new InvalidAccountDataError(
      `Failed to parse wallet: ${e instanceof Error ? e.message : String(e)}`
    )
  }
}

/**
 * Parse QuipFactory account data.
 *
 * @param data - Raw account data bytes
 * @returns Parsed QuipFactory
 * @throws InvalidAccountDataError if data is malformed
 */
export function parseFactoryAccount(data: Uint8Array): QuipFactory {
  if (data.length < FACTORY_SIZE) {
    throw new InvalidAccountDataError(
      `Factory data too short: ${data.length} < ${FACTORY_SIZE}`
    )
  }

  try {
    return deserialize(QuipFactorySchema, data) as QuipFactory
  } catch (e) {
    throw new InvalidAccountDataError(
      `Failed to parse factory: ${e instanceof Error ? e.message : String(e)}`
    )
  }
}
