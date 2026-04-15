// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { deserialize, type Schema } from 'borsh'
import type { QuipWallet, QuipFactory } from './types'
import { QuipWalletSchema, QuipFactorySchema } from './schemas'
import { InvalidAccountDataError } from './errors'

const PRIMITIVE_SIZES: Record<string, number> = {
  u8: 1,
  i8: 1,
  u16: 2,
  i16: 2,
  u32: 4,
  i32: 4,
  u64: 8,
  i64: 8,
  u128: 16,
  i128: 16,
  f32: 4,
  f64: 8,
  bool: 1,
}

/**
 * Compute the serialized size of a fixed-layout borsh schema.
 * Throws if the schema contains any variable-length node (vec, option, string, map, set).
 * Used to derive parser size constants directly from the schema definitions,
 * so account-size checks stay in sync if struct fields are added or removed.
 */
function schemaSize(schema: Schema): number {
  if (typeof schema === 'string') {
    const size = PRIMITIVE_SIZES[schema]
    if (size === undefined) {
      throw new Error(`schemaSize: unsupported primitive '${schema}'`)
    }
    return size
  }
  if ('struct' in schema) {
    let total = 0
    for (const field of Object.values(schema.struct)) {
      total += schemaSize(field as Schema)
    }
    return total
  }
  if ('array' in schema) {
    const { type, len } = schema.array
    if (len === undefined) {
      throw new Error('schemaSize: variable-length array is not fixed-size')
    }
    return schemaSize(type as Schema) * len
  }
  throw new Error('schemaSize: unsupported schema node (enum/option/vec/map)')
}

const WALLET_SIZE = schemaSize(QuipWalletSchema)
const FACTORY_SIZE = schemaSize(QuipFactorySchema)

/**
 * Parse QuipWallet account data.
 *
 * @param data - Raw account data bytes
 * @returns Parsed QuipWallet
 * @throws InvalidAccountDataError if data is malformed
 */
export function parseWalletAccount(data: Uint8Array): QuipWallet {
  if (data.length !== WALLET_SIZE) {
    throw new InvalidAccountDataError(
      `Wallet data size mismatch: expected ${WALLET_SIZE}, got ${data.length}`
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
  if (data.length !== FACTORY_SIZE) {
    throw new InvalidAccountDataError(
      `Factory data size mismatch: expected ${FACTORY_SIZE}, got ${data.length}`
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
