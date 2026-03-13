// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, it, expect } from 'vitest'
import {
  createVaultId,
  deriveFactoryAddress,
  deriveWalletAddress,
} from '../addresses'
import { TEST_PROGRAM_ID, TEST_OWNER, TEST_VAULT_ID } from './factories'

describe('createVaultId', () => {
  it('returns 32-byte array', () => {
    const vaultId = createVaultId(0)
    expect(vaultId).toBeInstanceOf(Uint8Array)
    expect(vaultId.length).toBe(32)
  })

  it('writes value as little-endian u64 in first 8 bytes', () => {
    // 0x0102030405060708 in little-endian is [08, 07, 06, 05, 04, 03, 02, 01]
    const value = 0x0102030405060708n
    const vaultId = createVaultId(value)

    expect(vaultId[0]).toBe(0x08)
    expect(vaultId[1]).toBe(0x07)
    expect(vaultId[2]).toBe(0x06)
    expect(vaultId[3]).toBe(0x05)
    expect(vaultId[4]).toBe(0x04)
    expect(vaultId[5]).toBe(0x03)
    expect(vaultId[6]).toBe(0x02)
    expect(vaultId[7]).toBe(0x01)
  })

  it('remaining 24 bytes are zeros', () => {
    const vaultId = createVaultId(12345)
    const trailingBytes = vaultId.slice(8)
    expect(trailingBytes.every((b) => b === 0)).toBe(true)
  })

  it('works with number input', () => {
    const vaultId = createVaultId(255)
    expect(vaultId[0]).toBe(255)
    expect(vaultId[1]).toBe(0)
  })

  it('works with bigint input', () => {
    const vaultId = createVaultId(BigInt(256))
    expect(vaultId[0]).toBe(0)
    expect(vaultId[1]).toBe(1)
  })

  it('handles large values (max u64)', () => {
    const maxU64 = 0xffffffffffffffffn
    const vaultId = createVaultId(maxU64)

    // All first 8 bytes should be 0xff
    for (let i = 0; i < 8; i++) {
      expect(vaultId[i]).toBe(0xff)
    }
    // Remaining should be zero
    for (let i = 8; i < 32; i++) {
      expect(vaultId[i]).toBe(0)
    }
  })

  it('handles zero', () => {
    const vaultId = createVaultId(0)
    expect(vaultId.every((b) => b === 0)).toBe(true)
  })
})

describe('deriveFactoryAddress', () => {
  it('returns address and bump', () => {
    const result = deriveFactoryAddress(TEST_PROGRAM_ID)
    expect(result).toHaveProperty('address')
    expect(result).toHaveProperty('bump')
  })

  it('address is 32 bytes', () => {
    const { address } = deriveFactoryAddress(TEST_PROGRAM_ID)
    expect(address).toBeInstanceOf(Uint8Array)
    expect(address.length).toBe(32)
  })

  it('bump is a number between 0 and 255', () => {
    const { bump } = deriveFactoryAddress(TEST_PROGRAM_ID)
    expect(typeof bump).toBe('number')
    expect(bump).toBeGreaterThanOrEqual(0)
    expect(bump).toBeLessThanOrEqual(255)
  })

  it('is deterministic (same input = same output)', () => {
    const result1 = deriveFactoryAddress(TEST_PROGRAM_ID)
    const result2 = deriveFactoryAddress(TEST_PROGRAM_ID)

    expect(result1.bump).toBe(result2.bump)
    expect(Array.from(result1.address)).toEqual(Array.from(result2.address))
  })

  it('different program IDs produce different addresses', () => {
    const programId1 = new Uint8Array(32).fill(0x01)
    const programId2 = new Uint8Array(32).fill(0x02)

    const result1 = deriveFactoryAddress(programId1)
    const result2 = deriveFactoryAddress(programId2)

    expect(Array.from(result1.address)).not.toEqual(Array.from(result2.address))
  })
})

describe('deriveWalletAddress', () => {
  it('returns address and bump', () => {
    const result = deriveWalletAddress(TEST_PROGRAM_ID, TEST_OWNER, TEST_VAULT_ID)
    expect(result).toHaveProperty('address')
    expect(result).toHaveProperty('bump')
  })

  it('address is 32 bytes', () => {
    const { address } = deriveWalletAddress(
      TEST_PROGRAM_ID,
      TEST_OWNER,
      TEST_VAULT_ID
    )
    expect(address).toBeInstanceOf(Uint8Array)
    expect(address.length).toBe(32)
  })

  it('bump is a number between 0 and 255', () => {
    const { bump } = deriveWalletAddress(
      TEST_PROGRAM_ID,
      TEST_OWNER,
      TEST_VAULT_ID
    )
    expect(typeof bump).toBe('number')
    expect(bump).toBeGreaterThanOrEqual(0)
    expect(bump).toBeLessThanOrEqual(255)
  })

  it('is deterministic (same input = same output)', () => {
    const result1 = deriveWalletAddress(TEST_PROGRAM_ID, TEST_OWNER, TEST_VAULT_ID)
    const result2 = deriveWalletAddress(TEST_PROGRAM_ID, TEST_OWNER, TEST_VAULT_ID)

    expect(result1.bump).toBe(result2.bump)
    expect(Array.from(result1.address)).toEqual(Array.from(result2.address))
  })

  it('different owners produce different addresses', () => {
    const owner1 = new Uint8Array(32).fill(0x01)
    const owner2 = new Uint8Array(32).fill(0x02)

    const result1 = deriveWalletAddress(TEST_PROGRAM_ID, owner1, TEST_VAULT_ID)
    const result2 = deriveWalletAddress(TEST_PROGRAM_ID, owner2, TEST_VAULT_ID)

    expect(Array.from(result1.address)).not.toEqual(Array.from(result2.address))
  })

  it('different vaultIds produce different addresses', () => {
    const vaultId1 = createVaultId(1)
    const vaultId2 = createVaultId(2)

    const result1 = deriveWalletAddress(TEST_PROGRAM_ID, TEST_OWNER, vaultId1)
    const result2 = deriveWalletAddress(TEST_PROGRAM_ID, TEST_OWNER, vaultId2)

    expect(Array.from(result1.address)).not.toEqual(Array.from(result2.address))
  })
})
