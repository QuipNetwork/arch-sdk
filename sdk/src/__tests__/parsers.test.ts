// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, it, expect } from 'vitest'
import { serialize } from 'borsh'
import { parseWalletAccount, parseFactoryAccount } from '../parsers'
import { QuipWalletSchema, QuipFactorySchema } from '../schemas'
import { InvalidAccountDataError } from '../errors'
import { getMockWinternitzPublicKey, TEST_OWNER, TEST_ADMIN } from './factories'

describe('parseWalletAccount', () => {
  const validWalletData = () => {
    const wallet = {
      version: 1,
      owner: TEST_OWNER,
      pqOwner: getMockWinternitzPublicKey(),
      createdAt: BigInt(1700000000),
      lastActivity: BigInt(1700000100),
      transactionCount: BigInt(5),
      bump: 255,
    }
    return serialize(QuipWalletSchema, wallet)
  }

  it('parses valid 122-byte wallet data', () => {
    const data = validWalletData()
    expect(data.length).toBe(122)

    const wallet = parseWalletAccount(data)

    expect(wallet.version).toBe(1)
    expect(wallet.bump).toBe(255)
  })

  it('returns all expected fields with exact values', () => {
    const data = validWalletData()
    const wallet = parseWalletAccount(data)
    const expectedPqOwner = getMockWinternitzPublicKey()

    expect(wallet.version).toBe(1)
    expect(Array.from(wallet.owner)).toEqual(Array.from(TEST_OWNER))
    expect(Array.from(wallet.pqOwner.publicSeed)).toEqual(
      Array.from(expectedPqOwner.publicSeed)
    )
    expect(Array.from(wallet.pqOwner.publicKeyHash)).toEqual(
      Array.from(expectedPqOwner.publicKeyHash)
    )
    expect(wallet.createdAt).toBe(BigInt(1700000000))
    expect(wallet.lastActivity).toBe(BigInt(1700000100))
    expect(wallet.transactionCount).toBe(BigInt(5))
    expect(wallet.bump).toBe(255)
  })

  it('throws InvalidAccountDataError for short data', () => {
    const shortData = new Uint8Array(100) // Less than 122 bytes

    expect(() => parseWalletAccount(shortData)).toThrow(InvalidAccountDataError)
    expect(() => parseWalletAccount(shortData)).toThrow(/size mismatch/)
  })

  it('throws InvalidAccountDataError for empty data', () => {
    const emptyData = new Uint8Array(0)

    expect(() => parseWalletAccount(emptyData)).toThrow(InvalidAccountDataError)
  })

  it('parses 0xff-filled data without throwing (borsh reads raw bytes)', () => {
    // Borsh will parse any bytes - 0xff filled data produces max integer values
    const filledData = new Uint8Array(122).fill(0xff)
    const wallet = parseWalletAccount(filledData)

    // Version byte 0xff = 255
    expect(wallet.version).toBe(255)
    // Bump byte 0xff = 255
    expect(wallet.bump).toBe(255)
    // All owner bytes are 0xff
    expect(wallet.owner.every((b) => b === 0xff)).toBe(true)
  })

  it('throws InvalidAccountDataError for data longer than expected', () => {
    const data = validWalletData()
    const paddedData = new Uint8Array(data.length + 10)
    paddedData.set(data)

    expect(() => parseWalletAccount(paddedData)).toThrow(InvalidAccountDataError)
    expect(() => parseWalletAccount(paddedData)).toThrow(/size mismatch/)
  })
})

describe('parseFactoryAccount', () => {
  const validFactoryData = () => {
    const factory = {
      admin: TEST_ADMIN,
      creationFee: BigInt(1000),
      transferFee: BigInt(100),
      executeFee: BigInt(50),
      totalWallets: BigInt(10),
      accumulatedFees: BigInt(5000),
      bump: 254,
    }
    return serialize(QuipFactorySchema, factory)
  }

  it('parses valid 73-byte factory data', () => {
    const data = validFactoryData()
    expect(data.length).toBe(73)

    const factory = parseFactoryAccount(data)

    expect(factory.creationFee).toBe(BigInt(1000))
    expect(factory.bump).toBe(254)
  })

  it('returns all expected fields with exact values', () => {
    const data = validFactoryData()
    const factory = parseFactoryAccount(data)

    expect(Array.from(factory.admin)).toEqual(Array.from(TEST_ADMIN))
    expect(factory.creationFee).toBe(BigInt(1000))
    expect(factory.transferFee).toBe(BigInt(100))
    expect(factory.executeFee).toBe(BigInt(50))
    expect(factory.totalWallets).toBe(BigInt(10))
    expect(factory.accumulatedFees).toBe(BigInt(5000))
    expect(factory.bump).toBe(254)
  })

  it('throws InvalidAccountDataError for short data', () => {
    const shortData = new Uint8Array(50) // Less than 73 bytes

    expect(() => parseFactoryAccount(shortData)).toThrow(InvalidAccountDataError)
    expect(() => parseFactoryAccount(shortData)).toThrow(/size mismatch/)
  })

  it('throws InvalidAccountDataError for empty data', () => {
    const emptyData = new Uint8Array(0)

    expect(() => parseFactoryAccount(emptyData)).toThrow(InvalidAccountDataError)
  })

  it('parses 0xff-filled data without throwing (borsh reads raw bytes)', () => {
    // Borsh will parse any bytes - 0xff filled data produces max integer values
    const filledData = new Uint8Array(73).fill(0xff)
    const factory = parseFactoryAccount(filledData)

    // All admin bytes are 0xff
    expect(factory.admin.every((b) => b === 0xff)).toBe(true)
    // u64 max = 0xffffffffffffffff
    expect(factory.creationFee).toBe(0xffffffffffffffffn)
    // Bump byte 0xff = 255
    expect(factory.bump).toBe(255)
  })

  it('throws InvalidAccountDataError for data longer than expected', () => {
    const data = validFactoryData()
    const paddedData = new Uint8Array(data.length + 10)
    paddedData.set(data)

    expect(() => parseFactoryAccount(paddedData)).toThrow(InvalidAccountDataError)
    expect(() => parseFactoryAccount(paddedData)).toThrow(/size mismatch/)
  })
})

describe('InvalidAccountDataError', () => {
  it('has correct error name', () => {
    const error = new InvalidAccountDataError('test')
    expect(error.name).toBe('InvalidAccountDataError')
  })

  it('includes custom message', () => {
    const error = new InvalidAccountDataError('custom message')
    expect(error.message).toBe('custom message')
  })

  it('is instance of Error', () => {
    const error = new InvalidAccountDataError('test')
    expect(error).toBeInstanceOf(Error)
  })
})
