// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, it, expect } from 'vitest'
import {
  buildTransferMessage,
  buildChangePqOwnerMessage,
  buildExecuteMessage,
  buildBtcTransferMessage,
} from '../messages'
import {
  getMockWinternitzPublicKey,
  getMockNextWinternitzPublicKey,
  getMockUtxoMeta,
  getMockCpiAccountMeta,
  TEST_RECIPIENT,
  TEST_TARGET_PROGRAM,
} from './factories'

describe('buildTransferMessage', () => {
  const currentKey = getMockWinternitzPublicKey()
  const nextKey = getMockNextWinternitzPublicKey()
  const recipient = TEST_RECIPIENT
  const amount = 1000000n

  it('returns correct total length (168 bytes)', () => {
    const message = buildTransferMessage(currentKey, nextKey, recipient, amount)
    // 64 (currentKey) + 64 (nextKey) + 32 (recipient) + 8 (amount) = 168
    expect(message.length).toBe(168)
  })

  it('currentKey at offset 0-63', () => {
    const message = buildTransferMessage(currentKey, nextKey, recipient, amount)

    // publicSeed at 0-31
    const publicSeed = message.slice(0, 32)
    expect(Array.from(publicSeed)).toEqual(Array.from(currentKey.publicSeed))

    // publicKeyHash at 32-63
    const publicKeyHash = message.slice(32, 64)
    expect(Array.from(publicKeyHash)).toEqual(
      Array.from(currentKey.publicKeyHash)
    )
  })

  it('nextKey at offset 64-127', () => {
    const message = buildTransferMessage(currentKey, nextKey, recipient, amount)

    // publicSeed at 64-95
    const publicSeed = message.slice(64, 96)
    expect(Array.from(publicSeed)).toEqual(Array.from(nextKey.publicSeed))

    // publicKeyHash at 96-127
    const publicKeyHash = message.slice(96, 128)
    expect(Array.from(publicKeyHash)).toEqual(Array.from(nextKey.publicKeyHash))
  })

  it('recipient at offset 128-159', () => {
    const message = buildTransferMessage(currentKey, nextKey, recipient, amount)
    const recipientBytes = message.slice(128, 160)
    expect(Array.from(recipientBytes)).toEqual(Array.from(recipient))
  })

  it('amount as u64 LE at offset 160-167', () => {
    const message = buildTransferMessage(currentKey, nextKey, recipient, amount)
    const amountBytes = message.slice(160, 168)

    // 1000000 = 0x0F4240 in little-endian
    expect(amountBytes[0]).toBe(0x40) // least significant byte
    expect(amountBytes[1]).toBe(0x42)
    expect(amountBytes[2]).toBe(0x0f)
    expect(amountBytes[3]).toBe(0x00)
    expect(amountBytes[4]).toBe(0x00)
    expect(amountBytes[5]).toBe(0x00)
    expect(amountBytes[6]).toBe(0x00)
    expect(amountBytes[7]).toBe(0x00)
  })

  it('handles max u64 amount', () => {
    const maxAmount = 0xffffffffffffffffn
    const message = buildTransferMessage(currentKey, nextKey, recipient, maxAmount)
    const amountBytes = message.slice(160, 168)

    // All bytes should be 0xff
    for (let i = 0; i < 8; i++) {
      expect(amountBytes[i]).toBe(0xff)
    }
  })
})

describe('buildChangePqOwnerMessage', () => {
  const currentKey = getMockWinternitzPublicKey()
  const nextKey = getMockNextWinternitzPublicKey()

  it('returns correct total length (140 bytes)', () => {
    const message = buildChangePqOwnerMessage(currentKey, nextKey)
    // 64 (currentKey) + 64 (nextKey) + 12 ("change_owner") = 140
    expect(message.length).toBe(140)
  })

  it('currentKey at offset 0-63', () => {
    const message = buildChangePqOwnerMessage(currentKey, nextKey)

    const publicSeed = message.slice(0, 32)
    expect(Array.from(publicSeed)).toEqual(Array.from(currentKey.publicSeed))

    const publicKeyHash = message.slice(32, 64)
    expect(Array.from(publicKeyHash)).toEqual(
      Array.from(currentKey.publicKeyHash)
    )
  })

  it('nextKey at offset 64-127', () => {
    const message = buildChangePqOwnerMessage(currentKey, nextKey)

    const publicSeed = message.slice(64, 96)
    expect(Array.from(publicSeed)).toEqual(Array.from(nextKey.publicSeed))

    const publicKeyHash = message.slice(96, 128)
    expect(Array.from(publicKeyHash)).toEqual(Array.from(nextKey.publicKeyHash))
  })

  it('ends with "change_owner" ASCII bytes', () => {
    const message = buildChangePqOwnerMessage(currentKey, nextKey)
    const suffix = message.slice(128)
    const expected = new TextEncoder().encode('change_owner')

    expect(suffix.length).toBe(12)
    expect(Array.from(suffix)).toEqual(Array.from(expected))
  })
})

describe('buildExecuteMessage', () => {
  const currentKey = getMockWinternitzPublicKey()
  const nextKey = getMockNextWinternitzPublicKey()
  const targetProgram = TEST_TARGET_PROGRAM
  const instructionData = new Uint8Array([1, 2, 3, 4])

  it('variable length based on accounts', () => {
    const accounts0 = buildExecuteMessage(
      currentKey,
      nextKey,
      targetProgram,
      instructionData,
      []
    )
    // 64 + 64 + 32 + 4 = 164
    expect(accounts0.length).toBe(164)

    const accounts1 = buildExecuteMessage(
      currentKey,
      nextKey,
      targetProgram,
      instructionData,
      [{ pubkey: TEST_RECIPIENT, meta: getMockCpiAccountMeta() }]
    )
    // 164 + 34 = 198
    expect(accounts1.length).toBe(198)

    const accounts2 = buildExecuteMessage(
      currentKey,
      nextKey,
      targetProgram,
      instructionData,
      [
        { pubkey: TEST_RECIPIENT, meta: getMockCpiAccountMeta() },
        {
          pubkey: new Uint8Array(32).fill(0x10),
          meta: getMockCpiAccountMeta(),
        },
      ]
    )
    // 164 + 68 = 232
    expect(accounts2.length).toBe(232)
  })

  it('each account is 34 bytes (32 pubkey + 2 flags)', () => {
    const account1 = TEST_RECIPIENT
    const accounts = [
      { pubkey: account1, meta: getMockCpiAccountMeta({ isSigner: true, isWritable: false }) },
    ]

    const message = buildExecuteMessage(
      currentKey,
      nextKey,
      targetProgram,
      instructionData,
      accounts
    )

    // Account starts at offset 164
    const accountPubkey = message.slice(164, 196)
    expect(Array.from(accountPubkey)).toEqual(Array.from(account1))

    // Flags at 196-197
    expect(message[196]).toBe(1) // isSigner = true
    expect(message[197]).toBe(0) // isWritable = false
  })

  it('account flags are 0/1 for isSigner/isWritable', () => {
    const accounts = [
      {
        pubkey: TEST_RECIPIENT,
        meta: getMockCpiAccountMeta({ isSigner: false, isWritable: false }),
      },
      {
        pubkey: new Uint8Array(32).fill(0x10),
        meta: getMockCpiAccountMeta({ isSigner: true, isWritable: true }),
      },
    ]

    const message = buildExecuteMessage(
      currentKey,
      nextKey,
      targetProgram,
      instructionData,
      accounts
    )

    // First account flags at 196-197
    expect(message[196]).toBe(0) // isSigner = false
    expect(message[197]).toBe(0) // isWritable = false

    // Second account flags at 230-231
    expect(message[230]).toBe(1) // isSigner = true
    expect(message[231]).toBe(1) // isWritable = true
  })

  it('instruction data is included after target program', () => {
    const message = buildExecuteMessage(
      currentKey,
      nextKey,
      targetProgram,
      instructionData,
      []
    )

    // instruction data at offset 160 (after 64+64+32 for keys and program)
    const data = message.slice(160, 164)
    expect(Array.from(data)).toEqual([1, 2, 3, 4])
  })
})

describe('buildBtcTransferMessage', () => {
  const currentKey = getMockWinternitzPublicKey()
  const nextKey = getMockNextWinternitzPublicKey()
  const scriptPubkey = new Uint8Array([0x00, 0x14, ...new Array(20).fill(0xab)])
  const amount = 50000n
  const sourceUtxo = getMockUtxoMeta({ vout: 1 })

  it('script length as u32 LE before script bytes', () => {
    const message = buildBtcTransferMessage(
      currentKey,
      nextKey,
      scriptPubkey,
      amount,
      sourceUtxo
    )

    // Script length at offset 128 (after 64+64)
    const lenBytes = message.slice(128, 132)
    // scriptPubkey.length = 22 = 0x16
    expect(lenBytes[0]).toBe(22)
    expect(lenBytes[1]).toBe(0)
    expect(lenBytes[2]).toBe(0)
    expect(lenBytes[3]).toBe(0)
  })

  it('scriptPubkey follows length', () => {
    const message = buildBtcTransferMessage(
      currentKey,
      nextKey,
      scriptPubkey,
      amount,
      sourceUtxo
    )

    // Script at offset 132
    const script = message.slice(132, 132 + scriptPubkey.length)
    expect(Array.from(script)).toEqual(Array.from(scriptPubkey))
  })

  it('amount after script as u64 LE', () => {
    const message = buildBtcTransferMessage(
      currentKey,
      nextKey,
      scriptPubkey,
      amount,
      sourceUtxo
    )

    // Amount at offset 132 + 22 = 154
    const amountOffset = 132 + scriptPubkey.length
    const amountBytes = message.slice(amountOffset, amountOffset + 8)

    // 50000 = 0xC350 in little-endian
    expect(amountBytes[0]).toBe(0x50)
    expect(amountBytes[1]).toBe(0xc3)
    expect(amountBytes[2]).toBe(0x00)
  })

  it('UTXO txid (32) at end minus 4', () => {
    const message = buildBtcTransferMessage(
      currentKey,
      nextKey,
      scriptPubkey,
      amount,
      sourceUtxo
    )

    // txid at offset 162 (132 + 22 + 8)
    const txidOffset = 132 + scriptPubkey.length + 8
    const txid = message.slice(txidOffset, txidOffset + 32)
    expect(Array.from(txid)).toEqual(Array.from(sourceUtxo.txid))
  })

  it('UTXO vout (4) at end', () => {
    const message = buildBtcTransferMessage(
      currentKey,
      nextKey,
      scriptPubkey,
      amount,
      sourceUtxo
    )

    // vout at end (last 4 bytes)
    const voutBytes = message.slice(-4)
    // vout = 1 in little-endian
    expect(voutBytes[0]).toBe(1)
    expect(voutBytes[1]).toBe(0)
    expect(voutBytes[2]).toBe(0)
    expect(voutBytes[3]).toBe(0)
  })

  it('total length matches expected', () => {
    const message = buildBtcTransferMessage(
      currentKey,
      nextKey,
      scriptPubkey,
      amount,
      sourceUtxo
    )

    // 64 + 64 + 4 + 22 + 8 + 32 + 4 = 198
    expect(message.length).toBe(64 + 64 + 4 + scriptPubkey.length + 8 + 32 + 4)
  })
})
