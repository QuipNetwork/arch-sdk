// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, it, expect, vi } from 'vitest'
import { serialize } from 'borsh'
import type { Provider, AccountInfoResult } from '@arch-network/arch-sdk'

import { QuipArchClient } from '../client'
import { deriveFactoryAddress, deriveWalletAddress } from '../addresses'
import { QuipFactorySchema, QuipWalletSchema } from '../schemas'
import {
  TEST_PROGRAM_ID,
  TEST_OWNER,
  TEST_RECIPIENT,
  TEST_ADMIN,
  TEST_VAULT_ID,
  getMockWinternitzPublicKey,
  getMockNextWinternitzPublicKey,
  getMockWinternitzSignature,
  getMockUtxoMeta,
} from './factories'

// A deterministic 64-char hex blockhash for tests.
const FAKE_BLOCKHASH =
  '0000000000000000000000000000000000000000000000000000000000000001'

function makeSigner(pubkey: Uint8Array) {
  const sign = vi.fn((messageHashUtf8: string) => {
    // Return a dummy 64-byte signature so assertions can verify the signer
    // was invoked. Content is a deterministic hash of the input string.
    const bytes = new TextEncoder().encode(messageHashUtf8)
    const sig = new Uint8Array(64)
    sig.set(bytes.slice(0, Math.min(32, bytes.length)), 0)
    return sig
  })
  return { pubkey, sign }
}

function makeProvider(overrides: Partial<Provider> = {}): Provider {
  return {
    sendTransaction: vi.fn(async () => 'mock-txid'),
    sendTransactions: vi.fn(async () => ['mock-txid']),
    readAccountInfo: vi.fn(async () => {
      throw new Error('readAccountInfo not mocked')
    }),
    getAccountAddress: vi.fn(async () => 'bc1qmock'),
    getBestBlockHash: vi.fn(async () => FAKE_BLOCKHASH),
    getBestFinalizedBlockHash: vi.fn(async () => FAKE_BLOCKHASH),
    getBlock: vi.fn(async () => undefined),
    getFullBlockByHash: vi.fn(async () => undefined),
    getFullBlockByHeight: vi.fn(async () => undefined),
    getBlockCount: vi.fn(async () => 0),
    getBlockHash: vi.fn(async () => FAKE_BLOCKHASH),
    getProgramAccounts: vi.fn(async () => []),
    getProcessedTransaction: vi.fn(async () => undefined),
    requestAirdrop: vi.fn(async () => undefined),
    createAccountWithFaucet: vi.fn(async () => ({
      version: 0,
      signatures: [],
      message: {} as any,
    })),
    getBlockByHeight: vi.fn(async () => undefined),
    getTransactionsByBlock: vi.fn(async () => []),
    getTransactionsByIds: vi.fn(async () => []),
    recentTransactions: vi.fn(async () => []),
    getMultipleAccounts: vi.fn(async () => []),
    getNetworkPubkey: vi.fn(async () => 'mock-network-pubkey'),
    checkPreAnchorConflict: vi.fn(async () => false),
    ...overrides,
  } as Provider
}

describe('QuipArchClient construction', () => {
  it('derives the factory address from the program ID', () => {
    const rpc = makeProvider()
    const client = new QuipArchClient({ rpc, programId: TEST_PROGRAM_ID })
    const expected = deriveFactoryAddress(TEST_PROGRAM_ID).address
    expect(Array.from(client.factoryAddress)).toEqual(Array.from(expected))
  })

  it('walletAddress() matches deriveWalletAddress()', () => {
    const client = new QuipArchClient({
      rpc: makeProvider(),
      programId: TEST_PROGRAM_ID,
    })
    const expected = deriveWalletAddress(
      TEST_PROGRAM_ID,
      TEST_OWNER,
      TEST_VAULT_ID
    ).address
    const got = client.walletAddress(TEST_OWNER, TEST_VAULT_ID)
    expect(Array.from(got)).toEqual(Array.from(expected))
  })
})

describe('QuipArchClient.getFactory', () => {
  it('returns null when the factory account is missing', async () => {
    const rpc = makeProvider({
      readAccountInfo: vi.fn(async () => {
        throw new Error('not found')
      }),
    })
    const client = new QuipArchClient({ rpc, programId: TEST_PROGRAM_ID })
    expect(await client.getFactory()).toBeNull()
  })

  it('parses factory account data via the on-chain schema', async () => {
    const factoryState = {
      admin: TEST_ADMIN,
      creationFee: 1000n,
      transferFee: 100n,
      executeFee: 50n,
      totalWallets: 7n,
      accumulatedFees: 5000n,
      bump: 254,
    }
    const data = serialize(QuipFactorySchema, factoryState)
    const rpc = makeProvider({
      readAccountInfo: vi.fn(async (): Promise<AccountInfoResult> => ({
        lamports: 1,
        owner: TEST_PROGRAM_ID,
        data,
        utxo: '',
        is_executable: false,
      })),
    })
    const client = new QuipArchClient({ rpc, programId: TEST_PROGRAM_ID })
    const parsed = await client.getFactory()
    expect(parsed).not.toBeNull()
    expect(parsed!.creationFee).toBe(1000n)
    expect(parsed!.totalWallets).toBe(7n)
    expect(parsed!.bump).toBe(254)
  })
})

describe('QuipArchClient.getWallet', () => {
  it('returns null when the wallet account is missing', async () => {
    const rpc = makeProvider({
      readAccountInfo: vi.fn(async () => {
        throw new Error('not found')
      }),
    })
    const client = new QuipArchClient({ rpc, programId: TEST_PROGRAM_ID })
    const got = await client.getWallet(TEST_OWNER, TEST_VAULT_ID)
    expect(got).toBeNull()
  })

  it('parses wallet account data', async () => {
    const walletState = {
      version: 1,
      owner: TEST_OWNER,
      pqOwner: getMockWinternitzPublicKey(),
      createdAt: 1700000000n,
      lastActivity: 1700000001n,
      transactionCount: 3n,
      bump: 253,
    }
    const data = serialize(QuipWalletSchema, walletState)
    const rpc = makeProvider({
      readAccountInfo: vi.fn(async (): Promise<AccountInfoResult> => ({
        lamports: 1,
        owner: TEST_PROGRAM_ID,
        data,
        utxo: '',
        is_executable: false,
      })),
    })
    const client = new QuipArchClient({ rpc, programId: TEST_PROGRAM_ID })
    const parsed = await client.getWallet(TEST_OWNER, TEST_VAULT_ID)
    expect(parsed).not.toBeNull()
    expect(parsed!.transactionCount).toBe(3n)
    expect(parsed!.version).toBe(1)
  })
})

describe('QuipArchClient.buildTransaction', () => {
  it('fetches blockhash, signs with the payer, and returns a RuntimeTransaction', async () => {
    const rpc = makeProvider()
    const client = new QuipArchClient({ rpc, programId: TEST_PROGRAM_ID })
    const signer = makeSigner(TEST_OWNER)

    const tx = await client.buildTransaction(
      {
        programId: TEST_PROGRAM_ID,
        accounts: [
          { pubkey: TEST_OWNER, isSigner: true, isWritable: true },
        ],
        data: new Uint8Array([1, 2, 3]),
      },
      [signer]
    )

    expect(rpc.getBestBlockHash).toHaveBeenCalledOnce()
    expect(signer.sign).toHaveBeenCalledOnce()
    expect(tx.signatures.length).toBe(1)
    expect(tx.signatures[0].length).toBe(64)
    expect(tx.version).toBe(0)
    expect(tx.message).toBeDefined()
  })

  it('throws if called with no signers', async () => {
    const client = new QuipArchClient({
      rpc: makeProvider(),
      programId: TEST_PROGRAM_ID,
    })
    await expect(
      client.buildTransaction(
        {
          programId: TEST_PROGRAM_ID,
          accounts: [],
          data: new Uint8Array(),
        },
        []
      )
    ).rejects.toThrow(/at least one signer/)
  })
})

describe('QuipArchClient.transfer', () => {
  it('builds a Transfer instruction and submits it via the RPC', async () => {
    const rpc = makeProvider()
    const client = new QuipArchClient({ rpc, programId: TEST_PROGRAM_ID })
    const owner = makeSigner(TEST_OWNER)

    const txid = await client.transfer({
      owner,
      vaultId: TEST_VAULT_ID,
      recipient: TEST_RECIPIENT,
      amount: 500n,
      pqNext: getMockNextWinternitzPublicKey(),
      signature: getMockWinternitzSignature(),
    })

    expect(txid).toBe('mock-txid')
    expect(owner.sign).toHaveBeenCalledOnce()
    expect(rpc.sendTransaction).toHaveBeenCalledOnce()

    const sent = (rpc.sendTransaction as any).mock.calls[0][0]
    expect(sent.version).toBe(0)
    expect(sent.signatures.length).toBe(1)
  })
})

describe('QuipArchClient.createWallet', () => {
  it('returns the derived wallet address alongside the txid', async () => {
    const rpc = makeProvider()
    const client = new QuipArchClient({ rpc, programId: TEST_PROGRAM_ID })
    const owner = makeSigner(TEST_OWNER)

    const { signature, walletAddress } = await client.createWallet({
      owner,
      vaultId: TEST_VAULT_ID,
      pqOwner: getMockWinternitzPublicKey(),
      deposit: 1_000_000n,
      walletUtxo: getMockUtxoMeta(),
    })

    const expected = deriveWalletAddress(
      TEST_PROGRAM_ID,
      TEST_OWNER,
      TEST_VAULT_ID
    ).address
    expect(signature).toBe('mock-txid')
    expect(Array.from(walletAddress)).toEqual(Array.from(expected))
  })
})
