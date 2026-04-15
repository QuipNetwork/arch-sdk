// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, it, expect } from 'vitest'
import {
  buildInitializeFactoryInstruction,
  buildDepositToWinternitzInstruction,
  buildTransferWithWinternitzInstruction,
  buildExecuteWithWinternitzInstruction,
  buildChangePqOwnerInstruction,
  buildUpdateFeesInstruction,
  buildWithdrawFeesInstruction,
  buildTransferOwnershipInstruction,
  buildBtcTransferWithWinternitzInstruction,
} from '../instructions'
import { InstructionType } from '../schemas'
import {
  TEST_PROGRAM_ID,
  TEST_OWNER,
  TEST_RECIPIENT,
  TEST_ADMIN,
  TEST_FACTORY,
  TEST_WALLET,
  TEST_TARGET_PROGRAM,
  TEST_VAULT_ID,
  SYSTEM_PROGRAM_ID,
  getMockWinternitzPublicKey,
  getMockNextWinternitzPublicKey,
  getMockWinternitzSignature,
  getMockUtxoMeta,
} from './factories'

describe('instruction builders common properties', () => {
  it('all return { programId, accounts, data }', () => {
    const ix = buildInitializeFactoryInstruction({
      programId: TEST_PROGRAM_ID,
      factoryAddress: TEST_FACTORY,
      payer: TEST_OWNER,
      admin: TEST_ADMIN,
      creationFee: 1000n,
      transferFee: 100n,
      executeFee: 50n,
      factoryUtxo: getMockUtxoMeta(),
    })

    expect(ix).toHaveProperty('programId')
    expect(ix).toHaveProperty('accounts')
    expect(ix).toHaveProperty('data')
    expect(ix.programId).toBeInstanceOf(Uint8Array)
    expect(Array.isArray(ix.accounts)).toBe(true)
    expect(ix.data).toBeInstanceOf(Uint8Array)
  })

  it('programId matches input', () => {
    const ix = buildInitializeFactoryInstruction({
      programId: TEST_PROGRAM_ID,
      factoryAddress: TEST_FACTORY,
      payer: TEST_OWNER,
      admin: TEST_ADMIN,
      creationFee: 1000n,
      transferFee: 100n,
      executeFee: 50n,
      factoryUtxo: getMockUtxoMeta(),
    })

    expect(Array.from(ix.programId)).toEqual(Array.from(TEST_PROGRAM_ID))
  })
})

describe('buildInitializeFactoryInstruction', () => {
  const params = {
    programId: TEST_PROGRAM_ID,
    factoryAddress: TEST_FACTORY,
    payer: TEST_OWNER,
    admin: TEST_ADMIN,
    creationFee: 1000n,
    transferFee: 100n,
    executeFee: 50n,
    factoryUtxo: getMockUtxoMeta(),
  }

  it('has 3 accounts: factory, payer, system', () => {
    const ix = buildInitializeFactoryInstruction(params)
    expect(ix.accounts.length).toBe(3)
  })

  it('account[0] is factory (writable, not signer)', () => {
    const ix = buildInitializeFactoryInstruction(params)
    expect(Array.from(ix.accounts[0].pubkey)).toEqual(Array.from(TEST_FACTORY))
    expect(ix.accounts[0].isSigner).toBe(false)
    expect(ix.accounts[0].isWritable).toBe(true)
  })

  it('account[1] is payer (signer, writable)', () => {
    const ix = buildInitializeFactoryInstruction(params)
    expect(Array.from(ix.accounts[1].pubkey)).toEqual(Array.from(TEST_OWNER))
    expect(ix.accounts[1].isSigner).toBe(true)
    expect(ix.accounts[1].isWritable).toBe(true)
  })

  it('account[2] is system program (not signer, not writable)', () => {
    const ix = buildInitializeFactoryInstruction(params)
    expect(Array.from(ix.accounts[2].pubkey)).toEqual(
      Array.from(SYSTEM_PROGRAM_ID)
    )
    expect(ix.accounts[2].isSigner).toBe(false)
    expect(ix.accounts[2].isWritable).toBe(false)
  })

  it('data starts with discriminant = 0', () => {
    const ix = buildInitializeFactoryInstruction(params)
    expect(ix.data[0]).toBe(InstructionType.InitializeFactory)
  })
})

describe('buildDepositToWinternitzInstruction', () => {
  const params = {
    programId: TEST_PROGRAM_ID,
    factoryAddress: TEST_FACTORY,
    walletAddress: TEST_WALLET,
    owner: TEST_OWNER,
    vaultId: TEST_VAULT_ID,
    pqOwner: getMockWinternitzPublicKey(),
    deposit: 1000000n,
    walletUtxo: getMockUtxoMeta(),
  }

  it('has 4 accounts: factory, wallet, owner, system', () => {
    const ix = buildDepositToWinternitzInstruction(params)
    expect(ix.accounts.length).toBe(4)
  })

  it('account[0] is factory (writable, not signer)', () => {
    const ix = buildDepositToWinternitzInstruction(params)
    expect(Array.from(ix.accounts[0].pubkey)).toEqual(Array.from(TEST_FACTORY))
    expect(ix.accounts[0].isSigner).toBe(false)
    expect(ix.accounts[0].isWritable).toBe(true)
  })

  it('account[1] is wallet (writable, not signer)', () => {
    const ix = buildDepositToWinternitzInstruction(params)
    expect(Array.from(ix.accounts[1].pubkey)).toEqual(Array.from(TEST_WALLET))
    expect(ix.accounts[1].isSigner).toBe(false)
    expect(ix.accounts[1].isWritable).toBe(true)
  })

  it('account[2] is owner (signer, writable)', () => {
    const ix = buildDepositToWinternitzInstruction(params)
    expect(Array.from(ix.accounts[2].pubkey)).toEqual(Array.from(TEST_OWNER))
    expect(ix.accounts[2].isSigner).toBe(true)
    expect(ix.accounts[2].isWritable).toBe(true)
  })

  it('account[3] is system program', () => {
    const ix = buildDepositToWinternitzInstruction(params)
    expect(Array.from(ix.accounts[3].pubkey)).toEqual(
      Array.from(SYSTEM_PROGRAM_ID)
    )
  })

  it('data starts with discriminant = 1', () => {
    const ix = buildDepositToWinternitzInstruction(params)
    expect(ix.data[0]).toBe(InstructionType.DepositToWinternitz)
  })
})

describe('buildTransferWithWinternitzInstruction', () => {
  const params = {
    programId: TEST_PROGRAM_ID,
    factoryAddress: TEST_FACTORY,
    walletAddress: TEST_WALLET,
    recipient: TEST_RECIPIENT,
    owner: TEST_OWNER,
    vaultId: TEST_VAULT_ID,
    pqNext: getMockNextWinternitzPublicKey(),
    amount: 500000n,
    signature: getMockWinternitzSignature(),
  }

  it('has 4 accounts: factory, wallet, recipient, owner', () => {
    const ix = buildTransferWithWinternitzInstruction(params)
    expect(ix.accounts.length).toBe(4)
  })

  it('account[0] is factory (writable)', () => {
    const ix = buildTransferWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[0].pubkey)).toEqual(Array.from(TEST_FACTORY))
    expect(ix.accounts[0].isWritable).toBe(true)
  })

  it('account[1] is wallet (writable)', () => {
    const ix = buildTransferWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[1].pubkey)).toEqual(Array.from(TEST_WALLET))
    expect(ix.accounts[1].isWritable).toBe(true)
  })

  it('account[2] is recipient (writable)', () => {
    const ix = buildTransferWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[2].pubkey)).toEqual(Array.from(TEST_RECIPIENT))
    expect(ix.accounts[2].isWritable).toBe(true)
  })

  it('account[3] is owner (signer, writable)', () => {
    const ix = buildTransferWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[3].pubkey)).toEqual(Array.from(TEST_OWNER))
    expect(ix.accounts[3].isSigner).toBe(true)
    expect(ix.accounts[3].isWritable).toBe(true)
  })

  it('data starts with discriminant = 2', () => {
    const ix = buildTransferWithWinternitzInstruction(params)
    expect(ix.data[0]).toBe(InstructionType.TransferWithWinternitz)
  })
})

describe('buildExecuteWithWinternitzInstruction', () => {
  const params = {
    programId: TEST_PROGRAM_ID,
    factoryAddress: TEST_FACTORY,
    walletAddress: TEST_WALLET,
    targetProgram: TEST_TARGET_PROGRAM,
    owner: TEST_OWNER,
    vaultId: TEST_VAULT_ID,
    pqNext: getMockNextWinternitzPublicKey(),
    instructionData: new Uint8Array([1, 2, 3]),
    cpiAccounts: [
      { pubkey: TEST_RECIPIENT, isSigner: false, isWritable: true },
    ],
    signature: getMockWinternitzSignature(),
  }

  it('has 5+ accounts: factory, wallet, target, owner, system, ...remaining', () => {
    const ix = buildExecuteWithWinternitzInstruction(params)
    // 5 base + 1 remaining = 6
    expect(ix.accounts.length).toBe(6)
  })

  it('account[0] is factory (writable)', () => {
    const ix = buildExecuteWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[0].pubkey)).toEqual(Array.from(TEST_FACTORY))
    expect(ix.accounts[0].isWritable).toBe(true)
  })

  it('account[1] is wallet (writable)', () => {
    const ix = buildExecuteWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[1].pubkey)).toEqual(Array.from(TEST_WALLET))
    expect(ix.accounts[1].isWritable).toBe(true)
  })

  it('account[2] is target program (not writable)', () => {
    const ix = buildExecuteWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[2].pubkey)).toEqual(
      Array.from(TEST_TARGET_PROGRAM)
    )
    expect(ix.accounts[2].isWritable).toBe(false)
  })

  it('account[3] is owner (signer, writable)', () => {
    const ix = buildExecuteWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[3].pubkey)).toEqual(Array.from(TEST_OWNER))
    expect(ix.accounts[3].isSigner).toBe(true)
    expect(ix.accounts[3].isWritable).toBe(true)
  })

  it('account[4] is system program', () => {
    const ix = buildExecuteWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[4].pubkey)).toEqual(
      Array.from(SYSTEM_PROGRAM_ID)
    )
  })

  it('remaining accounts are appended with flags passed through', () => {
    const ix = buildExecuteWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[5].pubkey)).toEqual(Array.from(TEST_RECIPIENT))
    // Critical: outer tx must mark the account writable so the CPI can write.
    expect(ix.accounts[5].isWritable).toBe(true)
    expect(ix.accounts[5].isSigner).toBe(false)
  })

  it('signer flag on cpiAccount is passed through to outer tx', () => {
    const ix = buildExecuteWithWinternitzInstruction({
      ...params,
      cpiAccounts: [
        { pubkey: TEST_RECIPIENT, isSigner: true, isWritable: false },
      ],
    })
    expect(ix.accounts[5].isSigner).toBe(true)
    expect(ix.accounts[5].isWritable).toBe(false)
  })

  it('data starts with discriminant = 3', () => {
    const ix = buildExecuteWithWinternitzInstruction(params)
    expect(ix.data[0]).toBe(InstructionType.ExecuteWithWinternitz)
  })
})

describe('buildChangePqOwnerInstruction', () => {
  const params = {
    programId: TEST_PROGRAM_ID,
    walletAddress: TEST_WALLET,
    owner: TEST_OWNER,
    vaultId: TEST_VAULT_ID,
    pqNext: getMockNextWinternitzPublicKey(),
    signature: getMockWinternitzSignature(),
  }

  it('has 2 accounts only: wallet, owner (no factory!)', () => {
    const ix = buildChangePqOwnerInstruction(params)
    expect(ix.accounts.length).toBe(2)
  })

  it('account[0] is wallet (writable)', () => {
    const ix = buildChangePqOwnerInstruction(params)
    expect(Array.from(ix.accounts[0].pubkey)).toEqual(Array.from(TEST_WALLET))
    expect(ix.accounts[0].isWritable).toBe(true)
    expect(ix.accounts[0].isSigner).toBe(false)
  })

  it('account[1] is owner (signer, writable)', () => {
    const ix = buildChangePqOwnerInstruction(params)
    expect(Array.from(ix.accounts[1].pubkey)).toEqual(Array.from(TEST_OWNER))
    expect(ix.accounts[1].isSigner).toBe(true)
    expect(ix.accounts[1].isWritable).toBe(true)
  })

  it('data starts with discriminant = 4', () => {
    const ix = buildChangePqOwnerInstruction(params)
    expect(ix.data[0]).toBe(InstructionType.ChangePqOwner)
  })
})

describe('buildUpdateFeesInstruction', () => {
  const params = {
    programId: TEST_PROGRAM_ID,
    factoryAddress: TEST_FACTORY,
    admin: TEST_ADMIN,
    creationFee: 2000n,
    transferFee: 200n,
    executeFee: 100n,
  }

  it('has 2 accounts: factory, admin', () => {
    const ix = buildUpdateFeesInstruction(params)
    expect(ix.accounts.length).toBe(2)
  })

  it('account[0] is factory (writable)', () => {
    const ix = buildUpdateFeesInstruction(params)
    expect(Array.from(ix.accounts[0].pubkey)).toEqual(Array.from(TEST_FACTORY))
    expect(ix.accounts[0].isWritable).toBe(true)
  })

  it('account[1] is admin (signer, not writable)', () => {
    const ix = buildUpdateFeesInstruction(params)
    expect(Array.from(ix.accounts[1].pubkey)).toEqual(Array.from(TEST_ADMIN))
    expect(ix.accounts[1].isSigner).toBe(true)
    expect(ix.accounts[1].isWritable).toBe(false)
  })

  it('data starts with discriminant = 5', () => {
    const ix = buildUpdateFeesInstruction(params)
    expect(ix.data[0]).toBe(InstructionType.UpdateFees)
  })
})

describe('buildWithdrawFeesInstruction', () => {
  const params = {
    programId: TEST_PROGRAM_ID,
    factoryAddress: TEST_FACTORY,
    admin: TEST_ADMIN,
    recipient: TEST_RECIPIENT,
    amount: 10000n,
  }

  it('has 3 accounts: factory, admin, recipient', () => {
    const ix = buildWithdrawFeesInstruction(params)
    expect(ix.accounts.length).toBe(3)
  })

  it('account[0] is factory (writable)', () => {
    const ix = buildWithdrawFeesInstruction(params)
    expect(Array.from(ix.accounts[0].pubkey)).toEqual(Array.from(TEST_FACTORY))
    expect(ix.accounts[0].isWritable).toBe(true)
  })

  it('account[1] is admin (signer, not writable)', () => {
    const ix = buildWithdrawFeesInstruction(params)
    expect(Array.from(ix.accounts[1].pubkey)).toEqual(Array.from(TEST_ADMIN))
    expect(ix.accounts[1].isSigner).toBe(true)
    expect(ix.accounts[1].isWritable).toBe(false)
  })

  it('account[2] is recipient (writable)', () => {
    const ix = buildWithdrawFeesInstruction(params)
    expect(Array.from(ix.accounts[2].pubkey)).toEqual(Array.from(TEST_RECIPIENT))
    expect(ix.accounts[2].isWritable).toBe(true)
  })

  it('data starts with discriminant = 6', () => {
    const ix = buildWithdrawFeesInstruction(params)
    expect(ix.data[0]).toBe(InstructionType.WithdrawFees)
  })
})

describe('buildTransferOwnershipInstruction', () => {
  const newAdmin = new Uint8Array(32).fill(0x99)
  const params = {
    programId: TEST_PROGRAM_ID,
    factoryAddress: TEST_FACTORY,
    currentAdmin: TEST_ADMIN,
    newAdmin,
  }

  it('has 2 accounts: factory, currentAdmin', () => {
    const ix = buildTransferOwnershipInstruction(params)
    expect(ix.accounts.length).toBe(2)
  })

  it('account[0] is factory (writable)', () => {
    const ix = buildTransferOwnershipInstruction(params)
    expect(Array.from(ix.accounts[0].pubkey)).toEqual(Array.from(TEST_FACTORY))
    expect(ix.accounts[0].isWritable).toBe(true)
  })

  it('account[1] is currentAdmin (signer, not writable)', () => {
    const ix = buildTransferOwnershipInstruction(params)
    expect(Array.from(ix.accounts[1].pubkey)).toEqual(Array.from(TEST_ADMIN))
    expect(ix.accounts[1].isSigner).toBe(true)
    expect(ix.accounts[1].isWritable).toBe(false)
  })

  it('data starts with discriminant = 7', () => {
    const ix = buildTransferOwnershipInstruction(params)
    expect(ix.data[0]).toBe(InstructionType.TransferOwnership)
  })
})

describe('buildBtcTransferWithWinternitzInstruction', () => {
  const params = {
    programId: TEST_PROGRAM_ID,
    factoryAddress: TEST_FACTORY,
    walletAddress: TEST_WALLET,
    payer: TEST_OWNER,
    vaultId: TEST_VAULT_ID,
    pqNext: getMockNextWinternitzPublicKey(),
    amount: 100000n,
    recipientScriptPubkey: new Uint8Array([0x00, 0x14, ...new Array(20).fill(0xab)]),
    feeTx: new Uint8Array([0x01, 0x02]),
    sourceUtxo: getMockUtxoMeta(),
    signature: getMockWinternitzSignature(),
  }

  it('has 4 accounts: factory, wallet, payer, system', () => {
    const ix = buildBtcTransferWithWinternitzInstruction(params)
    expect(ix.accounts.length).toBe(4)
  })

  it('account[0] is factory (writable)', () => {
    const ix = buildBtcTransferWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[0].pubkey)).toEqual(Array.from(TEST_FACTORY))
    expect(ix.accounts[0].isWritable).toBe(true)
  })

  it('account[1] is wallet (writable)', () => {
    const ix = buildBtcTransferWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[1].pubkey)).toEqual(Array.from(TEST_WALLET))
    expect(ix.accounts[1].isWritable).toBe(true)
  })

  it('account[2] is payer (signer, writable)', () => {
    const ix = buildBtcTransferWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[2].pubkey)).toEqual(Array.from(TEST_OWNER))
    expect(ix.accounts[2].isSigner).toBe(true)
    expect(ix.accounts[2].isWritable).toBe(true)
  })

  it('account[3] is system program', () => {
    const ix = buildBtcTransferWithWinternitzInstruction(params)
    expect(Array.from(ix.accounts[3].pubkey)).toEqual(
      Array.from(SYSTEM_PROGRAM_ID)
    )
  })

  it('data starts with discriminant = 8', () => {
    const ix = buildBtcTransferWithWinternitzInstruction(params)
    expect(ix.data[0]).toBe(InstructionType.BtcTransferWithWinternitz)
  })
})
