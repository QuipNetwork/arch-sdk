// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  SanitizedMessageUtil,
  SignatureUtil,
  SystemInstruction,
  type Provider,
  type Instruction as ArchInstruction,
  type AccountMeta as ArchAccountMeta,
  type Pubkey,
  type RuntimeTransaction,
  type SanitizedMessage,
} from '@arch-network/arch-sdk'

import type {
  Instruction,
  QuipFactory,
  QuipWallet,
  WinternitzPublicKey,
  WinternitzSignature,
  UtxoMeta,
} from './types'
import {
  deriveFactoryAddress,
  deriveWalletAddress,
} from './addresses'
import { parseFactoryAccount, parseWalletAccount } from './parsers'
import { InvalidAccountDataError, QuipError } from './errors'
import {
  buildInitializeFactoryInstruction,
  buildDepositToWinternitzInstruction,
  buildTransferWithWinternitzInstruction,
  buildChangePqOwnerInstruction,
  buildExecuteWithWinternitzInstruction,
  buildBtcTransferWithWinternitzInstruction,
  buildUpdateFeesInstruction,
  buildWithdrawFeesInstruction,
  buildTransferOwnershipInstruction,
  type ExecuteCpiAccount,
} from './instructions'

// =============================================================================
// Signer interface
// =============================================================================

/**
 * A classical signer for the outer transaction envelope.
 *
 * `pubkey` is the 32-byte x-only classical public key listed as a signer on
 * the transaction. `sign` receives the UTF-8-decoded string form of the
 * sanitized-message hash (per Arch convention) and must return a BIP-322
 * simple signature. The SDK normalizes the result via
 * `SignatureUtil.adjustSignature` before submission, so callers can return
 * either the raw base64 witness bytes from `bip322-js` or a browser wallet's
 * `signMessage({ type: 'bip322-simple' })` output.
 *
 * The SDK does not prescribe a signing library; plug in `bip322-js`, a
 * browser extension (Unisat/Xverse), or a hardware wallet.
 */
export interface ClassicalSigner {
  pubkey: Uint8Array
  sign(messageHashUtf8: string): Uint8Array | Promise<Uint8Array>
}

// =============================================================================
// Conversion helpers
// =============================================================================

function toArchInstruction(ix: Instruction): ArchInstruction {
  const accounts: ArchAccountMeta[] = ix.accounts.map((a) => ({
    pubkey: a.pubkey as Pubkey,
    is_signer: a.isSigner,
    is_writable: a.isWritable,
  }))
  return {
    program_id: ix.programId as Pubkey,
    accounts,
    data: ix.data,
  }
}

function isCompileError(x: unknown): x is number {
  // arch-sdk's createSanitizedMessage returns `SanitizedMessage | CompileError`;
  // CompileError is a numeric enum, whereas a valid SanitizedMessage is an object.
  return typeof x === 'number'
}

// =============================================================================
// QuipArchClient
// =============================================================================

export interface QuipArchClientConfig {
  /** arch-sdk Provider (typically an RpcConnection). */
  rpc: Provider
  /** 32-byte quip-arch program ID. */
  programId: Uint8Array
}

/**
 * High-level client for the quip-arch program.
 *
 * Wraps instruction builders with transaction assembly (blockhash fetch,
 * message sanitization, signing, submission) and account reads. The low-level
 * builders and parsers remain exported for callers who need more control.
 *
 * @example
 * ```ts
 * import { RpcConnection } from '@arch-network/arch-sdk'
 * import { QuipArchClient, programIdFor } from '@quip.network/arch-sdk'
 *
 * const client = new QuipArchClient({
 *   rpc: new RpcConnection('https://rpc.testnet.arch.network'),
 *   programId: programIdFor('testnet'),
 * })
 *
 * const factory = await client.getFactory()
 * const txid = await client.transfer({
 *   owner: ownerSigner,
 *   vaultId,
 *   recipient,
 *   amount: 1000n,
 *   pqNext,
 *   signature: { signatureData: wotsSig },
 *   currentPqKey,
 * })
 * ```
 */
export class QuipArchClient {
  readonly rpc: Provider
  readonly programId: Uint8Array
  readonly factoryAddress: Uint8Array

  constructor(config: QuipArchClientConfig) {
    this.rpc = config.rpc
    this.programId = config.programId
    this.factoryAddress = deriveFactoryAddress(config.programId).address
  }

  // ---------------------------------------------------------------------------
  // Address helpers
  // ---------------------------------------------------------------------------

  /** Derive a wallet PDA for (owner, vaultId) under this client's program. */
  walletAddress(owner: Uint8Array, vaultId: Uint8Array): Uint8Array {
    return deriveWalletAddress(this.programId, owner, vaultId).address
  }

  // ---------------------------------------------------------------------------
  // Reads
  // ---------------------------------------------------------------------------

  /**
   * Fetch and parse the factory account. Returns null if the account does not
   * exist yet (e.g. before `initializeFactory` has run).
   */
  async getFactory(): Promise<QuipFactory | null> {
    const info = await this.rpc
      .readAccountInfo(this.factoryAddress as Pubkey)
      .catch(() => null)
    if (!info || !info.data || info.data.length === 0) return null
    return parseFactoryAccount(info.data)
  }

  /**
   * Fetch and parse a wallet account by (owner, vaultId). Returns null if
   * the wallet has not been created.
   */
  async getWallet(
    owner: Uint8Array,
    vaultId: Uint8Array
  ): Promise<QuipWallet | null> {
    const addr = this.walletAddress(owner, vaultId)
    const info = await this.rpc
      .readAccountInfo(addr as Pubkey)
      .catch(() => null)
    if (!info || !info.data || info.data.length === 0) return null
    return parseWalletAccount(info.data)
  }

  // ---------------------------------------------------------------------------
  // Writes
  // ---------------------------------------------------------------------------

  /** Initialize the factory (one-time setup by the intended admin). */
  async initializeFactory(params: {
    payer: ClassicalSigner
    admin: Uint8Array
    creationFee: bigint
    transferFee: bigint
    executeFee: bigint
    factoryUtxo: UtxoMeta
  }): Promise<string> {
    const ix = buildInitializeFactoryInstruction({
      programId: this.programId,
      factoryAddress: this.factoryAddress,
      payer: params.payer.pubkey,
      admin: params.admin,
      creationFee: params.creationFee,
      transferFee: params.transferFee,
      executeFee: params.executeFee,
      factoryUtxo: params.factoryUtxo,
    })
    return this.sendIx(ix, [params.payer])
  }

  /** Create a new post-quantum wallet (DepositToWinternitz). */
  async createWallet(params: {
    owner: ClassicalSigner
    vaultId: Uint8Array
    pqOwner: WinternitzPublicKey
    deposit: bigint
    walletUtxo: UtxoMeta
  }): Promise<{ signature: string; walletAddress: Uint8Array }> {
    const walletAddress = this.walletAddress(params.owner.pubkey, params.vaultId)
    const ix = buildDepositToWinternitzInstruction({
      programId: this.programId,
      factoryAddress: this.factoryAddress,
      walletAddress,
      owner: params.owner.pubkey,
      vaultId: params.vaultId,
      pqOwner: params.pqOwner,
      deposit: params.deposit,
      walletUtxo: params.walletUtxo,
    })
    const signature = await this.sendIx(ix, [params.owner])
    return { signature, walletAddress }
  }

  /** Transfer lamports from a WOTS+ wallet. Caller provides the WOTS+ signature. */
  async transfer(params: {
    owner: ClassicalSigner
    vaultId: Uint8Array
    recipient: Uint8Array
    amount: bigint
    pqNext: WinternitzPublicKey
    signature: WinternitzSignature
  }): Promise<string> {
    const walletAddress = this.walletAddress(params.owner.pubkey, params.vaultId)
    const ix = buildTransferWithWinternitzInstruction({
      programId: this.programId,
      factoryAddress: this.factoryAddress,
      walletAddress,
      recipient: params.recipient,
      owner: params.owner.pubkey,
      vaultId: params.vaultId,
      pqNext: params.pqNext,
      amount: params.amount,
      signature: params.signature,
    })
    return this.sendIx(ix, [params.owner])
  }

  /** Rotate the WOTS+ owner key. */
  async changePqOwner(params: {
    owner: ClassicalSigner
    vaultId: Uint8Array
    pqNext: WinternitzPublicKey
    signature: WinternitzSignature
  }): Promise<string> {
    const walletAddress = this.walletAddress(params.owner.pubkey, params.vaultId)
    const ix = buildChangePqOwnerInstruction({
      programId: this.programId,
      walletAddress,
      owner: params.owner.pubkey,
      vaultId: params.vaultId,
      pqNext: params.pqNext,
      signature: params.signature,
    })
    return this.sendIx(ix, [params.owner])
  }

  /** CPI into another program from a WOTS+ wallet. */
  async execute(params: {
    owner: ClassicalSigner
    vaultId: Uint8Array
    targetProgram: Uint8Array
    pqNext: WinternitzPublicKey
    instructionData: Uint8Array
    cpiAccounts: ExecuteCpiAccount[]
    signature: WinternitzSignature
  }): Promise<string> {
    const walletAddress = this.walletAddress(params.owner.pubkey, params.vaultId)
    const ix = buildExecuteWithWinternitzInstruction({
      programId: this.programId,
      factoryAddress: this.factoryAddress,
      walletAddress,
      targetProgram: params.targetProgram,
      owner: params.owner.pubkey,
      vaultId: params.vaultId,
      pqNext: params.pqNext,
      instructionData: params.instructionData,
      cpiAccounts: params.cpiAccounts,
      signature: params.signature,
    })
    return this.sendIx(ix, [params.owner])
  }

  /** Send a Bitcoin transfer signed by the WOTS+ wallet. */
  async btcTransfer(params: {
    payer: ClassicalSigner
    vaultId: Uint8Array
    pqNext: WinternitzPublicKey
    amount: bigint
    recipientScriptPubkey: Uint8Array
    feeTx: Uint8Array
    sourceUtxo: UtxoMeta
    signature: WinternitzSignature
  }): Promise<string> {
    const walletAddress = this.walletAddress(params.payer.pubkey, params.vaultId)
    const ix = buildBtcTransferWithWinternitzInstruction({
      programId: this.programId,
      factoryAddress: this.factoryAddress,
      walletAddress,
      payer: params.payer.pubkey,
      vaultId: params.vaultId,
      pqNext: params.pqNext,
      amount: params.amount,
      recipientScriptPubkey: params.recipientScriptPubkey,
      feeTx: params.feeTx,
      sourceUtxo: params.sourceUtxo,
      signature: params.signature,
    })
    return this.sendIx(ix, [params.payer])
  }

  // ---------------------------------------------------------------------------
  // Admin writes
  // ---------------------------------------------------------------------------

  async updateFees(params: {
    admin: ClassicalSigner
    creationFee: bigint
    transferFee: bigint
    executeFee: bigint
  }): Promise<string> {
    const ix = buildUpdateFeesInstruction({
      programId: this.programId,
      factoryAddress: this.factoryAddress,
      admin: params.admin.pubkey,
      creationFee: params.creationFee,
      transferFee: params.transferFee,
      executeFee: params.executeFee,
    })
    return this.sendIx(ix, [params.admin])
  }

  async withdrawFees(params: {
    admin: ClassicalSigner
    recipient: Uint8Array
    amount: bigint
  }): Promise<string> {
    const ix = buildWithdrawFeesInstruction({
      programId: this.programId,
      factoryAddress: this.factoryAddress,
      admin: params.admin.pubkey,
      recipient: params.recipient,
      amount: params.amount,
    })
    return this.sendIx(ix, [params.admin])
  }

  async transferOwnership(params: {
    currentAdmin: ClassicalSigner
    newAdmin: Uint8Array
  }): Promise<string> {
    const ix = buildTransferOwnershipInstruction({
      programId: this.programId,
      factoryAddress: this.factoryAddress,
      currentAdmin: params.currentAdmin.pubkey,
      newAdmin: params.newAdmin,
    })
    return this.sendIx(ix, [params.currentAdmin])
  }

  // ---------------------------------------------------------------------------
  // Low-level: build a signed RuntimeTransaction without sending
  // ---------------------------------------------------------------------------

  /**
   * Assemble a signed `RuntimeTransaction` for one instruction without
   * submitting it. Useful for simulation, inspection, or batched sending
   * via `rpc.sendTransactions(...)`.
   *
   * Signers sign in the order provided. The first signer is taken as the
   * transaction payer.
   */
  async buildTransaction(
    ix: Instruction,
    signers: ClassicalSigner[]
  ): Promise<RuntimeTransaction> {
    if (signers.length === 0) {
      throw new QuipError('buildTransaction requires at least one signer')
    }
    const archIx = toArchInstruction(ix)
    const blockhashHex = await this.rpc.getBestBlockHash()
    const clean = blockhashHex.startsWith('0x')
      ? blockhashHex.slice(2)
      : blockhashHex
    const blockhash = SystemInstruction.hexStringToUint8Array(clean)

    const payer = signers[0].pubkey as Pubkey
    const msg = SanitizedMessageUtil.createSanitizedMessage(
      [archIx],
      payer,
      blockhash
    )
    if (isCompileError(msg)) {
      throw new QuipError(`createSanitizedMessage failed: CompileError ${msg}`)
    }

    const hash = SanitizedMessageUtil.hash(msg as SanitizedMessage)
    const hashUtf8 = new TextDecoder().decode(hash)
    const rawSignatures = await Promise.all(
      signers.map((s) => Promise.resolve(s.sign(hashUtf8)))
    )
    const signatures = rawSignatures.map((sig) =>
      SignatureUtil.adjustSignature(sig)
    )

    return {
      version: 0,
      signatures,
      message: msg as SanitizedMessage,
    }
  }

  // ---------------------------------------------------------------------------
  // Internal: build + submit
  // ---------------------------------------------------------------------------

  private async sendIx(
    ix: Instruction,
    signers: ClassicalSigner[]
  ): Promise<string> {
    const tx = await this.buildTransaction(ix, signers)
    return this.rpc.sendTransaction(tx)
  }
}

// Re-export for consumers that want to catch this specific failure mode
export { InvalidAccountDataError }
