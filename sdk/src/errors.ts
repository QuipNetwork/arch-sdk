// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Base class for all Quip SDK errors.
 */
export class QuipError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'QuipError'
  }
}

/**
 * Account data could not be deserialized.
 */
export class InvalidAccountDataError extends QuipError {
  constructor(message = 'Invalid account data') {
    super(message)
    this.name = 'InvalidAccountDataError'
  }
}

/**
 * Invalid input parameters provided.
 */
export class InvalidParamsError extends QuipError {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidParamsError'
  }
}

/**
 * PDA derivation failed.
 */
export class PdaDerivationError extends QuipError {
  constructor(message = 'Failed to derive PDA') {
    super(message)
    this.name = 'PdaDerivationError'
  }
}
