# Quip Arch

A quantum-resistant wallet system on ArchVM (Bitcoin) using WOTS+ signatures for post-quantum cryptographic security.

## Features

- **Quantum-Resistant Security**: WOTS+ signatures with Keccak256 hashing
- **Factory Pattern**: Centralized wallet creation and fee management  
- **Deterministic Addresses**: Derived from program ID and seeds
- **Cross-Program Invocation**: Execute arbitrary instructions on behalf of wallets

## Quick Start

```bash
# Clone repository
git clone <repository-url>
cd quip-arch

# Build
cargo build

# Run tests
cargo test --features no-entrypoint
```

## Development Commands

```bash
# Build program
cargo build

# Release build
cargo build --release

# Build with debug logging
cargo build --features debug

# Run tests (disable entrypoint for native testing)
cargo test --features no-entrypoint

# Linting and formatting
cargo fmt           # Format Rust code
cargo clippy        # Run linter
```

## Prerequisites

- [Rust](https://rustup.rs/) 1.75+
- ArchVM toolchain

## Architecture

### Core Instructions

- `initialize_factory` - Set up global factory configuration
- `deposit_to_winternitz` - Create quantum-resistant wallet with initial deposit
- `transfer_with_winternitz` - Transfer funds using WOTS+ signature
- `execute_with_winternitz` - Execute arbitrary CPI with WOTS+ auth
- `change_pq_owner` - Rotate WOTS+ key
- `store_signature` / `store_opdata` - Chunked data upload for large signatures
- `update_fees` / `withdraw_fees` / `transfer_ownership` - Admin management

### Account Structure

- **Factory Account**: Global configuration derived from `[b"factory", program_id]`
- **Wallet Accounts**: Individual wallets derived from `[b"wallet", owner, vault_id, program_id]`
- **Signature Storage**: Temporary storage derived from `[b"signature", owner, program_id]`
- **Opdata Storage**: Temporary storage derived from `[b"opdata", owner, program_id]`

## Important Notes

- **WOTS+ Keys are ONE-TIME USE** - must rotate after each transaction
- Uses Keccak256 (SHA-3) for quantum resistance
- Value transfers in ArchVM happen via UTXO model at transaction level; program authorizes via signature verification

## License

AGPL-3.0-or-later

