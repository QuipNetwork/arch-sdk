# Quip Arch

A quantum-resistant wallet system on ArchVM (Bitcoin) using WOTS+ signatures for post-quantum cryptographic security.

## Features

- **Quantum-Resistant Security**: WOTS+ signatures with Keccak256 hashing
- **Factory Pattern**: Centralized wallet creation and fee management
- **Deterministic Addresses**: PDA wallets derived from program ID, owner, and vault ID
- **Cross-Program Invocation**: Execute arbitrary instructions on behalf of wallets
- **Bitcoin Settlement**: Accounts anchored to Bitcoin UTXOs via Arch Network

## Quick Start

```bash
# Clone repository
git clone <repository-url>
cd quip-arch

# Build for sBPF target (ArchVM)
cargo build-sbpf

# Run tests (requires local Arch node and Bitcoin regtest)
cargo test --features "test no-entrypoint" -- --ignored --nocapture --test-threads=1
```

## Development Commands

```bash
# Build for sBPF target (deployable program)
cargo build-sbpf

# Build native (for IDE support)
cargo build

# Build with debug logging
cargo build --features debug

# Run all integration tests
cargo test --features "test no-entrypoint" -- --ignored --nocapture --test-threads=1

# Run a specific test
cargo test --features "test no-entrypoint" -- --ignored --nocapture test_transfer_success

# Linting and formatting
cargo fmt           # Format Rust code
cargo clippy        # Run linter
```

## Prerequisites

- [Rust](https://rustup.rs/) 1.75+
- ArchVM toolchain (`cargo build-sbpf`)
- Local Arch node (for testing)
- Bitcoin regtest node (for testing)

## Architecture

### Core Instructions

- `InitializeFactory` - Set up global factory configuration with admin and fees
- `DepositToWinternitz` - Create quantum-resistant wallet or top up existing wallet
- `TransferWithWinternitz` - Transfer funds using WOTS+ signature
- `ExecuteWithWinternitz` - Execute arbitrary CPI with WOTS+ authorization
- `ChangePqOwner` - Rotate WOTS+ key without transferring funds
- `UpdateFees` - Admin: update factory fee structure
- `WithdrawFees` - Admin: withdraw accumulated fees
- `TransferOwnership` - Admin: transfer factory ownership

### Account Structure

- **Factory Account**: Global singleton derived from `[b"factory"]`
- **Wallet Accounts**: Per-user wallets derived from `[b"wallet", owner, vault_id]`

### Data Sizes

- **QuipFactory**: 74 bytes (admin, fees, counters, bump)
- **QuipWallet**: 154 bytes (owner, pq_owner, timestamps, transaction count, bump)
- **WinternitzPublicKey**: 64 bytes (public_seed + public_key_hash)
- **WinternitzSignature**: ~2144 bytes (67 chunks of 32 bytes)

## Important Notes

- **WOTS+ Keys are ONE-TIME USE** - each transaction rotates to a new `pq_next` key
- Uses Keccak256 for hash-based signatures (quantum-resistant)
- Transfers from PDAs with data use direct lamport manipulation (system program limitation)
- Compute budget of 1.4M units required for WOTS+ signature verification

## License

AGPL-3.0-or-later

