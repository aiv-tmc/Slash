# Slash Protocol

[![CI](https://github.com/slash-protocol/slash/actions/workflows/ci.yml/badge.svg)](https://github.com/slash-protocol/slash/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

A cell-based blockchain with RandomX proof-of-work, paged multi-input state (PMIS), adaptive governance via version bits, layered onion routing for transaction privacy, and a cell-denominated bonding-curve treasury with a halving emission schedule.

## Overview

Slash introduces a **Paged Multi-Input State (PMIS)** engine that partitions a global ledger of one billion cells into 65,536-cell pages. This design enables:

- **O(1) balance lookups** via an incremental balance cache.
- **Atomic cross-page transactions** with speculative execution and rollback.
- **Light-client verification** through per-page Merkle roots and compact proofs.
- **Stake-locking** at the cell level for time-bound ownership.
- **Emission-backed security**: a Bitcoin-like subsidy schedule funds the RandomX hash rate from day one.

Consensus is secured by **RandomX proof-of-work**, ensuring CPU-friendly and ASIC-resistant mining. The network supports soft-fork upgrades through **BIP-9 style version bits** with real signal counting and threshold enforcement.

## Key Features

### PMIS — Paged Multi-Input State
- **1 billion cells** partitioned into 15,259 pages of 65,536 cells each.
- Dirty pages are materialized in memory; clean pages are lazily reconstructed as treasury-owned.
- Pristine page eviction automatically drops pages that return to a single treasury range, keeping memory bounded.

### RandomX Proof-of-Work
- Miner and verifier use identical hash inputs (`prev || time || height || nonce || miner`) for consensus consistency.
- Parallel mining with extranonce striding across all CPU cores.
- Cooperative cancellation via `Arc<AtomicBool>` so the event loop never stalls.
- Context cache with 600-second TTL separates full-memory mining contexts from light verification contexts.

### Emission Schedule (v0.3.0)
- **Coinbase subsidy** of 500 cells per block at genesis, halving every 4 years (420,480 blocks at a 300-second target).
- Nine eras; total emission **417,957,120 cells (~41.8 % of supply)** over ~36 years, after which security is fee-funded.
- Coinbase is a mandatory `txs[0]` treasury transaction paying the miner exactly `subsidy_at(height)`; all other treasury transactions require the treasury signer key.

### Governance (Version Bits)
- Soft-fork deployments track lifecycle states: `Defined → Started → LockedIn → Active / Failed`.
- Real cumulative signal counting against configurable thresholds.
- Active rules include `MinTxAmount`, `MaxBlockSize`, `AllowScheme1`, and `RequireBlockVersion2`.

### Onion Routing
- Three-hop onion envelopes with fixed-size layers (1024 bytes) and inner payloads (2048 bytes).
- X25519 ephemeral keys and AES-256-GCM encryption at each hop.
- P2P forwarding uses request-response unicast to the next relay, preventing broadcast-based traffic correlation.

### Economic Layer
- **Mandatory Fees**: every transaction pays at least 0.5 % of the transferred amount into the `FEE_VAULT`; miners claim accumulated fees in their blocks.
- **Bonding Curve Treasury**: linear price growth denominated in cells; buys are paid into `TREASURY_VAULT` and minted atomically in the same block; sells are paid back at 98 % of the curve price, keeping the 2 % spread in the vault.
- **Treasury Signer**: mint and payout transactions are signed with a dedicated Ed25519 key (key separation: VRF / signer / onion).

## Build Requirements

- **Rust** 1.75 or later
- **Cargo**
- **OpenSSL development headers** (for libp2p noise protocol)
- **CMake** (for RandomX VM compilation)

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev pkg-config
```

On macOS:
```bash
brew install cmake openssl
```

## Building

```bash
# Clone the repository
git clone https://github.com/slash-protocol/slash.git
cd slash

# Build in release mode
cargo build --release

# Build with all optimizations and benchmarks
cargo build --release --benches
```

## Testing

```bash
# Run the full test suite
cargo test

# Run tests with output visible
cargo test -- --nocapture

# Run a specific test
cargo test test_coinbase_amount_matches_schedule

# Run benchmarks
cargo bench
```

## Running a Node

```bash
# Start a full node on the default P2P port (0.0.0.0:30333) and RPC port (0.0.0.0:9944)
./target/release/slash-node --port 30333 --rpc-port 9944

# Start in testnet mode
./target/release/slash-node --testnet --port 30333 --rpc-port 9944

# Start in pruned mode (keeps only the last 10,000 blocks)
./target/release/slash-node --pruned --port 30333 --rpc-port 9944
```

## Project Structure

```
slash/
├── src/
│   ├── lib.rs           # Crate root, testnet flag, save/load helpers
│   ├── chain.rs         # Block, Chain, validation, coinbase rules, PoW verification, version bits
│   ├── state.rs         # PMIS engine, Page, State, transactions, min-fee rule, balance cache
│   ├── crypto.rs        # Ed25519, X25519, AES-GCM, Argon2id, wallet encryption
│   ├── mining.rs        # RandomX miner with parallel extranonce search
│   ├── p2p.rs           # libp2p swarm, mempool, sync, onion unicast forwarding
│   ├── rpc.rs           # JSON-RPC HTTP server (balance, block, tx, proofs)
│   ├── governance.rs    # Soft-fork rule registry and active rule validation
│   ├── storage.rs       # Atomic file writes, snapshots, pruned recovery
│   ├── treasury.rs      # Cell-denominated bonding curve math and treasury state
│   ├── vrf.rs           # ECVRF-RISTRETTO255-SHA512 prove/verify
│   ├── onion.rs         # 3-hop onion envelope construction and peeling
│   ├── ffi.rs           # C-API for external wallet integration
│   └── simulation.rs    # Economic stress tests (emission, hashrate drop, fee spike)
├── benches/
│   └── benchmarks.rs    # Criterion benchmarks for tx, PoV, serialization
├── tests/
│   ├── chain_tests.rs   # End-to-end chain, consensus, coinbase, emission tests
│   ├── crypto_tests.rs  # Signature, encryption, VRF roundtrip tests
│   ├── p2p_tests.rs     # Wire format, mempool policy, DoS resistance tests
│   ├── storage_tests.rs # Atomic storage, snapshot, recovery tests
│   ├── treasury_tests.rs# Bonding curve and treasury pairing tests
│   ├── onion_tests.rs   # Layered decryption and constant-size tests
│   └── integration_tests.rs # Wallet encryption, sync, staking, pruning
├── Cargo.toml
├── README.md
├── LICENSE
└── .github/
    └── workflows/
        └── ci.yml
```

## JSON-RPC API

The node exposes a JSON-RPC 2.0 HTTP endpoint.

| Method | Params | Description |
|--------|--------|-------------|
| `getBalance` | `["hex_address"]` | Returns the cell count for an address. |
| `getBlock` | `[height]` | Returns the full block at the given height, or `null`. |
| `sendRawTx` | `["hex_raw_tx"]` | Validates a raw transaction and broadcasts it to the mempool. |
| `getTip` | `[]` | Returns the current tip height and block hash. |
| `getDifficulty` | `[]` | Returns the difficulty target for the next block. |
| `getPageProof` | `[cell_index]` | Returns a Merkle proof for the page containing the cell. |

Example:
```bash
curl -X POST http://localhost:9944 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getTip","params":[],"id":1}'
```

## FFI

A C-compatible API is provided for hardware wallet and mobile integration:

- `slash_generate_keypair()` → hex-encoded public key
- `slash_get_balance(hex_public)` → balance as `uint64_t`
- `slash_sign_transaction(hex_secret, hex_payload)` → hex-encoded signature
- `slash_verify_page_proof(hex_root, hex_leaf, leaf_index, siblings_json)` → `int`
- `slash_free_string(char*)`

## Network Identifiers

- **Mainnet**: `/slash/0.3.0`
- **Testnet**: `/slash/test/0.3.0`

The `TESTNET_MODE` atomic boolean switches signature hashing between the two chain IDs, preventing replay across networks.

## Emission Reference

| Era | Heights | Subsidy/block | Era supply |
|---|---|---|---|
| 0 | 0 – 420,479 | 500 | 210,240,000 |
| 1 | 420,480 – 840,959 | 250 | 105,120,000 |
| 2 | 840,960 – 1,261,439 | 125 | 52,560,000 |
| 3 | 1,261,440 – 1,681,919 | 62 | 26,069,760 |
| 4 | 1,681,920 – 2,102,399 | 31 | 13,034,880 |
| 5 | 2,102,400 – 2,522,879 | 15 | 6,307,200 |
| 6 | 2,522,880 – 2,943,359 | 7 | 2,943,360 |
| 7 | 2,943,360 – 3,363,839 | 3 | 1,261,440 |
| 8 | 3,363,840 – 3,784,319 | 1 | 420,480 |
| 9+ | from 3,784,320 | 0 | 0 |

Total: **417,957,120 cells (~41.8 % of N)**. See `SLASH_EMISSION_AND_TREASURY_DESIGN.md` for the full specification.

## Security

Please see [SECURITY.md](SECURITY.md) for our security policy and vulnerability reporting process.

## Contributing

We welcome contributions. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code style, testing, and the pull request process.

All code comments and documentation must be written in English. Comments must describe what the code does, not the development process (avoid tags like `NEW`, `CHANGE`, `FIXME` in committed code).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- RandomX by the Monero project.
- libp2p by Protocol Labs.
- Ed25519/X25519 implementations by the dalek-cryptography project.
