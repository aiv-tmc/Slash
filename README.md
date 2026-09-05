# Slash Protocol

[![CI](https://github.com/slash-protocol/slash/actions/workflows/ci.yml/badge.svg)](https://github.com/slash-protocol/slash/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

A cell-based blockchain with RandomX proof-of-work, paged multi-input state (PMIS), adaptive governance via version bits, and layered onion routing for transaction privacy.

## Overview

Slash introduces a **Paged Multi-Input State (PMIS)** engine that partitions a global ledger of one billion cells into 65,536-cell pages. This design enables:

- **O(1) balance lookups** via an incremental balance cache.
- **Atomic cross-page transactions** with speculative execution and rollback.
- **Light-client verification** through per-page Merkle roots and compact proofs.
- **Stake-locking** at the cell level for time-bound ownership.
- **Algorithmic treasury** backed by a linear bonding curve with a 2% sell spread.

Consensus is secured by **RandomX proof-of-work**, ensuring CPU-friendly and ASIC-resistant mining. The network supports soft-fork upgrades through **BIP-9 style version bits** with real signal counting and threshold enforcement.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Application Layer                    │
│    JSON-RPC API  │  FFI Bindings  │  Wallet (separate repo) │
├─────────────────────────────────────────────────────────────┤
│                         P2P Layer                            │
│  libp2p (gossipsub, mdns, identify, request-response)       │
├─────────────────────────────────────────────────────────────┤
│                       Consensus Layer                        │
│  RandomX PoW  │  Adaptive Difficulty  │  Version Bits       │
├─────────────────────────────────────────────────────────────┤
│                        State Engine                          │
│  PMIS (Paged Multi-Input State)  │  Merkle Proofs  │  Locks │
├─────────────────────────────────────────────────────────────┤
│                      Cryptographic Primitives                │
│  Ed25519  │  X25519  │  AES-256-GCM  │  Blake3  │  VRF      │
├─────────────────────────────────────────────────────────────┤
│                        Storage Layer                         │
│  Atomic Writes  │  Snapshots  │  Pruned Recovery           │
└─────────────────────────────────────────────────────────────┘
```

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

### Governance (Version Bits)
- Soft-fork deployments track lifecycle states: `Defined → Started → LockedIn → Active / Failed`.
- Real cumulative signal counting against configurable thresholds.
- Active rules include `MinTxAmount`, `MaxBlockSize`, `AllowScheme1`, and `RequireBlockVersion2`.

### Onion Routing
- Three-hop onion envelopes with fixed-size layers (1024 bytes) and inner payloads (2048 bytes).
- X25519 ephemeral keys and AES-256-GCM encryption at each hop.
- P2P forwarding uses request-response unicast to the next relay, preventing broadcast-based traffic correlation.

### Economic Layer
- **Fee Vault**: Miners claim accumulated fees without a signature.
- **Bonding Curve**: Linear price growth with 2% sell spread protecting treasury reserves.
- **Stake Lock**: Cells can be locked until a specific block height, enforced by both mining and transaction validation.

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
cargo test test_mine_genesis_to_tip

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
│   ├── chain.rs         # Block, Chain, validation, PoW verification, version bits
│   ├── state.rs         # PMIS engine, Page, State, transactions, balance cache
│   ├── crypto.rs        # Ed25519, X25519, AES-GCM, Argon2id, wallet encryption
│   ├── mining.rs        # RandomX miner with parallel extranonce search
│   ├── p2p.rs           # libp2p swarm, mempool, sync, onion unicast forwarding
│   ├── rpc.rs           # JSON-RPC HTTP server (balance, block, tx, proofs)
│   ├── governance.rs    # Soft-fork rule registry and active rule validation
│   ├── storage.rs       # Atomic file writes, snapshots, pruned recovery
│   ├── treasury.rs      # Bonding curve math and treasury state
│   ├── vrf.rs           # ECVRF-RISTRETTO255-SHA512 prove/verify
│   ├── onion.rs         # 3-hop onion envelope construction and peeling
│   ├── ffi.rs           # C-API for external wallet integration
│   └── simulation.rs    # Economic stress tests (hashrate drop, fee spike)
├── benches/
│   └── benchmarks.rs    # Criterion benchmarks for tx, PoV, serialization
├── tests/
│   ├── chain_tests.rs   # End-to-end chain, consensus, reorg tests
│   ├── crypto_tests.rs  # Signature, encryption, VRF roundtrip tests
│   ├── p2p_tests.rs     # Wire format, mempool policy, DoS resistance tests
│   ├── storage_tests.rs # Atomic storage, snapshot, recovery tests
│   ├── treasury_tests.rs# Bonding curve arithmetic and persistence tests
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

- **Mainnet**: `/slash/0.2.0`
- **Testnet**: `/slash/test/0.2.0`

The `TESTNET_MODE` atomic boolean switches signature hashing between the two chain IDs, preventing replay across networks.

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
