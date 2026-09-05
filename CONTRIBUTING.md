# Contributing to Slash Protocol

Thank you for your interest in contributing. This document outlines the process and standards we follow.

## Code of Conduct

- Be respectful and constructive in all interactions.
- Focus on technical merit and reproducible evidence.
- Harassment, discrimination, or personal attacks will not be tolerated.

## Development Environment

### Prerequisites

- Rust 1.75 or later (`rustup update stable`)
- Cargo
- CMake, OpenSSL headers, pkg-config

### Setup

```bash
git clone https://github.com/slash-protocol/slash.git
cd slash
cargo build --release
```

### Running Tests

All changes must pass the full test suite before submission:

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo doc --no-deps
```

## Coding Standards

### Language

- **All comments, documentation, variable names, and user-facing strings must be in English.**
- This includes inline comments, doc comments (`///`), module-level documentation (`//!`), and error messages.

### Comment Style

- Comments must describe **what the code does** and **why**, not the history of changes.
- **Forbidden**: `NEW`, `CHANGE`, `OLD`, `FIXME`, `HACK`, `TEMP`.
- **Allowed**: explaining algorithms, invariants, safety conditions, and design trade-offs.

Example of a good comment:
```rust
// Each worker thread searches a disjoint nonce sub-space so that
// no two threads evaluate the same candidate, maximizing CPU utilization.
```

Example of a bad comment:
```rust
// NEW: added striding to fix duplicate nonce issue from v0.1.8
```

### Formatting

- Use `rustfmt` with the default configuration.
- Run `cargo fmt` before committing.
- Maximum line length is 100 characters where practical.

### Linting

- All code must pass `cargo clippy` with zero warnings.
- Explicitly allow lints only at the module level with a documented reason.

### Testing

- Every bug fix must include a regression test.
- Every new feature must include integration tests.
- Use `setup_test_dir` from `tests/common/mod.rs` for tests that touch the filesystem.
- Use `reset_testnet()` before tests that depend on mainnet genesis.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Commit** changes with clear, descriptive messages in English.
   - Use imperative mood: `Add` instead of `Added` or `Adds`.
   - Reference issues where applicable: `Fix side-fork block loss (closes #42)`.
3. **Push** your branch and open a Pull Request against `main`.
4. Ensure **CI passes** (build, test, clippy, format, documentation).
5. Request review from at least one maintainer.
6. Address review feedback promptly and push updates to the same branch.

## Commit Message Format

```
Short (50 chars or less) summary

More detailed explanatory text, if necessary. Wrap it to about 72
characters. Explain the problem that this commit solves and how it
solves it.

Reference issues or pull requests: Closes #123, Relates to #456
```

## Areas Needing Help

- **Performance**: Streaming block loading (L2), incremental global root (L9), O(1) duplicate detection (L3).
- **Networking**: NAT traversal (relay + dcutr), peer scoring, connection limits.
- **Tooling**: CLI wallet improvements, WASM crypto bindings, block explorer indexer.
- **Documentation**: Architecture deep-dives, API examples, deployment guides.

## Questions?

Open a [Discussion](https://github.com/slash-protocol/slash/discussions) or reach out in the development channel linked in the repository readme.
