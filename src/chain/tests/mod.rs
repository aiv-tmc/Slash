//! src/chain/tests/mod.rs — unit tests of the chain consensus rules,
//! split by subject so every file stays small enough to read whole.
//!
//! Every test builds its own genesis chain and drives the public and
//! crate-internal validation surfaces directly; no network, disk, or wall
//! clock outside the median-time rule participates. The shared fixtures
//! grind nonces through the light verification path at difficulty 1, so
//! no test ever allocates a full-memory RandomX dataset, and the
//! header-schedule tests push synthetic headers directly so no
//! proof-of-work context is allocated per block at all.
//!
//! Layout:
//! - `fixtures` — shared block builders and the nonce search
//! - `meta_tests` — side-fork admission, orphan adoption, recovery replay
//! - `schedule_tests` — retarget cadence, clamping, zero-difficulty PoW
//! - `emission_tests` — the subsidy schedule, eras, the perpetual slot
//! - `reorg_tests` — deployment rollback across a reorg
//! - `headers_tests` — header-batch validation and the signature domain
//! - `caps_tests` — per-transaction range and page amplification caps

mod caps_tests;
mod emission_tests;
mod fixtures;
mod headers_tests;
mod meta_tests;
mod reorg_tests;
mod schedule_tests;

pub(crate) use fixtures::*;
