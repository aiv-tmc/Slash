//! Chain: consensus core of the Slash protocol.
//!
//! This module owns every rule that decides which blocks and transactions
//! are part of the canonical ledger: block and transaction structures, the
//! emission schedule, proof-of-work verification, difficulty retargeting,
//! version-bit soft-fork signaling, reorgs, side-fork and orphan handling,
//! and the block-application pipeline shared by live sync, mining, and
//! crash recovery.
//!
//! Layout:
//! - `params` — consensus constants
//! - `subsidy` — the emission schedule
//! - `types` — block, transaction, header, result, and error types
//! - `version_bits` — soft-fork deployment records
//! - `chain` — the `Chain` aggregate and its constructors
//! - `pow` — proof-of-work verification and the PoW slot derivation
//! - `difficulty` — retargeting and difficulty lookups
//! - `meta` — block hashing, median time, checkpoints, `check_block_meta`
//! - `coinbase` — coinbase shape validation and construction
//! - `execution` — the speculative block execution pipeline
//! - `pairing` — the treasury buy/sell pairing tables and width arithmetic
//! - `apply` — the commit path (`apply`, `apply_recovered`)
//! - `validation` — block/transaction validation and the amplification caps
//! - `sighash` — the transaction signature hash
//! - `batch` — header-batch validation for header-first sync
//! - `ingress` — inbound block dispatch, duplicate detection, entry gates
//! - `forks` — competing-branch validation and side-fork retention
//! - `orphans` — the bounded orphan pool and its retry pass
//! - `reorg` — fork adoption, state/deployment rewind, work comparison
//! - `deployments` — the version-bit deployment lifecycle advance
//! - `history` — the bounded state/deployment history records
//! - `tests` — unit tests (test-only)
//!
//! This root file declares the submodules and re-exports their public
//! items so that downstream code keeps addressing everything through
//! `crate::chain::…` regardless of which file physically defines it.

mod apply;
mod batch;
// The `chain` submodule holds the `Chain` aggregate itself; the inception
// lint fires on the file naming convention, which the project keeps so
// every submodule addresses its subject directly.
#[allow(clippy::module_inception)]
mod chain;
mod coinbase;
mod deployments;
mod difficulty;
mod execution;
mod forks;
mod history;
mod ingress;
mod meta;
mod orphans;
pub(crate) mod pairing;
mod params;
mod pow;
mod reorg;
mod sighash;
mod subsidy;
#[cfg(test)]
mod tests;
mod types;
mod validation;
mod version_bits;

pub use chain::*;
pub use params::*;
pub use pow::*;
pub use subsidy::*;
pub use types::*;
pub use version_bits::*;
