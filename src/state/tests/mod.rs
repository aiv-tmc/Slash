//! Unit tests of the paged state engine, split by subject.
//!
//! The suite pins the structural invariants of the ledger — conservation
//! of the balance-cache sum, gapless page surgery, lock semantics inside
//! merged owner ranges, per-page balance, rejection without partial
//! mutation, and the canonical selection golden vectors — plus the
//! consensus security rules around treasury and dev-fund spending. Every
//! test drives the public state API directly; no chain or network state
//! participates.
//!
//! Layout:
//! - `engine` — conservation, lock-release ordering, and the shared
//!   treasury-signing fixtures (`with_signer`, `sign_treasury`)
//! - `mining` — the PoW slot mint and single-page mining rules
//! - `transfers` — ownership, overspend, and cross-page balance rules
//! - `treasury` — treasury signer enforcement and unissued-supply debits
//! - `locks` — the lock map semantics on mining and spends
//! - `merkle` — page roots, proofs, and the global root
//! - `selection` — canonical selection golden vectors and page surgery

mod engine;
mod locks;
mod merkle;
mod mining;
mod selection;
mod transfers;
mod treasury;

use super::page::{verify_page_proof, Output, Page, R};
use super::params::{page_count, page_size, FEE_VAULT, MAX_LOCKED_CELLS, N, PAGE_SIZE, TREASURY};
use super::state::State;
use std::collections::BTreeMap;
