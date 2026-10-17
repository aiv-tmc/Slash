//! src/dao/mod.rs — the on-chain DAO: proposals and votes ride transaction
//! memos, voting weight is snapshot-pinned locked supply, and treasury
//! movements execute only through passed proposals.
//!
//! Layout:
//! - `types` — the governance constants and the payload, status, proposal,
//!   and memo-operation types
//! - `state` — the `DaoState` aggregate and the proposal lifecycle
//! - `weight` — locked-weight scans and the quorum/majority outcome math
//! - `payload` — payload structural validation and execution

mod payload;
mod state;
mod types;
mod weight;

pub use payload::{execute_payload, payload_valid};
pub use state::DaoState;
pub use types::*;
pub use weight::{close_outcome, locked_weight, total_locked_weight};
