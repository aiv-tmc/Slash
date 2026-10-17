//! src/state/lock_range_tests/mod.rs — regression tests for full-range
//! lock registration and lock-map maintenance, split by subject.
//!
//! A locked output binds every cell of its range until the recorded
//! height: the ownership scan rejects any spend covering a live locked
//! cell anywhere inside the range, unlocked-cell selection routes around
//! the full span, and governance weight accrues over every cell. The
//! global lock cap bounds the live map on every transfer path. Pruning
//! retires a registration exactly when the executing height reaches its
//! expiry — never earlier, whatever cell the lock sits on — and a
//! rejected transfer leaves no lock entry behind. A locked output back
//! to the treasury is refused outright on every transfer path and in
//! mempool structural policy, because no key controls the treasury
//! address and a live lock inside a canonical funding range would wedge
//! every mint that selects it; canonical selection itself never returns
//! a locked range.
//!
//! Layout:
//! - `core` — registration semantics, expiry, pruning, governance weight
//! - `cap` — the global live-lock cap
//! - `treasury` — locked outputs to the treasury and lock-aware canonical
//!   selection

mod cap;
mod core;
mod treasury;
