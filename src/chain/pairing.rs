//! Treasury pairing tables and the width arithmetic they run on.
//!
//! Block execution and mempool admission share the same pairing model: a
//! buy pairs one earlier vault payment with one mint, a sell pairs one
//! earlier treasury-returning transfer with one vault payout at exactly
//! the curve sell price. The tables live in one struct so both sides of
//! the curve enforce the one-payment-one-mint and one-sell-one-payout
//! invariants in one place. The width helpers use checked arithmetic
//! throughout: an output range with a malformed width fails closed as
//! `None` instead of wrapping, and the callers reject the transaction.

use super::types::{Block, BlockError, Output, Tx};
use crate::state::{State, TREASURY, TREASURY_VAULT};
use std::collections::HashMap;

/// The funding source of a treasury-sender transaction, classified by
/// the ownership of its inputs. Treasury-owned inputs make it a curve
/// mint; vault-owned inputs make it a sell payout.
pub(crate) enum Funding {
    Mint,
    Payout,
}

/// The pairing state of one block's transaction list.
pub(crate) struct PairingTables {
    /// Consumed vault payments for the buy side: maps the index of a
    /// payment transaction to the index of the mint it funded, so one
    /// payment can never fund two mints.
    consumed_buys: HashMap<usize, usize>,
    /// Pending sells for the sell side: (transaction index, cells sold)
    /// for every executed ordinary transaction that paid cells back to
    /// the treasury address and has not been refunded by a payout yet.
    pending_sells: Vec<(usize, u64)>,
}

impl PairingTables {
    pub(crate) fn new() -> Self {
        Self {
            consumed_buys: HashMap::new(),
            pending_sells: Vec::new(),
        }
    }

    /// Classify a treasury-sender transaction by the ownership of its
    /// inputs against the executing state. Exactly one of the two
    /// ownership flags may hold: a span owned by neither address has no
    /// funding source, and a span owned by both is structurally
    /// impossible for non-empty inputs. Empty inputs leave both flags set
    /// and are rejected through the same arm.
    pub(crate) fn classify(state: &State, tx: &Tx, height: u64) -> Result<Funding, BlockError> {
        let mut treasury_owned = true;
        let mut vault_owned = true;
        for &(s, e) in &tx.inputs {
            if !state.owns(TREASURY, s, e, height) {
                treasury_owned = false;
            }
            if !state.owns(TREASURY_VAULT, s, e, height) {
                vault_owned = false;
            }
        }
        match (treasury_owned, vault_owned) {
            (true, false) => Ok(Funding::Mint),
            (false, true) => Ok(Funding::Payout),
            _ => Err(BlockError::InvalidTx),
        }
    }

    /// Pair a mint at `mint_index` with the earliest earlier ordinary
    /// transaction whose payment into the treasury vault covers `price`
    /// and has not funded a mint yet. Returns false when no unconsumed
    /// payment qualifies, in which case the mint has no funding reason
    /// and the block is invalid.
    pub(crate) fn pair_buy(&mut self, block: &Block, mint_index: usize, price: u64) -> bool {
        for (j, earlier) in block.txs[..mint_index].iter().enumerate() {
            if earlier.from == TREASURY || self.consumed_buys.contains_key(&j) {
                continue;
            }
            if vault_payment(earlier) >= price {
                self.consumed_buys.insert(j, mint_index);
                return true;
            }
        }
        false
    }

    /// Record an ordinary transaction's payment back to the treasury
    /// address as a pending sell. A sell that is never matched by a
    /// payout simply burns the cells: the sender receives nothing back,
    /// and the curve counters only move for paired sells.
    pub(crate) fn record_sell(&mut self, tx_index: usize, sold: u64) {
        if sold > 0 {
            self.pending_sells.push((tx_index, sold));
        }
    }

    /// Match a payout against the earliest pending sell whose curve sell
    /// price at `total_sold_at_start` equals the payout exactly. The
    /// price is evaluated at the curve position the block started with,
    /// so an intra-block buy cannot inflate the refund of a sell inside
    /// the same block. Removes and returns the matched sold amount on
    /// success; returns None when no pending sell prices exactly to the
    /// payout — overpaying would drain the vault, underpaying would
    /// short the seller, and a payout without a matching sell has no
    /// funding reason.
    pub(crate) fn match_payout(&mut self, payout: u64, total_sold_at_start: u64) -> Option<u64> {
        let position = self.pending_sells.iter().position(|&(_, sold)| {
            crate::treasury::sell_price(sold, total_sold_at_start) == payout
        })?;
        Some(self.pending_sells.remove(position).1)
    }
}

/// Sum the widths of output ranges with checked arithmetic: a range whose
/// end does not exceed its start, or a sum that overflows u64, fails
/// closed as None. Consensus callers treat None as a malformed
/// transaction and reject it.
pub(crate) fn total_width(outputs: &[Output]) -> Option<u64> {
    outputs.iter().try_fold(0u64, |acc, o| {
        let width = o.end.checked_sub(o.start)?;
        acc.checked_add(width)
    })
}

/// The total payment one transaction sends into the treasury vault,
/// computed with checked arithmetic. Treasury senders contribute nothing:
/// only ordinary transactions can fund a mint.
pub(crate) fn vault_payment(tx: &Tx) -> u64 {
    if tx.from == TREASURY {
        return 0;
    }
    tx.outputs
        .iter()
        .filter(|o| o.to == TREASURY_VAULT)
        .try_fold(0u64, |acc, o| {
            let width = o.end.checked_sub(o.start)?;
            acc.checked_add(width)
        })
        .unwrap_or(0)
}

/// The total payment one ordinary transaction sends back to the treasury
/// address, computed with checked arithmetic. Treasury senders contribute
/// nothing: only ordinary transactions can be sells.
pub(crate) fn treasury_returned(tx: &Tx) -> u64 {
    if tx.from == TREASURY {
        return 0;
    }
    tx.outputs
        .iter()
        .filter(|o| o.to == TREASURY)
        .try_fold(0u64, |acc, o| {
            let width = o.end.checked_sub(o.start)?;
            acc.checked_add(width)
        })
        .unwrap_or(0)
}
