//! Coinbase construction and validation.
//!
//! While the subsidy is positive (eras 0-8) every block must open with
//! an unsigned treasury transaction paying exactly `subsidy_at(height)`
//! to the miner, plus the exact dev-fund share while the dev fund rule
//! is active. From era 9 the subsidy is zero, the coinbase is omitted,
//! and any treasury-shaped transaction at position 0 — signed or not —
//! is rejected, because nothing may mint without a paired buyer payment.
//! All amount arithmetic is checked: a malformed range width fails
//! validation instead of wrapping.

use super::chain::Chain;
use super::subsidy::subsidy_at;
use super::types::{Block, BlockError, Output, Tx};
use crate::state;

impl Chain {
    /// Validate the coinbase of a block against the subsidy schedule and
    /// the active rule set. While the subsidy is positive, `txs[0]` must
    /// be an unsigned treasury transaction paying exactly
    /// `subsidy_at(height)`, with outputs only to the miner plus the
    /// exact dev-fund share while the dev fund rule is active, and
    /// inputs drawn from the canonical treasury range. From era 9 the
    /// subsidy is zero, the coinbase is omitted, and any treasury-shaped
    /// first transaction is rejected because nothing may mint without a
    /// paired payment.
    pub(crate) fn validate_coinbase(
        &self,
        state: &crate::state::State,
        block: &Block,
    ) -> Result<(), BlockError> {
        let subsidy = subsidy_at(block.height);
        let active = crate::governance::active_rules(&self.version_bits.deployments, block.height);
        let dev_active = active
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::DevFund));
        if subsidy > 0 {
            let cb = block.txs.first().ok_or(BlockError::InvalidCoinbase)?;
            if cb.from != state::TREASURY {
                return Err(BlockError::InvalidCoinbase);
            }
            if !cb.sig.is_empty() {
                return Err(BlockError::InvalidCoinbase);
            }
            // The coinbase may only pay the miner and, while the dev fund
            // rule is active, the dev fund address — nothing else.
            let dev_share = if dev_active {
                subsidy.saturating_mul(state.mine_fee_bps) / 10_000
            } else {
                0
            };
            let mut miner_total = 0u64;
            let mut dev_total = 0u64;
            for out in &cb.outputs {
                // A malformed range width fails the shape check instead
                // of wrapping into a bogus total.
                let width = out
                    .end
                    .checked_sub(out.start)
                    .ok_or(BlockError::InvalidCoinbase)?;
                // The miner check comes first: a miner's own address may
                // coincide with any well-known address (including the dev
                // fund), and the coinbase pays the miner by identity, not
                // by address class. Only outputs to the dev fund that are
                // not the miner's pay count toward the dev share.
                if out.to == block.miner {
                    miner_total = miner_total
                        .checked_add(width)
                        .ok_or(BlockError::InvalidCoinbase)?;
                } else if out.to == state::DEV_FUND {
                    dev_total = dev_total
                        .checked_add(width)
                        .ok_or(BlockError::InvalidCoinbase)?;
                } else {
                    return Err(BlockError::InvalidCoinbase);
                }
            }
            // The totals must partition the subsidy exactly: the miner
            // and the dev fund together receive precisely the minted
            // amount, and the dev fund receives precisely its scheduled
            // share.
            let total = miner_total
                .checked_add(dev_total)
                .ok_or(BlockError::InvalidCoinbase)?;
            if total != subsidy || dev_total != dev_share {
                return Err(BlockError::InvalidCoinbase);
            }
            // Inputs must be the canonical treasury range for the
            // subsidy, so the mint debits unissued supply through the
            // ordinary selection path.
            let canonical = state
                .select_single(state::TREASURY, subsidy)
                .ok_or(BlockError::InvalidCoinbase)?;
            if cb.inputs.as_slice() != [canonical] {
                return Err(BlockError::InvalidCoinbase);
            }
        } else {
            // Era 9 and beyond: an empty payload is valid, but a
            // treasury-shaped first transaction is not — a signed mint at
            // position 0 has no paired payment by definition, and an
            // unsigned one would mint without authorization.
            if let Some(tx) = block.txs.first() {
                if tx.from == state::TREASURY {
                    return Err(BlockError::InvalidCoinbase);
                }
            }
        }
        Ok(())
    }

    /// Build the unsigned coinbase transaction for a candidate block:
    /// inputs from the canonical treasury range of `subsidy_at(height)`,
    /// outputs paying the miner the subsidy minus the dev-fund share and
    /// the dev fund its exact share. Returns None from era 9 onward,
    /// where the subsidy is zero and the coinbase is omitted.
    pub fn build_coinbase(
        state: &crate::state::State,
        miner: [u8; 32],
        height: u64,
        dev_share: u64,
    ) -> Option<Tx> {
        let subsidy = subsidy_at(height);
        if subsidy == 0 {
            return None;
        }
        // The canonical selection returns a single contiguous range; the
        // coinbase always spends exactly one range.
        let inputs = state.select_single(state::TREASURY, subsidy)?;
        // A caller requesting more than the subsidy gets clamped to the
        // subsidy so the outputs never exceed the inputs.
        let dev_share = dev_share.min(subsidy);
        let mut outputs = Vec::new();
        if dev_share > 0 {
            // With a dev share the single input range splits in place:
            // the dev fund takes the head of the range, the miner takes
            // the tail, and the two outputs together pack the input
            // exactly.
            let dev_start = inputs.0;
            outputs.push(Output {
                start: dev_start,
                end: dev_start + dev_share,
                to: state::DEV_FUND,
                lock: None,
            });
            outputs.push(Output {
                start: dev_start + dev_share,
                end: dev_start + subsidy,
                to: miner,
                lock: None,
            });
        } else {
            outputs.push(Output {
                start: inputs.0,
                end: inputs.0 + subsidy,
                to: miner,
                lock: None,
            });
        }
        Some(Tx {
            from: state::TREASURY,
            inputs: vec![inputs],
            outputs,
            sig: Vec::new(),
            scheme: 0,
            memo: None,
        })
    }
}
