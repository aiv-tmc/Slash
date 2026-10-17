//! Validation gates for single transactions and whole blocks: mempool
//! admission, block pre-checks, and the structural policy both paths
//! share. Header-batch validation for header-first sync lives in
//! `batch.rs`; the transaction signature hash lives in `sighash.rs`.
//!
//! The mempool path (`validate_tx`) and the block path
//! (`execute_block_txs` in `execution.rs`) deliberately run the same
//! structural policy and the same state engine, so a transaction
//! admitted to the mempool is always executable in the next block.

use super::chain::Chain;
use super::params::{MAX_BLOCK_SIZE_BYTES, MAX_PAGES_PER_TX, MAX_RANGES_PER_TX};
use crate::state;

impl Chain {
    /// Validate a block against the current tip without applying it:
    /// metadata, then state-less execution on a speculative copy. Used by
    /// mining and by gossip admission before the block is applied.
    pub fn validate_block(&self, block: &super::types::Block) -> bool {
        if self.check_block_meta(block).is_err() {
            return false;
        }
        // Enforce an activated RequireBlockVersion2 deployment.
        let rules = crate::governance::active_rules(&self.version_bits.deployments, block.height);
        if rules
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::RequireBlockVersion2))
            && block.version < 2
        {
            return false;
        }
        // Enforce an activated MaxBlockSize deployment. The serialized
        // length is computed once and compared against the stricter of
        // the active deployment limit and the base consensus limit.
        let limit = rules
            .iter()
            .find_map(|r| match r {
                crate::governance::Rule::MaxBlockSize { max_bytes } => Some(*max_bytes),
                _ => None,
            })
            .unwrap_or(MAX_BLOCK_SIZE_BYTES)
            .min(MAX_BLOCK_SIZE_BYTES);
        if bincode::serialize(block)
            .map(|b| b.len())
            .unwrap_or(usize::MAX)
            > limit
        {
            return false;
        }
        self.execute_block_state(&self.state.clone(), block).is_ok()
    }

    /// Mempool admission for a transaction: run the structural checks and
    /// then the full state checks against the tip state without applying
    /// anything. Structural validity and policy mirror block execution so
    /// a transaction admitted here is executable in the next block.
    pub fn validate_tx(&self, tx: &super::types::Tx) -> bool {
        if !self.tx_structure_valid(tx) {
            return false;
        }
        // Speculatively execute the transaction against a clone of the tip
        // state: every consensus rule (ownership, locks, packing, fee,
        // dev share, scheme, signature, treasury signer) is enforced by
        // the same engine that executes blocks, so mempool admission and
        // block validation cannot diverge.
        let mut temp = self.state.clone();
        let height = self.tip_height() + 1;
        temp.tx(
            tx.from,
            &tx.inputs,
            &Self::to_state_outputs(&tx.outputs),
            &tx.sig,
            height,
            self.chain_id.as_bytes(),
            tx.scheme,
            &tx.memo,
        )
    }

    /// The per-transaction amplification caps: the total number of input
    /// and output ranges and the number of distinct pages the transaction
    /// touches. Both validation paths call this before any state work, so
    /// a transaction crafted to maximize per-range page-map operations or
    /// to fan out across many pages is rejected at the structural gate
    /// regardless of its signatures or funding.
    pub(crate) fn tx_caps_valid(&self, tx: &super::types::Tx) -> bool {
        if tx.inputs.len().saturating_add(tx.outputs.len()) > MAX_RANGES_PER_TX {
            return false;
        }
        let mut pages = std::collections::BTreeSet::new();
        for &(start, _) in &tx.inputs {
            pages.insert(state::page_id(start));
        }
        for out in &tx.outputs {
            pages.insert(state::page_id(out.start));
        }
        pages.len() <= MAX_PAGES_PER_TX
    }

    /// The structural policy shared by mempool admission and block
    /// validation: input sanity, exact output packing, the minimum output
    /// amount, the treasury-lock rule, the scheme gate, the mandatory
    /// fee, the dev-fund share while the rule is active, and the global
    /// lock cap.
    fn tx_structure_valid(&self, tx: &super::types::Tx) -> bool {
        if tx.inputs.is_empty() || tx.outputs.is_empty() {
            return false;
        }
        // Amplification caps run before every other structural check:
        // they are pure shape properties and bound the work of everything
        // below them.
        if !self.tx_caps_valid(tx) {
            return false;
        }
        // Inputs must be sorted and non-overlapping.
        let mut prev_end = 0u64;
        for &(s, e) in &tx.inputs {
            if e <= s || s < prev_end {
                return false;
            }
            prev_end = e;
        }
        // Outputs must pack the inputs exactly in declaration order.
        let mut cursor = tx.inputs[0].0;
        for out in &tx.outputs {
            if out.end <= out.start || out.start != cursor {
                return false;
            }
            cursor = out.end;
        }
        if cursor != tx.inputs.last().map(|(_, e)| *e).unwrap_or(0) {
            return false;
        }
        let total_out: u64 = tx.outputs.iter().map(|o| o.end - o.start).sum();
        if total_out < state::MIN {
            return false;
        }
        // A locked output back to the treasury is refused in both
        // validation paths. No key controls the treasury address, so a
        // lock there could never be spent out, and a live lock inside a
        // canonical funding range would wedge every mint that selects
        // that range. The state engine enforces the same refusal on the
        // block path, keeping mempool and consensus in parity.
        if tx
            .outputs
            .iter()
            .any(|o| o.to == state::TREASURY && o.lock.is_some())
        {
            return false;
        }
        let height = self.tip_height() + 1;
        let rules = crate::governance::active_rules(&self.version_bits.deployments, height);
        // Scheme gate: scheme 1 is accepted only while the deployment is
        // active; no other scheme exists.
        if rules
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::AllowScheme1))
        {
            if tx.scheme > 1 {
                return false;
            }
        } else if tx.scheme != 0 {
            return false;
        }
        // Mandatory fee: at least total_out / 200 (0.5%) to the vault.
        // Treasury sends are consensus-only constructions — the unsigned
        // coinbase and the curve pairing mints and payouts — and never
        // pay the user fee.
        let fee: u64 = tx
            .outputs
            .iter()
            .filter(|o| o.to == state::FEE_VAULT)
            .map(|o| o.end - o.start)
            .sum();
        if tx.from != state::TREASURY && fee.saturating_mul(state::MIN_FEE_DENOMINATOR) < total_out
        {
            return false;
        }
        // Treasury sends are consensus-only constructions (coinbase, curve
        // pairing); they never enter the mempool.
        let dao_active = rules
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::DaoV1));
        if dao_active && tx.from == state::TREASURY {
            return false;
        }
        // Dev-fund share while the rule is active, exempting treasury,
        // vault-pairing, and dev-fund-spend paths.
        let dev_active = rules
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::DevFund));
        if dev_active && tx.from != state::DEV_FUND && tx.from != state::TREASURY {
            let dev: u64 = tx
                .outputs
                .iter()
                .filter(|o| o.to == state::DEV_FUND)
                .map(|o| o.end - o.start)
                .sum();
            let required = (total_out.saturating_mul(self.state.dev_fee_bps) / 10_000).max(1);
            if dev < required {
                return false;
            }
        }
        // Global lock cap: locked outputs must keep the locked supply
        // bounded.
        let locked: u64 = tx
            .outputs
            .iter()
            .filter(|o| o.lock.is_some())
            .map(|o| o.end - o.start)
            .sum();
        if locked > state::MAX_LOCKED_CELLS {
            return false;
        }
        true
    }
}
