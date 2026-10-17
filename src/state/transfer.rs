// The transaction entry point takes the consensus parameter set verbatim
// (sender, inputs, outputs, signature, height, chain id, scheme, memo);
// bundling it into a struct would churn every caller — consensus,
// mempool, fixtures, FFI — without removing a real hazard.
#![allow(clippy::too_many_arguments)]

//! The transfer pipeline: the single entry point `tx` plus the internal
//! apply stage it drives.
//!
//! A transfer is staged on a scratch page map and applied to the live map
//! only when every check — packing, per-page balance, ownership with locks,
//! signatures, minimums, fees, the dev-fund share, the treasury-lock rule,
//! and the global lock cap — passed, so a rejected transaction leaves no
//! partial mutation behind. Lock registrations stage alongside the pages
//! and commit under the same gate: a locked output binds every cell of its
//! range, records its creation height for governance snapshot weight, and
//! a rejected transfer must not leave any lock entry behind in either map.

use super::page::Output;
use super::page::{Page, R};
use super::params::{
    page_id, page_offset, page_size, DEV_FUND, FEE_VAULT, MAX_LOCKED_CELLS, MIN,
    MIN_FEE_DENOMINATOR, N, TREASURY,
};
use super::state::State;
use std::collections::{BTreeMap, HashMap};

impl State {
    /// Execute a transaction: structure, conservation, fee, ownership,
    /// signature, and per-page balance, in that order. Rejection leaves
    /// the state untouched: every mutation is staged on a scratch page map
    /// and committed only when all checks pass.
    pub fn tx(
        &mut self,
        from: [u8; 32],
        inputs: &[(u64, u64)],
        outputs: &[Output],
        sig: &[u8],
        height: u64,
        chain_id: &[u8],
        scheme: u8,
        memo: &Option<Vec<u8>>,
    ) -> bool {
        if inputs.is_empty() || outputs.is_empty() {
            return false;
        }
        // Inputs must be sorted and non-overlapping, so staged removal can
        // walk them in order and every cell is charged exactly once.
        let mut prev_end = 0u64;
        for &(s, e) in inputs {
            if e <= s || s < prev_end {
                return false;
            }
            prev_end = e;
        }
        // Outputs must pack the inputs exactly in declaration order.
        let mut cursor = inputs[0].0;
        for out in outputs {
            if out.end <= out.start || out.start != cursor {
                return false;
            }
            cursor = out.end;
        }
        if cursor != prev_end {
            return false;
        }
        let total_out: u64 = outputs.iter().map(|o| o.end - o.start).sum();
        if total_out < MIN {
            return false;
        }
        if scheme > 1 {
            return false;
        }
        // A locked output back to the treasury is refused outright: no key
        // controls the treasury address, so a lock on a treasury-owned
        // cell could never be removed by spending it, and a live lock
        // inside a canonical funding range would wedge every mint that
        // selects that range. The refusal runs before any staging, so the
        // lock maps are never touched.
        if outputs.iter().any(|o| o.to == TREASURY && o.lock.is_some()) {
            return false;
        }
        // The treasury sender is not a user key: a treasury transaction
        // must be signed by the configured treasury signer, and a chain
        // without a configured signer refuses every treasury transaction
        // by construction. The check runs before any staging, so a
        // rejection never touches the state.
        if from == TREASURY {
            if self.treasury_signer == [0u8; 32] {
                return false;
            }
            let hash = crate::chain::Chain::tx_signature_hash(
                &from, inputs, outputs, chain_id, scheme, memo,
            );
            if !crate::crypto::verify(&self.treasury_signer, &hash, sig) {
                return false;
            }
        } else {
            // Signature over the shared hash: sender, inputs, outputs,
            // chain identifier, scheme, and memo. The digest function
            // lives on the chain so mempool and block paths compute the
            // identical hash.
            let hash = crate::chain::Chain::tx_signature_hash(
                &from, inputs, outputs, chain_id, scheme, memo,
            );
            let ok = crate::crypto::verify(&from, &hash, sig);
            if !ok {
                return false;
            }
        }
        // Fee: outputs to the fee vault must total at least total_out /
        // MIN_FEE_DENOMINATOR, recomputed from the transaction itself.
        // Treasury sends — the coinbase and the curve pairing mints and
        // payouts — are consensus-only constructions and never pay the
        // user fee.
        let fee_out: u64 = outputs
            .iter()
            .filter(|o| o.to == FEE_VAULT)
            .map(|o| o.end - o.start)
            .sum();
        if from != TREASURY && fee_out.saturating_mul(MIN_FEE_DENOMINATOR) < total_out {
            return false;
        }
        // Dev-fund share while configured. Zero disables the rule entirely.
        // Dev-fund spends and treasury paths are exempt: the dev fund
        // cannot pay itself, and treasury transfers are consensus
        // constructions.
        if self.dev_fee_bps > 0 && from != DEV_FUND && from != TREASURY {
            let dev_out: u64 = outputs
                .iter()
                .filter(|o| o.to == DEV_FUND)
                .map(|o| o.end - o.start)
                .sum();
            let required = (total_out.saturating_mul(self.dev_fee_bps) / 10_000).max(1);
            if dev_out < required {
                return false;
            }
        }
        self.apply_transfer(from, inputs, outputs, height)
    }

    /// Stage a transfer on a scratch page map, then commit. Every check
    /// runs before any mutation of the live map, so a rejection leaves the
    /// state exactly as it was. Ownership failures short-circuit before
    /// any page materialization work.
    pub(crate) fn apply_transfer(
        &mut self,
        from: [u8; 32],
        inputs: &[(u64, u64)],
        outputs: &[Output],
        height: u64,
    ) -> bool {
        // Locked outputs to the treasury are structurally impossible and
        // refused here so that no caller of the transfer engine — user
        // transactions, coinbase mints, DAO mints, vault payouts — can
        // ever route a lock onto an address no key controls.
        if outputs.iter().any(|o| o.to == TREASURY && o.lock.is_some()) {
            return false;
        }
        // Stage on a copy of the dirty map so a failed transfer never
        // materializes pages or mutates ranges.
        let mut staged = self.pages.clone();
        let mut per_page: BTreeMap<u16, i128> = BTreeMap::new();
        // Balance-cache deltas accumulate alongside the page staging and
        // commit only when every check passed. The treasury debit starts
        // from the full unissued supply: the cache is filled lazily, so a
        // treasury entry debited before any credit exists starts at N.
        let mut delta_cache: HashMap<[u8; 32], i128> = HashMap::new();
        // Lock registrations stage alongside the pages: a locked output
        // binds every cell of its range until the recorded height, so a
        // rejected transfer must not leave any lock entry behind in
        // either map.
        let mut staged_locks: Vec<(u64, u64, u64)> = Vec::new();
        // Verify ownership and remove the inputs from the staged map. Each
        // input span is checked with locks inside `owns`.
        for &(s, e) in inputs {
            let pid = page_id(s);
            if !self.owns(from, s, e, height) {
                return false;
            }
            let page = staged.entry(pid).or_insert_with(|| {
                let mut p = Page {
                    ranges: BTreeMap::new(),
                };
                p.ranges.insert(
                    0,
                    R {
                        e: page_size(pid),
                        o: TREASURY,
                    },
                );
                p
            });
            if !page.remove_range(page_offset(s), page_offset(s) + (e - s)) {
                return false;
            }
            *per_page.entry(pid).or_insert(0) -= (e - s) as i128;
            *delta_cache.entry(from).or_insert(0) -= (e - s) as i128;
        }
        // Insert the outputs and accumulate the per-page balance delta.
        for out in outputs {
            let pid = page_id(out.start);
            let page = staged.entry(pid).or_insert_with(|| {
                let mut p = Page {
                    ranges: BTreeMap::new(),
                };
                p.ranges.insert(
                    0,
                    R {
                        e: page_size(pid),
                        o: TREASURY,
                    },
                );
                p
            });
            page.insert_output(
                page_offset(out.start),
                page_offset(out.start) + (out.end - out.start),
                out.to,
            );
            *per_page.entry(pid).or_insert(0) += (out.end - out.start) as i128;
            *delta_cache.entry(out.to).or_insert(0) += (out.end - out.start) as i128;
            // A locked output locks every cell of its range until the
            // recorded height. The registration itself stages here and
            // commits only when every check passed.
            if let Some(lock) = out.lock {
                staged_locks.push((out.start, out.end, lock));
            }
        }
        // Per-page balance: each affected page must net to exactly zero, so
        // cells cannot be smuggled across page boundaries inside one
        // transaction.
        for delta in per_page.values() {
            if *delta != 0 {
                return false;
            }
        }
        // Global lock cap: the live map plus this transaction's locked
        // cells must stay within MAX_LOCKED_CELLS. Only locks still live
        // at the executing height count — a lock binds spending while its
        // expiry is strictly greater than the height, the same predicate
        // the ownership scan uses — so expired entries, which are due for
        // pruning, neither block spending nor consume capacity.
        let live_locks = self
            .locks
            .values()
            .filter(|&&expiry| expiry > height)
            .count() as u64;
        let new_locked: u64 = staged_locks.iter().map(|(s, e, _)| e - s).sum();
        if live_locks.saturating_add(new_locked) > MAX_LOCKED_CELLS {
            return false;
        }
        // Commit the staged lock registrations: every cell of every
        // locked output range is registered individually in both global
        // maps — the expiry it binds spending with, and the creation
        // height governance snapshot weight reads — so ownership checks,
        // unlocked-cell selection, and weight scans observe the full
        // locked span.
        for (s, e, lock) in staged_locks {
            for cell in s..e {
                self.locks.insert(cell, lock);
                self.lock_created.insert(cell, height);
            }
        }
        // Apply the staged pages to the live map, dropping pristine pages
        // that returned to the canonical single-range form.
        for (pid, page) in staged {
            if page.ranges.len() == 1 {
                if let Some((&s, r)) = page.ranges.iter().next() {
                    if s == 0 && r.o == TREASURY && r.e == page_size(pid) {
                        self.pages.remove(&pid);
                        continue;
                    }
                }
            }
            self.pages.insert(pid, page);
        }
        // Commit the balance cache deltas only after every page check
        // passed, so a rejected transfer leaves the cache untouched too.
        // A treasury debit on an untouched ledger starts from the full
        // unissued supply; every other address starts from zero.
        for (owner, d) in delta_cache {
            let default = if owner == TREASURY { N } else { 0 };
            let entry = self.balance_cache.entry(owner).or_insert(default);
            *entry = (*entry as i128 + d) as u64;
        }
        true
    }

    /// Remove an owned span from the live map for a spend, re-checking
    /// ownership with locks first. The balance cache debits in lockstep;
    /// a treasury debit on an untouched ledger starts from the full
    /// unissued supply.
    pub(crate) fn remove_for_spend(
        &mut self,
        owner: [u8; 32],
        start: u64,
        end: u64,
        height: u64,
    ) -> bool {
        if !self.owns(owner, start, end, height) {
            return false;
        }
        let pid = page_id(start);
        let page = self.get_page_mut(pid);
        if !page.remove_range(page_offset(start), page_offset(start) + (end - start)) {
            return false;
        }
        self.evict_if_pristine(pid);
        let default = if owner == TREASURY { N } else { 0 };
        *self.balance_cache.entry(owner).or_insert(default) -= end - start;
        true
    }
}
