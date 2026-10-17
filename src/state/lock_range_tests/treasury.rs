//! Locked outputs to the treasury are structurally impossible: the
//! transfer engine refuses them on every path (user transactions, coinbase
//! mints, DAO mints, vault payouts), mempool structural validation rejects
//! them before any state work, and canonical selection never returns a
//! dirty range intersecting the lock map. These tests pin all three
//! layers. Balance assertions follow the balance-cache convention: an
//! untouched address reports zero, and the treasury entry starts from
//! the full unissued supply the first time the cache debits it.

use crate::chain::Chain;
use crate::state::{Output, State, TREASURY};

/// Fund `count` contiguous cells starting at `start` for `owner` through
/// the test backfill primitive. Each funded cell debits the treasury
/// cache entry, so after funding `count` cells the treasury reports
/// `N - count`.
fn fund(state: &mut State, start: u64, count: u64, owner: [u8; 32]) {
    for cell in start..start + count {
        state.mine(cell, owner, 0);
    }
}

/// Build, sign, and attempt a sale of 200 funded cells back to the
/// treasury with the given lock on the treasury-bound output: 180 cells
/// go to the treasury and the 20-cell tail pays the mandatory fee.
/// Returns the engine verdict.
fn attempt_sell_to_treasury(
    state: &mut State,
    sk: &[u8; 32],
    pk: [u8; 32],
    start: u64,
    lock: Option<u64>,
) -> bool {
    let outputs = vec![
        Output {
            start,
            end: start + 180,
            to: TREASURY,
            lock,
        },
        Output {
            start: start + 180,
            end: start + 200,
            to: crate::state::FEE_VAULT,
            lock: None,
        },
    ];
    let hash = Chain::tx_signature_hash(
        &pk,
        &[(start, start + 200)],
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(sk, &hash);
    state.tx(
        pk,
        &[(start, start + 200)],
        &outputs,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    )
}

#[test]
fn unlocked_sell_to_treasury_is_admitted() {
    // An ordinary sale returning cells to the treasury is a valid curve
    // interaction: the transfer engine accepts it, the cells return to
    // treasury ownership, and no lock registration appears. The balance
    // cache tracks the round trip exactly: 200 cells left the treasury
    // to fund the seller, 180 came back, and 20 paid the fee.
    let mut state = State::genesis();
    let (sk, pk) = crate::crypto::generate_keypair();
    fund(&mut state, 0, 200, pk);
    assert!(attempt_sell_to_treasury(&mut state, &sk, pk, 0, None));
    assert_eq!(state.balance(pk), 0);
    assert_eq!(state.balance(TREASURY), crate::state::N - 20);
    assert_eq!(state.balance(crate::state::FEE_VAULT), 20);
    assert!(state.locks.is_empty());
    assert!(state.lock_created.is_empty());
}

#[test]
fn locked_sell_to_treasury_is_rejected_by_the_engine() {
    // A locked output back to the treasury is refused by the transfer
    // engine: no key controls the treasury address, so such a lock could
    // never be spent out, and a live lock inside a canonical funding
    // range would wedge every mint that selects the range. The refusal
    // happens before staging, so the lock maps, the page map, and the
    // balance cache are all untouched.
    let mut state = State::genesis();
    let (sk, pk) = crate::crypto::generate_keypair();
    fund(&mut state, 0, 200, pk);
    let pages_before = state.pages.clone();
    let cache_before = state.balance_cache.clone();
    assert!(!attempt_sell_to_treasury(
        &mut state,
        &sk,
        pk,
        0,
        Some(u64::MAX)
    ));
    assert!(state.locks.is_empty());
    assert!(state.lock_created.is_empty());
    assert_eq!(state.pages, pages_before);
    assert_eq!(state.balance_cache, cache_before);
    assert_eq!(state.balance(pk), 200);
}

#[test]
fn locked_sell_to_treasury_is_rejected_by_mempool_structural_policy() {
    // Mempool structural validation refuses the transaction before any
    // state work, keeping admission and block execution in parity: the
    // same transaction the engine refuses inside a block never enters
    // the mempool either.
    let mut chain = Chain::genesis();
    let (sk, pk) = crate::crypto::generate_keypair();
    fund(&mut chain.state, 0, 200, pk);
    let outputs = vec![
        Output {
            start: 0,
            end: 180,
            to: TREASURY,
            lock: Some(u64::MAX),
        },
        Output {
            start: 180,
            end: 200,
            to: crate::state::FEE_VAULT,
            lock: None,
        },
    ];
    let hash = Chain::tx_signature_hash(
        &pk,
        &[(0, 200)],
        &outputs,
        chain.chain_id.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(&sk, &hash);
    let locked_tx = crate::chain::Tx {
        from: pk,
        inputs: vec![(0, 200)],
        outputs: outputs
            .iter()
            .map(|o| crate::chain::Output {
                start: o.start,
                end: o.end,
                to: o.to,
                lock: o.lock,
            })
            .collect(),
        sig,
        scheme: 0,
        memo: None,
    };
    assert!(!chain.validate_tx(&locked_tx));
    // The unlocked control transaction is admitted, so the refusal is
    // specific to the lock, not to the sale itself.
    let control_outputs = vec![
        Output {
            start: 0,
            end: 180,
            to: TREASURY,
            lock: None,
        },
        Output {
            start: 180,
            end: 200,
            to: crate::state::FEE_VAULT,
            lock: None,
        },
    ];
    let control_hash = Chain::tx_signature_hash(
        &pk,
        &[(0, 200)],
        &control_outputs,
        chain.chain_id.as_bytes(),
        0,
        &None,
    );
    let control_sig = crate::crypto::sign(&sk, &control_hash);
    let control_tx = crate::chain::Tx {
        from: pk,
        inputs: vec![(0, 200)],
        outputs: control_outputs
            .iter()
            .map(|o| crate::chain::Output {
                start: o.start,
                end: o.end,
                to: o.to,
                lock: o.lock,
            })
            .collect(),
        sig: control_sig,
        scheme: 0,
        memo: None,
    };
    assert!(chain.validate_tx(&control_tx));
}

#[test]
fn mint_over_locked_span_is_refused_by_ownership_scan() {
    // A mint debits a treasury range through the ownership scan, which
    // rejects any span covering a live lock: a lock sitting on a treasury
    // cell refuses every mint that selects it. The lock is inserted
    // directly because the transfer engine itself never produces one.
    // The treasury cache entry is never created by the refused mint, so
    // the untouched treasury still reports a zero balance.
    let mut state = State::genesis();
    let (canonical_s, canonical_e) = state
        .select_single(TREASURY, 50)
        .expect("treasury owns the supply");
    state.locks.insert(canonical_s, u64::MAX);
    assert!(!state.mint(
        &[(canonical_s, canonical_e)],
        &[Output {
            start: canonical_s,
            end: canonical_e,
            to: [9u8; 32],
            lock: None,
        }],
        0,
    ));
    assert_eq!(state.balance(TREASURY), 0);
}

#[test]
fn select_single_never_returns_a_locked_range() {
    // Canonical selection probes the lock map for every dirty candidate
    // range and skips a range that intersects a live lock: a canonical
    // funding answer must always be spendable by its owner. The probe
    // runs in global coordinates and falls through to the next dirty
    // range or, for the treasury, to a pristine page. A pristine page
    // has never been materialized, so it carries no locks by
    // construction and needs no probe.
    let mut state = State::genesis();
    let funded = crate::crypto::generate_keypair().1;
    // Materialize page 0 with a single user cell at its base: the
    // remaining page stays one treasury range, now dirty and therefore
    // subject to the lock probe.
    state.mine(0, funded, 0);
    let (s, _e) = state
        .select_single(TREASURY, 50)
        .expect("treasury owns the page tail");
    state.locks.insert(s, u64::MAX);
    let (next_s, next_e) = state
        .select_single(TREASURY, 50)
        .expect("a lock-free treasury range exists");
    assert_ne!(next_s, s);
    assert_eq!(next_e - next_s, 50);
    let (_, _, owner) = state.get(next_s).expect("range start resolves");
    assert_eq!(owner, TREASURY);
    assert!(state.locks.range(next_s..next_e).next().is_none());
}
