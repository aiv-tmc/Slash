//! Core lock-range semantics: one registration per cell, tail spends
//! rejected while live, full-range spend after expiry, pruning by expiry
//! (never by cell index), and governance weight over the full range.

use crate::state::{Output, State, FEE_VAULT, TREASURY};

/// Install a random treasury signer on the state and return the secret
/// key so tests can sign treasury transactions.
pub(crate) fn with_signer(state: &mut State) -> [u8; 32] {
    let (sk, pk) = crate::crypto::generate_keypair();
    state.treasury_signer = pk;
    sk
}

/// Sign a treasury transaction payload against the mainnet chain id.
pub(crate) fn sign_treasury(sk: &[u8; 32], inputs: &[(u64, u64)], outputs: &[Output]) -> Vec<u8> {
    let hash = crate::chain::Chain::tx_signature_hash(
        &TREASURY,
        inputs,
        outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    crate::crypto::sign(sk, &hash)
}

/// Fund `count` contiguous cells starting at `start` for `owner` through
/// the test backfill primitive.
fn fund(state: &mut State, start: u64, count: u64, owner: [u8; 32]) {
    for cell in start..start + count {
        state.mine(cell, owner, 0);
    }
}

/// Lock cells 0..100 of a freshly funded owner until `expiry`, paying
/// cell 100 as the fee and sending cells 100..199 to `[2u8; 32]`, and
/// assert the transfer applied.
fn lock_hundred(state: &mut State, sk: &[u8; 32], pk: [u8; 32], expiry: u64) {
    let funded_recipient = [2u8; 32];
    fund(state, 0, 200, pk);
    let outputs = vec![
        Output {
            start: 0,
            end: 100,
            to: pk,
            lock: Some(expiry),
        },
        Output {
            start: 100,
            end: 199,
            to: funded_recipient,
            lock: None,
        },
        Output {
            start: 199,
            end: 200,
            to: FEE_VAULT,
            lock: None,
        },
    ];
    let hash = crate::chain::Chain::tx_signature_hash(
        &pk,
        &[(0, 200)],
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(sk, &hash);
    assert!(state.tx(
        pk,
        &[(0, 200)],
        &outputs,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
}

/// Sign and attempt a spend of `inputs` by `pk` at `height` with the
/// given outputs; returns the engine verdict.
fn attempt_spend(
    state: &mut State,
    sk: &[u8; 32],
    pk: [u8; 32],
    inputs: &[(u64, u64)],
    outputs: Vec<Output>,
    height: u64,
) -> bool {
    let hash = crate::chain::Chain::tx_signature_hash(
        &pk,
        inputs,
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(sk, &hash);
    state.tx(
        pk,
        inputs,
        &outputs,
        &sig,
        height,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    )
}

#[test]
fn locked_range_tail_cannot_be_spent_before_expiry() {
    // A locked output binds every cell of its range, not just its first
    // cell: a spend covering only the tail of the range is rejected
    // while the lock is live, and the rejection leaves no partial
    // mutation — no page, no cache entry, and no lock registration.
    let mut state = State::genesis();
    let (sk, pk) = crate::crypto::generate_keypair();
    lock_hundred(&mut state, &sk, pk, 10);
    // Every cell of the locked range carries its own registration.
    assert_eq!(state.locks.len(), 100);
    assert_eq!(state.locks.get(&0), Some(&10));
    assert_eq!(state.locks.get(&99), Some(&10));
    // A spend covering only the tail of the locked range is rejected at
    // height 5: cells 1..100 are live-locked.
    let recipient = [3u8; 32];
    let tail_outputs = vec![
        Output {
            start: 1,
            end: 100,
            to: recipient,
            lock: None,
        },
        Output {
            start: 100,
            end: 101,
            to: FEE_VAULT,
            lock: None,
        },
    ];
    let pages_before = state.pages.clone();
    let cache_before = state.balance_cache.clone();
    assert!(!attempt_spend(
        &mut state,
        &sk,
        pk,
        &[(1, 101)],
        tail_outputs,
        5
    ));
    assert_eq!(state.pages, pages_before);
    assert_eq!(state.balance_cache, cache_before);
    // The rejected transfer added no lock registrations.
    assert_eq!(state.locks.len(), 100);
}

#[test]
fn full_locked_range_spend_succeeds_after_expiry() {
    // Once the recorded height is reached, every cell of the range is
    // spendable again: the lock binds spending only while its expiry is
    // strictly greater than the executing height.
    let mut state = State::genesis();
    let (sk, pk) = crate::crypto::generate_keypair();
    lock_hundred(&mut state, &sk, pk, 10);
    let funded_recipient = [2u8; 32];
    let spend_recipient = [3u8; 32];
    // At the expiry height the lock no longer blocks: the full range
    // moves in one spend.
    let spend_outputs = vec![
        Output {
            start: 0,
            end: 99,
            to: spend_recipient,
            lock: None,
        },
        Output {
            start: 99,
            end: 100,
            to: FEE_VAULT,
            lock: None,
        },
    ];
    assert!(attempt_spend(
        &mut state,
        &sk,
        pk,
        &[(0, 100)],
        spend_outputs,
        10
    ));
    assert_eq!(state.balance(pk), 0);
    assert_eq!(state.balance(funded_recipient), 99);
    assert_eq!(state.balance(spend_recipient), 99);
}

#[test]
fn locked_range_weight_counts_every_cell() {
    // Governance weight accrues over every cell of a locked range: the
    // snapshot-pinned weight scan observes the full registered span, so
    // a range locked past the snapshot horizon contributes its full
    // width to the owner and to the quorum denominator.
    let mut state = State::genesis();
    let (sk, pk) = crate::crypto::generate_keypair();
    // The governance weight horizon is DAO_LOCK_MIN (10_000) blocks past
    // the snapshot, so a lock at exactly 10_000 with snapshot 0 sits on
    // the horizon and counts.
    lock_hundred(&mut state, &sk, pk, 10_000);
    assert_eq!(crate::dao::locked_weight(&state, pk, 0), 100);
    assert_eq!(crate::dao::total_locked_weight(&state, 0), 100);
    // An unlocked range of equal size accrues no weight.
    let unlocked_owner = [4u8; 32];
    fund(&mut state, 1000, 100, unlocked_owner);
    assert_eq!(crate::dao::locked_weight(&state, unlocked_owner, 0), 0);
    assert_eq!(crate::dao::total_locked_weight(&state, 0), 100);
}

#[test]
fn prune_locks_filters_by_expiry_not_cell_index() {
    // Pruning retires a registration exactly when the executing height
    // reaches its expiry — never earlier, and regardless of where the
    // locked cell lives in the index space: a lock on a low-indexed cell
    // with a far expiry survives pruning at small heights and keeps
    // blocking spends, and pruning at the expiry releases it.
    let mut state = State::genesis();
    let (sk, pk) = crate::crypto::generate_keypair();
    lock_hundred(&mut state, &sk, pk, 1_000_000);
    assert_eq!(state.locks.len(), 100);
    // Pruning at height 100 is far below the expiry: every registration
    // survives, including those on cells whose index is below 100.
    state.prune_locks(100);
    assert_eq!(state.locks.len(), 100);
    // A spend at height 100 is still blocked: the locks are live.
    let recipient = [6u8; 32];
    let tail_outputs = vec![
        Output {
            start: 1,
            end: 100,
            to: recipient,
            lock: None,
        },
        Output {
            start: 100,
            end: 101,
            to: FEE_VAULT,
            lock: None,
        },
    ];
    assert!(!attempt_spend(
        &mut state,
        &sk,
        pk,
        &[(1, 101)],
        tail_outputs,
        100
    ));
    // Pruning at the expiry height releases the whole range at once.
    state.prune_locks(1_000_000);
    assert!(state.locks.is_empty());
}
