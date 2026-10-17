//! The conservation invariant and the lock-release ordering: the
//! balance-cache sum is exactly N after every mutation, and an expired
//! lock moves the cell only when the claimant differs from the owner.

use super::*;

/// Install a random treasury signer on the state and return the secret
/// key so tests can sign treasury transactions.
pub(super) fn with_signer(state: &mut State) -> [u8; 32] {
    let (sk, pk) = crate::crypto::generate_keypair();
    state.treasury_signer = pk;
    sk
}

/// Sign a treasury transaction payload against the mainnet chain id.
pub(super) fn sign_treasury(sk: &[u8; 32], inputs: &[(u64, u64)], outputs: &[Output]) -> Vec<u8> {
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

#[test]
fn conservation_invariant() {
    // Every mutation keeps the balance cache sum at exactly N. Mining a
    // cell moves one unit of balance from the treasury to the owner;
    // re-mining an owned cell is a no-op, and the lock release path
    // must be too. The conservation invariant pins the total.
    let mut state = State::genesis();
    let owner = [1u8; 32];
    state.mine(100, owner, 0);
    assert_eq!(state.balance(owner), 1);
    assert_eq!(state.balance(TREASURY), N - 1);
    state.mine(100, owner, 0);
    state.mine(100, owner, 5);
    assert_eq!(state.balance(owner), 1);
    assert_eq!(state.balance(TREASURY), N - 1);
    let supply: u64 = state.balance_cache.values().sum();
    assert_eq!(supply, N);
}

#[test]
fn mine_expired_lock_releases_only_after_reassignment() {
    // An expired lock with a different claimant must move the cell and
    // drop the lock; an expired lock whose claimant already owns the
    // cell must drop only the lock. Both paths leave the balance sum
    // exact, which pins the lock-release ordering against the page
    // mutation.
    let mut state = State::genesis();
    let a = [1u8; 32];
    let b = [2u8; 32];
    state.mine(100, a, 0);
    state.locks.insert(100, 10);
    state.mine(100, b, 10);
    assert_eq!(state.get(100).map(|(_, _, o)| o), Some(b));
    assert!(!state.locks.contains_key(&100));
    assert_eq!(state.balance(a), 0);
    assert_eq!(state.balance(b), 1);
    let supply: u64 = state.balance_cache.values().sum();
    assert_eq!(supply, N);
    // Re-lock and expire with the same owner: only the lock goes away.
    state.locks.insert(100, 20);
    state.mine(100, b, 20);
    assert_eq!(state.get(100).map(|(_, _, o)| o), Some(b));
    assert!(!state.locks.contains_key(&100));
    assert_eq!(state.balance(b), 1);
}
