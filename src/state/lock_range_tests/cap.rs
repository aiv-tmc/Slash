//! The global live-lock cap: the map holds at most MAX_LOCKED_CELLS
//! live registrations across all transactions, and expired registrations
//! release their capacity.

use super::core::{sign_treasury, with_signer};
use crate::state::{Output, State, MAX_LOCKED_CELLS, PAGE_SIZE, TREASURY};

#[test]
fn global_lock_cap_rejects_transfers_past_the_live_map() {
    // The global lock cap bounds the number of live locked cells, not
    // the width of a single transaction: once the map holds
    // MAX_LOCKED_CELLS live entries, any further transfer carrying
    // locked outputs is rejected before committing anything, and
    // expired registrations release their capacity.
    let mut state = State::genesis();
    let sk = with_signer(&mut state);
    let owner = [5u8; 32];
    // Fill the map to exactly the cap. Every input range must stay
    // inside a single page, so the fill walks the pages one treasury
    // mint at a time, locking each page-sized span until height 1000.
    let mut start = 0u64;
    while start < MAX_LOCKED_CELLS {
        let end = (start + PAGE_SIZE).min(MAX_LOCKED_CELLS);
        let outputs = vec![Output {
            start,
            end,
            to: owner,
            lock: Some(1000),
        }];
        let sig = sign_treasury(&sk, &[(start, end)], &outputs);
        assert!(state.tx(
            TREASURY,
            &[(start, end)],
            &outputs,
            &sig,
            0,
            crate::chain::MAINNET_ID.as_bytes(),
            0,
            &None
        ));
        assert_eq!(state.locks.len() as u64, end);
        start = end;
    }
    assert_eq!(state.locks.len() as u64, MAX_LOCKED_CELLS);
    // One more locked cell at height 0 exceeds the live cap: the whole
    // transfer is rejected and the map is untouched.
    let over_outputs = vec![
        Output {
            start: MAX_LOCKED_CELLS,
            end: MAX_LOCKED_CELLS + 1,
            to: owner,
            lock: Some(2000),
        },
        Output {
            start: MAX_LOCKED_CELLS + 1,
            end: MAX_LOCKED_CELLS + 100,
            to: owner,
            lock: None,
        },
    ];
    let over_sig = sign_treasury(
        &sk,
        &[(MAX_LOCKED_CELLS, MAX_LOCKED_CELLS + 100)],
        &over_outputs,
    );
    assert!(!state.tx(
        TREASURY,
        &[(MAX_LOCKED_CELLS, MAX_LOCKED_CELLS + 100)],
        &over_outputs,
        &over_sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    assert_eq!(state.locks.len() as u64, MAX_LOCKED_CELLS);
    // At height 1000 the first ranges are expired: their registrations
    // no longer count against the cap, and a new locked transfer of the
    // same span is accepted again.
    let refill_outputs = vec![Output {
        start: MAX_LOCKED_CELLS,
        end: MAX_LOCKED_CELLS + 100,
        to: owner,
        lock: Some(3000),
    }];
    let refill_sig = sign_treasury(
        &sk,
        &[(MAX_LOCKED_CELLS, MAX_LOCKED_CELLS + 100)],
        &refill_outputs,
    );
    assert!(state.tx(
        TREASURY,
        &[(MAX_LOCKED_CELLS, MAX_LOCKED_CELLS + 100)],
        &refill_outputs,
        &refill_sig,
        1000,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
}
