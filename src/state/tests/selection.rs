//! Canonical selection golden vectors and page surgery: the scan order,
//! the whole-range coverage predicate, the dirty-before-pristine
//! priority, the unlocked sweep around locked runs, and adjacent-range
//! surgery. Golden vectors are serialization-level consensus: any
//! intentional change to the selection rule must update them.

use super::*;

/// Build the canonical dust layout used by the selection tests: page 0
/// holds two single user cells inside short treasury ranges, so no
/// treasury range at the lowest offsets covers the era-0 subsidy.
///
/// Resulting page 0 ranges:
///   [0, 100) T, [100, 101) u1, [101, 200) T, [200, 201) u2, [201, 65536) T
fn dust_state() -> (State, [u8; 32], [u8; 32]) {
    let mut state = State::genesis();
    let u1 = [1u8; 32];
    let u2 = [2u8; 32];
    state.mine(100, u1, 0);
    state.mine(200, u2, 0);
    (state, u1, u2)
}

#[test]
fn select_single_golden_vectors() {
    // Consensus golden vectors for the canonical selection: the scan
    // order (lowest page first, lowest offset first, dirty pages before
    // pristine pages) and the whole-range coverage predicate are pinned
    // here. Any intentional change to the selection rule must update
    // these vectors and be treated as a serialization-level fork.
    let (state, u1, u2) = dust_state();

    // A pristine genesis state selects from the implicit page-0 range.
    let genesis = State::genesis();
    assert_eq!(genesis.select_single(TREASURY, 500), Some((0, 500)));
    assert_eq!(genesis.select_single(TREASURY, 0), None);
    assert_eq!(genesis.select_single([9u8; 32], 1), None);

    // Exact fit of the lowest short treasury range is selected as-is.
    assert_eq!(state.select_single(TREASURY, 100), Some((0, 100)));
    // Amounts exceeding the first range skip over the foreign cells and
    // land in the first later range that alone covers the amount.
    assert_eq!(state.select_single(TREASURY, 101), Some((201, 302)));
    assert_eq!(state.select_single(TREASURY, 500), Some((201, 701)));
    // The largest single treasury range on the dirty page is
    // [201, 65536); one cell more overflows to the pristine page 1,
    // whose full-page range covers the remainder of the scan.
    assert_eq!(state.select_single(TREASURY, 65_335), Some((201, 65_536)));
    assert_eq!(
        state.select_single(TREASURY, 65_336),
        Some((65_536, 130_872))
    );
    // Single-cell user ranges select exactly and refuse larger amounts.
    assert_eq!(state.select_single(u1, 1), Some((100, 101)));
    assert_eq!(state.select_single(u1, 2), None);
    assert_eq!(state.select_single(u2, 1), Some((200, 201)));
    // An uninvolved party owns nothing.
    assert_eq!(state.select_single([3u8; 32], 1), None);
}

#[test]
fn select_single_never_spans_foreign_cells() {
    // Regression guard for the consensus halt triggered by dust: when
    // user-owned cells fragment the lowest treasury ranges below the
    // subsidy, the canonical selection must jump to a whole treasury
    // range instead of returning a synthetic span across foreign cells.
    // The selected range must always execute cleanly through the
    // consensus transfer engine, which is what makes a coinbase built
    // from it valid.
    let (mut state, u1, u2) = dust_state();
    let range = state
        .select_single(TREASURY, 500)
        .expect("the long treasury tail range always covers the era-0 subsidy");
    let out = Output {
        start: range.0,
        end: range.1,
        to: [9u8; 32],
        lock: None,
    };
    assert!(
        state.mint(&[range], &[out], 0),
        "the selected range lies entirely inside one treasury range, so the mint must succeed"
    );
    assert_eq!(state.balance([9u8; 32]), 500);
    // The treasury gave up the two dust cells during seeding and the
    // 500 minted cells here, nothing else.
    assert_eq!(state.balance(TREASURY), N - 502);
    // The user cells inside the skipped span are untouched.
    assert_eq!(state.balance(u1), 1);
    assert_eq!(state.balance(u2), 1);
    // The conservation invariant holds after the mint.
    let supply: u64 = state.balance_cache.values().sum();
    assert_eq!(supply, N);
}

#[test]
fn select_single_prefers_dirty_ranges_over_pristine_pages() {
    // Dirty treasury ranges have priority over pristine pages even when
    // the pristine page has a lower absolute index: with page 0 dirty
    // and holding a treasury range that covers the amount, the selection
    // comes from page 0 and page 1 (still pristine) is never consulted.
    // The layout is constructed directly on the page map so the test
    // pins the scan priority without depending on the transfer engine.
    let mut state = State::genesis();
    let owner = [4u8; 32];
    // Materialize page 0: [0, 100) owner, [100, 65536) treasury.
    {
        let page = state.get_page_mut(0);
        page.ranges.insert(0, R { e: 100, o: owner });
        page.ranges.insert(
            100,
            R {
                e: page_size(0),
                o: TREASURY,
            },
        );
    }
    *state.balance_cache.entry(owner).or_insert(0) += 100;
    *state.balance_cache.entry(TREASURY).or_insert(N) -= 100;

    assert_eq!(state.select_single(TREASURY, 500), Some((100, 600)));

    // Restore page 0 to a single treasury range so it evicts; the
    // selection then falls through to the pristine page scan starting
    // at page 1, whose implicit range is identical to page 0's, so the
    // selected range moves back to offset 0.
    {
        let page = state.get_page_mut(0);
        page.ranges.clear();
        page.ranges.insert(
            0,
            R {
                e: page_size(0),
                o: TREASURY,
            },
        );
    }
    *state.balance_cache.entry(owner).or_insert(0) -= 100;
    *state.balance_cache.entry(TREASURY).or_insert(N) += 100;
    state.evict_if_pristine(0);
    assert!(!state.pages.contains_key(&0), "page 0 must evict");
    assert_eq!(state.select_single(TREASURY, 500), Some((0, 500)));
}

#[test]
fn select_unlocked_skips_locked_spans() {
    // The unlocked sweep splits owner ranges around locked runs and
    // keeps going, so a griefing lock can delay only its own cells and
    // never invalidates a whole claim sweep. Expired locks (until <=
    // height) no longer block the sweep.
    let mut state = State::genesis();
    {
        let page = state.get_page_mut(0);
        page.ranges.insert(
            0,
            R {
                e: 200,
                o: FEE_VAULT,
            },
        );
        page.ranges.insert(
            200,
            R {
                e: page_size(0),
                o: TREASURY,
            },
        );
    }
    // Lock two runs inside the vault range: [50, 60) and [150, 160).
    for cell in 50..60 {
        state.locks.insert(cell, 100);
    }
    for cell in 150..160 {
        state.locks.insert(cell, 100);
    }
    // At height 50 the locked runs are skipped and the sweep continues
    // past them in canonical order.
    let ranges = state.select_unlocked(FEE_VAULT, 200, 50);
    assert_eq!(ranges, vec![(0, 50), (60, 150), (160, 200)]);
    // A partial amount truncates at the first locked span.
    let ranges = state.select_unlocked(FEE_VAULT, 55, 50);
    assert_eq!(ranges, vec![(0, 50), (60, 65)]);
    // At the expiry height the cells are spendable again.
    let ranges = state.select_unlocked(FEE_VAULT, 200, 100);
    assert_eq!(ranges, vec![(0, 200)]);
}

#[test]
fn remove_range_spans_adjacent_same_owner_ranges() {
    // Regression guard: adjacent ranges of the same owner occur around
    // proof-of-work slot cells and must be crossed cleanly by a removal.
    // Removing a span that covers the head of the second range must drop
    // the second range's original key; leaving it in place would create
    // overlapping ranges and break the page invariant.
    let mut page = Page {
        ranges: BTreeMap::new(),
    };
    page.ranges.insert(0, R { e: 10, o: TREASURY });
    page.ranges.insert(10, R { e: 20, o: TREASURY });
    page.ranges.insert(
        20,
        R {
            e: 30,
            o: [7u8; 32],
        },
    );

    // Remove [3, 12): crosses from the first treasury range into the
    // second, covering the head of the second range.
    assert!(page.remove_range(3, 12));
    let expected: BTreeMap<u64, R> = [
        (0, R { e: 3, o: TREASURY }),
        (12, R { e: 20, o: TREASURY }),
        (
            20,
            R {
                e: 30,
                o: [7u8; 32],
            },
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(page.ranges, expected);

    // Full removal across both treasury ranges plus the foreign range's
    // head is refused (foreign ownership), leaving the map untouched.
    assert!(!page.remove_range(0, 25));
    assert_eq!(page.ranges, expected);

    // Exact removal of the remaining second treasury range.
    assert!(page.remove_range(12, 20));
    let expected2: BTreeMap<u64, R> = [
        (0, R { e: 3, o: TREASURY }),
        (
            20,
            R {
                e: 30,
                o: [7u8; 32],
            },
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(page.ranges, expected2);
}

#[test]
fn lock_inside_merged_owner_range_blocks_spend() {
    // A lock registered in the interior of a merged owner range must
    // still block a spend that covers it. The ownership map compacts
    // the ten single-cell assignments into one range; the lock check
    // scans the full queried span, so the interior lock is visible.
    let mut state = State::genesis();
    let owner = [7u8; 32];
    for cell in 0..10 {
        state.mine(cell, owner, 0);
    }
    state.locks.insert(5, 100);
    assert!(!state.owns(owner, 0, 10, 50));
    assert!(state.owns(owner, 0, 10, 100));
    assert!(state.owns(owner, 6, 10, 50));
}

#[test]
fn empty_fee_claims_are_valid_and_claims_pay_miner_only() {
    // An empty claim set is a valid no-op: unclaimed fees stay in the
    // vault for a later sweep, and the block carrying it is not
    // penalized.
    let mut state = State::genesis();
    assert!(state.claim_fees([1u8; 32], &[], 10));

    // Claims paying anyone other than the block miner are refused;
    // claims paying the miner execute and debit the vault.
    for cell in 0..100 {
        state.mine(cell, FEE_VAULT, 0);
    }
    let wrong = Output {
        start: 0,
        end: 10,
        to: [2u8; 32],
        lock: None,
    };
    assert!(!state.claim_fees([1u8; 32], &[wrong], 10));
    let right = Output {
        start: 0,
        end: 10,
        to: [1u8; 32],
        lock: None,
    };
    assert!(state.claim_fees([1u8; 32], &[right], 10));
    assert_eq!(state.balance(FEE_VAULT), 90);
}
