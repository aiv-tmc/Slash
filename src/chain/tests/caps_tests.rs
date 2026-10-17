//! Amplification-cap tests: the per-transaction range and page caps
//! reject shape attacks before any state work.

use crate::chain::*;

#[test]
fn tx_caps_reject_range_and_page_amplification() {
    // The amplification caps bound the shape of a transaction before
    // any state work: too many ranges in total, or ranges fanned out
    // across too many pages, are rejected structurally. Both cases are
    // built from one-cell ranges, the cheapest possible unit, so the
    // caps — not the amount — are what stops them.
    let chain = Chain::genesis();
    // Exactly MAX_RANGES_PER_TX ranges in total, split half inputs and
    // half outputs, all on one page: passes the caps.
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    for i in 0..(MAX_RANGES_PER_TX / 2) as u64 {
        let start = i * 2;
        inputs.push((start, start + 1));
        outputs.push(Output {
            start,
            end: start + 1,
            to: [1u8; 32],
            lock: None,
        });
    }
    let at_cap = Tx {
        from: [1u8; 32],
        inputs,
        outputs,
        sig: vec![0u8; 64],
        scheme: 0,
        memo: None,
    };
    assert!(chain.tx_caps_valid(&at_cap));
    // One more range pair over the cap fails even though every range is
    // tiny.
    let last_end = at_cap.inputs.last().map(|(_, e)| *e).unwrap();
    let mut over = at_cap.clone();
    over.inputs.push((last_end, last_end + 1));
    over.outputs.push(Output {
        start: last_end,
        end: last_end + 1,
        to: [1u8; 32],
        lock: None,
    });
    assert!(!chain.tx_caps_valid(&over));
    // Ranges spread across MAX_PAGES_PER_TX + 1 pages fail the page cap
    // even though the range count stays small.
    let mut wide_inputs = Vec::new();
    let mut wide_outputs = Vec::new();
    for i in 0..=MAX_PAGES_PER_TX as u64 {
        // PAGE_SIZE is a u64 constant, so each page base is a plain
        // multiplication in global cell coordinates.
        let start = i * crate::state::PAGE_SIZE;
        wide_inputs.push((start, start + 1));
        wide_outputs.push(Output {
            start,
            end: start + 1,
            to: [1u8; 32],
            lock: None,
        });
    }
    let too_wide = Tx {
        from: [1u8; 32],
        inputs: wide_inputs,
        outputs: wide_outputs,
        sig: vec![0u8; 64],
        scheme: 0,
        memo: None,
    };
    assert!(!chain.tx_caps_valid(&too_wide));
}
