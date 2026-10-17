//! Shared fixtures for the chain tests: the nonce search and the block
//! builders every test drives. All searches run through the light
//! verification path at difficulty 1 so no test allocates a full-memory
//! RandomX dataset.

use crate::chain::*;
use std::collections::BTreeMap;

/// Search a nonce satisfying the block's difficulty whose proof-of-work
/// slot is treasury-owned in the pre-block state. The search runs through
/// the light verification context, keeping the test memory footprint
/// bounded; the full mining dataset is never allocated.
pub(crate) fn grind(chain: &Chain, block: &mut Block) {
    loop {
        if let Some(cell) = verify_pow(
            block.prev,
            block.time,
            block.height,
            block.miner,
            block.nonce,
            block.difficulty,
        ) {
            let owned_by_treasury = chain
                .state
                .get(cell)
                .is_some_and(|(_, _, owner)| owner == crate::state::TREASURY);
            if owned_by_treasury {
                block.mined_cell = cell;
                return;
            }
        }
        block.nonce += 1;
    }
}

/// Timestamp for the next block: one second past the tip block, so the
/// median-time rule always passes even when several blocks are produced
/// within the same wall-clock second. A chain without blocks (the implicit
/// genesis) takes the current time.
pub(crate) fn next_time(chain: &Chain) -> u64 {
    chain
        .blocks
        .last()
        .map(|b| b.time.saturating_add(1))
        .unwrap_or_else(|| chrono::Utc::now().timestamp() as u64)
}

/// Mine a block on the current tip with the given miner, carrying the
/// mandatory coinbase of a positive-subsidy era and no user transactions,
/// using difficulty 1 so the search terminates on the first qualifying
/// nonce. Returns the applied block.
pub(crate) fn mine_tip_block(chain: &mut Chain, miner: [u8; 32]) -> Block {
    let height = chain.tip_height() + 1;
    // The coinbase is attached through the ordinary builder so the block
    // carries exactly the shape consensus validation requires.
    let mut txs = Vec::new();
    if let Some(coinbase) = Chain::build_coinbase(&chain.state, miner, height, 0) {
        txs.push(coinbase);
    }
    let mut block = Block {
        version: 2,
        prev: chain.tip_hash(),
        time: next_time(chain),
        height,
        nonce: 0,
        miner,
        mined_cell: 0,
        txs,
        fee_claims: Vec::new(),
        difficulty: 1,
        page_roots: BTreeMap::new(),
    };
    // The consensus slot rule derives the rewarded cell from the proof
    // hash. The proof input is prev || time || height || nonce || miner —
    // it does not commit to the transactions — so the nonce search runs
    // before the block is prepared at all, and the declared slot is the
    // cell the search found.
    grind(chain, &mut block);
    let block = chain.prepare_block(block);
    // The prepared block must carry the recomputed roots. An empty map
    // means execution failed during preparation, and applying the block
    // would then surface that failure as a page-root mismatch, masking
    // the real error — fail here, at the stage that actually broke.
    assert!(
        !block.page_roots.is_empty(),
        "mine_tip_block fixture failed to execute during prepare"
    );
    chain.apply(block.clone()).expect("test block applies");
    block
}

/// Build a block extending `prev` at `height` without applying it,
/// carrying the mandatory coinbase of a positive-subsidy era and a
/// proof-of-work-valid nonce for its exact header. Callers that build
/// several sibling blocks must apply each one before building the next
/// so the canonical coinbase inputs advance with the state.
pub(crate) fn build_block_extending(
    chain: &Chain,
    prev: [u8; 32],
    height: u64,
    miner: [u8; 32],
) -> Block {
    let mut txs = Vec::new();
    if let Some(coinbase) = Chain::build_coinbase(&chain.state, miner, height, 0) {
        txs.push(coinbase);
    }
    let mut block = Block {
        version: 2,
        prev,
        time: next_time(chain),
        height,
        nonce: 0,
        miner,
        mined_cell: 0,
        txs,
        fee_claims: Vec::new(),
        difficulty: chain.next_difficulty(),
        page_roots: BTreeMap::new(),
    };
    // The declared slot cell must equal the cell derived from the proof
    // hash, so the nonce search runs for this exact header.
    grind(chain, &mut block);
    block
}

/// Assemble a valid block at the next height for tests: the header
/// continues the current tip, the coinbase is attached whenever the
/// subsidy is positive, the difficulty follows the schedule, and the
/// nonce search runs so the declared slot cell equals the proof-of-work
/// output.
pub(crate) fn test_block(chain: &Chain, miner: [u8; 32], version: u32) -> Block {
    let height = chain.tip_height() + 1;
    let (tip_hash, tip_time) = chain
        .get_block(chain.tip_height())
        .map(|b| (chain.block_hash(b), b.time))
        .unwrap_or(([0u8; 32], 0));
    let mut txs = Vec::new();
    if let Some(coinbase) = Chain::build_coinbase(&chain.state, miner, height, 0) {
        txs.push(coinbase);
    }
    let mut block = Block {
        version,
        prev: tip_hash,
        time: tip_time + 300,
        height,
        nonce: 0,
        miner,
        mined_cell: 0,
        txs,
        fee_claims: Vec::new(),
        difficulty: chain.next_difficulty(),
        page_roots: BTreeMap::new(),
    };
    // The consensus slot rule derives the rewarded cell from the proof
    // hash, so the nonce search must cover this exact header before the
    // block is applied.
    grind(chain, &mut block);
    block
}
