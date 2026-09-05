//! Shared test utilities for the Slash integration test suite.
//! Every test receives its own temporary directory so that on-disk state
//! never leaks between concurrent runs.

use std::path::PathBuf;
use std::sync::atomic::Ordering;

/// Create a unique temporary directory, switch the process working directory
/// into it, and return the path so the caller can clean it up on drop.
pub fn setup_test_dir(test_name: &str) -> PathBuf {
    let pid = std::process::id();
    let tmp = std::env::temp_dir().join(format!("slash_integ_{}_{}", test_name, pid));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    std::env::set_current_dir(&tmp).unwrap();
    tmp
}

/// Reset the global testnet flag to false so tests run against
/// the mainnet genesis and chain identifier by default.
pub fn reset_testnet() {
    slash::TESTNET_MODE.store(false, Ordering::SeqCst);
}

/// Enable testnet mode for tests that require the testnet chain id.
pub fn enable_testnet() {
    slash::TESTNET_MODE.store(true, Ordering::SeqCst);
}

/// Build a valid proof-of-work block that extends the current tip of `chain`.
/// The caller supplies the miner address and an optional list of transactions.
/// The function searches for a nonce that satisfies the current difficulty target.
pub fn mine_next_block(
    chain: &mut slash::chain::Chain,
    miner: [u8; 32],
    txs: Vec<slash::chain::Tx>,
) -> slash::chain::Block {
    use std::collections::BTreeMap;
    let prev = chain.tip_hash();
    let height = chain.blocks.len() as u64 + chain.base_height;
    let diff = chain.next_difficulty();
    let mut b = slash::chain::Block {
        version: 1,
        prev,
        time: height.saturating_mul(100),
        height,
        nonce: 0,
        miner,
        mined_cell: 0,
        txs,
        fee_claims: vec![],
        difficulty: diff,
        page_roots: BTreeMap::new(),
    };
    loop {
        if let Some(cell) = slash::chain::Chain::verify_pow(b.prev, b.time, b.height, b.miner, b.nonce, b.difficulty) {
            b.mined_cell = cell;
            break;
        }
        b.nonce += 1;
    }
    chain.prepare_block(b)
}

/// Mine an empty block and apply it so that `owner` receives one cell.
/// Returns the global index of the mined cell.
pub fn mine_cell_for(chain: &mut slash::chain::Chain, owner: [u8; 32]) -> u64 {
    let b = mine_next_block(chain, owner, vec![]);
    let cell = b.mined_cell;
    chain.apply(b).unwrap();
    cell
}

/// Create a signed transaction that spends `inputs` and creates `outputs`.
/// The signature covers the chain identifier to enforce replay protection.
pub fn make_tx(
    from: [u8; 32],
    sk: &[u8; 32],
    inputs: &[(u64, u64)],
    outputs: &[slash::state::Output],
    chain_id: &[u8],
) -> slash::chain::Tx {
    let hash = slash::chain::tx_signature_hash(&from, inputs, outputs, chain_id, 0);
    let sig = slash::crypto::sign(sk, &hash);
    slash::chain::Tx {
        from,
        inputs: inputs.to_vec(),
        outputs: outputs.to_vec(),
        sig,
        scheme: 0,
    }
}
