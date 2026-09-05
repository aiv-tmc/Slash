//! End-to-end tests for the core blockchain, state engine, consensus rules,
//! and economic mechanisms (fee vault, stake-lock, reorg, checkpoints).

use slash::*;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

mod common;
use common::*;

// ---------------------------------------------------------------------------
// Mining & Basic Chain Extension
// ---------------------------------------------------------------------------

#[test]
fn test_mine_genesis_to_tip() {
    let _tmp = setup_test_dir("mine_genesis");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    for _ in 0..5 {
        let b = mine_next_block(&mut chain, miner, vec![]);
        chain.apply(b).unwrap();
    }

    assert_eq!(chain.blocks.len(), 6);
    assert_eq!(chain.state.balance(miner), 5);
}

#[test]
fn test_mine_respects_locked_cells() {
    let _tmp = setup_test_dir("mine_locked");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    let cell = mine_cell_for(&mut chain, owner);

    let outputs = vec![state::Output { start: cell, end: cell + 1, to: owner, lock: Some(10) }];
    let (sk, _pk) = crypto::generate_keypair();
    let tx = make_tx(owner, &sk, &[(cell, cell + 1)], &outputs, &chain.chain_id);
    let b = mine_next_block(&mut chain, owner, vec![tx]);
    chain.apply(b).unwrap();

    chain.state.mine(cell, [2u8; 32], 5);
    assert_eq!(chain.state.balance(owner), 1);

    chain.state.mine(cell, [2u8; 32], 10);
    assert_eq!(chain.state.balance([2u8; 32]), 1);
}

#[test]
fn test_difficulty_retargets_every_interval() {
    let _tmp = setup_test_dir("diff_retarget");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    for h in 1..=chain::DIFFICULTY_ADJUSTMENT_INTERVAL {
        let mut b = chain::Block {
            version: 1,
            prev: chain.tip_hash(),
            time: 0,
            height: h,
            nonce: 0,
            miner: [1u8; 32],
            mined_cell: 0,
            txs: vec![],
            fee_claims: vec![],
            difficulty: chain.next_difficulty(),
            page_roots: BTreeMap::new(),
        };
        loop {
            if let Some(cell) = chain::verify_pow(b.prev, b.time, b.height, b.miner, b.nonce, b.difficulty) {
                b.mined_cell = cell;
                break;
            }
            b.nonce += 1;
        }
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    let next = chain.next_difficulty();
    assert_eq!(next, 4000);
}

#[test]
fn test_time_drift_rejects_future_block() {
    let _tmp = setup_test_dir("time_future");
    reset_testnet();
    let chain = chain::Chain::genesis();

    let future = chain::Block {
        version: 1,
        prev: chain.tip_hash(),
        time: chrono::Utc::now().timestamp() as u64 + 10_000,
        height: 1,
        nonce: 0,
        miner: [1u8; 32],
        mined_cell: 0,
        txs: vec![],
        fee_claims: vec![],
        difficulty: chain.next_difficulty(),
        page_roots: BTreeMap::new(),
    };
    assert!(!chain.validate_block(&future));
}

#[test]
fn test_time_drift_rejects_early_block() {
    let _tmp = setup_test_dir("time_early");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    let mut b1 = mine_next_block(&mut chain, [1u8; 32], vec![]);
    b1.time = 100;
    chain.apply(b1.clone()).unwrap();

    let mut b2 = mine_next_block(&mut chain, [1u8; 32], vec![]);
    b2.time = 50;
    loop {
        if chain::verify_pow(b2.prev, b2.time, b2.height, b2.miner, b2.nonce, b2.difficulty).is_some() {
            break;
        }
        b2.nonce += 1;
    }
    let b2 = chain.prepare_block(b2);
    assert!(!chain.validate_block(&b2));
}

#[test]
fn test_median_timestamp_calculation() {
    let _tmp = setup_test_dir("median_time");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    for i in 1..=11 {
        let mut b = mine_next_block(&mut chain, miner, vec![]);
        b.time = i * 100;
        b.nonce = 0;
        loop {
            if let Some(cell) = chain::verify_pow(b.prev, b.time, b.height, b.miner, b.nonce, b.difficulty) {
                b.mined_cell = cell;
                break;
            }
            b.nonce += 1;
        }
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    let median = chain.median_timestamp();
    assert_eq!(median, 600);
}

// ---------------------------------------------------------------------------
// Transfers & Signature Enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_transfer_between_wallets() {
    let _tmp = setup_test_dir("transfer");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let alice = [1u8; 32];
    let bob = [2u8; 32];

    let cell = mine_cell_for(&mut chain, alice);

    let outputs = vec![state::Output { start: cell, end: cell + 1, to: bob, lock: None }];
    let (sk, _pk) = crypto::generate_keypair();
    let tx = make_tx(alice, &sk, &[(cell, cell + 1)], &outputs, &chain.chain_id);
    let b = mine_next_block(&mut chain, alice, vec![tx]);
    chain.apply(b).unwrap();

    assert_eq!(chain.state.balance(bob), 1);
    assert_eq!(chain.state.balance(alice), 1);
}

#[test]
fn test_transfer_rejects_bad_signature() {
    let _tmp = setup_test_dir("transfer_bad_sig");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let alice = [1u8; 32];
    let bob = [2u8; 32];

    let cell = mine_cell_for(&mut chain, alice);

    let outputs = vec![state::Output { start: cell, end: cell + 1, to: bob, lock: None }];
    let tx = chain::Tx {
        from: alice,
        inputs: vec![(cell, cell + 1)],
        outputs,
        sig: vec![0u8; 64],
        scheme: 0,
    };

    let b = mine_next_block(&mut chain, alice, vec![tx]);
    assert!(!chain.validate_block(&b));
}

#[test]
fn test_transfer_rejects_double_spend_in_block() {
    let _tmp = setup_test_dir("transfer_ds");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    let charlie = [3u8; 32];

    let cell = mine_cell_for(&mut chain, alice);

    let (sk, _pk) = crypto::generate_keypair();
    let tx1 = make_tx(alice, &sk, &[(cell, cell + 1)], &[state::Output { start: cell, end: cell + 1, to: bob, lock: None }], &chain.chain_id);
    let tx2 = make_tx(alice, &sk, &[(cell, cell + 1)], &[state::Output { start: cell, end: cell + 1, to: charlie, lock: None }], &chain.chain_id);

    let b = mine_next_block(&mut chain, alice, vec![tx1, tx2]);
    assert!(!chain.validate_block(&b));
}

#[test]
fn test_transfer_rejects_spend_from_wrong_owner() {
    let _tmp = setup_test_dir("transfer_wrong_owner");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let alice = [1u8; 32];
    let bob = [2u8; 32];

    let cell = mine_cell_for(&mut chain, alice);

    let outputs = vec![state::Output { start: cell, end: cell + 1, to: bob, lock: None }];
    let (sk, _pk) = crypto::generate_keypair();
    let tx = make_tx(bob, &sk, &[(cell, cell + 1)], &outputs, &chain.chain_id);

    let b = mine_next_block(&mut chain, alice, vec![tx]);
    assert!(!chain.validate_block(&b));
}

// ---------------------------------------------------------------------------
// Multi-Input & Cross-Page
// ---------------------------------------------------------------------------

#[test]
fn test_multi_input_cross_page() {
    let _tmp = setup_test_dir("cross_page");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];
    let recipient = [2u8; 32];

    let cell0 = state::PAGE_SIZE - 2;
    let cell1 = state::PAGE_SIZE + 2;

    chain.state.mine(cell0, owner, 0);
    chain.state.mine(cell0 + 1, owner, 0);
    chain.state.mine(cell1, owner, 0);
    chain.state.mine(cell1 + 1, owner, 0);

    let inputs = vec![(cell0, cell0 + 2), (cell1, cell1 + 2)];
    let outputs = vec![
        state::Output { start: cell0, end: cell0 + 1, to: recipient, lock: None },
        state::Output { start: cell0 + 1, end: cell0 + 2, to: owner, lock: None },
        state::Output { start: cell1, end: cell1 + 1, to: recipient, lock: None },
        state::Output { start: cell1 + 1, end: cell1 + 2, to: owner, lock: None },
    ];
    let mut h = blake3::Hasher::new();
    h.update(&owner);
    for (s, e) in &inputs {
        h.update(&s.to_le_bytes());
        h.update(&e.to_le_bytes());
    }
    for o in &outputs {
        h.update(&o.start.to_le_bytes());
        h.update(&o.end.to_le_bytes());
        h.update(&o.to);
    }
    // Include the chain identifier and scheme byte in the signed payload
    // to match the consensus signature hash construction.
    h.update(&chain.chain_id);
    h.update(&[0u8]);
    let (sk, _pk) = crypto::generate_keypair();
    let sig = crypto::sign(&sk, h.finalize().as_bytes());
    assert!(chain.state.tx(owner, &inputs, &outputs, &sig, 0, &chain.chain_id, 0));
    assert_eq!(chain.state.balance(recipient), 2);
    assert_eq!(chain.state.balance(owner), 2);
}

#[test]
fn test_multi_input_rejects_unbalanced_outputs() {
    let _tmp = setup_test_dir("unbalanced");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    chain.state.mine(10, owner, 0);
    chain.state.mine(11, owner, 0);

    let inputs = vec![(10, 12)];
    let outputs = vec![state::Output { start: 10, end: 11, to: [2u8; 32], lock: None }];
    let (sk, _pk) = crypto::generate_keypair();
    let tx = make_tx(owner, &sk, &inputs, &outputs, &chain.chain_id);

    let b = mine_next_block(&mut chain, owner, vec![tx]);
    assert!(!chain.validate_block(&b));
}

#[test]
fn test_multi_input_rejects_gap_in_outputs() {
    let _tmp = setup_test_dir("output_gap");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    chain.state.mine(10, owner, 0);
    chain.state.mine(11, owner, 0);

    let inputs = vec![(10, 12)];
    let outputs = vec![
        state::Output { start: 10, end: 11, to: [2u8; 32], lock: None },
        state::Output { start: 12, end: 13, to: owner, lock: None },
    ];
    let (sk, _pk) = crypto::generate_keypair();
    let tx = make_tx(owner, &sk, &inputs, &outputs, &chain.chain_id);

    let b = mine_next_block(&mut chain, owner, vec![tx]);
    assert!(!chain.validate_block(&b));
}

// ---------------------------------------------------------------------------
// Consolidation
// ---------------------------------------------------------------------------

#[test]
fn test_consolidate_fragments() {
    let _tmp = setup_test_dir("consolidate");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    for i in 0..5 {
        chain.state.mine(i * 10, owner, 0);
    }

    let inputs: Vec<(u64, u64)> = (0..5).map(|i| (i * 10, i * 10 + 1)).collect();
    let total: u64 = inputs.iter().map(|(s, e)| e - s).sum();
    let outputs = vec![state::Output { start: 0, end: total, to: owner, lock: None }];

    let (sk, _pk) = crypto::generate_keypair();
    let tx = make_tx(owner, &sk, &inputs, &outputs, &chain.chain_id);

    let b = mine_next_block(&mut chain, owner, vec![tx]);
    chain.apply(b).unwrap();

    assert_eq!(chain.state.balance(owner), 6);
    let single = chain.state.select_single(owner, 6);
    assert!(single.is_some());
}

// ---------------------------------------------------------------------------
// Stake-Lock
// ---------------------------------------------------------------------------

#[test]
fn test_stake_and_unlock() {
    let _tmp = setup_test_dir("stake");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    let cell = mine_cell_for(&mut chain, owner);

    let lock_until = 10;
    let outputs = vec![state::Output { start: cell, end: cell + 1, to: owner, lock: Some(lock_until) }];
    let (sk, _pk) = crypto::generate_keypair();
    let tx = make_tx(owner, &sk, &[(cell, cell + 1)], &outputs, &chain.chain_id);

    let b = mine_next_block(&mut chain, owner, vec![tx]);
    chain.apply(b).unwrap();

    assert_eq!(chain.state.locks.get(&cell), Some(&lock_until));

    let mut thief = mine_next_block(&mut chain, [2u8; 32], vec![]);
    thief.height = 5;
    thief.time = 500;
    loop {
        if chain::verify_pow(thief.prev, thief.time, thief.height, thief.miner, thief.nonce, thief.difficulty).is_some() {
            break;
        }
        thief.nonce += 1;
    }
    chain.state.mine(cell, [2u8; 32], 5);
    assert_eq!(chain.state.balance(owner), 1);

    chain.state.mine(cell, [2u8; 32], 10);
    assert_eq!(chain.state.balance([2u8; 32]), 1);
}

#[test]
fn test_stake_rejects_early_spend() {
    let _tmp = setup_test_dir("stake_early");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    let cell = mine_cell_for(&mut chain, owner);

    let outputs = vec![state::Output { start: cell, end: cell + 1, to: owner, lock: Some(100) }];
    let (sk, _pk) = crypto::generate_keypair();
    let tx = make_tx(owner, &sk, &[(cell, cell + 1)], &outputs, &chain.chain_id);
    let b = mine_next_block(&mut chain, owner, vec![tx]);
    chain.apply(b).unwrap();

    let spend_outputs = vec![state::Output { start: cell, end: cell + 1, to: [2u8; 32], lock: None }];
    let spend_tx = make_tx(owner, &sk, &[(cell, cell + 1)], &spend_outputs, &chain.chain_id);
    let b2 = mine_next_block(&mut chain, owner, vec![spend_tx]);
    assert!(!chain.validate_block(&b2));
}

// ---------------------------------------------------------------------------
// Fee Vault
// ---------------------------------------------------------------------------

#[test]
fn test_fee_vault_claim() {
    let _tmp = setup_test_dir("fee_vault");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    let out = state::Output { start: 0, end: 10, to: state::FEE_VAULT, lock: None };
    assert!(chain.state.tx(state::TREASURY, &[(0, 10)], &[out], &[], 0, &chain.chain_id, 0));

    let miner = [3u8; 32];
    let claims = vec![state::Output { start: 0, end: 5, to: miner, lock: None }];
    assert!(chain.state.claim_fees(miner, &claims, 0));

    assert_eq!(chain.state.balance(state::FEE_VAULT), 5);
    assert_eq!(chain.state.balance(miner), 5);
}

#[test]
fn test_fee_vault_blocks_invalid_claim() {
    let _tmp = setup_test_dir("fee_vault_invalid");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    let claims = vec![state::Output { start: 0, end: 5, to: [1u8; 32], lock: None }];
    assert!(!chain.state.claim_fees([1u8; 32], &claims, 0));
}

// ---------------------------------------------------------------------------
// Reorganization
// ---------------------------------------------------------------------------

#[test]
fn test_reorg_to_heavier_fork() {
    let _tmp = setup_test_dir("reorg");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let miner_a = [1u8; 32];
    let miner_b = [2u8; 32];

    for _ in 0..3 {
        let b = mine_next_block(&mut chain, miner_a, vec![]);
        chain.apply(b).unwrap();
    }
    assert_eq!(chain.blocks.len(), 4);
    let main_tip = chain.tip_hash();

    let fork_parent_hash = chain.block_hash(&chain.blocks[1]);
    let mut fork_blocks = Vec::new();
    for h in 2..=4 {
        let prev = if h == 2 { fork_parent_hash } else { chain.block_hash(fork_blocks.last().unwrap()) };
        let mut b = chain::Block {
            version: 1,
            prev,
            time: h * 100 + 50,
            height: h,
            nonce: 0,
            miner: miner_b,
            mined_cell: 0,
            txs: vec![],
            fee_claims: vec![],
            difficulty: 1,
            page_roots: BTreeMap::new(),
        };
        loop {
            if let Some(cell) = chain::verify_pow(b.prev, b.time, b.height, b.miner, b.nonce, b.difficulty) {
                b.mined_cell = cell;
                break;
            }
            b.nonce += 1;
        }

        let base_state = chain.state_history.get(&(h - 1)).cloned().unwrap_or_else(|| chain.state.clone());
        let mut temp = base_state.clone();
        for fb in &fork_blocks {
            temp.mine(fb.mined_cell, fb.miner, fb.height);
        }
        temp.mine(b.mined_cell, b.miner, b.height);
        let mut page_roots = BTreeMap::new();
        for (&page_id, page) in &temp.pages {
            page_roots.insert(page_id, page.merkle_root());
        }
        b.page_roots = page_roots;
        fork_blocks.push(b);
    }

    for fb in &fork_blocks {
        let result = chain.process_block(fb.clone()).unwrap();
        if fb.height == 4 {
            assert!(matches!(result, chain::BlockProcessResult::Reorged { .. }));
        }
    }

    assert_eq!(chain.blocks.len(), 5);
    assert_eq!(chain.blocks.last().unwrap().miner, miner_b);
    // The old main tip block was popped during reorg; it is not an orphan
    // because its parent was known, so it does not appear in the orphan pool.
}

#[test]
fn test_orphan_block_acceptance() {
    let _tmp = setup_test_dir("orphan");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    let b1 = mine_next_block(&mut chain, miner, vec![]);
    let b1_hash = chain.block_hash(&b1);

    let mut b2 = chain::Block {
        version: 1,
        prev: b1_hash,
        time: 200,
        height: 2,
        nonce: 0,
        miner,
        mined_cell: 0,
        txs: vec![],
        fee_claims: vec![],
        difficulty: 1,
        page_roots: BTreeMap::new(),
    };
    loop {
        if let Some(cell) = chain::verify_pow(b2.prev, b2.time, b2.height, b2.miner, b2.nonce, b2.difficulty) {
            b2.mined_cell = cell;
            break;
        }
        b2.nonce += 1;
    }

    let result = chain.process_block(b2.clone()).unwrap();
    assert!(matches!(result, chain::BlockProcessResult::Orphan));
    // b2 is retained in the orphan pool because its parent has not arrived yet.

    chain.apply(b1).unwrap();
    // apply triggers process_orphans, which discovers that b2's parent is now
    // the main tip and automatically adopts b2.
    assert_eq!(chain.blocks.len(), 3);
    assert_eq!(chain.tip_hash(), chain.block_hash(&b2));

    // Re-processing the same block after adoption returns Duplicate.
    let result2 = chain.process_block(b2).unwrap();
    assert!(matches!(result2, chain::BlockProcessResult::Duplicate));
}

#[test]
fn test_process_block_duplicate_rejection() {
    let _tmp = setup_test_dir("duplicate");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    let b = mine_next_block(&mut chain, miner, vec![]);
    chain.apply(b.clone()).unwrap();

    let result = chain.process_block(b).unwrap();
    assert!(matches!(result, chain::BlockProcessResult::Duplicate));
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

#[test]
fn test_checkpoint_prevents_deep_reorg() {
    let _tmp = setup_test_dir("checkpoint");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    let mut b1 = mine_next_block(&mut chain, [1u8; 32], vec![]);
    b1.difficulty = 1;
    loop {
        if let Some(cell) = chain::verify_pow(b1.prev, b1.time, b1.height, b1.miner, b1.nonce, b1.difficulty) {
            b1.mined_cell = cell;
            break;
        }
        b1.nonce += 1;
    }
    let b1 = chain.prepare_block(b1);
    chain.apply(b1.clone()).unwrap();

    let b1_hash = chain.block_hash(&b1);
    chain.checkpoints.insert(1, b1_hash);

    let result = chain.reorg_to_fork(0, &[]);
    assert!(matches!(result, Err(chain::BlockError::CheckpointViolation)));
}

// ---------------------------------------------------------------------------
// Version Bits (Soft-Fork Signaling)
// ---------------------------------------------------------------------------

#[test]
fn test_version_bits_activation() {
    let _tmp = setup_test_dir("version_bits");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    chain.version_bits.deployments.push(chain::Deployment {
        name: "test_fork".to_string(),
        bit: 0,
        start_height: 1,
        timeout_height: 5000,
        threshold: 2,
        status: chain::DeploymentStatus::Defined,
        activation_height: None,
        signals: 0,
    });

    for _ in 1..=3 {
        let mut b = mine_next_block(&mut chain, [1u8; 32], vec![]);
        b.version = 1 | (1 << 0);
        chain.apply(b).unwrap();
    }

    let d = &chain.version_bits.deployments[0];
    // After 3 signaled blocks the threshold (2) is reached at block 2, so the
    // deployment becomes LockedIn with activation scheduled for the next retarget.
    assert_eq!(d.status, chain::DeploymentStatus::LockedIn);
    assert_eq!(d.activation_height, Some(2 + chain::DIFFICULTY_ADJUSTMENT_INTERVAL));
}

#[test]
fn test_version_bits_timeout_fails() {
    let _tmp = setup_test_dir("version_bits_fail");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    chain.version_bits.deployments.push(chain::Deployment {
        name: "fail_fork".to_string(),
        bit: 1,
        start_height: 1,
        timeout_height: 3,
        threshold: 10,
        status: chain::DeploymentStatus::Defined,
        activation_height: None,
        signals: 0,
    });

    for _ in 1..=4 {
        let b = mine_next_block(&mut chain, [1u8; 32], vec![]);
        chain.apply(b).unwrap();
    }

    let d = &chain.version_bits.deployments[0];
    assert_eq!(d.status, chain::DeploymentStatus::Failed);
}

// ---------------------------------------------------------------------------
// Block Size Limits
// ---------------------------------------------------------------------------

#[test]
fn test_block_tx_count_limit_enforced() {
    let _tmp = setup_test_dir("tx_count");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    let mut txs = Vec::new();
    for i in 0..=chain::MAX_TX_PER_BLOCK {
        txs.push(chain::Tx {
            from: state::TREASURY,
            inputs: vec![(i, i + 1)],
            outputs: vec![state::Output { start: i, end: i + 1, to: [1u8; 32], lock: None }],
            sig: vec![],
            scheme: 0,
        });
    }

    let mut b = mine_next_block(&mut chain, [1u8; 32], txs);
    assert!(!chain.validate_block(&b));

    b.txs.pop();
    b = chain.prepare_block(b);
    assert!(chain.validate_block(&b));
}

#[test]
fn test_block_serialized_size_limit() {
    let _tmp = setup_test_dir("block_size");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    let mut txs = Vec::new();
    for i in 0..100 {
        txs.push(chain::Tx {
            from: state::TREASURY,
            inputs: vec![(i, i + 1)],
            outputs: vec![state::Output { start: i, end: i + 1, to: [1u8; 32], lock: None }],
            sig: vec![0u8; 64],
            scheme: 0,
        });
    }

    let mut b = mine_next_block(&mut chain, [1u8; 32], txs);
    // The hard consensus limit checks bincode serialized size, which is the
    // same format used for P2P transmission and disk storage.
    while bincode::serialize(&b).map_or(0, |v| v.len()) <= chain::MAX_BLOCK_SIZE_BYTES {
        b.txs.push(chain::Tx {
            from: state::TREASURY,
            inputs: vec![(0, 1)],
            outputs: vec![state::Output { start: 0, end: 1, to: [1u8; 32], lock: None }],
            sig: vec![0u8; 64],
            scheme: 0,
        });
    }

    assert!(!chain.validate_block(&b));
}

// ---------------------------------------------------------------------------
// Replay Protection & Network Separation
// ---------------------------------------------------------------------------

#[test]
fn test_replay_protection_across_networks() {
    let _tmp = setup_test_dir("replay");
    reset_testnet();
    let mut mainnet = chain::Chain::genesis();
    let mut testnet = chain::Chain::testnet_genesis();
    let owner = [1u8; 32];

    mainnet.state.mine(100, owner, 0);
    testnet.state.mine(100, owner, 0);

    let outputs = vec![state::Output { start: 100, end: 101, to: [2u8; 32], lock: None }];
    let hash = chain::tx_signature_hash(&owner, &[(100, 101)], &outputs, &mainnet.chain_id, 0);
    let (sk, _pk) = crypto::generate_keypair();
    let sig = crypto::sign(&sk, &hash);
    let tx = chain::Tx { from: owner, inputs: vec![(100, 101)], outputs, sig, scheme: 0 };

    assert!(mainnet.state.tx(owner, &tx.inputs, &tx.outputs, &tx.sig, 0, &mainnet.chain_id, 0));
    assert!(!testnet.state.tx(owner, &tx.inputs, &tx.outputs, &tx.sig, 0, &testnet.chain_id, 0));
}

// ---------------------------------------------------------------------------
// State Pruning & Pristine Pages
// ---------------------------------------------------------------------------

#[test]
fn test_pristine_page_eviction_reduces_dirty_set() {
    let _tmp = setup_test_dir("pristine_evict");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    chain.state.mine(10, owner, 0);
    assert!(chain.state.pages.contains_key(&0));

    let outputs = vec![state::Output { start: 10, end: 11, to: state::TREASURY, lock: None }];
    let (sk, _pk) = crypto::generate_keypair();
    let tx = make_tx(owner, &sk, &[(10, 11)], &outputs, &chain.chain_id);
    let b = mine_next_block(&mut chain, owner, vec![tx]);
    chain.apply(b).unwrap();

    assert!(!chain.state.pages.contains_key(&0));
}

#[test]
fn test_global_root_is_deterministic() {
    let _tmp = setup_test_dir("global_root");
    reset_testnet();
    let chain = chain::Chain::genesis();

    let r1 = chain.state.global_root();
    let r2 = chain.state.global_root();
    assert_eq!(r1, r2);
}

#[test]
fn test_state_history_pruned_after_max_reorg_depth() {
    let _tmp = setup_test_dir("history_prune");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    for _ in 0..=chain::MAX_REORG_DEPTH + 5 {
        let b = mine_next_block(&mut chain, miner, vec![]);
        chain.apply(b).unwrap();
    }

    let history_len = chain.state_history.len();
    assert!(history_len <= (chain::MAX_REORG_DEPTH + 1) as usize);
}

// ---------------------------------------------------------------------------
// Header-First Validation
// ---------------------------------------------------------------------------

#[test]
fn test_header_validation_succeeds_without_body() {
    let _tmp = setup_test_dir("header_only");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    let block = mine_next_block(&mut chain, [1u8; 32], vec![]);
    let header = chain::BlockHeader::from_block(&block);
    assert!(chain.validate_header(&header));
}

#[test]
fn test_header_rejects_wrong_height() {
    let _tmp = setup_test_dir("header_height");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    let mut block = mine_next_block(&mut chain, [1u8; 32], vec![]);
    block.height = 99;
    block.nonce = 0;
    loop {
        if chain::verify_pow(block.prev, block.time, block.height, block.miner, block.nonce, block.difficulty).is_some() {
            break;
        }
        block.nonce += 1;
    }
    let header = chain::BlockHeader::from_block(&block);
    assert!(!chain.validate_header(&header));
}
