//! End-to-end tests for the core blockchain, state engine, consensus rules,
//! and economic mechanisms (fee vault, stake-lock, reorg, checkpoints).
//!
//! Every signed transaction in this suite is built with `make_tx`, which
//! derives the signature hash from the sender address. The sender address
//! must therefore always be the public half of the keypair that signs,
//! otherwise the Ed25519 verification inside `State::tx` rejects the
//! transaction before any state is touched.

use slash::*;
use std::collections::BTreeMap;

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

    // Extend the chain by five empty blocks; every apply() runs full validation.
    for _ in 0..5 {
        let b = mine_next_block(&mut chain, miner, vec![]);
        chain.apply(b).unwrap();
    }

    // Six blocks total including genesis, and the miner owns one cell per block.
    assert_eq!(chain.blocks.len(), 6);
    assert_eq!(chain.state.balance(miner), 5);
}

#[test]
fn test_mine_respects_locked_cells() {
    let _tmp = setup_test_dir("mine_locked");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    // The owner is the public key matching the signing secret below.
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;

    // Seed owner with 50 cells. Both blocks are mined by the treasury so the
    // PoW reward cell can never land inside the seeded range and change the
    // balances this test asserts on (mining a treasury-owned cell is a no-op).
    let seed = state::Output {
        start: 0,
        end: 50,
        to: owner,
        lock: None,
    };
    let seed_tx = chain::Tx {
        from: state::TREASURY,
        inputs: vec![(0, 50)],
        outputs: vec![seed],
        sig: vec![],
        scheme: 0,
    };
    let b1 = mine_next_block(&mut chain, state::TREASURY, vec![seed_tx]);
    chain.apply(b1).unwrap();

    // Re-lock the same range until height 10.
    let outputs = vec![state::Output {
        start: 0,
        end: 50,
        to: owner,
        lock: Some(10),
    }];
    let tx = make_tx(owner, &sk, &[(0, 50)], &outputs, &chain.chain_id);
    let b2 = mine_next_block(&mut chain, state::TREASURY, vec![tx]);
    chain.apply(b2).unwrap();

    // Mining at height 5 should fail because the cells are still locked.
    chain.state.mine(0, [2u8; 32], 5);
    assert_eq!(chain.state.balance(owner), 50);

    // Mining at height 10 should succeed because the lock has expired.
    chain.state.mine(0, [2u8; 32], 10);
    assert_eq!(chain.state.balance([2u8; 32]), 1);
    assert_eq!(chain.state.balance(owner), 49);
}

#[test]
fn test_difficulty_retargets_every_interval() {
    let _tmp = setup_test_dir("diff_retarget");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    // Mine the full adjustment interval with blocks arriving 4x faster than
    // the 120-second target. The retarget formula therefore demands a 4x
    // difficulty increase, which is exactly the clamp boundary.
    for h in 1..=chain::DIFFICULTY_ADJUSTMENT_INTERVAL {
        let mut b = chain::Block {
            version: 1,
            prev: chain.tip_hash(),
            time: h * 30,
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
            if let Some(cell) =
                chain::verify_pow(b.prev, b.time, b.height, b.miner, b.nonce, b.difficulty)
            {
                b.mined_cell = cell;
                break;
            }
            b.nonce += 1;
        }
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    // The raw retarget yields slightly more than a 4x increase, so the
    // clamp caps the next difficulty at exactly 4x the last value.
    let next = chain.next_difficulty();
    assert_eq!(next, 4000);
}

#[test]
fn test_time_drift_rejects_future_block() {
    let _tmp = setup_test_dir("time_future");
    reset_testnet();
    let chain = chain::Chain::genesis();

    // A timestamp more than two hours in the future violates the drift rule
    // and must be rejected before the proof-of-work is even considered.
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

    // A block whose time is not greater than the median of the last 11
    // blocks must be rejected; re-mine the nonce so the PoW stays valid.
    let mut b2 = mine_next_block(&mut chain, [1u8; 32], vec![]);
    b2.time = 50;
    loop {
        if chain::verify_pow(
            b2.prev,
            b2.time,
            b2.height,
            b2.miner,
            b2.nonce,
            b2.difficulty,
        )
        .is_some()
        {
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
            if let Some(cell) =
                chain::verify_pow(b.prev, b.time, b.height, b.miner, b.nonce, b.difficulty)
            {
                b.mined_cell = cell;
                break;
            }
            b.nonce += 1;
        }
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    // The window covers the last 11 blocks (heights 1..=11), excluding genesis.
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
    let bob = [3u8; 32];
    // Alice is the public key matching the signing secret used below.
    let (sk, pk) = crypto::generate_keypair();
    let alice = pk;

    // Seed alice with 50 cells. Both blocks are mined by the treasury so the
    // balances below stay exact: a treasury-mined reward cell is a no-op and
    // can never land inside the seeded range or cancel alice's spend.
    let seed = state::Output {
        start: 0,
        end: 50,
        to: alice,
        lock: None,
    };
    let seed_tx = chain::Tx {
        from: state::TREASURY,
        inputs: vec![(0, 50)],
        outputs: vec![seed],
        sig: vec![],
        scheme: 0,
    };
    let b1 = mine_next_block(&mut chain, state::TREASURY, vec![seed_tx]);
    chain.apply(b1).unwrap();

    let outputs = vec![state::Output {
        start: 0,
        end: 50,
        to: bob,
        lock: None,
    }];
    let tx = make_tx(alice, &sk, &[(0, 50)], &outputs, &chain.chain_id);
    let b2 = mine_next_block(&mut chain, state::TREASURY, vec![tx]);
    chain.apply(b2).unwrap();

    assert_eq!(chain.state.balance(bob), 50);
    // Alice spent her entire seed range and the treasury-mined block moved
    // no reward cell, so her balance is exactly zero.
    assert_eq!(chain.state.balance(alice), 0);
}

#[test]
fn test_transfer_rejects_bad_signature() {
    let _tmp = setup_test_dir("transfer_bad_sig");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let alice = [1u8; 32];
    let bob = [2u8; 32];

    let cell = mine_cell_for(&mut chain, alice);

    // A structurally well-formed transaction whose 64-byte signature is all
    // zeroes must fail Ed25519 verification inside the state transition.
    let outputs = vec![state::Output {
        start: cell,
        end: cell + 1,
        to: bob,
        lock: None,
    }];
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
    let bob = [2u8; 32];
    let charlie = [3u8; 32];
    // Alice is the public key matching the signing secret used for both spends.
    let (sk, pk) = crypto::generate_keypair();
    let alice = pk;

    // Seed alice with 50 cells; both transactions below are individually
    // well-formed and correctly signed.
    let seed = state::Output {
        start: 0,
        end: 50,
        to: alice,
        lock: None,
    };
    let seed_tx = chain::Tx {
        from: state::TREASURY,
        inputs: vec![(0, 50)],
        outputs: vec![seed],
        sig: vec![],
        scheme: 0,
    };
    let b1 = mine_next_block(&mut chain, state::TREASURY, vec![seed_tx]);
    chain.apply(b1).unwrap();

    let tx1 = make_tx(
        alice,
        &sk,
        &[(0, 50)],
        &[state::Output {
            start: 0,
            end: 50,
            to: bob,
            lock: None,
        }],
        &chain.chain_id,
    );
    let tx2 = make_tx(
        alice,
        &sk,
        &[(0, 50)],
        &[state::Output {
            start: 0,
            end: 50,
            to: charlie,
            lock: None,
        }],
        &chain.chain_id,
    );

    // The first spend consumes the range during the state replay, so the
    // second one no longer finds it owned by alice and the block is invalid.
    let b2 = mine_next_block(&mut chain, state::TREASURY, vec![tx1, tx2]);
    assert!(!chain.validate_block(&b2));
}

#[test]
fn test_transfer_rejects_spend_from_wrong_owner() {
    let _tmp = setup_test_dir("transfer_wrong_owner");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let alice = [1u8; 32];
    // Bob is a real keypair: his signature is valid, so the block can only be
    // rejected by the ownership check, which is what this test exercises.
    let (bob_sk, bob_pk) = crypto::generate_keypair();
    let bob = bob_pk;

    let cell = mine_cell_for(&mut chain, alice);

    let outputs = vec![state::Output {
        start: cell,
        end: cell + 1,
        to: bob,
        lock: None,
    }];
    let tx = make_tx(bob, &bob_sk, &[(cell, cell + 1)], &outputs, &chain.chain_id);

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
    // The owner is the public key matching the signing secret below; the
    // manual signature hash mirrors chain::tx_signature_hash exactly.
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;
    let recipient = [2u8; 32];

    let cell0 = state::PAGE_SIZE - 25;
    let cell1 = state::PAGE_SIZE;

    // Mine 25 cells near the end of page 0 and 25 at the start of page 1.
    for i in 0..25 {
        chain.state.mine(cell0 + i, owner, 0);
        chain.state.mine(cell1 + i, owner, 0);
    }

    // Spend both ranges atomically in one transaction. Each page must
    // balance independently, so the outputs mirror the inputs per page.
    let inputs = vec![(cell0, cell0 + 25), (cell1, cell1 + 25)];
    let outputs = vec![
        state::Output {
            start: cell0,
            end: cell0 + 25,
            to: recipient,
            lock: None,
        },
        state::Output {
            start: cell1,
            end: cell1 + 25,
            to: owner,
            lock: None,
        },
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
    h.update(&chain.chain_id);
    h.update(&[0u8]);
    let sig = crypto::sign(&sk, h.finalize().as_bytes());
    assert!(chain
        .state
        .tx(owner, &inputs, &outputs, &sig, 0, &chain.chain_id, 0));
    assert_eq!(chain.state.balance(recipient), 25);
    assert_eq!(chain.state.balance(owner), 25);
}

#[test]
fn test_multi_input_rejects_unbalanced_outputs() {
    let _tmp = setup_test_dir("unbalanced");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;

    // Mine 50 contiguous cells for the owner.
    for i in 10..60 {
        chain.state.mine(i, owner, 0);
    }

    // The outputs only account for one cell, violating conservation of cells.
    let inputs = vec![(10, 60)];
    let outputs = vec![state::Output {
        start: 10,
        end: 11,
        to: [2u8; 32],
        lock: None,
    }];
    let tx = make_tx(owner, &sk, &inputs, &outputs, &chain.chain_id);

    let b = mine_next_block(&mut chain, owner, vec![tx]);
    assert!(!chain.validate_block(&b));
}

#[test]
fn test_multi_input_rejects_gap_in_outputs() {
    let _tmp = setup_test_dir("output_gap");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;

    // Mine 50 contiguous cells for the owner.
    for i in 10..60 {
        chain.state.mine(i, owner, 0);
    }

    // Outputs must pack contiguously starting at the first input start;
    // the jump from 11 to 12 leaves cell 11 unaccounted for.
    let inputs = vec![(10, 60)];
    let outputs = vec![
        state::Output {
            start: 10,
            end: 11,
            to: [2u8; 32],
            lock: None,
        },
        state::Output {
            start: 12,
            end: 13,
            to: owner,
            lock: None,
        },
    ];
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
    let recipient = [2u8; 32];
    // The owner is the public key matching the signing secret below. The
    // block is mined by the treasury so no reward cell can interfere with
    // the balances and ranges this test asserts on.
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;

    // Mine 50 contiguous cells; identical adjacent owners merge during mining,
    // so the page already stores a single [0, 50) range for the owner.
    for i in 0..50 {
        chain.state.mine(i, owner, 0);
    }
    assert_eq!(chain.state.balance(owner), 50);

    // Spend the range with two adjacent outputs back to the owner plus one
    // output to the recipient. The adjacent owner outputs must merge into a
    // single contiguous range after insert_outputs.
    let inputs = vec![(0, 50)];
    let outputs = vec![
        state::Output {
            start: 0,
            end: 10,
            to: owner,
            lock: None,
        },
        state::Output {
            start: 10,
            end: 25,
            to: owner,
            lock: None,
        },
        state::Output {
            start: 25,
            end: 50,
            to: recipient,
            lock: None,
        },
    ];
    let tx = make_tx(owner, &sk, &inputs, &outputs, &chain.chain_id);

    let b = mine_next_block(&mut chain, state::TREASURY, vec![tx]);
    chain.apply(b).unwrap();

    assert_eq!(chain.state.balance(owner), 25);
    assert_eq!(chain.state.balance(recipient), 25);
    // The two adjacent owner outputs merged into one contiguous range.
    assert_eq!(chain.state.select_single(owner, 25), Some((0, 25)));
    assert!(chain.state.select_single(owner, 26).is_none());
}

// ---------------------------------------------------------------------------
// Stake-Lock
// ---------------------------------------------------------------------------

#[test]
fn test_stake_and_unlock() {
    let _tmp = setup_test_dir("stake");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    // The owner is the public key matching the signing secret below.
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;

    // Seed owner with 50 cells. Both blocks are mined by the treasury so the
    // owner's balance stays exactly 50 for the assertions below.
    let seed = state::Output {
        start: 0,
        end: 50,
        to: owner,
        lock: None,
    };
    let seed_tx = chain::Tx {
        from: state::TREASURY,
        inputs: vec![(0, 50)],
        outputs: vec![seed],
        sig: vec![],
        scheme: 0,
    };
    let b1 = mine_next_block(&mut chain, state::TREASURY, vec![seed_tx]);
    chain.apply(b1).unwrap();

    let lock_until = 10;
    let outputs = vec![state::Output {
        start: 0,
        end: 50,
        to: owner,
        lock: Some(lock_until),
    }];
    let tx = make_tx(owner, &sk, &[(0, 50)], &outputs, &chain.chain_id);

    let b2 = mine_next_block(&mut chain, state::TREASURY, vec![tx]);
    chain.apply(b2).unwrap();

    assert_eq!(chain.state.locks.get(&0), Some(&lock_until));

    // Mining at height 5 must not move the locked cell.
    chain.state.mine(0, [2u8; 32], 5);
    assert_eq!(chain.state.balance(owner), 50);

    // Mining at height 10 succeeds because the lock has expired.
    chain.state.mine(0, [2u8; 32], 10);
    assert_eq!(chain.state.balance([2u8; 32]), 1);
    assert_eq!(chain.state.balance(owner), 49);
}

#[test]
fn test_stake_rejects_early_spend() {
    let _tmp = setup_test_dir("stake_early");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;

    // Seed owner with 50 cells.
    let seed = state::Output {
        start: 0,
        end: 50,
        to: owner,
        lock: None,
    };
    let seed_tx = chain::Tx {
        from: state::TREASURY,
        inputs: vec![(0, 50)],
        outputs: vec![seed],
        sig: vec![],
        scheme: 0,
    };
    let b1 = mine_next_block(&mut chain, state::TREASURY, vec![seed_tx]);
    chain.apply(b1).unwrap();

    let outputs = vec![state::Output {
        start: 0,
        end: 50,
        to: owner,
        lock: Some(100),
    }];
    let tx = make_tx(owner, &sk, &[(0, 50)], &outputs, &chain.chain_id);
    let b2 = mine_next_block(&mut chain, state::TREASURY, vec![tx]);
    chain.apply(b2).unwrap();

    // The next block is at height 3, well before the lock expires at 100.
    let spend_outputs = vec![state::Output {
        start: 0,
        end: 50,
        to: [2u8; 32],
        lock: None,
    }];
    let spend_tx = make_tx(owner, &sk, &[(0, 50)], &spend_outputs, &chain.chain_id);
    let b3 = mine_next_block(&mut chain, state::TREASURY, vec![spend_tx]);
    assert!(!chain.validate_block(&b3));
}

// ---------------------------------------------------------------------------
// Fee Vault
// ---------------------------------------------------------------------------

#[test]
fn test_fee_vault_claim() {
    let _tmp = setup_test_dir("fee_vault");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    // Send 50 cells to the fee vault; the treasury signs nothing.
    let out = state::Output {
        start: 0,
        end: 50,
        to: state::FEE_VAULT,
        lock: None,
    };
    assert!(chain.state.tx(
        state::TREASURY,
        &[(0, 50)],
        &[out],
        &[],
        0,
        &chain.chain_id,
        0
    ));

    // The miner claims half of the vault without a signature.
    let miner = [3u8; 32];
    let claims = vec![state::Output {
        start: 0,
        end: 25,
        to: miner,
        lock: None,
    }];
    assert!(chain.state.claim_fees(miner, &claims, 0));

    assert_eq!(chain.state.balance(state::FEE_VAULT), 25);
    assert_eq!(chain.state.balance(miner), 25);
}

#[test]
fn test_fee_vault_blocks_invalid_claim() {
    let _tmp = setup_test_dir("fee_vault_invalid");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    // Cells 0..5 still belong to the treasury, so claiming them from the
    // fee vault must fail the vault-ownership check.
    let claims = vec![state::Output {
        start: 0,
        end: 5,
        to: [1u8; 32],
        lock: None,
    }];
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
    let _main_tip = chain.tip_hash();

    // Build a three-block fork on top of the height-1 block. Page roots are
    // recomputed from the state history snapshot at the common ancestor.
    let fork_parent_hash = chain.block_hash(&chain.blocks[1]);
    let mut fork_blocks = Vec::new();
    for h in 2..=4 {
        let prev = if h == 2 {
            fork_parent_hash
        } else {
            chain.block_hash(fork_blocks.last().unwrap())
        };
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
            difficulty: chain.next_difficulty(),
            page_roots: BTreeMap::new(),
        };
        loop {
            if let Some(cell) =
                chain::verify_pow(b.prev, b.time, b.height, b.miner, b.nonce, b.difficulty)
            {
                b.mined_cell = cell;
                break;
            }
            b.nonce += 1;
        }

        let base_state = chain
            .state_history
            .get(&(h - 1))
            .cloned()
            .unwrap_or_else(|| chain.state.clone());
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
}

#[test]
fn test_orphan_block_acceptance() {
    let _tmp = setup_test_dir("orphan");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    let b1 = mine_next_block(&mut chain, miner, vec![]);
    let b1_hash = chain.block_hash(&b1);

    // Build a child of b1 while b1 is still unknown to the chain.
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
        difficulty: chain.next_difficulty(),
        page_roots: BTreeMap::new(),
    };
    loop {
        if let Some(cell) = chain::verify_pow(
            b2.prev,
            b2.time,
            b2.height,
            b2.miner,
            b2.nonce,
            b2.difficulty,
        ) {
            b2.mined_cell = cell;
            break;
        }
        b2.nonce += 1;
    }

    // Page roots must commit to the state after both the parent reward and this
    // block's own reward, exactly as a miner holding the full chain would build
    // them. Without this, the orphan would be discarded as invalid the moment
    // process_orphans tries to adopt it after b1 arrives.
    let mut temp = chain.state.clone();
    temp.mine(b1.mined_cell, b1.miner, b1.height);
    temp.mine(b2.mined_cell, b2.miner, b2.height);
    let mut page_roots = BTreeMap::new();
    for (&page_id, page) in &temp.pages {
        page_roots.insert(page_id, page.merkle_root());
    }
    b2.page_roots = page_roots;

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
    loop {
        if let Some(cell) = chain::verify_pow(
            b1.prev,
            b1.time,
            b1.height,
            b1.miner,
            b1.nonce,
            b1.difficulty,
        ) {
            b1.mined_cell = cell;
            break;
        }
        b1.nonce += 1;
    }
    let b1 = chain.prepare_block(b1);
    chain.apply(b1.clone()).unwrap();

    // Pin height 1, then attempt to roll back below the checkpoint.
    let b1_hash = chain.block_hash(&b1);
    chain.checkpoints.insert(1, b1_hash);

    let result = chain.reorg_to_fork(0, &[]);
    assert!(matches!(
        result,
        Err(chain::BlockError::CheckpointViolation)
    ));
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
    assert_eq!(
        d.activation_height,
        Some(2 + chain::DIFFICULTY_ADJUSTMENT_INTERVAL)
    );
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

    // One transaction more than the protocol cap must be rejected. The block
    // is mined by the treasury so the reward cell can never collide with the
    // transaction ranges (mining a treasury-owned cell is a no-op).
    let mut txs = Vec::new();
    for i in 0..=chain::MAX_TX_PER_BLOCK {
        let start = i as u64 * 50;
        txs.push(chain::Tx {
            from: state::TREASURY,
            inputs: vec![(start, start + 50)],
            outputs: vec![state::Output {
                start,
                end: start + 50,
                to: [1u8; 32],
                lock: None,
            }],
            sig: vec![],
            scheme: 0,
        });
    }

    let mut b = mine_next_block(&mut chain, state::TREASURY, txs);
    assert!(!chain.validate_block(&b));

    // Removing one transaction brings the count back to the cap.
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
        let start = i as u64 * 50;
        txs.push(chain::Tx {
            from: state::TREASURY,
            inputs: vec![(start, start + 50)],
            outputs: vec![state::Output {
                start,
                end: start + 50,
                to: [1u8; 32],
                lock: None,
            }],
            sig: vec![0u8; 64],
            scheme: 0,
        });
    }

    let mut b = mine_next_block(&mut chain, [1u8; 32], txs);
    // The hard consensus limit checks bincode serialized size, which is the
    // same format used for P2P transmission and disk storage.
    while bincode::serialize(&b).map_or(0, |v| v.len()) <= chain::MAX_BLOCK_SIZE_BYTES {
        let start = b.txs.len() as u64 * 50;
        b.txs.push(chain::Tx {
            from: state::TREASURY,
            inputs: vec![(start, start + 50)],
            outputs: vec![state::Output {
                start,
                end: start + 50,
                to: [1u8; 32],
                lock: None,
            }],
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
    // The owner is the public key matching the signing secret below.
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;

    // Seed both networks with 50 contiguous cells for the owner.
    for i in 100..150 {
        mainnet.state.mine(i, owner, 0);
        testnet.state.mine(i, owner, 0);
    }

    // The signature commits to the mainnet chain identifier, so the same
    // transaction must fail verification on the testnet.
    let outputs = vec![state::Output {
        start: 100,
        end: 150,
        to: [2u8; 32],
        lock: None,
    }];
    let hash = chain::tx_signature_hash(&owner, &[(100, 150)], &outputs, &mainnet.chain_id, 0);
    let sig = crypto::sign(&sk, &hash);
    let tx = chain::Tx {
        from: owner,
        inputs: vec![(100, 150)],
        outputs,
        sig,
        scheme: 0,
    };

    assert!(mainnet.state.tx(
        owner,
        &tx.inputs,
        &tx.outputs,
        &tx.sig,
        0,
        &mainnet.chain_id,
        0
    ));
    assert!(!testnet.state.tx(
        owner,
        &tx.inputs,
        &tx.outputs,
        &tx.sig,
        0,
        &testnet.chain_id,
        0
    ));
}

// ---------------------------------------------------------------------------
// State Pruning & Pristine Pages
// ---------------------------------------------------------------------------

#[test]
fn test_pristine_page_eviction_reduces_dirty_set() {
    let _tmp = setup_test_dir("pristine_evict");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;

    // Mine 50 cells so page 0 becomes dirty.
    for i in 10..60 {
        chain.state.mine(i, owner, 0);
    }
    assert!(chain.state.pages.contains_key(&0));

    // Returning the full range to the treasury restores the lazy default,
    // so the dirty page is evicted automatically. The block is mined by the
    // treasury so no reward cell can land inside the returned range.
    let outputs = vec![state::Output {
        start: 10,
        end: 60,
        to: state::TREASURY,
        lock: None,
    }];
    let tx = make_tx(owner, &sk, &[(10, 60)], &outputs, &chain.chain_id);
    let b = mine_next_block(&mut chain, state::TREASURY, vec![tx]);
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

    // Apply more blocks than the reorg window; history must stay bounded.
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
        if chain::verify_pow(
            block.prev,
            block.time,
            block.height,
            block.miner,
            block.nonce,
            block.difficulty,
        )
        .is_some()
        {
            break;
        }
        block.nonce += 1;
    }
    let header = chain::BlockHeader::from_block(&block);
    assert!(!chain.validate_header(&header));
}
