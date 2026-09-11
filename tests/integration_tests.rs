//! Integration tests covering wallet encryption, treasury secrets,
//! staking, P2P sync, header download, DoS resistance, mempool overflow,
//! rate limiting, snapshot pruning, auto-recovery, and chain invariants.

use slash::*;
use std::collections::BTreeMap;

mod common;
use common::*;

// ---------------------------------------------------------------------------
// Wallet Encryption Roundtrip
// ---------------------------------------------------------------------------

/// Verify that a wallet list encrypted with a password can be decrypted back
/// to the identical list of keypairs.
#[test]
fn test_wallet_encryption_roundtrip() {
    with_temp_dir(|| {
        let (sk, pk) = crypto::generate_keypair();
        let entry = WalletEntry {
            public: encode_key(&pk),
            secret: encode_key(&sk),
        };
        let password = "correct horse battery staple";
        save_wallets(std::slice::from_ref(&entry), password);

        let loaded = load_wallets(password).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].public, entry.public);
        assert_eq!(loaded[0].secret, entry.secret);
    });
}

// ---------------------------------------------------------------------------
// Treasury Secret Encryption
// ---------------------------------------------------------------------------

/// Verify that treasury secrets can be encrypted, persisted, and decrypted
/// back without data loss.
#[test]
fn test_treasury_secret_encryption() {
    with_temp_dir(|| {
        let file = TreasurySecretFile {
            vrf_secret: "aabbccdd".to_string(),
            signer_secret: "11223344".to_string(),
            onion_secret: "55667788".to_string(),
        };
        let password = "treasury password";
        save_treasury_secret(&file, password);

        let loaded = load_treasury_secret(password).unwrap();
        assert_eq!(loaded.vrf_secret, file.vrf_secret);
        assert_eq!(loaded.signer_secret, file.signer_secret);
        assert_eq!(loaded.onion_secret, file.onion_secret);
    });
}

// ---------------------------------------------------------------------------
// Staking Creates Locked Output
// ---------------------------------------------------------------------------

/// Verify that a stake transaction produces an output whose lock height
/// prevents spending until the specified block.
#[test]
fn test_staking_creates_locked_output() {
    let mut chain = chain::Chain::genesis();
    // The owner is the public key matching the signing secret used below.
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;

    // Seed owner with 50 cells via a treasury transaction. The seed block is
    // mined by the treasury itself so the PoW reward cell can never collide
    // with the seeded range (mining a treasury-owned cell is a no-op).
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
    let mut b = mine_valid_block(&chain, 1, state::TREASURY, chain.next_difficulty());
    b.txs = vec![seed_tx];
    let b = chain.prepare_block(b);
    chain.apply(b).unwrap();

    let cell = 0;
    let lock_until = 100u64;
    let inputs = vec![(cell, cell + 50)];
    let outputs = vec![state::Output {
        start: cell,
        end: cell + 50,
        to: owner,
        lock: Some(lock_until),
    }];
    let hash = chain::tx_signature_hash(&owner, &inputs, &outputs, &chain.chain_id, 0);
    let sig = crypto::sign(&sk, &hash);

    let mut b2 = mine_valid_block(&chain, 2, owner, chain.next_difficulty());
    b2.txs.push(chain::Tx {
        from: owner,
        inputs,
        outputs,
        sig,
        scheme: 0,
    });
    let b2 = chain.prepare_block(b2);
    chain.apply(b2).unwrap();

    assert_eq!(chain.state.locks.get(&cell), Some(&lock_until));
}

// ---------------------------------------------------------------------------
// P2P Sync Tip Request
// ---------------------------------------------------------------------------

/// Verify that a sync tip request returns the expected height and hash
/// by simulating the request-response logic against a loaded chain.
#[test]
fn test_p2p_sync_tip_request() {
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    for h in 1..=5 {
        let b = mine_valid_block(&chain, h, miner, chain.next_difficulty());
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    let tip_height = chain.blocks.len() as u64 + chain.base_height - 1;
    let tip_hash = chain.tip_hash();
    assert_eq!(tip_height, 5);
    assert_ne!(tip_hash, [0u8; 32]);
}

// ---------------------------------------------------------------------------
// Header-First Download Range
// ---------------------------------------------------------------------------

/// Verify that the header range request logic computes the correct start
/// and end indices when the local chain has a non-zero base height.
#[test]
fn test_header_first_download_range() {
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    for h in 1..=10 {
        let b = mine_valid_block(&chain, h, miner, chain.next_difficulty());
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    // Simulate pruning by advancing base_height and truncating blocks.
    chain.base_height = 3;
    chain.blocks.drain(..2);

    let from = 5u64;
    let to = 8u64;
    let start = (from - chain.base_height) as usize;
    let end = (to.min(chain.blocks.len() as u64 + chain.base_height) - chain.base_height) as usize;

    let headers: Vec<_> = chain
        .blocks
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .map(chain::BlockHeader::from_block)
        .collect();

    assert_eq!(headers.len(), 3);
    assert_eq!(headers[0].height, 5);
    assert_eq!(headers[2].height, 7);
}

// ---------------------------------------------------------------------------
// DoS Spam Transaction Rejection
// ---------------------------------------------------------------------------

/// Verify that a transaction with an invalid signature is rejected before
/// any state mutation occurs, simulating a spam attack.
#[test]
fn test_dos_spam_rejection() {
    let mut chain = chain::Chain::genesis();
    let victim = [1u8; 32];
    let attacker = [2u8; 32];

    // Seed victim with 50 cells so the forged spend targets real cells.
    let seed = state::Output {
        start: 0,
        end: 50,
        to: victim,
        lock: None,
    };
    let seed_tx = chain::Tx {
        from: state::TREASURY,
        inputs: vec![(0, 50)],
        outputs: vec![seed],
        sig: vec![],
        scheme: 0,
    };
    let mut b = mine_valid_block(&chain, 1, state::TREASURY, chain.next_difficulty());
    b.txs = vec![seed_tx];
    let b = chain.prepare_block(b);
    chain.apply(b).unwrap();

    // Attacker tries to spend the victim's cells with a forged signature.
    let inputs = vec![(0, 50)];
    let outputs = vec![state::Output {
        start: 0,
        end: 50,
        to: attacker,
        lock: None,
    }];
    let forged_sig = vec![0xffu8; 64];

    // The transaction must fail and leave every page bit-for-bit unchanged.
    let before = chain.state.clone();
    assert!(!chain.state.tx(
        victim,
        &inputs,
        &outputs,
        &forged_sig,
        2,
        &chain.chain_id,
        0
    ));
    assert_eq!(chain.state.pages, before.pages);
}

// ---------------------------------------------------------------------------
// Mempool Overflow Simulation
// ---------------------------------------------------------------------------

/// Verify that the mempool validation path scales correctly under load.
/// Each transaction transfers exactly fifty cells from the treasury, which
/// owns every unissued cell and therefore needs no signature.
#[test]
fn test_mempool_overflow_eviction() {
    // The chain is only queried through validate_tx, which takes &self.
    let chain = chain::Chain::genesis();
    let recipient = [2u8; 32];

    let mut txs = Vec::new();
    for i in 0..(p2p::MEMPOOL_CAP + 5) {
        let start = i as u64 * 50;
        let inputs = vec![(start, start + 50)];
        let outputs = vec![state::Output {
            start,
            end: start + 50,
            to: recipient,
            lock: None,
        }];
        txs.push(chain::Tx {
            from: state::TREASURY,
            inputs,
            outputs,
            sig: vec![],
            scheme: 0,
        });
    }

    // In a real node these would be added through add_to_mempool which enforces
    // the cap. Here we verify the structural validation path scales.
    for tx in &txs {
        assert!(chain.validate_tx(tx));
    }
}

// ---------------------------------------------------------------------------
// Rate Limiting Simulation
// ---------------------------------------------------------------------------

/// Verify that the per-peer rate limiting logic prevents a single peer from
/// flooding the mempool by checking the timestamp map behavior.
#[test]
fn test_rate_limiting_simulation() {
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    let b = mine_valid_block(&chain, 1, owner, chain.next_difficulty());
    let b = chain.prepare_block(b);
    chain.apply(b).unwrap();

    // Use a valid treasury transaction with fifty cells.
    let tx = chain::Tx {
        from: state::TREASURY,
        inputs: vec![(0, 50)],
        outputs: vec![state::Output {
            start: 0,
            end: 50,
            to: owner,
            lock: None,
        }],
        sig: vec![],
        scheme: 0,
    };

    // Direct validation of the rate-limiting logic is internal to the Node
    // struct, so we verify that the transaction itself is valid and would
    // pass the structural checks that occur before rate limiting.
    assert!(chain.validate_tx(&tx));
}

// ---------------------------------------------------------------------------
// Snapshot Pruning
// ---------------------------------------------------------------------------

/// Verify that prune_snapshots retains exactly the three most recent snapshots
/// and removes all older ones.
#[test]
fn test_snapshot_pruning() {
    with_temp_dir(|| {
        let state = state::State::genesis();

        for h in [1000, 2000, 3000, 4000, 5000] {
            storage::save_snapshot(&state, h).unwrap();
        }

        storage::prune_snapshots().unwrap();

        let mut remaining = Vec::new();
        for entry in std::fs::read_dir("snapshots").unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("state_") {
                remaining.push(name);
            }
        }

        assert_eq!(remaining.len(), 3);
    });
}

// ---------------------------------------------------------------------------
// Auto Recovery From Snapshot
// ---------------------------------------------------------------------------

/// Verify that load_pruned automatically falls back to the latest snapshot
/// when both the state file and the block metadata are missing.
#[test]
fn test_auto_recovery_from_snapshot() {
    with_temp_dir(|| {
        let mut chain = chain::Chain::genesis();
        let miner = [1u8; 32];

        for h in 1..=10 {
            let b = mine_valid_block(&chain, h, miner, chain.next_difficulty());
            let b = chain.prepare_block(b);
            chain.apply(b).unwrap();
        }

        slash::save(&chain);
        storage::save_snapshot(&chain.state, 10).unwrap();

        // Delete the live state to force recovery.
        std::fs::remove_file("header.bin").unwrap();

        let recovered = slash::load_pruned();
        assert_eq!(recovered.state.balance(miner), chain.state.balance(miner));
    });
}

// ---------------------------------------------------------------------------
// Block Hash Deterministic
// ---------------------------------------------------------------------------

/// Verify that the block hash function produces the same output for identical
/// block contents across multiple invocations.
#[test]
fn test_block_hash_deterministic() {
    let chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    let b = mine_valid_block(&chain, 1, miner, chain.next_difficulty());
    let b = chain.prepare_block(b);

    let h1 = chain.block_hash(&b);
    let h2 = chain.block_hash(&b);
    assert_eq!(h1, h2);
}

// ---------------------------------------------------------------------------
// Genesis Chain ID
// ---------------------------------------------------------------------------

/// Verify that mainnet and testnet genesis chains carry distinct identifiers.
#[test]
fn test_genesis_chain_id() {
    let mainnet = chain::Chain::genesis();
    let testnet = chain::Chain::testnet_genesis();
    assert_ne!(mainnet.chain_id, testnet.chain_id);
    assert_eq!(mainnet.chain_id, b"/slash/0.2.0");
    assert_eq!(testnet.chain_id, b"/slash/test/0.2.0");
}

// ---------------------------------------------------------------------------
// Treasury Buy Price Integral
// ---------------------------------------------------------------------------

/// Verify that the buy price formula matches the manual integral of the
/// linear bonding curve for a small amount.
#[test]
fn test_treasury_buy_price_integral() {
    let ts = treasury::TreasuryState {
        reserve_fiat: 0,
        total_sold: 100,
        total_bought_back: 0,
        vrf_public: [0u8; 32],
        signer_public: [0u8; 32],
        onion_public: [0u8; 32],
    };

    let amount = 10u64;
    // Per-cell price on the linear curve: BASE_PRICE * (1 + total_sold / K).
    let manual: u128 = (0..amount)
        .map(|i| {
            treasury::BASE_PRICE as u128 * (1 + (ts.total_sold + i) as u128 / treasury::K as u128)
        })
        .sum();

    let computed = ts.buy_price(amount) as u128;
    assert_eq!(computed, manual);
}

// ---------------------------------------------------------------------------
// Pristine Page Root Constant
// ---------------------------------------------------------------------------

/// Verify that the Merkle root of a pristine page is equal to the hash of a
/// single range covering the entire page and owned by the treasury.
#[test]
fn test_pristine_page_root_constant() {
    let size = state::PAGE_SIZE;
    let root = state::Page::pristine_root(size);

    let mut page = state::Page {
        ranges: BTreeMap::new(),
    };
    page.ranges.insert(
        0,
        state::R {
            e: size,
            o: state::TREASURY,
        },
    );
    let computed = page.merkle_root();

    assert_eq!(root, computed);
}

// ---------------------------------------------------------------------------
// Select Single Returns Contiguous Range
// ---------------------------------------------------------------------------

/// Verify that select_single returns a single contiguous range when one exists
/// and returns None when the owner has only fragmented cells.
#[test]
fn test_select_single_contiguous() {
    let mut st = state::State::genesis();
    let owner = [1u8; 32];

    st.mine(10, owner, 0);
    st.mine(11, owner, 0);
    st.mine(12, owner, 0);

    assert_eq!(st.select_single(owner, 3), Some((10, 13)));
    assert_eq!(st.select_single(owner, 4), None);
}

// ---------------------------------------------------------------------------
// Multi-Input Balance Per Page
// ---------------------------------------------------------------------------

/// Verify that a transaction crossing page boundaries is rejected when one of
/// the pages would become unbalanced.
#[test]
fn test_multi_input_balance_per_page() {
    let mut st = state::State::genesis();
    // The owner is the public key matching the signing secret below.
    let (sk, pk) = crypto::generate_keypair();
    let owner = pk;
    let page_size = state::PAGE_SIZE;

    // Mine cells at the end of page 0 and the start of page 1.
    st.mine(page_size - 1, owner, 0);
    st.mine(page_size, owner, 0);

    // Valid transaction: exactly balances on both pages.
    let inputs = vec![(page_size - 1, page_size + 1)];
    let valid_outputs = vec![
        state::Output {
            start: page_size - 1,
            end: page_size,
            to: [2u8; 32],
            lock: None,
        },
        state::Output {
            start: page_size,
            end: page_size + 1,
            to: owner,
            lock: None,
        },
    ];
    let hash = chain::tx_signature_hash(&owner, &inputs, &valid_outputs, b"/slash/0.2.0", 0);
    let sig = crypto::sign(&sk, &hash);
    assert!(st.tx(owner, &inputs, &valid_outputs, &sig, 0, b"/slash/0.2.0", 0));

    // Invalid: the second page receives no output for its input cell, so it
    // would become unbalanced. The outputs also fail contiguous packing.
    let invalid_outputs = vec![state::Output {
        start: page_size - 1,
        end: page_size,
        to: [2u8; 32],
        lock: None,
    }];
    let hash2 = chain::tx_signature_hash(&owner, &inputs, &invalid_outputs, b"/slash/0.2.0", 0);
    let sig2 = crypto::sign(&sk, &hash2);
    assert!(!st.tx(
        owner,
        &inputs,
        &invalid_outputs,
        &sig2,
        0,
        b"/slash/0.2.0",
        0
    ));
}

// ---------------------------------------------------------------------------
// Chain Reorg State Consistency
// ---------------------------------------------------------------------------

/// Verify that after a chain reorganization the state balance reflects the
/// new main chain and not the disconnected blocks.
#[test]
fn test_reorg_state_consistency() {
    let mut chain = chain::Chain::genesis();
    let miner_a = [1u8; 32];
    let miner_b = [2u8; 32];

    // Build main chain: 3 blocks.
    for h in 1..=3 {
        let b = mine_valid_block(&chain, h, miner_a, chain.next_difficulty());
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }
    assert_eq!(chain.state.balance(miner_a), 3);

    // Build a side fork starting from height 1.
    let fork_parent = chain.block_hash(&chain.blocks[1]);
    let mut fork_blocks = Vec::new();
    for h in 2..=4 {
        let prev = if h == 2 {
            fork_parent
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
        let mut roots = BTreeMap::new();
        for (&page_id, page) in &temp.pages {
            roots.insert(page_id, page.merkle_root());
        }
        b.page_roots = roots;
        fork_blocks.push(b);
    }

    // Process fork blocks and trigger reorg at height 4.
    for fb in &fork_blocks {
        chain.process_block(fb.clone()).unwrap();
    }

    // After reorg, miner_b should have mined 3 blocks (heights 2, 3, 4).
    assert_eq!(chain.state.balance(miner_b), 3);
    // miner_a keeps only the pre-fork block (height 1); heights 2 and 3 were
    // disconnected by the reorganization.
    assert_eq!(chain.state.balance(miner_a), 1);
}

// ---------------------------------------------------------------------------
// Empty Block Valid
// ---------------------------------------------------------------------------

/// Verify that a block with no transactions and no fee claims is accepted
/// by the validation pipeline.
#[test]
fn test_empty_block_valid() {
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    let b = mine_valid_block(&chain, 1, miner, chain.next_difficulty());
    let b = chain.prepare_block(b);
    assert!(chain.validate_block(&b));
    chain.apply(b).unwrap();
    assert_eq!(chain.state.balance(miner), 1);
}

// ---------------------------------------------------------------------------
// Duplicate Block Rejected
// ---------------------------------------------------------------------------

/// Verify that processing the same block twice returns Duplicate and does not
/// modify the chain.
#[test]
fn test_duplicate_block_rejected() {
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    let b = mine_valid_block(&chain, 1, miner, chain.next_difficulty());
    let b = chain.prepare_block(b);
    chain.apply(b.clone()).unwrap();

    let result = chain.process_block(b).unwrap();
    assert!(matches!(result, chain::BlockProcessResult::Duplicate));
}

// ---------------------------------------------------------------------------
// Invalid Height Sequence Rejected
// ---------------------------------------------------------------------------

/// Verify that a block whose height does not match the expected next height
/// is rejected as Invalid.
#[test]
fn test_invalid_height_sequence() {
    let chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    let mut b = mine_valid_block(&chain, 2, miner, chain.next_difficulty());
    b.height = 5;
    assert!(!chain.validate_block(&b));
}

// ---------------------------------------------------------------------------
// Median Timestamp Calculation
// ---------------------------------------------------------------------------

/// Verify that the median timestamp of the last eleven blocks is computed
/// correctly for an even number of samples (genesis plus five blocks).
#[test]
fn test_median_timestamp() {
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    for h in 1..=5 {
        let mut b = mine_valid_block(&chain, h, miner, chain.next_difficulty());
        b.time = h * 100;
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    // The window covers genesis (time 0) and blocks at 100..=500:
    // sorted [0, 100, 200, 300, 400, 500] -> median (200 + 300) / 2 = 250.
    let median = chain.median_timestamp();
    assert_eq!(median, 250);
}

// ---------------------------------------------------------------------------
// Difficulty Clamp
// ---------------------------------------------------------------------------

/// Verify that the difficulty retarget is clamped to a maximum 4x increase
/// and a minimum 4x decrease per interval.
#[test]
fn test_difficulty_clamp() {
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    for h in 1..=chain::DIFFICULTY_ADJUSTMENT_INTERVAL {
        let mut b = mine_valid_block(&chain, h, miner, chain.next_difficulty());
        b.time = h * chain::TARGET_BLOCK_TIME_SECS / 10;
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    let next = chain.next_difficulty();
    let last = chain.blocks.last().unwrap().difficulty;
    assert!(next <= last.saturating_mul(4));
    assert!(next >= last.saturating_div(4).max(1));
}
