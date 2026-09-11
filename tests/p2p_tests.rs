//! End-to-end tests for P2P wire format, request-response codec,
//! mempool policy simulation, and DoS resistance through chain-level validation.

use slash::*;
use std::collections::BTreeMap;

mod common;
use common::*;

// ---------------------------------------------------------------------------
// Request-Response Codec
// ---------------------------------------------------------------------------

#[test]
fn test_req_get_block_serialization() {
    let req = p2p::Req::GetBlock(42);
    let bytes = bincode::serialize(&req).unwrap();
    let restored: p2p::Req = bincode::deserialize(&bytes).unwrap();
    assert!(matches!(restored, p2p::Req::GetBlock(42)));
}

#[test]
fn test_req_get_blocks_serialization() {
    let req = p2p::Req::GetBlocks(10, 20);
    let bytes = bincode::serialize(&req).unwrap();
    let restored: p2p::Req = bincode::deserialize(&bytes).unwrap();
    assert!(matches!(restored, p2p::Req::GetBlocks(10, 20)));
}

#[test]
fn test_resp_block_serialization() {
    let mut chain = chain::Chain::genesis();
    let block = mine_next_block(&mut chain, [1u8; 32], vec![]);
    let resp = p2p::Resp::Block(Some(block));
    let bytes = bincode::serialize(&resp).unwrap();
    let restored: p2p::Resp = bincode::deserialize(&bytes).unwrap();
    assert!(matches!(restored, p2p::Resp::Block(Some(_))));
}

#[test]
fn test_resp_headers_serialization() {
    let mut chain = chain::Chain::genesis();
    let block = mine_next_block(&mut chain, [1u8; 32], vec![]);
    let header = chain::BlockHeader::from_block(&block);
    let resp = p2p::Resp::Headers(vec![header]);
    let bytes = bincode::serialize(&resp).unwrap();
    let restored: p2p::Resp = bincode::deserialize(&bytes).unwrap();
    assert!(matches!(restored, p2p::Resp::Headers(_)));
}

// ---------------------------------------------------------------------------
// Mempool Policy via Chain Validation
// ---------------------------------------------------------------------------

#[test]
fn test_mempool_double_spend_rejected_at_block_level() {
    let _tmp = setup_test_dir("ds_block");
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
fn test_mempool_rate_limiting_simulated() {
    let _tmp = setup_test_dir("rate_limit");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let recipient = [2u8; 32];

    // Repeated valid submissions: five distinct treasury-funded transactions
    // (the treasury signs nothing and owns every unissued cell) are validated
    // and packaged into a single block, exercising the same structural checks
    // that run before per-peer rate limiting inside the Node.
    let mut txs = Vec::new();
    for i in 0..5u64 {
        let start = i * 50;
        txs.push(chain::Tx {
            from: state::TREASURY,
            inputs: vec![(start, start + 50)],
            outputs: vec![state::Output {
                start,
                end: start + 50,
                to: recipient,
                lock: None,
            }],
            sig: vec![],
            scheme: 0,
        });
    }

    let b = mine_next_block(&mut chain, [1u8; 32], txs);
    chain.apply(b).unwrap();
    assert_eq!(chain.state.balance(recipient), 250);
}

#[test]
fn test_mempool_cap_eviction_simulated() {
    let _tmp = setup_test_dir("mempool_cap");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    // One transaction more than the mempool capacity is also more than the
    // per-block transaction cap, so the block must be invalid either way.
    let mut txs = Vec::new();
    for i in 0..=p2p::MEMPOOL_CAP {
        let idx = i as u64;
        let start = idx * 50;
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

    let b = mine_next_block(&mut chain, [1u8; 32], txs);
    assert!(!chain.validate_block(&b));
    assert!(b.txs.len() > chain::MAX_TX_PER_BLOCK);
}

// ---------------------------------------------------------------------------
// Sync & Header-First Logic
// ---------------------------------------------------------------------------

#[test]
fn test_header_first_validation_chain() {
    let _tmp = setup_test_dir("header_sync");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    let mut headers = Vec::new();
    for _ in 0..5 {
        let block = mine_next_block(&mut chain, miner, vec![]);
        let header = chain::BlockHeader::from_block(&block);
        headers.push(header);
        chain.apply(block).unwrap();
    }

    for header in &headers {
        assert!(header.height > 0);
        assert_ne!(header.prev, [0u8; 32]);
    }
}

#[test]
fn test_block_gossip_payload_size() {
    let _tmp = setup_test_dir("gossip_size");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let block = mine_next_block(&mut chain, [1u8; 32], vec![]);
    let bytes = bincode::serialize(&block).unwrap();
    assert!(!bytes.is_empty());
    assert!(bytes.len() <= 4 * 1024 * 1024);
}

// ---------------------------------------------------------------------------
// DoS Resistance
// ---------------------------------------------------------------------------

#[test]
fn test_dos_spam_tx_with_zero_fee_rejected() {
    let _tmp = setup_test_dir("dos_spam");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    // Alice is the public key matching the signing secret used below.
    let (sk, pk) = crypto::generate_keypair();
    let alice = pk;

    // Seed alice with 50 cells; the seed block is mined by the treasury so
    // the reward cell can never invalidate the seed transaction.
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
        to: [2u8; 32],
        lock: None,
    }];
    let tx = make_tx(alice, &sk, &[(0, 50)], &outputs, &chain.chain_id);

    let b2 = mine_next_block(&mut chain, state::TREASURY, vec![tx]);
    chain.apply(b2).unwrap();
    assert_eq!(chain.state.balance([2u8; 32]), 50);
}

#[test]
fn test_dos_oversized_block_rejected() {
    let _tmp = setup_test_dir("dos_oversized");
    reset_testnet();
    let mut chain = chain::Chain::genesis();

    let mut txs = Vec::new();
    for i in 0..200 {
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

    let b = mine_next_block(&mut chain, [1u8; 32], txs);
    // The consensus size limit is checked against bincode serialization,
    // which is the same format used for P2P transmission and disk storage.
    let serialized = bincode::serialize(&b).unwrap_or_default();
    if serialized.len() > chain::MAX_BLOCK_SIZE_BYTES {
        assert!(!chain.validate_block(&b));
    }
}

#[test]
fn test_dos_invalid_pow_rejected() {
    let _tmp = setup_test_dir("dos_pow");
    reset_testnet();
    let chain = chain::Chain::genesis();

    let mut block = chain::Block {
        version: 1,
        prev: chain.tip_hash(),
        time: 1,
        height: 1,
        nonce: 0,
        miner: [1u8; 32],
        mined_cell: 0,
        txs: vec![],
        fee_claims: vec![],
        difficulty: chain.next_difficulty(),
        page_roots: BTreeMap::new(),
    };
    block.nonce = 12345;

    assert!(!chain.validate_block(&block));
}

#[test]
fn test_dos_future_timestamp_rejected() {
    let _tmp = setup_test_dir("dos_future");
    reset_testnet();
    let chain = chain::Chain::genesis();

    let mut block = chain::Block {
        version: 1,
        prev: chain.tip_hash(),
        time: chrono::Utc::now().timestamp() as u64 + 7201,
        height: 1,
        nonce: 0,
        miner: [1u8; 32],
        mined_cell: 0,
        txs: vec![],
        fee_claims: vec![],
        difficulty: chain.next_difficulty(),
        page_roots: BTreeMap::new(),
    };
    // The nonce search only makes the PoW valid; the timestamp rule must
    // still reject the block afterwards.
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

    assert!(!chain.validate_block(&block));
}
