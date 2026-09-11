//! End-to-end tests for atomic storage, snapshot lifecycle, and pruned recovery.

use slash::*;

mod common;
use common::*;

#[test]
fn test_storage_save_and_load_state() {
    let _tmp = setup_test_dir("storage_state");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    chain.state.mine(100, owner, 0);
    storage::save(&chain.state).unwrap();

    let loaded = storage::load().unwrap();
    assert_eq!(loaded.balance(owner), 1);
}

#[test]
fn test_storage_save_and_load_blocks() {
    let _tmp = setup_test_dir("storage_blocks");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    for _ in 0..3 {
        let b = mine_next_block(&mut chain, miner, vec![]);
        chain.apply(b).unwrap();
    }

    storage::save_blocks(&chain.blocks).unwrap();
    let loaded = storage::load_blocks().unwrap();

    assert_eq!(loaded.len(), chain.blocks.len());
}

#[test]
fn test_storage_chain_meta_roundtrip() {
    let _tmp = setup_test_dir("storage_meta");
    reset_testnet();

    storage::save_chain_meta(12345).unwrap();
    let loaded = storage::load_chain_meta().unwrap();
    assert_eq!(loaded, 12345);
}

#[test]
fn test_snapshot_save_and_load() {
    let _tmp = setup_test_dir("storage_snapshot");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let owner = [1u8; 32];

    chain.state.mine(50, owner, 0);
    storage::save_snapshot(&chain.state, 10).unwrap();

    let (height, loaded) = storage::load_latest_snapshot(10).unwrap();
    assert_eq!(height, 10);
    assert_eq!(loaded.balance(owner), 1);
}

#[test]
fn test_snapshot_prune_keeps_last_three() {
    let _tmp = setup_test_dir("storage_prune");
    reset_testnet();
    let state = chain::Chain::genesis().state;

    for h in 1..=6 {
        storage::save_snapshot(&state, h).unwrap();
    }

    storage::prune_snapshots().unwrap();

    let mut remaining = 0;
    if let Ok(entries) = std::fs::read_dir("snapshots") {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().ends_with(".bin") {
                remaining += 1;
            }
        }
    }
    assert_eq!(remaining, 3);
}

#[test]
fn test_load_pruned_recovers_from_snapshot() {
    let _tmp = setup_test_dir("storage_load_pruned");
    reset_testnet();

    let mut chain = chain::Chain::genesis();
    let miner = [1u8; 32];

    for _ in 0..5 {
        let b = mine_next_block(&mut chain, miner, vec![]);
        chain.apply(b).unwrap();
    }

    let height = chain.blocks.len() as u64 + chain.base_height;
    storage::save_blocks(&chain.blocks).unwrap();
    storage::save(&chain.state).unwrap();
    storage::save_chain_meta(chain.base_height).unwrap();
    storage::save_snapshot(&chain.state, height).unwrap();

    let pruned = slash::load_pruned();
    assert_eq!(pruned.blocks.len(), chain.blocks.len());
}
