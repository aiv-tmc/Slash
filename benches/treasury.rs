//! Treasury pairing benchmark: a block carrying 64 complete buy pairs,
//! every transaction constructed against a scratch state that mirrors the
//! block's own sequential execution so all pairs genuinely pair, mint,
//! and advance the running total_sold.

use super::{engine_outputs, wire_outputs};
use criterion::{black_box, Criterion};
use std::collections::BTreeMap;

/// Benchmark the treasury buy/sell pairing scan inside block validation.
/// The block carries 64 complete buy pairs (one T_buy plus one signed
/// T_mint each); every transaction is constructed against a scratch state
/// that mirrors the block's own sequential execution (slot mint, coinbase
/// mint, and every preceding pair included), so all 64 pairs genuinely
/// pair, mint, and advance the running total_sold. Validation at
/// difficulty 1 still performs one real RandomX hash per iteration.
pub fn bench_treasury_pairing_scan(c: &mut Criterion) {
    const PAIRS: usize = 64;
    const AMOUNT: u64 = 50;

    let mut chain = slash::chain::Chain::genesis();
    let (signer_sk, signer_pk) = slash::crypto::generate_keypair();
    chain.state.treasury_signer = signer_pk;
    let chain_id = slash::chain::MAINNET_ID.as_bytes().to_vec();
    let miner = [9u8; 32];

    // Fund every buyer on the real chain state first: block validation
    // checks input ownership against the live state, so the buyers' cells
    // must exist there, not only in the scratch mirror.
    let mut buyer_keys = Vec::with_capacity(PAIRS);
    for i in 0..PAIRS {
        let (buyer_sk, buyer_pk) = slash::crypto::generate_keypair();
        let base = 1_000_000u64 + i as u64 * 200;
        for cell in base..base + 120 {
            chain.state.mine(cell, buyer_pk, 0);
        }
        buyer_keys.push((buyer_sk, buyer_pk));
    }

    // The coinbase is part of the block execution, so the scratch state
    // must absorb it before any canonical mint inputs are computed.
    let coinbase = slash::chain::Chain::build_coinbase(&chain.state, miner, 1, 0).unwrap();
    let mut scratch = chain.state.clone();
    // Mirror the PoW slot mint before the coinbase: execute_block_state
    // mints the slot first, and because canonical selection scans the dirty
    // page map, the slot's page enters the selection order ahead of the
    // buyers' pages. Skipping this step desynchronizes every canonical
    // mint-input computation below from the consensus execution.
    scratch.mine(500_000, miner, 1);
    assert!(scratch.mint(&coinbase.inputs, &engine_outputs(&coinbase.outputs), 1));

    let mut txs: Vec<slash::chain::Tx> = Vec::new();

    for (i, (buyer_sk, buyer_pk)) in buyer_keys.iter().enumerate() {
        let base = 1_000_000u64 + i as u64 * 200;

        // T_buy: enough cells fund the vault payment (buy_price grows with
        // the running total_sold), the mandatory fee, and change.
        let cost = slash::treasury::buy_price(AMOUNT, scratch.total_sold) + 10;
        let inputs = vec![(base, base + 120)];
        let outputs = vec![
            slash::state::Output {
                start: base,
                end: base + cost,
                to: slash::state::TREASURY_VAULT,
                lock: None,
            },
            slash::state::Output {
                start: base + cost,
                end: base + cost + 1,
                to: slash::state::FEE_VAULT,
                lock: None,
            },
            slash::state::Output {
                start: base + cost + 1,
                end: base + 120,
                to: *buyer_pk,
                lock: None,
            },
        ];
        let hash = slash::chain::Chain::tx_signature_hash(
            buyer_pk, &inputs, &outputs, &chain_id, 0, &None,
        );
        let sig = slash::crypto::sign(buyer_sk, &hash);
        let buy = slash::chain::Tx {
            from: *buyer_pk,
            inputs,
            outputs: wire_outputs(&outputs),
            sig,
            scheme: 0,
            memo: None,
        };
        // Mirror the payment on the scratch state before computing the
        // canonical mint inputs for this pair.
        assert!(scratch.tx(
            *buyer_pk,
            &buy.inputs,
            &engine_outputs(&buy.outputs),
            &buy.sig,
            0,
            &chain_id,
            0,
            &None
        ));

        // T_mint: treasury-signer-signed mint at the canonical
        // select_single range for the running total_sold.
        let mint_inputs = [scratch
            .select_single(slash::state::TREASURY, AMOUNT)
            .unwrap()];
        let mint_outputs = vec![slash::state::Output {
            start: mint_inputs[0].0,
            end: mint_inputs[0].1,
            to: *buyer_pk,
            lock: None,
        }];
        let hash = slash::chain::Chain::tx_signature_hash(
            &slash::state::TREASURY,
            &mint_inputs,
            &mint_outputs,
            &chain_id,
            0,
            &None,
        );
        let sig = slash::crypto::sign(&signer_sk, &hash);
        let mint = slash::chain::Tx {
            from: slash::state::TREASURY,
            inputs: mint_inputs.to_vec(),
            outputs: wire_outputs(&mint_outputs),
            sig,
            scheme: 0,
            memo: None,
        };
        assert!(scratch.mint(&mint.inputs, &engine_outputs(&mint.outputs), 0));
        scratch.total_sold += AMOUNT;

        txs.push(buy);
        txs.push(mint);
    }

    let mut block_txs = vec![coinbase];
    block_txs.extend(txs);
    let mut block = slash::chain::Block {
        version: 1,
        prev: chain.tip_hash(),
        time: chrono::Utc::now().timestamp() as u64,
        height: 1,
        nonce: 0,
        miner,
        mined_cell: 0,
        txs: block_txs,
        fee_claims: vec![],
        difficulty: 1,
        page_roots: BTreeMap::new(),
    };
    // The consensus slot rule binds the declared mined_cell to the
    // proof hash: grind a nonce with the light verifier (identical
    // RandomX hash, bounded memory) and declare the drawn slot.
    let mut nonce = 0u64;
    let slot = loop {
        if let Some(cell) = slash::chain::verify_pow(
            block.prev,
            block.time,
            block.height,
            block.miner,
            nonce,
            block.difficulty,
        ) {
            break cell;
        }
        nonce += 1;
    };
    block.nonce = nonce;
    block.mined_cell = slot;
    let block = chain.prepare_block(block);
    if !chain.validate_block(&block) {
        // Staged diagnosis: replay the consensus pipeline with public APIs
        // to localize the exact stage and transaction index that rejects the
        // fixture. Every consensus branch of execute_block_txs is mirrored
        // here (slot mint, coinbase mint, ordinary transfer, treasury mint),
        // so the printed stage pinpoints the first divergence.
        let mut temp = chain.state.clone();
        temp.mine(500_000, miner, 1);
        let cb = &block.txs[0];
        let coinbase_ok = temp.mint(&cb.inputs, &engine_outputs(&cb.outputs), block.height);
        eprintln!("diagnosis: coinbase mint ok = {coinbase_ok}");
        for (idx, tx) in block.txs.iter().enumerate().skip(1) {
            if tx.from == slash::state::TREASURY {
                let mint_ok = temp.mint(&tx.inputs, &engine_outputs(&tx.outputs), block.height);
                eprintln!("diagnosis: tx {idx} treasury mint ok = {mint_ok}");
                if mint_ok {
                    temp.total_sold += tx.outputs.iter().map(|o| o.end - o.start).sum::<u64>();
                }
            } else {
                let ok = temp.tx(
                    tx.from,
                    &tx.inputs,
                    &engine_outputs(&tx.outputs),
                    &tx.sig,
                    block.height,
                    chain.chain_id.as_bytes(),
                    tx.scheme,
                    &tx.memo,
                );
                eprintln!("diagnosis: tx {idx} transfer ok = {ok}");
            }
            if chain.validate_block(&block) {
                break;
            }
        }
        panic!("treasury pairing fixture failed validate_block");
    }

    let mut group = c.benchmark_group("treasury_pairing");
    group.sample_size(10);
    group.bench_function("validate_block_64_buy_pairs", |b| {
        b.iter(|| {
            black_box(chain.validate_block(&block));
        });
    });
    group.finish();
}
