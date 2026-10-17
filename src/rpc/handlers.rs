//! src/rpc/handlers.rs — the JSON-RPC method handlers.
//!
//! Every chain-reading handler resolves the chain through
//! `crate::cached_load()`, the shared in-memory cache keyed on the
//! manifest, so no handler re-reads or re-deserializes the chain from
//! disk per request. `sendRawTx` validates against the chain tip and
//! queues into the global pending buffer that the P2P node drains into
//! the mempool; the returned transaction id is the content-based id the
//! mempool uses, so wallets can track their submission through
//! `getMempool` without a second id scheme. The treasury quote handlers
//! evaluate the curve at the chain's current position and report that
//! position alongside the unsigned transaction: the quote is valid
//! exactly at the reported curve position, and the treasury signer
//! re-verifies the price at signing time, because every earlier pair in
//! the block advances the position the execution prices against.

use super::{RpcError, RpcShared};
use serde_json::{json, Value};

/// The maximum number of transactions the getMempool response renders.
/// The queue depth is reported before truncation so fee estimation keeps
/// working when the buffer runs ahead of the response cap.
const MEMPOOL_RESPONSE_CAP: usize = 100;

/// Decoded request parameters: a hex-encoded address at `index`.
fn decode_address(params: &Value, index: usize) -> Result<[u8; 32], RpcError> {
    let hex_str = params
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing address parameter"))?;
    let bytes =
        hex::decode(hex_str).map_err(|_| RpcError::invalid_params("address is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| RpcError::invalid_params("address must be 32 bytes"))
}

/// getBalance: the cell count of an address, served from the balance
/// cache maintained by the state engine.
pub(super) async fn handle_get_balance(params: &Value) -> Result<Value, RpcError> {
    let address = decode_address(params, 0)?;
    let chain = crate::cached_load();
    Ok(json!(chain.state.balance(address)))
}

/// getBlock: the full block at a height, or null below the retained
/// window and above the tip.
pub(super) async fn handle_get_block(params: &Value) -> Result<Value, RpcError> {
    let height = params
        .get(0)
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::invalid_params("missing height parameter"))?;
    let chain = crate::cached_load();
    if height < chain.base_height {
        return Ok(Value::Null);
    }
    let index = (height - chain.base_height) as usize;
    Ok(chain
        .blocks
        .get(index)
        .map(|block| serde_json::to_value(block).unwrap_or(Value::Null))
        .unwrap_or(Value::Null))
}

/// getTip: the current tip height and block hash.
pub(super) async fn handle_get_tip() -> Result<Value, RpcError> {
    let chain = crate::cached_load();
    Ok(json!({
        "height": chain.tip_height(),
        "hash": hex::encode(chain.tip_hash()),
    }))
}

/// getDifficulty: the difficulty target for the next block.
pub(super) async fn handle_get_difficulty() -> Result<Value, RpcError> {
    let chain = crate::cached_load();
    Ok(json!(chain.next_difficulty()))
}

/// sendRawTx: decode, validate against the tip, and queue into the
/// pending buffer the node drains into its mempool. The returned id is
/// the content-based transaction id the mempool deduplicates, assembles,
/// and purges by — blake3 over the signature concatenated with the
/// serialized body — so a wallet tracks one id end to end, and unsigned
/// transactions no longer collapse onto the id of the empty signature.
pub(super) async fn handle_send_raw_tx(params: &Value) -> Result<Value, RpcError> {
    let hex_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing raw transaction parameter"))?;
    let bytes = hex::decode(hex_str)
        .map_err(|_| RpcError::invalid_params("transaction is not valid hex"))?;
    let tx: crate::chain::Tx = bincode::deserialize(&bytes)
        .map_err(|_| RpcError::invalid_params("transaction deserialization failed"))?;
    let chain = crate::cached_load();
    if !chain.validate_tx(&tx) {
        return Err(RpcError::invalid_tx("consensus validation failed"));
    }
    let txid = crate::p2p::tx_id(&tx);
    if let Some(mut pending) = crate::PENDING_TXS.get().and_then(|buf| buf.lock().ok()) {
        pending.push(tx);
    }
    Ok(json!(hex::encode(txid)))
}

/// getPageProof: the Merkle proof of the page containing a cell, so
/// light clients can verify ownership against the page root committed in
/// the block header without replaying the chain. Pristine pages carry no
/// materialized range map, so a proof is only served for cells on pages
/// that actually moved; a pristine page's commitment is publicly
/// derivable from the page id and size alone.
pub(super) async fn handle_get_page_proof(params: &Value) -> Result<Value, RpcError> {
    let cell = params
        .get(0)
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::invalid_params("missing cell index parameter"))?;
    if cell >= crate::state::N {
        return Err(RpcError::invalid_params("cell index out of range"));
    }
    let chain = crate::cached_load();
    let page = chain
        .state
        .pages
        .get(&crate::state::page_id(cell))
        .ok_or_else(|| RpcError::internal("no page proof available for this cell"))?;
    let proof = page
        .merkle_proof(crate::state::page_offset(cell))
        .ok_or_else(|| RpcError::internal("no page proof available for this cell"))?;
    Ok(serde_json::to_value(&proof).unwrap_or(Value::Null))
}

/// getStatus: a health snapshot for monitoring: tip height and hash,
/// difficulty, the pending buffer depth, and the local time.
pub(super) async fn handle_get_status() -> Result<Value, RpcError> {
    let chain = crate::cached_load();
    let pending = crate::PENDING_TXS
        .get()
        .and_then(|buf| buf.lock().ok())
        .map(|pending| pending.len())
        .unwrap_or(0);
    Ok(json!({
        "height": chain.tip_height(),
        "hash": hex::encode(chain.tip_hash()),
        "difficulty": chain.next_difficulty(),
        "pending": pending,
        "time": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }))
}

/// getMempool: the pending buffer as hex-encoded transactions with the
/// queue depth, capped at MEMPOOL_RESPONSE_CAP entries so a flooded
/// buffer cannot be turned into a bandwidth amplifier against the node.
pub(super) async fn handle_get_mempool(_params: &Value) -> Result<Value, RpcError> {
    let mut txs = crate::PENDING_TXS
        .get()
        .and_then(|buf| buf.lock().ok())
        .map(|pending| {
            pending
                .iter()
                .filter_map(|tx| bincode::serialize(tx).ok())
                .map(hex::encode)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // Report the true queue depth before truncating the rendered list, so
    // fee estimation keeps working even when the buffer runs far ahead of
    // the response cap.
    let queue_depth = txs.len();
    let truncated = queue_depth > MEMPOOL_RESPONSE_CAP;
    txs.truncate(MEMPOOL_RESPONSE_CAP);
    Ok(json!({
        "count": txs.len(),
        "queue_depth": queue_depth,
        "truncated": truncated,
        "txs": txs,
    }))
}

/// getTreasuryState: expose the bonding-curve counters and the configured
/// signer keys so explorers can render the treasury without replaying blocks.
pub(super) async fn handle_get_treasury_state(_params: &Value) -> Result<Value, RpcError> {
    let chain = crate::cached_load();
    Ok(json!({
        "total_sold": chain.state.total_sold,
        "total_bought_back": chain.state.total_bought_back,
        "treasury_signer": hex::encode(chain.state.treasury_signer),
        "dev_fund_signer": hex::encode(chain.state.dev_fund_signer),
        "dev_fee_bps": chain.state.dev_fee_bps,
        "mine_fee_bps": chain.state.mine_fee_bps,
    }))
}

/// buildTreasuryBuy: price an amount of treasury cells and return the
/// unsigned mint transaction that the treasury signer must sign. The
/// quoted cost is evaluated at the chain's current curve position, which
/// the response reports as `price_position`: the quote holds exactly at
/// that position, and the signer re-verifies the price at signing time,
/// because every earlier pair included in the block advances the
/// position the execution prices against.
pub(super) async fn handle_build_treasury_buy(params: &Value) -> Result<Value, RpcError> {
    let buyer = decode_address(params, 0)?;
    let amount = params
        .get(1)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::invalid_params("missing or invalid amount parameter"))?;
    if amount < crate::state::MIN {
        return Err(RpcError::invalid_params(
            "amount is below the minimum transaction size",
        ));
    }
    if amount > crate::state::N {
        return Err(RpcError::invalid_params(
            "amount exceeds the total cell supply",
        ));
    }
    let chain = crate::cached_load();
    let cost = crate::treasury::buy_price(amount, chain.state.total_sold);
    let mint_inputs = chain
        .state
        .select_single(crate::state::TREASURY, amount)
        .ok_or_else(|| RpcError::invalid_tx("treasury cannot fund this mint"))?;
    let mint_tx = crate::chain::Tx {
        from: crate::state::TREASURY,
        inputs: vec![mint_inputs],
        outputs: vec![crate::chain::Output {
            start: mint_inputs.0,
            end: mint_inputs.1,
            to: buyer,
            lock: None,
        }],
        sig: vec![],
        scheme: 0,
        // The memo stays empty: treasury pairs ride the pairing rule, not
        // the governance payload channel.
        memo: None,
    };
    let encoded_mint = bincode::serialize(&mint_tx)
        .map_err(|_| RpcError::invalid_params("mint transaction serialization failed"))?;
    Ok(json!({
        "cost": cost,
        "price_position": chain.state.total_sold,
        "unsigned_mint_tx": hex::encode(encoded_mint),
    }))
}

/// buildTreasurySell: price a sell-back and return the unsigned payout
/// transaction that the treasury signer must sign, paying 98% of the curve
/// price out of the treasury vault. Amounts whose payout rounds to zero
/// are refused with a named error instead of an unpayable quote. The
/// quoted payout is evaluated at the chain's current curve position and
/// reported as `price_position`, exactly as the buy side reports it.
pub(super) async fn handle_build_treasury_sell(params: &Value) -> Result<Value, RpcError> {
    let seller = decode_address(params, 0)?;
    let amount = params
        .get(1)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::invalid_params("missing or invalid amount parameter"))?;
    if amount == 0 {
        return Err(RpcError::invalid_params("amount must be positive"));
    }
    if amount > crate::state::N {
        return Err(RpcError::invalid_params(
            "amount exceeds the total cell supply",
        ));
    }
    let chain = crate::cached_load();
    let payout = crate::treasury::sell_price(amount, chain.state.total_sold);
    if payout == 0 {
        return Err(RpcError::invalid_tx("payout rounds to zero"));
    }
    let (start, end) = chain
        .state
        .select_single(crate::state::TREASURY_VAULT, payout)
        .ok_or_else(|| RpcError::invalid_tx("treasury vault cannot fund this payout"))?;
    let payout_tx = crate::chain::Tx {
        from: crate::state::TREASURY,
        inputs: vec![(start, end)],
        outputs: vec![crate::chain::Output {
            start,
            end,
            to: seller,
            lock: None,
        }],
        sig: vec![],
        scheme: 0,
        // The memo stays empty: treasury pairs ride the pairing rule, not
        // the governance payload channel.
        memo: None,
    };
    let encoded = bincode::serialize(&payout_tx)
        .map_err(|_| RpcError::invalid_params("payout transaction serialization failed"))?;
    Ok(json!({
        "payout": payout,
        "price_position": chain.state.total_sold,
        "unsigned_payout_tx": hex::encode(encoded),
    }))
}

/// stop: ask the node to shut down. The command travels the node command
/// channel; an endpoint started without a configured channel reports a
/// plain internal error instead of pretending the node heard it.
pub(super) async fn handle_stop(shared: &RpcShared) -> Result<Value, RpcError> {
    match &shared.cmd {
        Some(tx) => {
            let _ = tx.send(crate::p2p::NodeCommand::Shutdown).await;
            Ok(json!(true))
        }
        None => Err(RpcError::internal(
            "node control channel is not configured on this endpoint",
        )),
    }
}

/// mine: ask the node to start a mining attempt. A node without a
/// configured miner key validates the command but produces no block; the
/// acceptance acknowledges only that the command reached the event loop.
pub(super) async fn handle_mine(shared: &RpcShared) -> Result<Value, RpcError> {
    match &shared.cmd {
        Some(tx) => {
            let _ = tx.send(crate::p2p::NodeCommand::Mine).await;
            Ok(json!(true))
        }
        None => Err(RpcError::internal(
            "node control channel is not configured on this endpoint",
        )),
    }
}
