use axum::{extract::Json, response::IntoResponse, routing::post, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// JSON-RPC 2.0 request envelope.
#[derive(Deserialize, Debug)]
struct RpcRequest {
    method: String,
    #[serde(default)]
    params: Vec<Value>,
    id: Value,
}

/// Start the JSON-RPC HTTP server on the given port.
/// Each handler reloads the chain from disk so it always sees the latest committed state.
pub async fn start_rpc(port: u16) -> anyhow::Result<()> {
    let app = Router::new().route("/", post(rpc_handler));
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("[rpc] listening on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Dispatch incoming JSON-RPC requests to the appropriate handler.
async fn rpc_handler(Json(req): Json<RpcRequest>) -> impl IntoResponse {
    let result = match req.method.as_str() {
        "getBalance" => handle_get_balance(&req.params),
        "getBlock" => handle_get_block(&req.params),
        "sendRawTx" => handle_send_raw_tx(&req.params),
        "getTip" => handle_get_tip(),
        "getDifficulty" => handle_get_difficulty(),
        "getPageProof" => handle_get_page_proof(&req.params),
        _ => Err(anyhow::anyhow!("method not found: {}", req.method)),
    };

    let response = match result {
        Ok(val) => json!({
            "id": req.id,
            "result": val,
        }),
        Err(e) => json!({
            "id": req.id,
            "error": {
                "code": -32000,
                "message": format!("{}", e),
            },
        }),
    };

    Json(response)
}

/// Parse the first parameter as a hex-encoded 32-byte address.
fn parse_address(params: &[Value]) -> anyhow::Result<[u8; 32]> {
    let hex_str = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing address parameter"))?;
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("address must be 32 bytes (64 hex chars)"))?;
    Ok(arr)
}

/// Parse the first parameter as a u64 height.
fn parse_height(params: &[Value]) -> anyhow::Result<u64> {
    params
        .first()
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid height parameter"))
}

/// Parse the first parameter as a hex string.
fn parse_hex(params: &[Value]) -> anyhow::Result<Vec<u8>> {
    let hex_str = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing hex parameter"))?;
    Ok(hex::decode(hex_str)?)
}

/// Return the cell count for the given address.
fn handle_get_balance(params: &[Value]) -> anyhow::Result<Value> {
    let addr = parse_address(params)?;
    let chain = crate::load();
    let balance = chain.state.balance(addr);
    Ok(json!(balance))
}

/// Return the full block at the requested absolute height, or null if absent.
fn handle_get_block(params: &[Value]) -> anyhow::Result<Value> {
    let height = parse_height(params)?;
    let chain = crate::load();
    if height < chain.base_height {
        return Ok(Value::Null);
    }
    let idx = (height - chain.base_height) as usize;
    let block = chain.blocks.get(idx);
    match block {
        Some(b) => Ok(serde_json::to_value(b)?),
        None => Ok(Value::Null),
    }
}

/// Deserialize a raw transaction from hex-encoded bincode bytes and validate it
/// against the current chain tip. If valid, the transaction is queued into the
/// global pending buffer so that the P2P node can ingest it into the local
/// mempool and forward it to the network.
fn handle_send_raw_tx(params: &[Value]) -> anyhow::Result<Value> {
    let raw = parse_hex(params)?;
    let tx: crate::chain::Tx = bincode::deserialize(&raw)
        .map_err(|e| anyhow::anyhow!("invalid transaction encoding: {}", e))?;
    let chain = crate::load();
    let height = chain.blocks.len() as u64 + chain.base_height;

    // Basic structural validation.
    if tx.inputs.is_empty() {
        return Err(anyhow::anyhow!("transaction has no inputs"));
    }
    let total_in: u64 = tx.inputs.iter().map(|(s, e)| e - s).sum();
    let total_out: u64 = tx.outputs.iter().map(|o| o.end - o.start).sum();
    if total_in != total_out {
        return Err(anyhow::anyhow!("transaction is unbalanced"));
    }
    if total_out < crate::state::MIN {
        return Err(anyhow::anyhow!("transaction output below minimum"));
    }

    // Reject scheme identifiers outside the known set (0 and 1).
    if tx.scheme != 0 && tx.scheme != 1 {
        return Err(anyhow::anyhow!("unknown signature scheme {}", tx.scheme));
    }

    // Signature check (skip for treasury) using the canonical tx_signature_hash
    // so that RPC validation always agrees with consensus validation.
    if tx.from != crate::state::TREASURY {
        let hash = crate::chain::tx_signature_hash(
            &tx.from,
            &tx.inputs,
            &tx.outputs,
            &chain.chain_id,
            tx.scheme,
        );
        if !crate::crypto::verify(&tx.from, &hash, &tx.sig) {
            return Err(anyhow::anyhow!("invalid signature"));
        }
    }

    // Ownership and lock checks.
    for (s, e) in &tx.inputs {
        let mut cur = *s;
        while cur < *e {
            let (_, en, owner) = match chain.state.get(cur) {
                Some(x) => x,
                None => return Err(anyhow::anyhow!("input cell {} does not exist", cur)),
            };
            if owner != tx.from {
                return Err(anyhow::anyhow!("input cell {} is not owned by sender", cur));
            }
            if let Some(&until) = chain.state.locks.get(&cur) {
                if until > height {
                    return Err(anyhow::anyhow!("input cell {} is locked", cur));
                }
            }
            cur = en;
        }
    }

    // Scheme 1 requires the AllowScheme1 soft-fork to be active.
    if tx.scheme == 1 {
        let rules = crate::governance::active_rules(&chain.version_bits.deployments, height);
        if !rules
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::AllowScheme1))
        {
            return Err(anyhow::anyhow!("scheme 1 not yet activated"));
        }
    }

    // Queue the validated transaction into the global pending buffer
    // so that the P2P node can ingest it into the local mempool and
    // forward it to peers via gossipsub.
    crate::submit_pending_tx(tx.clone());

    // Return the transaction hash so the caller can track inclusion.
    let tx_hash = blake3::hash(&tx.sig).as_bytes().to_vec();
    Ok(json!(hex::encode(tx_hash)))
}

/// Return the current tip height and its block hash.
fn handle_get_tip() -> anyhow::Result<Value> {
    let chain = crate::load();
    let height = chain.blocks.len() as u64 - 1 + chain.base_height;
    let hash = chain.tip_hash();
    Ok(json!({
        "height": height,
        "hash": hex::encode(hash),
    }))
}

/// Return the difficulty target expected for the next block.
fn handle_get_difficulty() -> anyhow::Result<Value> {
    let chain = crate::load();
    Ok(json!(chain.next_difficulty()))
}

/// Return a Merkle proof for the page containing the given cell.
/// Light clients use this to verify ownership in O(log R_page).
fn handle_get_page_proof(params: &[Value]) -> anyhow::Result<Value> {
    let cell = params
        .first()
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid cell parameter"))?;
    let chain = crate::load();
    if cell >= crate::state::N {
        return Err(anyhow::anyhow!("cell index out of range"));
    }
    let page_id = (cell / crate::state::PAGE_SIZE) as u16;
    let offset = cell % crate::state::PAGE_SIZE;

    // Load the page (materialising it if it is still clean).
    let page = chain.state.get_page(page_id);
    let proof = page
        .merkle_proof(offset)
        .ok_or_else(|| anyhow::anyhow!("cell {} is not contained in any range", cell))?;

    // Include the page root so the verifier knows what to check against.
    let root = page.merkle_root();
    Ok(json!({
        "page_id": page_id,
        "page_root": hex::encode(root),
        "leaf_hash": hex::encode(proof.leaf_hash),
        "leaf_index": proof.leaf_index,
        "siblings": proof.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
    }))
}
