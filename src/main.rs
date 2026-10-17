//! The Slash full node binary.
//!
//! Startup selects the network, loads the persisted chain through the
//! crash-consistent manifest machinery, optionally prunes the retained
//! block window, serves the JSON-RPC API in the background with node
//! control wired to it, and runs the libp2p event loop until shutdown.
//! Chain persistence lives inside the node's housekeeping tick, so the
//! binary carries no save logic of its own.

use clap::Parser;
use slash::p2p::{Node, NodeCommand};
use slash::{load, prune, rpc, TESTNET_MODE};
use std::sync::atomic::Ordering;

/// Command-line interface of the node.
#[derive(Parser, Debug)]
#[command(name = "slash-node", about = "Slash Protocol full node")]
struct Cli {
    /// P2P listen port.
    #[arg(long, default_value_t = 30333)]
    port: u16,

    /// JSON-RPC listen port.
    #[arg(long, default_value_t = 9944)]
    rpc_port: u16,

    /// Keep only the most recent retained window of blocks after
    /// loading, advancing the base height accordingly.
    #[arg(long)]
    pruned: bool,

    /// Run on the testnet replay domain instead of mainnet.
    #[arg(long)]
    testnet: bool,

    /// Extra bootstrap multiaddresses written to bootstrap.json before
    /// the swarm starts.
    #[arg(long)]
    bootstrap: Vec<String>,

    /// Hex-encoded Ed25519 secret key that authorizes this node to
    /// mine: assembled blocks pay the coinbase and the fee claims to
    /// the corresponding address. Without a key the node validates and
    /// relays but never mines.
    #[arg(long)]
    miner_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    TESTNET_MODE.store(args.testnet, Ordering::Relaxed);
    if !args.bootstrap.is_empty() {
        std::fs::write("bootstrap.json", serde_json::to_string(&args.bootstrap)?)?;
    }

    // Load the persisted chain; recovery replays the journal against the
    // last consistent snapshot so the in-memory chain resumes from the
    // height the node actually reached before stopping. Pruned mode
    // forgets every block below the retained window immediately after
    // the load.
    let mut chain = load();
    if args.pruned {
        prune(&mut chain);
    }

    // The command channel feeds the node's event loop. The event loop
    // treats a closed channel as a shutdown signal, so the sender must
    // outlive the run: main holds one clone for the process lifetime,
    // and the RPC server holds another, which is how the stop and mine
    // methods reach the loop.
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<NodeCommand>(32);

    let miner_key = args
        .miner_key
        .as_deref()
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());

    // Start the P2P node: it listens on the given TCP port and dials the
    // bootstrap seeds. Without a miner key the node validates and relays
    // but never mines.
    let node = Node::new(args.port, chain, cmd_rx, miner_key).await?;

    // Spawn the JSON-RPC server in a background task with node control
    // installed: the stop and mine methods forward to the event loop
    // through the channel clone.
    let rpc_addr = args.rpc_port;
    let rpc_cmd = cmd_tx.clone();
    tokio::spawn(async move {
        let _ = rpc::serve_with(rpc_addr, Some(rpc_cmd)).await;
    });

    node.run().await?;
    // The run ended: drop the command sender held for the process
    // lifetime.
    drop(cmd_tx);
    println!("node stopped");
    Ok(())
}
