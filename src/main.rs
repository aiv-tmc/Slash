use clap::Parser;
use slash::p2p::Node;
use std::sync::atomic::Ordering;

/// Slash Protocol Layer-1 node binary.
/// Drives the libp2p swarm, the JSON-RPC server, and the blockchain state machine.
#[derive(Parser, Debug)]
#[command(name = "slash-node")]
#[command(about = "Slash Protocol Layer-1 node")]
struct Args {
    /// TCP port for libp2p peer-to-peer communication.
    #[arg(long, default_value_t = 30333)]
    port: u16,

    /// TCP port for the JSON-RPC HTTP server.
    #[arg(long, default_value_t = 9944)]
    rpc_port: u16,

    /// Run in testnet mode with a distinct chain identifier.
    #[arg(long)]
    testnet: bool,

    /// Enable pruned mode, keeping only the last N blocks on disk.
    #[arg(long)]
    pruned: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Toggle the global testnet flag before any genesis or load operation
    // so that the correct chain identifier is used for replay protection.
    if args.testnet {
        slash::TESTNET_MODE.store(true, Ordering::SeqCst);
    }

    // Load the chain from disk. Falls back to genesis if no state is found.
    let chain = slash::load();

    // Start the P2P node. It will listen on the given TCP port and
    // attempt to dial bootstrap seeds from bootstrap.json.
    let (mut node, cmd_tx) = Node::new(args.port, chain, args.pruned).await?;

    // Spawn the JSON-RPC server in a background task so that the node
    // can be controlled via HTTP while the P2P event loop runs.
    let rpc_port = args.rpc_port;
    let _rpc_handle = tokio::spawn(async move {
        if let Err(e) = slash::rpc::start_rpc(rpc_port).await {
            eprintln!("[rpc] fatal: {}", e);
        }
    });

    println!(
        "[main] Slash node running. network={} p2p={} rpc={}",
        if args.testnet { "testnet" } else { "mainnet" },
        args.port,
        args.rpc_port
    );

    // Block on the P2P event loop until a shutdown command is received.
    node.run().await;

    // Graceful shutdown: drop the command sender so that any pending
    // RPC tasks observe the channel closure.
    drop(cmd_tx);

    Ok(())
}
