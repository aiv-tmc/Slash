use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::StreamExt;
use libp2p::{
    gossipsub, identify, mdns, noise, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, SwarmBuilder, Multiaddr,
};
use serde::{Serialize, Deserialize};
use zeroize::Zeroizing;
// Import the async_trait macro so that async methods in trait implementations
// desugar into pinned boxed futures with explicit lifetimes, matching the
// signature expected by libp2p-request-response's Codec trait.
use async_trait::async_trait;

use crate::chain::{Block, BlockHeader, Chain, Tx, BlockProcessResult};
use crate::mining::Miner;

/// Maximum number of unconfirmed transactions held in the mempool.
pub const MEMPOOL_CAP: usize = 10_000;
/// Number of recent blocks to retain when running in pruned mode.
pub const PRUNED_KEEP_BLOCKS: u64 = 10_000;

/// Request types exchanged during header-first sync, block download,
/// and onion-key discovery.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Req {
    GetBlock(u64),
    GetBlocks(u64, u64),
    GetTip,
    GetHeaders(u64, u64),
    /// Ask a peer to return its X25519 public key used for onion routing.
    GetOnionKey,
    /// Deliver a peeled onion envelope to the next relay.
    ForwardOnion(Vec<u8>),
}

/// Response types paired with the request enum.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Resp {
    Block(Option<Block>),
    Blocks(Vec<Block>),
    Tip(u64, [u8; 32]),
    Headers(Vec<BlockHeader>),
    /// The peer's X25519 public key for onion routing.
    OnionKey([u8; 32]),
    /// Empty acknowledgment for fire-and-forget requests.
    Ack,
}

/// A length-delimited bincode codec for the request-response subsystem.
/// Each frame is prefixed with a 4-byte little-endian length header.
#[derive(Clone, Debug, Default)]
struct BincodeCodec;

// The libp2p request-response Codec trait is expanded via async-trait,
// which introduces explicit lifetime parameters on the returned futures.
// Applying the async_trait macro here ensures the implementation signature
// matches the trait's expanded form exactly, avoiding lifetime mismatches.
#[async_trait]
impl request_response::Codec for BincodeCodec {
    /// The protocol identifier is a plain static string compatible with
    /// libp2p 0.54 request-response, which requires AsRef<str> + Send + Clone.
    type Protocol = &'static str;
    type Request = Req;
    type Response = Resp;

    /// Read a length-prefixed request frame from the given async I/O source,
    /// then deserialize the payload from bincode into a Req value.
    /// The maximum frame size is capped to prevent memory exhaustion.
    async fn read_request<T>(&mut self, _protocol: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_length_prefixed(io, 10 * 1024 * 1024).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Read a length-prefixed response frame from the given async I/O source,
    /// then deserialize the payload from bincode into a Resp value.
    async fn read_response<T>(&mut self, _protocol: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_length_prefixed(io, 10 * 1024 * 1024).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Serialize a Req value into bincode, prefix it with a 4-byte little-endian
    /// length header, and write the complete frame to the given async I/O sink.
    async fn write_request<T>(&mut self, _protocol: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let buf = bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_length_prefixed(io, &buf).await
    }

    /// Serialize a Resp value into bincode, prefix it with a 4-byte little-endian
    /// length header, and write the complete frame to the given async I/O sink.
    async fn write_response<T>(&mut self, _protocol: &Self::Protocol, io: &mut T, res: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let buf = bincode::serialize(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_length_prefixed(io, &buf).await
    }
}

/// Read a length-prefixed byte vector from an async reader.
/// The first 4 bytes are interpreted as a little-endian length.
/// If the declared length exceeds `max`, the function returns an error.
async fn read_length_prefixed<T: AsyncRead + Unpin + Send>(io: &mut T, max: usize) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    io.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds maximum allowed size"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a byte slice to an async writer, prefixing it with a 4-byte
/// little-endian length header, then flush the sink.
async fn write_length_prefixed<T: AsyncWrite + Unpin + Send>(io: &mut T, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    io.write_all(&len.to_le_bytes()).await?;
    io.write_all(data).await?;
    io.flush().await
}

/// On-disk node key file stores the full 64-byte Ed25519 keypair seed
/// (32-byte secret followed by 32-byte public) so that libp2p's
/// try_from_bytes can reconstruct the Keypair directly.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct NodeKeyFile {
    secret: Vec<u8>,
}

/// On-disk X25519 key material for onion routing.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct X25519File {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

/// Composite network behaviour bundling gossipsub, mdns, identify,
/// and request-response sub-protocols.
#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    identify: identify::Behaviour,
    req_res: request_response::Behaviour<BincodeCodec>,
}

/// Commands that can be sent to the node from external tasks.
#[derive(Clone, Debug)]
pub enum NodeCommand {
    Shutdown,
    Mine { miner: [u8; 32] },
    PublishOnion { data: Vec<u8> },
}

/// The main P2P node struct. It owns the libp2p swarm, the blockchain,
/// the mempool, peer tracking, onion routing key tables, and mining cancellation state.
pub struct Node {
    swarm: libp2p::Swarm<Behaviour>,
    rx: mpsc::Receiver<NodeCommand>,
    chain: Chain,
    mempool: Vec<Tx>,
    mempool_spent: BTreeMap<u64, Vec<u8>>,
    peer_last_tx: HashMap<PeerId, Instant>,
    peers: HashSet<PeerId>,
    block_topic: gossipsub::IdentTopic,
    tx_topic: gossipsub::IdentTopic,
    onion_topic: gossipsub::IdentTopic,
    x25519_secret: Zeroizing<[u8; 32]>,
    /// The X25519 public key derived from the secret, advertised to peers
    /// so they can route onions through this node.
    x25519_public: [u8; 32],
    /// Maps a connected peer to its advertised X25519 public key.
    peer_onion_keys: HashMap<PeerId, [u8; 32]>,
    /// Reverse map: from a relay's X25519 public key to its PeerId,
    /// used to forward peeled onions via unicast request-response.
    onion_key_to_peer: HashMap<[u8; 32], PeerId>,
    bootstrap_seeds: Vec<Multiaddr>,
    pruned: bool,
    keep_blocks: u64,
    /// Flag that is set to true when a new tip arrives or shutdown is requested.
    /// Mining tasks poll this flag and abort immediately when it becomes true.
    mining_cancel: Arc<AtomicBool>,
    /// Set to true whenever the chain tip moves so that periodic persistence
    /// knows there is new data to flush to disk.
    chain_dirty: bool,
}

impl Node {
    /// Construct a new Node listening on the given TCP port.
    /// Loads or generates persistent identity keys and X25519 secrets.
    /// Derives the X25519 public key and initializes empty onion routing tables.
    /// Returns the node instance together with a command sender channel.
    pub async fn new(port: u16, chain: Chain, pruned: bool) -> anyhow::Result<(Self, mpsc::Sender<NodeCommand>)> {
        let local_key = load_node_keypair();
        
        let mut gossip_cfg = gossipsub::ConfigBuilder::default();
        gossip_cfg.max_transmit_size(4 * 1024 * 1024);
        let gossip_cfg = gossip_cfg.build().unwrap();
        
        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, || yamux::Config::default())?
            .with_behaviour(|key| {
                let peer_id = key.public().to_peer_id();
                let gossip = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossip_cfg,
                )?;
                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;
                let identify = identify::Behaviour::new(identify::Config::new("/slash/0.2.0".into(), key.public()));
                let req_res = request_response::Behaviour::new(
                    [("/slash/req/1", request_response::ProtocolSupport::Full)],
                    request_response::Config::default(),
                );
                Ok(Behaviour { gossipsub: gossip, mdns, identify, req_res })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let (tx, rx) = mpsc::channel(100);
        let x25519_secret = load_x25519_secret();
        // Derive the public key from the loaded secret so that other peers
        // can encrypt onion layers targeted at this node.
        let x25519_public = {
            let sec = x25519_dalek::StaticSecret::from(*x25519_secret);
            x25519_dalek::PublicKey::from(&sec).to_bytes()
        };
        let bootstrap_seeds = load_bootstrap_seeds();
        let keep_blocks = if pruned { PRUNED_KEEP_BLOCKS } else { u64::MAX };
        let mut node = Self {
            swarm,
            rx,
            chain,
            mempool: Vec::new(),
            mempool_spent: BTreeMap::new(),
            peer_last_tx: HashMap::new(),
            peers: HashSet::new(),
            block_topic: gossipsub::IdentTopic::new("slash_blocks"),
            tx_topic: gossipsub::IdentTopic::new("slash_txs"),
            onion_topic: gossipsub::IdentTopic::new("slash_onion"),
            x25519_secret,
            x25519_public,
            peer_onion_keys: HashMap::new(),
            onion_key_to_peer: HashMap::new(),
            bootstrap_seeds,
            pruned,
            keep_blocks,
            mining_cancel: Arc::new(AtomicBool::new(false)),
            chain_dirty: false,
        };
        node.swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", port).parse()?).unwrap();
        
        for addr in &node.bootstrap_seeds {
            node.swarm.dial(addr.clone()).ok();
        }
        
        Ok((node, tx))
    }

    /// Run the main event loop. Drives the swarm, timers, command channel,
    /// and periodic maintenance tasks until a shutdown command is received.
    pub async fn run(&mut self) {
        self.swarm.behaviour_mut().gossipsub.subscribe(&self.block_topic).unwrap();
        self.swarm.behaviour_mut().gossipsub.subscribe(&self.tx_topic).unwrap();
        self.swarm.behaviour_mut().gossipsub.subscribe(&self.onion_topic).unwrap();

        let mut sync_interval = tokio::time::interval(Duration::from_secs(5));
        let mut bootstrap_timer = tokio::time::interval(Duration::from_secs(10));
        let mut maintenance_timer = tokio::time::interval(Duration::from_secs(60));
        let mut snapshot_timer = tokio::time::interval(Duration::from_secs(600));
        // Periodic flush of chain state to disk. Writing on every block creates
        // an I/O storm during sync, so we batch changes and flush every 30 s.
        let mut save_timer = tokio::time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = sync_interval.tick() => {
                    self.sync().await;
                }
                _ = bootstrap_timer.tick() => {
                    if self.peers.is_empty() {
                        for addr in &self.bootstrap_seeds {
                            self.swarm.dial(addr.clone()).ok();
                        }
                    }
                }
                _ = maintenance_timer.tick() => {
                    self.background_maintenance().await;
                }
                _ = snapshot_timer.tick() => {
                    let _ = crate::storage::prune_snapshots();
                }
                _ = save_timer.tick() => {
                    if self.chain_dirty {
                        crate::save(&self.chain);
                        self.chain_dirty = false;
                    }
                }
                cmd = self.rx.recv() => {
                    match cmd {
                        Some(NodeCommand::Mine { miner }) => {
                            self.mine(miner).await;
                        }
                        Some(NodeCommand::PublishOnion { data }) => {
                            self.swarm.behaviour_mut().gossipsub.publish(self.onion_topic.clone(), data).ok();
                        }
                        Some(NodeCommand::Shutdown) | None => {
                            self.mining_cancel.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                event = self.swarm.select_next_some() => {
                    self.handle(event).await;
                }
            }
        }
    }

    /// Remove stale page files that no longer belong to the dirty set,
    /// prune on-disk block lists in pruned mode, and evict disconnected peers.
    async fn background_maintenance(&mut self) {
        // Clean up page files that are no longer referenced by the current state.
        if let Ok(entries) = std::fs::read_dir("pages") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(stem) = name.strip_suffix(".bin") {
                    if let Ok(page_id) = u16::from_str_radix(stem, 16) {
                        if !self.chain.state.pages.contains_key(&page_id) {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
        // In pruned mode truncate the on-disk block list to match memory.
        if self.pruned {
            let len = self.chain.blocks.len() as u64;
            if len > self.keep_blocks {
                let drain = (len - self.keep_blocks) as usize;
                if let Ok(mut all) = crate::storage::load_blocks() {
                    if all.len() > drain {
                        all.drain(..drain);
                        let _ = crate::storage::save_blocks(&all);
                    }
                }
            }
        }
        // Evict peers that have not sent any message recently.
        let now = Instant::now();
        self.peer_last_tx.retain(|_, last| now.duration_since(*last) < Duration::from_secs(300));
        self.peers.retain(|p| self.peer_last_tx.contains_key(p));
        // Also clean up onion key mappings for departed peers.
        let gone: Vec<PeerId> = self.peer_onion_keys.keys()
            .filter(|p| !self.peers.contains(p))
            .cloned()
            .collect();
        for peer_id in gone {
            if let Some(key) = self.peer_onion_keys.remove(&peer_id) {
                self.onion_key_to_peer.remove(&key);
            }
        }
    }

    /// Request the current tip from all connected peers to discover
    /// whether the local chain is behind.
    async fn sync(&mut self) {
        if self.peers.is_empty() { return; }
        let req = Req::GetTip;
        for peer in self.peers.iter().cloned().collect::<Vec<_>>() {
            self.swarm.behaviour_mut().req_res.send_request(&peer, req.clone());
        }
    }

    /// Start a parallel RandomX mining task. If a block is found, package
    /// mempool transactions and fee claims, then process the block locally
    /// and broadcast it to the network.
    async fn mine(&mut self, miner: [u8; 32]) {
        // Cancel any previous mining operation before starting a new one.
        self.mining_cancel.store(true, Ordering::Relaxed);
        // Yield briefly so old workers observe the flag.
        tokio::time::sleep(Duration::from_millis(10)).await;
        self.mining_cancel.store(false, Ordering::Relaxed);

        let tip = self.chain.tip_hash();
        let height = self.chain.blocks.len() as u64 + self.chain.base_height;
        let diff = self.chain.next_difficulty();
        let cancel = Arc::clone(&self.mining_cancel);
        let mut block = match tokio::task::spawn_blocking(move || {
            Miner::mine(tip, height, miner, diff, Some(cancel))
        }).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                println!("[node] mining cancelled");
                return;
            }
            Err(e) => {
                eprintln!("[node] mining task panicked: {}", e);
                return;
            }
        };
        
        let take = self.mempool.len().min(crate::chain::MAX_TX_PER_BLOCK);
        block.txs = self.mempool.drain(..take).collect();
        for tx in &block.txs {
            for (s, e) in &tx.inputs {
                for cell in *s..*e {
                    self.mempool_spent.remove(&cell);
                }
            }
        }
        
        let fee_balance = self.chain.state.balance(crate::state::FEE_VAULT);
        if fee_balance > 0 {
            if let Some(ranges) = self.chain.state.select(crate::state::FEE_VAULT, fee_balance) {
                for (s, e) in ranges {
                    block.fee_claims.push(crate::state::Output { start: s, end: e, to: miner, lock: None });
                }
            }
        }
        
        // Compute the page Merkle roots for this block before validation.
        let block = self.chain.prepare_block(block);
        
        // Use process_block so that orphan handling and reorg logic are active.
        match self.chain.process_block(block.clone()) {
            Ok(BlockProcessResult::ExtendedMain) | Ok(BlockProcessResult::Reorged { .. }) => {
                println!("[node] mined block {} cell={} diff={}", block.height, block.mined_cell, block.difficulty);
                // A locally mined block is immediately persisted so the node never
                // loses its own work even if it crashes before the next periodic flush.
                crate::save(&self.chain);
                self.chain_dirty = false;
                let data = bincode::serialize(&block).unwrap();
                self.swarm.behaviour_mut().gossipsub.publish(self.block_topic.clone(), data).ok();
            }
            Ok(BlockProcessResult::Orphan) => {
                eprintln!("[node] mined block became orphan");
                let local_peer_id = self.swarm.local_peer_id().clone();
                for tx in block.txs {
                    self.add_to_mempool(tx, local_peer_id);
                }
            }
            Ok(BlockProcessResult::Duplicate) => {
                println!("[node] mined duplicate block");
            }
            Ok(BlockProcessResult::SideFork) => {
                println!("[node] mined block became side fork");
                let local_peer_id = self.swarm.local_peer_id().clone();
                for tx in block.txs {
                    self.add_to_mempool(tx, local_peer_id);
                }
            }
            Err(e) => {
                eprintln!("[node] mined block failed to apply: {:?}", e);
                let local_peer_id = self.swarm.local_peer_id().clone();
                for tx in block.txs {
                    self.add_to_mempool(tx, local_peer_id);
                }
            }
        }
    }

    /// Attempt to insert a transaction into the mempool.
    /// Enforces per-peer rate limiting, structural validation, deduplication,
    /// and double-spend protection within the mempool.
    fn add_to_mempool(&mut self, tx: Tx, peer_id: PeerId) -> bool {
        let now = Instant::now();
        if let Some(last) = self.peer_last_tx.get(&peer_id) {
            if now.duration_since(*last).as_secs_f64() < 1.0 {
                return false;
            }
        }
        self.peer_last_tx.insert(peer_id, now);
        
        if !self.validate_tx(&tx) {
            return false;
        }
        if self.mempool.iter().any(|t| same_tx(t, &tx)) {
            return false;
        }
        
        let id = tx_id(&tx);
        
        for (s, e) in &tx.inputs {
            for cell in *s..*e {
                if self.mempool_spent.contains_key(&cell) {
                    return false;
                }
            }
        }
        
        if self.mempool.len() >= MEMPOOL_CAP {
            if let Some(evicted) = self.evict_lowest_fee() {
                for (s, e) in &evicted.inputs {
                    for cell in *s..*e {
                        self.mempool_spent.remove(&cell);
                    }
                }
            } else {
                return false;
            }
        }
        
        for (s, e) in &tx.inputs {
            for cell in *s..*e {
                self.mempool_spent.insert(cell, id.clone());
            }
        }
        self.mempool.push(tx);
        true
    }

    /// Remove the transaction with the lowest fee output from the mempool
    /// to make room for a new transaction when capacity is reached.
    fn evict_lowest_fee(&mut self) -> Option<Tx> {
        let mut lowest_idx = None;
        let mut lowest_fee = u64::MAX;
        for (i, tx) in self.mempool.iter().enumerate() {
            let fee = tx.outputs.iter()
                .filter(|o| o.to == crate::state::FEE_VAULT)
                .map(|o| o.end - o.start)
                .sum::<u64>();
            if fee < lowest_fee {
                lowest_fee = fee;
                lowest_idx = Some(i);
            }
        }
        lowest_idx.map(|i| self.mempool.remove(i))
    }

    /// Validate a transaction by delegating to the chain state validator.
    /// This guarantees that mempool validation and consensus validation use
    /// exactly the same rules, including signature hashing and soft-fork checks.
    fn validate_tx(&self, tx: &Tx) -> bool {
        self.chain.validate_tx(tx)
    }

    /// Process an onion transaction received from any source.
    /// Attempts to peel one layer using this node's X25519 secret.
    /// If this node is the exit relay, decrypts the inner transaction and
    /// adds it to the mempool, then publishes the plaintext tx via gossipsub.
    /// If another relay remains, forwards the peeled onion directly to the
    /// next relay's PeerId using request-response unicast.
    fn handle_onion(&mut self, onion: crate::onion::OnionTx, peer_id: PeerId) {
        if let Some(peel) = crate::onion::peel(&onion, &self.x25519_secret) {
            if peel.next_relay == [0u8; 32] {
                // We are the exit relay: decrypt the inner transaction.
                if let Some(tx) = crate::onion::decrypt_inner(&peel.remaining, &self.x25519_secret) {
                    if self.add_to_mempool(tx.clone(), peer_id) {
                        let data = bincode::serialize(&tx).unwrap();
                        self.swarm.behaviour_mut().gossipsub.publish(self.tx_topic.clone(), data).ok();
                    }
                }
            } else {
                // Forward the remaining onion to the next relay via unicast.
                // Look up the PeerId associated with the next relay's X25519 public key.
                if let Some(&next_peer) = self.onion_key_to_peer.get(&peel.next_relay) {
                    let data = bincode::serialize(&peel.remaining).unwrap();
                    self.swarm.behaviour_mut().req_res.send_request(&next_peer, Req::ForwardOnion(data));
                } else {
                    eprintln!("[p2p] unknown next relay {} for onion, dropping", hex::encode(&peel.next_relay));
                }
            }
        }
    }

    /// Dispatch a swarm event to the appropriate handler.
    async fn handle(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer, addr) in list {
                    self.swarm.dial(addr).ok();
                    self.peers.insert(peer);
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, .. })) => {
                self.peers.insert(peer_id);
                // Ask the newly identified peer for its X25519 public key
                // so that onions can be routed to it via unicast.
                self.swarm.behaviour_mut().req_res.send_request(&peer_id, Req::GetOnionKey);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message { message, propagation_source, .. })) => {
                let peer_id = propagation_source;
                if message.topic == self.block_topic.hash() {
                    if let Ok(b) = bincode::deserialize::<Block>(&message.data) {
                        self.handle_block(b).await;
                    }
                } else if message.topic == self.tx_topic.hash() {
                    if let Ok(t) = bincode::deserialize::<Tx>(&message.data) {
                        if self.add_to_mempool(t.clone(), peer_id) {
                            self.swarm.behaviour_mut().gossipsub.publish(self.tx_topic.clone(), message.data).ok();
                        }
                    }
                } else if message.topic == self.onion_topic.hash() {
                    if let Ok(onion) = bincode::deserialize::<crate::onion::OnionTx>(&message.data) {
                        self.handle_onion(onion, peer_id);
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::ReqRes(request_response::Event::Message { peer, message })) => {
                match message {
                    request_response::Message::Request { request, channel, .. } => {
                        let resp = match request {
                            Req::GetBlock(h) => {
                                let block = if h >= self.chain.base_height {
                                    self.chain.blocks.get((h - self.chain.base_height) as usize).cloned()
                                } else {
                                    None
                                };
                                Resp::Block(block)
                            }
                            Req::GetBlocks(from, to) => {
                                if from < self.chain.base_height {
                                    Resp::Blocks(vec![])
                                } else {
                                    let start = (from - self.chain.base_height) as usize;
                                    let end = (to.min(self.chain.blocks.len() as u64 + self.chain.base_height).saturating_sub(self.chain.base_height)) as usize;
                                    let blocks: Vec<_> = self.chain.blocks.iter()
                                        .skip(start)
                                        .take(end.saturating_sub(start))
                                        .cloned().collect();
                                    Resp::Blocks(blocks)
                                }
                            }
                            Req::GetTip => Resp::Tip(self.chain.blocks.len() as u64 - 1 + self.chain.base_height, self.chain.tip_hash()),
                            Req::GetHeaders(from, to) => {
                                if from < self.chain.base_height {
                                    Resp::Headers(vec![])
                                } else {
                                    let start = (from - self.chain.base_height) as usize;
                                    let end = (to.min(self.chain.blocks.len() as u64 + self.chain.base_height).saturating_sub(self.chain.base_height)) as usize;
                                    let headers: Vec<_> = self.chain.blocks.iter()
                                        .skip(start)
                                        .take(end.saturating_sub(start))
                                        .map(|b| BlockHeader::from_block(b))
                                        .collect();
                                    Resp::Headers(headers)
                                }
                            }
                            Req::GetOnionKey => Resp::OnionKey(self.x25519_public),
                            Req::ForwardOnion(data) => {
                                if let Ok(onion) = bincode::deserialize::<crate::onion::OnionTx>(&data) {
                                    self.handle_onion(onion, peer);
                                }
                                Resp::Ack
                            }
                        };
                        self.swarm.behaviour_mut().req_res.send_response(channel, resp).ok();
                    }
                    request_response::Message::Response { response, .. } => {
                        match response {
                            Resp::Block(Some(b)) => {
                                self.handle_block(b).await;
                            }
                            Resp::Block(None) => {}
                            Resp::Blocks(blocks) => {
                                for b in blocks {
                                    self.handle_block(b).await;
                                }
                            }
                            Resp::Tip(height, _) => {
                                let my = self.chain.blocks.len() as u64 - 1 + self.chain.base_height;
                                if height > my {
                                    let req = Req::GetHeaders(my + 1, height + 1);
                                    self.swarm.behaviour_mut().req_res.send_request(&peer, req);
                                }
                            }
                            Resp::Headers(headers) => {
                                let mut valid = true;
                                let mut expected_height = self.chain.blocks.len() as u64 + self.chain.base_height;
                                for h in &headers {
                                    if h.height != expected_height {
                                        valid = false;
                                        break;
                                    }
                                    if !self.chain.validate_header(h) {
                                        valid = false;
                                        break;
                                    }
                                    expected_height += 1;
                                }
                                if valid && !headers.is_empty() {
                                    let from = headers[0].height;
                                    let to = headers.last().unwrap().height + 1;
                                    let req = Req::GetBlocks(from, to);
                                    self.swarm.behaviour_mut().req_res.send_request(&peer, req);
                                }
                            }
                            Resp::OnionKey(key) => {
                                self.peer_onion_keys.insert(peer, key);
                                self.onion_key_to_peer.insert(key, peer);
                            }
                            Resp::Ack => {}
                        }
                    }
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("[p2p] listening on {}", address);
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                // Remove the peer from the active set so we stop sending requests to it.
                self.peers.remove(&peer_id);
                self.peer_last_tx.remove(&peer_id);
                // Remove onion routing mappings for the departed peer.
                if let Some(key) = self.peer_onion_keys.remove(&peer_id) {
                    self.onion_key_to_peer.remove(&key);
                }
                if let Some(err) = cause {
                    eprintln!("[p2p] connection closed with {}: {}", peer_id, err);
                }
            }
            _ => {}
        }
    }

    /// Attempt to append a block received from the network to the chain.
    /// Updates mempool state and pruning metadata on successful application.
    async fn handle_block(&mut self, b: Block) {
        // Use process_block so that orphan handling, reorg, and checkpoints are evaluated.
        match self.chain.process_block(b.clone()) {
            Ok(BlockProcessResult::ExtendedMain) | Ok(BlockProcessResult::Reorged { .. }) => {
                println!("[p2p] applied block {}", b.height);
                if self.pruned {
                    let len = self.chain.blocks.len() as u64;
                    if len > self.keep_blocks {
                        let drain = (len - self.keep_blocks) as usize;
                        self.chain.blocks.drain(..drain);
                        if let Some(first) = self.chain.blocks.first() {
                            self.chain.base_height = first.height;
                        }
                    }
                }
                // Mark the chain as dirty so the periodic save timer will flush
                // it to disk instead of performing a synchronous fsync storm here.
                self.chain_dirty = true;
                let mut i = 0;
                while i < self.mempool.len() {
                    if b.txs.iter().any(|btx| same_tx(btx, &self.mempool[i])) {
                        let tx = self.mempool.remove(i);
                        for (s, e) in &tx.inputs {
                            for cell in *s..*e {
                                self.mempool_spent.remove(&cell);
                            }
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            Ok(BlockProcessResult::Orphan) => {
                println!("[p2p] orphan block {}", b.height);
            }
            Ok(BlockProcessResult::Duplicate) => {
                println!("[p2p] duplicate block {}", b.height);
            }
            Ok(BlockProcessResult::SideFork) => {
                println!("[p2p] side-fork block {}", b.height);
            }
            Err(e) => {
                eprintln!("[p2p] invalid block {}: {:?}", b.height, e);
            }
        }
    }
}

/// Compute a unique identifier for a transaction from its signature bytes.
fn tx_id(tx: &Tx) -> Vec<u8> {
    blake3::hash(&tx.sig).as_bytes().to_vec()
}

/// Determine whether two transactions are identical in all fields that matter
/// for mempool deduplication: sender, inputs, outputs, signature and scheme.
fn same_tx(a: &Tx, b: &Tx) -> bool {
    a.from == b.from && a.inputs == b.inputs && a.outputs == b.outputs && a.sig == b.sig && a.scheme == b.scheme
}

/// Load the node's Ed25519 identity from disk, or generate and persist a new one.
fn load_node_keypair() -> libp2p::identity::Keypair {
    if let Ok(bytes) = std::fs::read("node_key.bin") {
        if let Ok(file) = bincode::deserialize::<NodeKeyFile>(&bytes) {
            let mut secret = file.secret;
            if let Ok(ed_kp) = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut secret) {
                return libp2p::identity::Keypair::from(ed_kp);
            }
        }
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let ed_kp = kp.clone().try_into_ed25519().unwrap();
    let secret = ed_kp.to_bytes();
    let file = NodeKeyFile { secret: secret.to_vec() };
    let encoded = bincode::serialize(&file).unwrap();
    crate::storage::atomic_write("node_key.bin", &encoded).unwrap();
    kp
}

/// Load bootstrap seed addresses from bootstrap.json.
fn load_bootstrap_seeds() -> Vec<Multiaddr> {
    if let Ok(data) = std::fs::read_to_string("bootstrap.json") {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(&data) {
            return list.into_iter().filter_map(|s| s.parse().ok()).collect();
        }
    }
    Vec::new()
}

/// Load the X25519 static secret for onion routing from disk, or generate
/// and persist a new keypair.
fn load_x25519_secret() -> Zeroizing<[u8; 32]> {
    if let Ok(bytes) = std::fs::read("x25519.bin") {
        if let Ok(file) = bincode::deserialize::<X25519File>(&bytes) {
            return Zeroizing::new(file.secret);
        }
    }
    let (sec, pub_bytes) = crate::crypto::x25519_generate();
    let file = X25519File { secret: sec.to_bytes(), public: pub_bytes };
    let encoded = bincode::serialize(&file).unwrap();
    crate::storage::atomic_write("x25519.bin", &encoded).unwrap();
    Zeroizing::new(sec.to_bytes())
}
