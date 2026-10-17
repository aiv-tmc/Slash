//! The libp2p node: swarm construction, peer bookkeeping, and the event
//! loop. The node owns the composite behaviour (gossipsub, mdns,
//! identify, request-response, Kademlia), the mempool and pairing
//! tables, the rate-limit buckets, the ban list, and the inbound
//! connection budgets; the per-event logic lives in `handlers/`, the
//! connection lifecycle in `lifecycle.rs`, and the periodic work in
//! `housekeeping.rs`.

use super::behaviour::{
    Behaviour, AGENT_VERSION, IDENTIFY_PROTOCOL, TOPIC_BLOCKS, TOPIC_ONION, TOPIC_TXS,
};
use super::conn::ConnectionBudgets;
use super::lifecycle::load_or_create_node_key;
use super::limits::*;
use super::util::{bootstrap_addrs, peer_id_of};
use super::wire::{BincodeCodec, SlashProtocol};
use crate::chain::Tx;
use futures::StreamExt;
use libp2p::request_response;
use libp2p::swarm::Swarm;
use libp2p::{gossipsub, identify, kad, mdns, noise, tcp, yamux, Multiaddr, PeerId, SwarmBuilder};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// The node command channel: external callers ask the event loop to mine a
/// block or shut down.
pub enum NodeCommand {
    Mine,
    Shutdown,
}

/// The P2P node: owns the swarm, the chain, the mempool, rate limiters,
/// and all peer bookkeeping tables. A single instance runs per process.
pub struct Node {
    pub(crate) swarm: Swarm<Behaviour>,
    pub(crate) chain: crate::chain::Chain,
    pub(crate) mempool: Vec<Tx>,
    /// Pairing table of treasury payloads admitted to the mempool: payload
    /// id to (funding payment id, payment mempool index).
    pub(crate) pairs: HashMap<Vec<u8>, (Vec<u8>, usize)>,
    /// Persistent per-peer token buckets, consulted by the gossip handler.
    pub(crate) buckets: HashMap<PeerId, PeerBuckets>,
    pub(crate) strikes: HashMap<PeerId, u32>,
    pub(crate) banned_until: HashMap<PeerId, Instant>,
    /// Inbound connection budgets: the node-wide cap and the per-subnet
    /// caps, charged at establishment and released at close.
    pub(crate) budgets: ConnectionBudgets,
    /// Remote addresses whose admission verdict was negative at
    /// incoming-connection time. Their connections are closed at
    /// establishment, since the incoming event cannot refuse a dial.
    pub(crate) rejected_inbound: HashSet<Multiaddr>,
    pub(crate) onion_keys: HashMap<PeerId, [u8; 32]>,
    pub(crate) onion_key_to_peer: HashMap<[u8; 32], PeerId>,
    pub(crate) seen_onions: super::replay::OnionReplayCache,
    pub(crate) known_addrs: Vec<Multiaddr>,
    pub(crate) cmd_rx: mpsc::Receiver<NodeCommand>,
    pub(crate) miner_key: Option<[u8; 32]>,
    pub(crate) syncing: bool,
    /// The end of the header window the node is currently syncing toward.
    /// Block responses keep requesting the next chunk until the window is
    /// exhausted, so catch-up does not stall at one serving cap per tip
    /// poll.
    pub(crate) sync_upto: Option<u64>,
    pub(crate) tick: u64,
    pub(crate) mine_cancel: Option<Arc<AtomicBool>>,
}

impl Node {
    /// Build a new node: key material, transport, behaviour, and the
    /// mempool tables. Bootstrap addresses from the compiled-in defaults
    /// are dialed immediately; any entry that carries a `/p2p/<peer-id>`
    /// component also registers in the Kademlia routing table under that
    /// identity. Identity-less entries stay out of the routing table
    /// until the identify exchange learns their identity.
    pub async fn new(
        port: u16,
        chain: crate::chain::Chain,
        cmd_rx: mpsc::Receiver<NodeCommand>,
        miner_key: Option<[u8; 32]>,
    ) -> anyhow::Result<Self> {
        let id_keys = load_or_create_node_key();
        let peer_id = id_keys.public().to_peer_id();
        let mut swarm = SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("transport builds")
            .with_behaviour(|key| {
                // Gossipsub: messages are signed with the node key so
                // gossip cannot be spoofed, and message ids are content
                // hashes so duplicates collapse network-wide.
                let gossip_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(|message| {
                        gossipsub::MessageId::from(
                            blake3::hash(&message.data).as_bytes()[..20].to_vec(),
                        )
                    })
                    .build()
                    .expect("gossipsub config");
                let mut gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossip_config,
                )
                .expect("gossipsub behaviour");
                for topic in [TOPIC_BLOCKS, TOPIC_TXS, TOPIC_ONION] {
                    gossipsub
                        .subscribe(&gossipsub::IdentTopic::new(topic))
                        .expect("subscribe");
                }
                let mdns =
                    mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id).expect("mdns");
                let identify = identify::Behaviour::new(
                    identify::Config::new(IDENTIFY_PROTOCOL.to_string(), key.public())
                        .with_agent_version(AGENT_VERSION.to_string()),
                );
                // Length-prefixed bincode request-response over the custom
                // codec; the default config keeps in-flight requests
                // bounded by the protocol's own limits.
                let req_resp = request_response::Behaviour::<BincodeCodec>::new(
                    [(SlashProtocol, request_response::ProtocolSupport::Full)],
                    request_response::Config::default(),
                );
                let mut kademlia =
                    kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));
                // Register a bootstrap address only under the identity it
                // carries: the routing table maps peer identity to
                // addresses, so an address keyed by any other identity —
                // including the local one — poisons every lookup that
                // follows. An identity-less address is dialed below and
                // registered after the identify exchange.
                for addr in bootstrap_addrs() {
                    if let Some(remote) = peer_id_of(&addr) {
                        let _ = kademlia.add_address(&remote, addr);
                    }
                }
                Behaviour {
                    gossipsub,
                    mdns,
                    identify,
                    req_resp,
                    kademlia,
                }
            })
            .expect("behaviour")
            .build();
        // Bind the listen address on every interface; the port is part of
        // the node's public reachability. A bind failure is ignored: the
        // node can still dial out and operate as a light participant.
        let _ = swarm.listen_on(
            format!("/ip4/0.0.0.0/tcp/{}", port)
                .parse()
                .expect("listen addr"),
        );
        // Dial every compiled-in bootstrap address: an identity-less
        // address is a perfectly good dial target, and the identify
        // exchange that follows registers the learned identity in the
        // routing table under the remote peer.
        for addr in bootstrap_addrs() {
            let _ = swarm.dial(addr);
        }
        Ok(Self {
            swarm,
            chain,
            mempool: Vec::new(),
            pairs: HashMap::new(),
            buckets: HashMap::new(),
            strikes: HashMap::new(),
            banned_until: HashMap::new(),
            budgets: ConnectionBudgets::default(),
            rejected_inbound: HashSet::new(),
            onion_keys: HashMap::new(),
            onion_key_to_peer: HashMap::new(),
            seen_onions: super::replay::OnionReplayCache::load(),
            known_addrs: Vec::new(),
            cmd_rx,
            miner_key,
            syncing: false,
            sync_upto: None,
            tick: 0,
            mine_cancel: None,
        })
    }

    /// Add a multiaddress to the known-addresses table, evicting the
    /// oldest entry at capacity so the table footprint stays bounded.
    pub fn add_known_addr(&mut self, addr: Multiaddr) {
        if self.known_addrs.len() >= KNOWN_ADDRS_CAP {
            self.known_addrs.remove(0);
        }
        self.known_addrs.push(addr);
    }

    /// The event loop: load the persisted bootstrap file, resolve the DNS
    /// seeds, dial every discovered address, then dispatch swarm events
    /// to their handlers, external commands (mine, shutdown), and the
    /// housekeeping tick. Runs until a Shutdown command or a closed
    /// command channel signals termination.
    pub async fn run(mut self) -> anyhow::Result<()> {
        self.load_bootstrap_file("bootstrap.json");
        self.resolve_dns_seeds().await;
        // Dial every address discovered from the bootstrap file and the
        // DNS seeds: discovery only fills the known-addresses table, and
        // a table entry is worth nothing until the transport connects to
        // it. A dialing failure costs nothing and is retried never; the
        // next resolution pass repopulates the table.
        for addr in self.known_addrs.clone() {
            let _ = self.swarm.dial(addr);
        }
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.handle_swarm_event(event).await?,
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(NodeCommand::Mine) => self.mine().await,
                        Some(NodeCommand::Shutdown) | None => break,
                    }
                }
                _ = interval.tick() => self.housekeeping().await,
            }
        }
        if let Some(cancel) = self.mine_cancel.take() {
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
}
