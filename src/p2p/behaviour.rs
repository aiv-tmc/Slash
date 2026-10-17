//! The composite libp2p behaviour: gossipsub for broadcast, mDNS for
//! local discovery, identify for version exchange, request-response for
//! header-first sync, block download, and onion unicast forwarding, and
//! Kademlia for address propagation. The event enum merges the five
//! behaviours into one swarm event stream.

use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, kad, mdns, request_response};

/// Gossip topics.
pub(crate) const TOPIC_BLOCKS: &str = "slash_blocks";
pub(crate) const TOPIC_TXS: &str = "slash_txs";
pub(crate) const TOPIC_ONION: &str = "slash_onion";

/// The wire protocol name of the request-response channel. It gates frame
/// compatibility only; the consensus identifier lives on the chain
/// (`Chain::chain_id`), so a protocol-compatible consensus upgrade does
/// not change this string and does not force peering changes.
pub(crate) const IDENTIFY_PROTOCOL: &str = "/slash/identify/1.0.0";

/// The agent version this node advertises: `slash/<crate version>`, so
/// the advertised version is always the version of the shipped release
/// and can never drift from it. Peers parse the prefix and compare the
/// version to gate consensus mismatches at identify time, before any
/// gossip or sync traffic flows.
pub(crate) const AGENT_VERSION: &str = concat!("slash/", env!("CARGO_PKG_VERSION"));

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
pub(crate) struct Behaviour {
    pub(crate) gossipsub: gossipsub::Behaviour,
    pub(crate) mdns: mdns::tokio::Behaviour,
    pub(crate) identify: identify::Behaviour,
    pub(crate) req_resp: request_response::Behaviour<super::wire::BincodeCodec>,
    pub(crate) kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

/// The composite swarm event.
#[derive(Debug)]
pub(crate) enum BehaviourEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
    Identify(identify::Event),
    ReqResp(request_response::Event<super::wire::Req, super::wire::Resp>),
    Kademlia(kad::Event),
}

impl From<gossipsub::Event> for BehaviourEvent {
    fn from(e: gossipsub::Event) -> Self {
        Self::Gossipsub(e)
    }
}
impl From<mdns::Event> for BehaviourEvent {
    fn from(e: mdns::Event) -> Self {
        Self::Mdns(e)
    }
}
impl From<identify::Event> for BehaviourEvent {
    fn from(e: identify::Event) -> Self {
        Self::Identify(e)
    }
}
impl From<request_response::Event<super::wire::Req, super::wire::Resp>> for BehaviourEvent {
    fn from(e: request_response::Event<super::wire::Req, super::wire::Resp>) -> Self {
        Self::ReqResp(e)
    }
}
impl From<kad::Event> for BehaviourEvent {
    fn from(e: kad::Event) -> Self {
        Self::Kademlia(e)
    }
}
