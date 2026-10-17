//! src/p2p/handlers/mod.rs — swarm event handlers: the event fan-out,
//! gossip admission and relay, block processing, onion peeling and
//! forwarding, request serving, and response-driven sync.
//!
//! Every handler follows the same contract: rate-limit first, validate
//! second, mutate last. A gossip message earns a strike and a `Reject`
//! report only when it is semantically invalid; honest network noise —
//! a duplicate from mesh overlap, an out-of-order block, a missing
//! route, a rate-limit refusal — is dropped with `Ignore` and no strike,
//! so the gossip layer never partitions itself by penalizing normal
//! operation. A strike threshold bans the peer with exponential backoff.
//! Identify connections are gated on the advertised consensus version:
//! a peer running different consensus rules disconnects here, before
//! any gossip or sync traffic flows.
//!
//! Layout:
//! - `gossip` — transaction, block, and onion-envelope admission and relay
//! - `sync` — request serving and response-driven header/sync download

mod gossip;
mod sync;

use super::behaviour::{BehaviourEvent, AGENT_VERSION, TOPIC_BLOCKS, TOPIC_ONION, TOPIC_TXS};
use super::node::Node;
use gossip::GossipVerdict;
use libp2p::gossipsub::MessageAcceptance;
use libp2p::swarm::SwarmEvent;

impl Node {
    /// Fan a swarm event out to its handler. Behaviour events match on the
    /// composite enum; connection lifecycle events maintain the inbound
    /// connection budgets and the onion routing table.
    pub(crate) async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<BehaviourEvent>,
    ) -> anyhow::Result<()> {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(ev)) => self.handle_gossipsub(ev).await,
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(ev)) => self.handle_mdns(ev).await,
            SwarmEvent::Behaviour(BehaviourEvent::Identify(ev)) => self.handle_identify(ev).await,
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(ev)) => self.handle_kademlia(ev).await,
            SwarmEvent::Behaviour(BehaviourEvent::ReqResp(ev)) => self.handle_req_resp(ev).await,
            SwarmEvent::IncomingConnection { send_back_addr, .. } => {
                self.on_incoming_connection(send_back_addr);
                Ok(())
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.on_connection_closed(peer_id);
                Ok(())
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                self.on_connection_established(peer_id, endpoint);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// mDNS discovery: every newly discovered peer address enters the
    /// known-addresses table, the Kademlia routing table under the
    /// discovered peer identity, and the dial queue.
    async fn handle_mdns(&mut self, event: libp2p::mdns::Event) -> anyhow::Result<()> {
        use libp2p::mdns::Event;
        match event {
            Event::Discovered(list) => {
                for (peer, addr) in list {
                    self.add_known_addr(addr.clone());
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer, addr.clone());
                    let _ = self.swarm.dial(addr);
                }
            }
            Event::Expired(_) => {}
        }
        Ok(())
    }

    /// Identify: gate the connection on the advertised consensus version
    /// first, then learn addresses. A peer whose agent version parses as
    /// a slash consensus version different from this node's is running
    /// different consensus rules: it disconnects here instead of meshing,
    /// cross-posting transactions half the network rejects, and
    /// accumulating misdirected strikes during an upgrade window. Agents
    /// of other shapes carry no slash consensus version and are
    /// tolerated.
    async fn handle_identify(&mut self, event: libp2p::identify::Event) -> anyhow::Result<()> {
        use libp2p::identify::Event;
        match event {
            Event::Received { peer_id, info, .. } => {
                if let Some(remote) = info.agent_version.strip_prefix("slash/") {
                    if remote != AGENT_VERSION.strip_prefix("slash/").unwrap_or_default() {
                        self.onion_keys.remove(&peer_id);
                        self.onion_key_to_peer.retain(|_, p| *p != peer_id);
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        return Ok(());
                    }
                }
                for addr in info.listen_addrs {
                    self.add_known_addr(addr.clone());
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
                }
            }
            Event::Sent { .. } | Event::Pushed { .. } | Event::Error { .. } => {}
        }
        Ok(())
    }

    /// Kademlia routing events need no reaction from the node.
    async fn handle_kademlia(&mut self, _event: libp2p::kad::Event) -> anyhow::Result<()> {
        Ok(())
    }

    /// Gossip admission and relay. Each topic routes to its own handler
    /// under the sender's persistent token buckets, and the verdict maps
    /// onto the gossipsub report: `Accept` propagates, `Ignore` drops
    /// without consequence, `Reject` scores the source down and records a
    /// strike. A rate-limit refusal spends nothing but the token and
    /// costs no strike, so an honest peer that talks slightly too fast is
    /// never penalized; a message that fails deserialization is garbage
    /// and is struck.
    async fn handle_gossipsub(&mut self, event: libp2p::gossipsub::Event) -> anyhow::Result<()> {
        use libp2p::gossipsub::Event;
        if let Event::Message {
            propagation_source,
            message_id,
            message,
        } = event
        {
            let topic = message.topic.clone();
            let source = propagation_source;
            // Take the sender's buckets out for the duration of the checks
            // so the handlers can borrow the node mutably; put them back
            // before the validation report either way.
            let mut buckets = std::mem::take(self.buckets.entry(source).or_default());
            let verdict = if topic.as_str() == TOPIC_TXS {
                if !buckets.take_tx() {
                    // Rate-limit refusal: drop without a strike.
                    GossipVerdict::Ignore
                } else {
                    match bincode::deserialize::<crate::chain::Tx>(&message.data) {
                        Ok(tx) => self.handle_tx(source, tx).await,
                        Err(_) => GossipVerdict::Reject,
                    }
                }
            } else if topic.as_str() == TOPIC_BLOCKS {
                if !buckets.take_block() {
                    GossipVerdict::Ignore
                } else {
                    match bincode::deserialize::<crate::chain::Block>(&message.data) {
                        Ok(block) => self.handle_block(source, block).await,
                        Err(_) => GossipVerdict::Reject,
                    }
                }
            } else if topic.as_str() == TOPIC_ONION {
                if !buckets.take_onion() {
                    GossipVerdict::Ignore
                } else {
                    self.handle_onion(source, &message.data).await
                }
            } else {
                // A topic the node never subscribed to cannot carry
                // meaningful content; drop it silently.
                GossipVerdict::Ignore
            };
            self.buckets.insert(source, buckets);
            let acceptance = match verdict {
                GossipVerdict::Accept => MessageAcceptance::Accept,
                GossipVerdict::Ignore => MessageAcceptance::Ignore,
                GossipVerdict::Reject => {
                    self.record_strike(source);
                    MessageAcceptance::Reject
                }
            };
            let _ = self
                .swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &source, acceptance);
        }
        Ok(())
    }
}
