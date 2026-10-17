//! Request serving and response-driven sync: capped header/block ranges,
//! onion-key registration with challenge attestation, and the
//! tip-comparison pipeline that drives header-first synchronization.

use super::super::node::Node;
use super::super::util::peer_id_ed25519_key;
use super::super::wire::{Req, Resp};
use libp2p::request_response;
use libp2p::PeerId;

impl Node {
    /// Request-response events: inbound requests are served, inbound
    /// responses drive the sync pipeline and attestation verification, and
    /// failures record strikes.
    pub(super) async fn handle_req_resp(
        &mut self,
        event: request_response::Event<Req, Resp>,
    ) -> anyhow::Result<()> {
        use request_response::Event;
        match event {
            Event::Message { peer, message } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    let response = self.serve_request(peer, request).await;
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .req_resp
                        .send_response(channel, response);
                }
                request_response::Message::Response { response, .. } => {
                    self.handle_response(peer, response).await;
                }
            },
            Event::OutboundFailure { peer, .. } => {
                self.record_strike(peer);
            }
            Event::InboundFailure { peer, .. } => {
                self.record_strike(peer);
            }
            Event::ResponseSent { .. } => {}
        }
        Ok(())
    }

    /// Serve one inbound request from local state. Header and block ranges
    /// are capped per response (256 headers, 64 blocks) so a single request
    /// cannot exhaust the frame budget. The onion-key requests register
    /// this peer's key in the local routing table and answer from the
    /// persisted onion secret; the V2 challenge binds the answer to this
    /// peer's Ed25519 identity.
    async fn serve_request(&mut self, peer: PeerId, req: Req) -> Resp {
        match req {
            Req::GetBlock(height) => {
                let idx = height.wrapping_sub(self.chain.base_height) as usize;
                let block = self
                    .chain
                    .blocks
                    .get(idx)
                    .filter(|_| height >= self.chain.base_height && idx < self.chain.blocks.len())
                    .cloned();
                Resp::Block(block)
            }
            Req::GetBlocks(from, to) => {
                let mut out = Vec::new();
                for h in from..to {
                    let idx = h.wrapping_sub(self.chain.base_height) as usize;
                    if h < self.chain.base_height || idx >= self.chain.blocks.len() {
                        break;
                    }
                    out.push(self.chain.blocks[idx].clone());
                    if out.len() >= 64 {
                        break;
                    }
                }
                Resp::Blocks(out)
            }
            Req::GetTip => Resp::Tip(self.chain.tip_height(), self.chain.tip_hash()),
            Req::GetHeaders(from, to) => {
                let mut out = Vec::new();
                for h in from..to {
                    let idx = h.wrapping_sub(self.chain.base_height) as usize;
                    if h < self.chain.base_height || idx >= self.chain.blocks.len() {
                        break;
                    }
                    out.push(crate::chain::BlockHeader::from_block(
                        &self.chain.blocks[idx],
                    ));
                    if out.len() >= 256 {
                        break;
                    }
                }
                Resp::Headers(out)
            }
            Req::GetOnionKey => {
                let key = self.onion_public();
                self.onion_keys.insert(peer, key);
                self.onion_key_to_peer.insert(key, peer);
                Resp::OnionKey(key)
            }
            Req::GetOnionKeyV2(nonce) => {
                let key = self.onion_public();
                let mut msg = nonce.to_vec();
                msg.extend_from_slice(&key);
                let digest = blake3::hash(&msg);
                let sig = crate::crypto::sign(&self.node_secret(), digest.as_bytes());
                self.onion_keys.insert(peer, key);
                self.onion_key_to_peer.insert(key, peer);
                Resp::OnionKeyV2(nonce, key, sig)
            }
            Req::ForwardOnion(bytes) => {
                self.handle_onion(peer, &bytes).await;
                Resp::Ack
            }
        }
    }

    /// Handle a response to one of our requests: header sync, block sync,
    /// and onion-key attestation verification. Only attested keys enter
    /// the routing table, which closes the relay substitution hole.
    async fn handle_response(&mut self, peer: PeerId, response: Resp) {
        match response {
            Resp::Tip(height, _hash) => {
                // A tip claim beyond the bounded lookahead is ignored:
                // honest peers never advertise more than a bounded window
                // ahead, and chasing an absurd claim would start a header
                // fetch the claimant must prove, block by block, at
                // RandomX cost.
                let within_bound =
                    height <= self.chain.tip_height() + super::super::limits::SYNC_MAX_TIP_AHEAD;
                if height > self.chain.tip_height() && !self.syncing && within_bound {
                    self.syncing = true;
                    let _ = self.swarm.behaviour_mut().req_resp.send_request(
                        &peer,
                        Req::GetHeaders(self.chain.tip_height() + 1, height + 1),
                    );
                }
            }
            Resp::Headers(headers) => {
                if self.chain.validate_headers_batch(&headers) {
                    let from = headers.first().map(|h| h.height).unwrap_or(0);
                    let to = headers.last().map(|h| h.height + 1).unwrap_or(0);
                    if to > from {
                        // Remember the end of the header window: block
                        // responses keep requesting the next chunk until
                        // the window is exhausted.
                        self.sync_upto = Some(to);
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&peer, Req::GetBlocks(from, to));
                    }
                } else {
                    self.record_strike(peer);
                    self.syncing = false;
                }
            }
            Resp::Blocks(blocks) => {
                let mut failed = false;
                let mut last_height = 0u64;
                let mut count = 0usize;
                for block in blocks {
                    last_height = block.height;
                    count += 1;
                    if self.chain.process_block(block).is_err() {
                        failed = true;
                        break;
                    }
                }
                if failed {
                    self.record_strike(peer);
                    self.syncing = false;
                    self.sync_upto = None;
                } else if count == super::super::limits::SYNC_BLOCKS_PER_RESPONSE
                    && self.sync_upto.is_some_and(|to| last_height + 1 < to)
                {
                    // The window is not exhausted and the peer served a
                    // full chunk: request the next one immediately
                    // instead of waiting for the next tip poll, so
                    // catch-up advances the whole window per round.
                    let to = self.sync_upto.unwrap_or(last_height + 1);
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .req_resp
                        .send_request(&peer, Req::GetBlocks(last_height + 1, to));
                } else {
                    self.syncing = false;
                    self.sync_upto = None;
                }
            }
            Resp::Block(_) => {}
            Resp::OnionKey(key) => {
                // Legacy unauthenticated key: usable only as a fallback
                // when no attested key exists for the peer.
                self.onion_keys.entry(peer).or_insert(key);
                self.onion_key_to_peer.entry(key).or_insert(peer);
            }
            Resp::OnionKeyV2(nonce, key, sig) => {
                // Attested key: verify the Ed25519 signature over the
                // challenge nonce and key against the peer's identity key.
                // Only a verified attestation enters the routing table,
                // which closes the relay key-substitution hole.
                let mut msg = nonce.to_vec();
                msg.extend_from_slice(&key);
                let digest = blake3::hash(&msg);
                let ok = peer_id_ed25519_key(&peer)
                    .is_some_and(|pk| crate::crypto::verify(&pk, digest.as_bytes(), &sig));
                if ok {
                    self.onion_keys.insert(peer, key);
                    self.onion_key_to_peer.insert(key, peer);
                }
            }
            // Acknowledgement to our own forwarded onion: nothing to do.
            Resp::Ack => {}
        }
    }
}
