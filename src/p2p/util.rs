//! Peer helpers: key extraction, peer identity parsing, subnet
//! accounting, ban backoff, and the compiled-in bootstrap table.
//!
//! These free functions are pure and synchronous; everything here either
//! derives data from libp2p types or reads constants, which keeps the
//! event-loop handlers thin.

use libp2p::{Multiaddr, PeerId};

/// The default bootstrap multiaddresses used when DNS seeds and the
/// bootstrap file both come up empty.
const DEFAULT_BOOTSTRAP: &[&str] = &[
    "/dns4/seed1.slash-protocol.org/tcp/30333",
    "/dns4/seed2.slash-protocol.org/tcp/30333",
    "/dns4/seed3.slash-protocol.org/tcp/30333",
];

/// DNS seeds resolved at startup; each seed may return multiple A/AAAA
/// records, and every record is dialed as a bootstrap candidate.
const DNS_SEEDS: &[&str] = &[
    "seed1.slash-protocol.org",
    "seed2.slash-protocol.org",
    "seed3.slash-protocol.org",
];

use super::limits::{PEER_BAN_BASE_SECS, PEER_BAN_MAX_SECS, PEER_BAN_STRIKES};

/// Extract the Ed25519 public key behind a peer id. libp2p peer ids for
/// Ed25519 identities encode the public key as an identity multihash; the
/// framing is 36 bytes of multihash header plus the 32-byte key inside a
/// protobuf field. Returns None for any other key type or a malformed
/// encoding, so callers never trust an unauthenticated key.
pub fn peer_id_ed25519_key(peer: &PeerId) -> Option<[u8; 32]> {
    let bytes = peer.to_bytes();
    // Identity multihash: the multihash codec is 0x00 with the raw length,
    // and the payload is the protobuf-encoded PublicKey where field 1
    // carries the key bytes (type 2: tag byte 0x0a, length, payload).
    if bytes.len() < 38
        || bytes[0] != 0x00
        || bytes[1] != 36
        || bytes[2] != 0x08
        || bytes[3] != 0x01
        || bytes[4] != 0x12
        || bytes[5] != 32
    {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[6..38]);
    Some(out)
}

/// Extract the remote peer identity from a multiaddress carrying a
/// `/p2p/<peer-id>` component. Bootstrap sources register in the Kademlia
/// routing table only under this identity: the routing table maps peer
/// identity to addresses, so registering an identity-less address under
/// any key — including the local one — would corrupt every lookup that
/// follows. An address without the component is still a valid dial
/// target; its identity is learned through the identify exchange.
pub(crate) fn peer_id_of(addr: &Multiaddr) -> Option<PeerId> {
    use libp2p::multiaddr::Protocol;
    addr.iter().find_map(|protocol| match protocol {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

/// The subnet key of a multiaddress for inbound budgeting: the /24 prefix
/// of an IPv4 address or the /64 prefix of an IPv6 address, formatted so
/// that one Sybil cluster behind a single subnet shares one budget. DNS
/// names and other address forms carry no subnet and are not budgeted.
pub(crate) fn subnet_of(addr: &Multiaddr) -> Option<String> {
    use libp2p::multiaddr::Protocol;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                let o = ip.octets();
                return Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]));
            }
            Protocol::Ip6(ip) => {
                let s = ip.segments();
                return Some(format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]));
            }
            _ => {}
        }
    }
    None
}

/// The ban duration for the given strike count: exponential backoff from a
/// 60-second base, doubling per strike beyond the ban threshold and
/// saturating at one hour. Returns None below the strike threshold, so the
/// caller only acts once the threshold is crossed.
pub(crate) fn ban_duration_secs(strikes: u32) -> Option<u64> {
    if strikes < PEER_BAN_STRIKES {
        return None;
    }
    let extra = strikes - PEER_BAN_STRIKES;
    Some(
        PEER_BAN_BASE_SECS
            .saturating_mul(2u64.saturating_pow(extra))
            .min(PEER_BAN_MAX_SECS),
    )
}

/// Parse the compiled-in bootstrap multiaddresses. Used as the fallback
/// when DNS resolution and the bootstrap file yield nothing.
pub(crate) fn bootstrap_addrs() -> Vec<Multiaddr> {
    DEFAULT_BOOTSTRAP
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// The DNS seed hostnames, re-exported for the startup resolver.
pub(crate) fn dns_seeds() -> &'static [&'static str] {
    DNS_SEEDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_of_reads_embedded_identity() {
        // An address carrying a /p2p component yields the embedded peer
        // identity; a bare transport address carries none and is a dial
        // target only.
        let keypair = libp2p::identity::ed25519::Keypair::generate();
        let peer = libp2p::identity::PublicKey::from(keypair.public()).to_peer_id();
        let mut addr: Multiaddr = "/ip4/203.0.113.10/tcp/30333".parse().unwrap();
        addr.push(libp2p::multiaddr::Protocol::P2p(peer));
        assert_eq!(peer_id_of(&addr), Some(peer));
        let bare: Multiaddr = "/ip4/203.0.113.10/tcp/30333".parse().unwrap();
        assert_eq!(peer_id_of(&bare), None);
    }

    #[test]
    fn ban_duration_starts_at_threshold_and_saturates() {
        // Below the strike threshold there is no ban; from the threshold
        // on the duration backs off exponentially and saturates at the
        // maximum.
        assert_eq!(ban_duration_secs(PEER_BAN_STRIKES - 1), None);
        assert_eq!(
            ban_duration_secs(PEER_BAN_STRIKES),
            Some(PEER_BAN_BASE_SECS)
        );
        assert_eq!(
            ban_duration_secs(PEER_BAN_STRIKES + 10),
            Some(PEER_BAN_MAX_SECS)
        );
    }
}
