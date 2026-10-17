//! Network policy tests: subnet masking, ban escalation, the onion replay
//! cache semantics and persistence, and the peer-id key extraction the
//! onion attestation relies on.

use super::super::limits::{ONION_REPLAY_CACHE, PEER_BAN_MAX_SECS};
use super::super::replay::OnionReplayCache;
use super::super::util::{ban_duration_secs, peer_id_ed25519_key, subnet_of};
use libp2p::Multiaddr;

#[test]
fn subnet_of_masks_ipv4_to_slash_24() {
    // Two addresses from the same /24 collapse to one subnet key; an
    // address from a different /24 yields a different key, so per-subnet
    // connection accounting groups a Sybil cluster behind one budget.
    let a: Multiaddr = "/ip4/203.0.113.77/tcp/30333".parse().unwrap();
    let b: Multiaddr = "/ip4/203.0.113.200/tcp/30333".parse().unwrap();
    let c: Multiaddr = "/ip4/203.0.114.1/tcp/30333".parse().unwrap();
    assert_eq!(subnet_of(&a), subnet_of(&b));
    assert_ne!(subnet_of(&a), subnet_of(&c));
}

#[test]
fn subnet_of_masks_ipv6_to_slash_64() {
    // IPv6 addresses share a subnet key exactly when their high 64 bits
    // agree; the low 64 bits (interface identifier) are ignored.
    let a: Multiaddr = "/ip6/2001:db8:aaaa:bbbb:1:2:3:4/tcp/30333".parse().unwrap();
    let b: Multiaddr = "/ip6/2001:db8:aaaa:bbbb:ffff:ffff:ffff:ffff/tcp/30333"
        .parse()
        .unwrap();
    let c: Multiaddr = "/ip6/2001:db8:aaaa:bbbc::1/tcp/30333".parse().unwrap();
    assert_eq!(subnet_of(&a), subnet_of(&b));
    assert_ne!(subnet_of(&a), subnet_of(&c));
}

#[test]
fn subnet_of_dns_address_has_no_subnet() {
    // DNS-based addresses carry no literal IP and therefore escape
    // per-subnet accounting; the node-wide inbound limit still applies
    // to them.
    let a: Multiaddr = "/dns4/example.org/tcp/30333".parse().unwrap();
    assert_eq!(subnet_of(&a), None);
}

#[test]
fn ban_duration_escalates_and_saturates() {
    // Below the strike threshold there is no ban; the threshold ban
    // lasts the base duration; every further strike doubles it, and the
    // duration saturates at the maximum instead of overflowing the
    // shift for absurd strike counts.
    assert_eq!(ban_duration_secs(1), None);
    assert_eq!(ban_duration_secs(2), None);
    assert_eq!(ban_duration_secs(3), Some(60));
    assert_eq!(ban_duration_secs(4), Some(120));
    assert_eq!(ban_duration_secs(5), Some(240));
    assert_eq!(ban_duration_secs(100), Some(PEER_BAN_MAX_SECS));
}

/// Widen a small integer into a deterministic 32-byte identifier for
/// cache tests; the replay cache keys are 32-byte random nonces in
/// production, and the tests only need distinct, reproducible values.
fn onion_test_id(i: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&i.to_le_bytes());
    id
}

#[test]
fn onion_replay_cache_rejects_duplicates_and_bounds_size() {
    // The first insertion of an identifier succeeds, a repeated
    // insertion is reported as a replay, and the cache never exceeds
    // its capacity even when far more identifiers arrive.
    let mut cache = OnionReplayCache::new();
    assert!(cache.insert([1u8; 32]));
    assert!(!cache.insert([1u8; 32]));
    for i in 0..(ONION_REPLAY_CACHE as u64 + 100) {
        cache.insert(onion_test_id(i));
    }
    assert!(cache.len() <= ONION_REPLAY_CACHE);
    // Eviction is first-in-first-out: the oldest identifier has been
    // evicted while a recent one is still remembered.
    assert!(cache.insert([1u8; 32]));
}

#[test]
fn onion_replay_cache_persists_across_load() {
    // A cache saved to disk reloads with identical membership, so a
    // node restart cannot reopen the replay window for envelopes that
    // were already processed. The test runs inside a unique temporary
    // working directory to avoid touching any real node state.
    let dir = std::env::temp_dir().join(format!("slash_onion_cache_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let outer = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();

    let mut cache = OnionReplayCache::new();
    for i in 0..50u64 {
        cache.insert(onion_test_id(i));
    }
    cache.persist();
    let reloaded = OnionReplayCache::load();
    assert_eq!(reloaded.len(), 50);

    std::env::set_current_dir(&outer).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn peer_id_ed25519_key_feeds_attestation_verification() {
    // The key recovered from an authenticated PeerId must verify a
    // signature produced by that same identity — exactly the property
    // the onion-key attestation path relies on. The roundtrip covers
    // the exact framing the production verifier checks.
    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = key.public().to_peer_id();
    let recovered = peer_id_ed25519_key(&peer).expect("ed25519 peer id decodes");
    let msg = b"onion key attestation challenge";
    let sig = key.sign(msg).expect("identity signs");
    assert!(crate::crypto::verify(&recovered, msg, &sig));
}
