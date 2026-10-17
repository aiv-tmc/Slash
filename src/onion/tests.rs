//! Construction and peeling regressions: typed rejection of short relay
//! paths, rejection of crafted layers with undersized payloads, and the
//! honest three-hop round trip through every relay.

use super::*;
use zeroize::Zeroizing;

/// A minimal transaction used as the onion payload in tests.
fn sample_tx() -> crate::chain::Tx {
    crate::chain::Tx {
        from: [1u8; 32],
        inputs: vec![(0, 1)],
        outputs: vec![crate::chain::Output {
            start: 0,
            end: 1,
            to: [2u8; 32],
            lock: None,
        }],
        sig: vec![0u8; 64],
        scheme: 0,
        memo: None,
    }
}

#[test]
fn create_onion_rejects_short_relay_paths() {
    // Envelope construction is a fallible operation: relay lists shorter
    // than the mandatory three hops yield a typed input error that a
    // wallet or FFI caller can surface, instead of aborting the process.
    let (_r1_sec, r1_pub) = crate::crypto::x25519_generate();
    let (_r2_sec, r2_pub) = crate::crypto::x25519_generate();
    let err = create_onion(&sample_tx(), &[r1_pub, r2_pub]).unwrap_err();
    assert_eq!(
        err,
        OnionError::TooFewRelays {
            provided: 2,
            required: MIN_RELAYS
        }
    );
    // The error renders a human-readable explanation for logs and UI.
    assert!(err.to_string().contains("at least 3 relays"));
    // An empty path is rejected the same way.
    assert!(create_onion(&sample_tx(), &[]).is_err());
}

#[test]
fn peel_rejects_layer_with_short_payload() {
    // Regression guard: the envelope originator encrypts the entry layer
    // itself, so it can claim a payload shorter than one 32-byte relay
    // address. Peeling such an envelope must return None; without the
    // length guard the fixed-size slice indexing panicked and killed the
    // relay node.
    let (r1_sec, r1_pub) = crate::crypto::x25519_generate();
    let (_r2_sec, r2_pub) = crate::crypto::x25519_generate();
    let (_r3_sec, r3_pub) = crate::crypto::x25519_generate();

    let mut onion = create_onion(&sample_tx(), &[r1_pub, r2_pub, r3_pub]).unwrap();

    // Replace the entry layer with a correctly encrypted layer whose
    // length prefix claims a 5-byte next-hop address.
    let (eph_sec, eph_pub) = crate::crypto::x25519_generate();
    let key = Zeroizing::new(crate::crypto::x25519_shared(&eph_sec, &r1_pub));
    let mut payload = Vec::new();
    payload.extend_from_slice(&5u16.to_le_bytes());
    payload.extend_from_slice(&[0xAB; 5]);
    payload.resize(LAYER_SIZE, 0);
    let (ciphertext, nonce) = crate::crypto::aes_encrypt(&key, &payload);
    onion.layers[0] = Layer {
        ephemeral: eph_pub,
        nonce,
        ciphertext,
    };

    // The malformed envelope is rejected without panicking.
    assert!(peel(&onion, &r1_sec.to_bytes()).is_none());
}

#[test]
fn peel_rejects_layer_with_empty_payload() {
    // A layer whose length prefix claims zero payload bytes carries no
    // next-hop address at all and must be rejected the same way.
    let (r1_sec, r1_pub) = crate::crypto::x25519_generate();
    let (_r2_sec, r2_pub) = crate::crypto::x25519_generate();
    let (_r3_sec, r3_pub) = crate::crypto::x25519_generate();

    let mut onion = create_onion(&sample_tx(), &[r1_pub, r2_pub, r3_pub]).unwrap();

    let (eph_sec, eph_pub) = crate::crypto::x25519_generate();
    let key = Zeroizing::new(crate::crypto::x25519_shared(&eph_sec, &r1_pub));
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.resize(LAYER_SIZE, 0);
    let (ciphertext, nonce) = crate::crypto::aes_encrypt(&key, &payload);
    onion.layers[0] = Layer {
        ephemeral: eph_pub,
        nonce,
        ciphertext,
    };

    assert!(peel(&onion, &r1_sec.to_bytes()).is_none());
}

#[test]
fn honest_onion_still_peels() {
    // The length guard must not disturb honest envelopes: a correctly
    // built onion peels at every hop and decrypts at the exit relay.
    let (r1_sec, r1_pub) = crate::crypto::x25519_generate();
    let (r2_sec, r2_pub) = crate::crypto::x25519_generate();
    let (r3_sec, r3_pub) = crate::crypto::x25519_generate();
    let tx = sample_tx();
    let onion = create_onion(&tx, &[r1_pub, r2_pub, r3_pub]).unwrap();

    let peel1 = peel(&onion, &r1_sec.to_bytes()).unwrap();
    assert_eq!(peel1.next_relay, r2_pub);
    let peel2 = peel(&peel1.remaining, &r2_sec.to_bytes()).unwrap();
    assert_eq!(peel2.next_relay, r3_pub);
    let peel3 = peel(&peel2.remaining, &r3_sec.to_bytes()).unwrap();
    assert_eq!(peel3.next_relay, [0u8; 32]);
    let decrypted = decrypt_inner(&peel3.remaining, &r3_sec.to_bytes()).unwrap();
    assert_eq!(decrypted.from, tx.from);
}
