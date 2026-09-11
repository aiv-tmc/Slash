//! End-to-end tests for the 3-hop onion routing envelope:
//! creation, layered decryption, constant wire size, and failure modes.

use slash::*;

mod common;
use common::*;

#[test]
fn test_onion_create_and_peel() {
    let _tmp = setup_test_dir("onion_peel");
    reset_testnet();

    let (r1_sec, r1_pub) = crypto::x25519_generate();
    let (r2_sec, r2_pub) = crypto::x25519_generate();
    let (r3_sec, r3_pub) = crypto::x25519_generate();

    let tx = chain::Tx {
        from: [1u8; 32],
        inputs: vec![(0, 1)],
        outputs: vec![state::Output {
            start: 0,
            end: 1,
            to: [2u8; 32],
            lock: None,
        }],
        sig: vec![0u8; 64],
        scheme: 0,
    };

    let onion = onion::create_onion(&tx, &[r1_pub, r2_pub, r3_pub]);
    assert_eq!(onion.layers.len(), 3);

    let peel1 = onion::peel(&onion, &r1_sec.to_bytes()).unwrap();
    assert_eq!(peel1.next_relay, r2_pub);

    let peel2 = onion::peel(&peel1.remaining, &r2_sec.to_bytes()).unwrap();
    assert_eq!(peel2.next_relay, r3_pub);

    let peel3 = onion::peel(&peel2.remaining, &r3_sec.to_bytes()).unwrap();
    assert_eq!(peel3.next_relay, [0u8; 32]);
}

#[test]
fn test_onion_decrypt_inner() {
    let _tmp = setup_test_dir("onion_inner");
    reset_testnet();

    let (r1_sec, r1_pub) = crypto::x25519_generate();
    let (r2_sec, r2_pub) = crypto::x25519_generate();
    let (r3_sec, r3_pub) = crypto::x25519_generate();

    let tx = chain::Tx {
        from: [1u8; 32],
        inputs: vec![(0, 1)],
        outputs: vec![state::Output {
            start: 0,
            end: 1,
            to: [2u8; 32],
            lock: None,
        }],
        sig: vec![0u8; 64],
        scheme: 0,
    };

    let onion = onion::create_onion(&tx, &[r1_pub, r2_pub, r3_pub]);

    let peel1 = onion::peel(&onion, &r1_sec.to_bytes()).unwrap();
    let peel2 = onion::peel(&peel1.remaining, &r2_sec.to_bytes()).unwrap();
    let peel3 = onion::peel(&peel2.remaining, &r3_sec.to_bytes()).unwrap();
    let decrypted = onion::decrypt_inner(&peel3.remaining, &r3_sec.to_bytes()).unwrap();

    assert_eq!(decrypted.from, tx.from);
    assert_eq!(decrypted.inputs, tx.inputs);
}

#[test]
fn test_onion_constant_size() {
    let _tmp = setup_test_dir("onion_size");
    reset_testnet();

    let (_r1_sec, r1_pub) = crypto::x25519_generate();
    let (_r2_sec, r2_pub) = crypto::x25519_generate();
    let (_r3_sec, r3_pub) = crypto::x25519_generate();

    let tx = chain::Tx {
        from: [1u8; 32],
        inputs: vec![(0, 1)],
        outputs: vec![state::Output {
            start: 0,
            end: 1,
            to: [2u8; 32],
            lock: None,
        }],
        sig: vec![0u8; 64],
        scheme: 0,
    };

    let onion = onion::create_onion(&tx, &[r1_pub, r2_pub, r3_pub]);
    for layer in &onion.layers {
        assert_eq!(layer.ciphertext.len(), 1024);
    }
    assert_eq!(onion.inner.len(), 2048);
}

#[test]
fn test_onion_wrong_relay_fails() {
    let _tmp = setup_test_dir("onion_wrong");
    reset_testnet();

    let (_r1_sec, r1_pub) = crypto::x25519_generate();
    let (r2_sec, r2_pub) = crypto::x25519_generate();

    let tx = chain::Tx {
        from: [1u8; 32],
        inputs: vec![(0, 1)],
        outputs: vec![state::Output {
            start: 0,
            end: 1,
            to: [2u8; 32],
            lock: None,
        }],
        sig: vec![0u8; 64],
        scheme: 0,
    };

    let onion = onion::create_onion(&tx, &[r1_pub, r2_pub, r1_pub]);
    // Attempt to peel with the second relay's secret instead of the first.
    // The AES-GCM authentication will fail because the key is wrong.
    let result = onion::peel(&onion, &r2_sec.to_bytes());
    assert!(result.is_none());
}

#[test]
fn test_onion_peel_empty_fails() {
    let _tmp = setup_test_dir("onion_empty");
    reset_testnet();

    let empty = onion::OnionTx {
        layers: vec![],
        inner: vec![],
        inner_nonce: [0u8; 12],
        final_ephemeral: [0u8; 32],
    };
    // Peeling requires at least one layer to derive a shared secret.
    let result = onion::peel(&empty, &[0u8; 32]);
    assert!(result.is_none());
}

#[test]
fn test_onion_serialization_roundtrip() {
    let _tmp = setup_test_dir("onion_roundtrip");
    reset_testnet();

    let (_r1_sec, r1_pub) = crypto::x25519_generate();
    let (_r2_sec, r2_pub) = crypto::x25519_generate();
    let (_r3_sec, r3_pub) = crypto::x25519_generate();

    let tx = chain::Tx {
        from: [1u8; 32],
        inputs: vec![(0, 1)],
        outputs: vec![state::Output {
            start: 0,
            end: 1,
            to: [2u8; 32],
            lock: None,
        }],
        sig: vec![0u8; 64],
        scheme: 0,
    };

    let original = onion::create_onion(&tx, &[r1_pub, r2_pub, r3_pub]);
    let bytes = bincode::serialize(&original).unwrap();
    let restored: onion::OnionTx = bincode::deserialize(&bytes).unwrap();

    assert_eq!(restored.layers.len(), original.layers.len());
    assert_eq!(restored.inner.len(), original.inner.len());
    assert_eq!(restored.final_ephemeral, original.final_ephemeral);
}
