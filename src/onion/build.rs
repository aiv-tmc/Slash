//! Envelope construction: one ephemeral-static Diffie-Hellman key per hop,
//! fixed-size padded ciphertexts, and the inner transaction encrypted for
//! the exit relay.

use super::{
    clear_ephemeral_secret_copy, pad_payload, Layer, OnionError, OnionTx, INNER_SIZE, LAYER_SIZE,
    MIN_RELAYS,
};
use zeroize::Zeroizing;

/// Build a 3-hop onion around `tx` using the provided relay public keys.
/// Every layer ciphertext and the inner ciphertext are padded to fixed sizes
/// so all onion messages are indistinguishable on the wire.
///
/// Returns `OnionError::TooFewRelays` when fewer than three relays are
/// supplied; the caller decides how to surface the input error.
pub fn create_onion(tx: &crate::chain::Tx, relays: &[[u8; 32]]) -> Result<OnionTx, OnionError> {
    if relays.len() < MIN_RELAYS {
        return Err(OnionError::TooFewRelays {
            provided: relays.len(),
            required: MIN_RELAYS,
        });
    }
    let tx_bytes = bincode::serialize(tx).unwrap();
    let padded_tx = pad_payload(&tx_bytes, INNER_SIZE);

    // Layer 2 (final relay) encrypts the padded inner transaction.
    let (eph2_sec, eph2_pub) = crate::crypto::x25519_generate();
    // The layer key wraps the derived shared secret in Zeroizing so the 32
    // bytes are overwritten as soon as the value goes out of scope.
    let key2 = Zeroizing::new(crate::crypto::x25519_shared(&eph2_sec, &relays[2]));
    clear_ephemeral_secret_copy(&eph2_sec);
    let (inner_ct, inner_nonce) = crate::crypto::aes_encrypt(&key2, &padded_tx);

    // Layer 2 also carries a dummy final-marker payload padded to LAYER_SIZE.
    let final_marker = [0u8; 32];
    let padded_final = pad_payload(&final_marker, LAYER_SIZE);
    let (ct2, nonce2) = crate::crypto::aes_encrypt(&key2, &padded_final);
    let layer2 = Layer {
        ephemeral: eph2_pub,
        nonce: nonce2,
        ciphertext: ct2,
    };

    // Layer 1 (middle relay) carries the next-hop address (relay 3).
    let (eph1_sec, eph1_pub) = crate::crypto::x25519_generate();
    let key1 = Zeroizing::new(crate::crypto::x25519_shared(&eph1_sec, &relays[1]));
    clear_ephemeral_secret_copy(&eph1_sec);
    let mut payload1 = Vec::new();
    payload1.extend_from_slice(&relays[2]);
    let padded1 = pad_payload(&payload1, LAYER_SIZE);
    let (ct1, nonce1) = crate::crypto::aes_encrypt(&key1, &padded1);
    let layer1 = Layer {
        ephemeral: eph1_pub,
        nonce: nonce1,
        ciphertext: ct1,
    };

    // Layer 0 (entry relay) carries the next-hop address (relay 2).
    let (eph0_sec, eph0_pub) = crate::crypto::x25519_generate();
    let key0 = Zeroizing::new(crate::crypto::x25519_shared(&eph0_sec, &relays[0]));
    clear_ephemeral_secret_copy(&eph0_sec);
    let mut payload0 = Vec::new();
    payload0.extend_from_slice(&relays[1]);
    let padded0 = pad_payload(&payload0, LAYER_SIZE);
    let (ct0, nonce0) = crate::crypto::aes_encrypt(&key0, &padded0);
    let layer0 = Layer {
        ephemeral: eph0_pub,
        nonce: nonce0,
        ciphertext: ct0,
    };

    Ok(OnionTx {
        layers: vec![layer0, layer1, layer2],
        inner: inner_ct,
        inner_nonce,
        final_ephemeral: eph2_pub,
        onion_id: rand::random::<[u8; 32]>(),
    })
}
