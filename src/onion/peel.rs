//! Layer removal and exit decryption. Peeling re-derives the layer key
//! from the relay's static secret and the layer's ephemeral public key,
//! and the length guard rejects crafted envelopes whose decrypted payload
//! is shorter than one relay address — a malformed envelope must never be
//! able to crash the peeling node.

use super::{unpad_payload, OnionTx, PeelResult};
use zeroize::Zeroizing;

/// Remove the outermost onion layer using the relay's X25519 secret.
/// Returns the next relay address and the remaining onion.
pub fn peel(onion: &OnionTx, secret: &[u8; 32]) -> Option<PeelResult> {
    if onion.layers.is_empty() {
        return None;
    }
    let layer = &onion.layers[0];
    let sec = x25519_dalek::StaticSecret::from(*secret);
    // The derived layer key is wrapped in Zeroizing so it is overwritten as
    // soon as the decrypt call returns, regardless of which branch exits.
    let key = Zeroizing::new(crate::crypto::x25519_shared(&sec, &layer.ephemeral));
    let padded = crate::crypto::aes_decrypt(&key, &layer.nonce, &layer.ciphertext)?;
    let plaintext = unpad_payload(&padded)?;
    // The next-hop address occupies the first 32 bytes of the decrypted
    // layer payload. The envelope originator encrypts every layer and
    // therefore fully controls the padded plaintext, so a payload shorter
    // than one address is well-formed ciphertext carrying malformed
    // routing data. The length guard rejects the envelope instead of
    // indexing out of bounds: a crafted onion must never be able to crash
    // the peeling node.
    if plaintext.len() < 32 {
        return None;
    }
    let next_relay: [u8; 32] = plaintext[..32].try_into().ok()?;
    let remaining = OnionTx {
        layers: onion.layers[1..].to_vec(),
        inner: onion.inner.clone(),
        inner_nonce: onion.inner_nonce,
        final_ephemeral: onion.final_ephemeral,
        onion_id: onion.onion_id,
    };
    Some(PeelResult {
        next_relay,
        remaining,
    })
}

/// Decrypt the inner transaction when no layers remain.
/// The final relay uses the final_ephemeral together with its static secret
/// to derive the key that decrypts the inner ciphertext.
pub fn decrypt_inner(onion: &OnionTx, secret: &[u8; 32]) -> Option<crate::chain::Tx> {
    // When every layer has been peeled, the onion contains zero layers.
    // The final relay decrypts the inner payload using final_ephemeral.
    if !onion.layers.is_empty() {
        return None;
    }
    let sec = x25519_dalek::StaticSecret::from(*secret);
    let key = Zeroizing::new(crate::crypto::x25519_shared(&sec, &onion.final_ephemeral));
    let padded = crate::crypto::aes_decrypt(&key, &onion.inner_nonce, &onion.inner)?;
    let plaintext = unpad_payload(&padded)?;
    bincode::deserialize(&plaintext).ok()
}
