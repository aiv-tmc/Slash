use serde::{Serialize, Deserialize};

/// Fixed ciphertext size for every onion layer after encryption.
/// All layer ciphertexts are padded to this length so traffic analysis
/// cannot distinguish hop count or payload size from the outer envelope.
const LAYER_SIZE: usize = 1024;
/// Fixed ciphertext size for the inner transaction payload.
const INNER_SIZE: usize = 2048;

/// One layer of the onion envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Layer {
    pub ephemeral: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// A 3-hop onion-wrapped transaction.
/// The final_ephemeral field stores the X25519 public key needed by the
/// exit relay to decrypt the inner payload after all layers are peeled away.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionTx {
    pub layers: Vec<Layer>,
    pub inner: Vec<u8>,
    pub inner_nonce: [u8; 12],
    /// Public ephemeral key used to encrypt the inner transaction payload.
    /// The final relay uses this together with its static secret to derive
    /// the AES-GCM key for the inner ciphertext.
    pub final_ephemeral: [u8; 32],
}

/// Result of peeling one layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeelResult {
    pub next_relay: [u8; 32],
    pub remaining: OnionTx,
}

/// Pad a variable-length payload to a fixed size by prepending a 2-byte length
/// and appending zero bytes. The length prefix is hidden inside the AES-GCM ciphertext.
fn pad_payload(data: &[u8], size: usize) -> Vec<u8> {
    assert!(data.len() + 2 <= size, "payload exceeds maximum padded size");
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(data);
    out.resize(size, 0);
    out
}

/// Strip the length prefix and padding from a decrypted payload.
/// Returns None if the length prefix is malformed.
fn unpad_payload(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 2 {
        return None;
    }
    let len = u16::from_le_bytes(padded[..2].try_into().ok()?) as usize;
    if 2 + len > padded.len() {
        return None;
    }
    Some(padded[2..2 + len].to_vec())
}

/// Build a 3-hop onion around `tx` using the provided relay public keys.
/// Every layer ciphertext and the inner ciphertext are padded to fixed sizes
/// so all onion messages are indistinguishable on the wire.
/// Panics if fewer than 3 relays are supplied.
pub fn create_onion(tx: &crate::chain::Tx, relays: &[[u8; 32]]) -> OnionTx {
    assert!(relays.len() >= 3, "onion routing requires at least 3 relays");
    let tx_bytes = bincode::serialize(tx).unwrap();
    let padded_tx = pad_payload(&tx_bytes, INNER_SIZE);

    // Layer 2 (final relay) encrypts the padded inner transaction.
    let (eph2_sec, eph2_pub) = crate::crypto::x25519_generate();
    let key2 = crate::crypto::x25519_shared(&eph2_sec, &relays[2]);
    let (inner_ct, inner_nonce) = crate::crypto::aes_encrypt(&key2, &padded_tx);

    // Layer 2 also carries a dummy final-marker payload padded to LAYER_SIZE.
    let final_marker = [0u8; 32];
    let padded_final = pad_payload(&final_marker, LAYER_SIZE);
    let (ct2, nonce2) = crate::crypto::aes_encrypt(&key2, &padded_final);
    let layer2 = Layer { ephemeral: eph2_pub, nonce: nonce2, ciphertext: ct2 };

    // Layer 1 (middle relay) carries the next-hop address (relay 3).
    let (eph1_sec, eph1_pub) = crate::crypto::x25519_generate();
    let key1 = crate::crypto::x25519_shared(&eph1_sec, &relays[1]);
    let mut payload1 = Vec::new();
    payload1.extend_from_slice(&relays[2]);
    let padded1 = pad_payload(&payload1, LAYER_SIZE);
    let (ct1, nonce1) = crate::crypto::aes_encrypt(&key1, &padded1);
    let layer1 = Layer { ephemeral: eph1_pub, nonce: nonce1, ciphertext: ct1 };

    // Layer 0 (entry relay) carries the next-hop address (relay 2).
    let (eph0_sec, eph0_pub) = crate::crypto::x25519_generate();
    let key0 = crate::crypto::x25519_shared(&eph0_sec, &relays[0]);
    let mut payload0 = Vec::new();
    payload0.extend_from_slice(&relays[1]);
    let padded0 = pad_payload(&payload0, LAYER_SIZE);
    let (ct0, nonce0) = crate::crypto::aes_encrypt(&key0, &padded0);
    let layer0 = Layer { ephemeral: eph0_pub, nonce: nonce0, ciphertext: ct0 };

    OnionTx { layers: vec![layer0, layer1, layer2], inner: inner_ct, inner_nonce, final_ephemeral: eph2_pub }
}

/// Remove the outermost onion layer using the relay's X25519 secret.
/// Returns the next relay address and the remaining onion.
pub fn peel(onion: &OnionTx, secret: &[u8; 32]) -> Option<PeelResult> {
    if onion.layers.is_empty() {
        return None;
    }
    let layer = &onion.layers[0];
    let sec = x25519_dalek::StaticSecret::from(*secret);
    let key = crate::crypto::x25519_shared(&sec, &layer.ephemeral);
    let padded = crate::crypto::aes_decrypt(&key, &layer.nonce, &layer.ciphertext)?;
    let plaintext = unpad_payload(&padded)?;
    let next_relay: [u8; 32] = plaintext[..32].try_into().ok()?;
    let remaining = OnionTx {
        layers: onion.layers[1..].to_vec(),
        inner: onion.inner.clone(),
        inner_nonce: onion.inner_nonce,
        final_ephemeral: onion.final_ephemeral,
    };
    Some(PeelResult { next_relay, remaining })
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
    let key = crate::crypto::x25519_shared(&sec, &onion.final_ephemeral);
    let padded = crate::crypto::aes_decrypt(&key, &onion.inner_nonce, &onion.inner)?;
    let plaintext = unpad_payload(&padded)?;
    bincode::deserialize(&plaintext).ok()
}
