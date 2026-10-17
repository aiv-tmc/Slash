//! Proof-of-work verification.
//!
//! Slash uses RandomX so that mining stays CPU-friendly and ASIC-resistant.
//! The consensus-critical property here is that the verifier reconstructs
//! the exact byte string the miner searched over: `prev || time || height ||
//! nonce || miner`, hashed through a light verification context. Any drift
//! between the two sides would make valid blocks unverifiable, so the input
//! layout is part of the protocol and must never change without a
//! network-identifier bump.

/// Verify the proof-of-work of a header candidate and return the derived
/// slot cell. The hash input is exactly `prev || time || height || nonce ||
/// miner`, matching the mining loop bit for bit. A zero difficulty fails
/// closed: no nonce can satisfy it because the modulo never evaluates.
///
/// The returned value is the proof-of-work slot: the treasury-owned cell
/// index `value % N` that the header claims as `mined_cell`. Returning the
/// slot alongside the verdict pins the slot to the hash output, so a miner
/// cannot pick an arbitrary cell and must claim whatever the nonce draws.
pub fn verify_pow(
    prev: [u8; 32],
    time: u64,
    height: u64,
    miner: [u8; 32],
    nonce: u64,
    diff: u64,
) -> Option<u64> {
    if diff == 0 {
        return None;
    }
    // Light context: full-memory mining contexts are cached separately with
    // a TTL; verification only needs the fast variant.
    let ctx = crate::mining::get_context(&prev, false);
    let hasher = rust_randomx::Hasher::new(ctx);
    // 88 bytes: 32 prev + 8 time + 8 height + 8 nonce + 32 miner. The
    // capacity is stated exactly so the buffer is allocated once.
    let mut inp = Vec::with_capacity(88);
    inp.extend_from_slice(&prev);
    inp.extend_from_slice(&time.to_le_bytes());
    inp.extend_from_slice(&height.to_le_bytes());
    inp.extend_from_slice(&nonce.to_le_bytes());
    inp.extend_from_slice(&miner);
    let out = hasher.hash(&inp);
    let h = out.as_ref();
    // The first eight bytes of the hash, little-endian, are the candidate
    // value; the difficulty game is divisibility of that value.
    let value = u64::from_le_bytes(h[..8].try_into().ok()?);
    if value % diff == 0 {
        Some(value % crate::state::N)
    } else {
        None
    }
}
