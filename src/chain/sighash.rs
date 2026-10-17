//! The transaction signature hash: the single digest every signer and
//! verifier must agree on, kept in its own module because both the
//! transfer engine and the RPC/FFI surfaces build signatures against it.

use crate::state;

impl super::chain::Chain {
    /// Transaction signature hash over the concatenation of the sender, the
    /// input ranges, the output ranges with owners and optional locks, the
    /// chain identifier, the scheme byte, and the memo commitment. The chain
    /// identifier pins the signature to one network so a signed transaction
    /// cannot be replayed across networks, and the memo commitment binds any
    /// governance payload riding the transaction so a signed transfer cannot
    /// be repurposed as a vote. The hash inputs match the serialization order
    /// of the wire format exactly so every implementation derives the same
    /// digest from the same transaction. Outputs are taken in the state-level
    /// type because the transfer engine signs over its canonical output form.
    pub fn tx_signature_hash(
        from: &[u8; 32],
        inputs: &[(u64, u64)],
        outputs: &[state::Output],
        chain_id: impl AsRef<[u8]>,
        scheme: u8,
        memo: &Option<Vec<u8>>,
    ) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(from);
        for &(s, e) in inputs {
            h.update(&s.to_le_bytes());
            h.update(&e.to_le_bytes());
        }
        for out in outputs {
            h.update(&out.start.to_le_bytes());
            h.update(&out.end.to_le_bytes());
            h.update(&out.to);
            match out.lock {
                Some(lock) => {
                    h.update(&[1u8]);
                    h.update(&lock.to_le_bytes());
                }
                None => {
                    h.update(&[0u8]);
                }
            }
        }
        h.update(chain_id.as_ref());
        h.update(&[scheme]);
        match memo {
            Some(memo) => {
                h.update(&[1u8]);
                h.update(&(memo.len() as u64).to_le_bytes());
                h.update(memo);
            }
            None => {
                h.update(&[0u8]);
            }
        }
        *h.finalize().as_bytes()
    }
}
