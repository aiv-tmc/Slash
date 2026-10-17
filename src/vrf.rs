//! ECVRF-EDWARDS25519-SHA512-TAI verifiable random function (RFC 9381).
//!
//! This module implements the ECVRF-EDWARDS25519-SHA512-TAI ciphersuite from
//! RFC 9381 section 5.5 exactly:
//!
//! - suite_string = 0x03.
//! - Key generation follows RFC 8032: the secret scalar is the first half of
//!   SHA-512(SK) after pruning (three low bits of octet 0 cleared, the high
//!   bit of octet 31 cleared, the second-highest bit set), and the public key
//!   is the standard RFC 8032 point encoding.
//! - ECVRF_encode_to_curve is try-and-increment (RFC 9381 section 5.4.1.1.1):
//!   SHA-512(suite || 0x01 || PK || alpha || ctr || 0x00), decoding the first
//!   32 octets with RFC 8032 string_to_point and clearing the cofactor
//!   (H = 8*H). TAI runs in time variable in the message; every alpha
//!   processed here (treasury selection seeds, block-derived data) is public,
//!   which matches the usage preconditions of RFC 9381 section 7.5.
//! - ECVRF_nonce_generation uses the RFC 8032 hash function (RFC 9381 section
//!   5.4.2.2): k = int(SHA-512(SHA-512(SK)[32..64] || H_string)) mod q. The
//!   nonce is deterministic, which makes proofs reproducible — a hard
//!   precondition for pinning cross-implementation conformance vectors.
//! - The Fiat-Shamir challenge (RFC 9381 section 5.4.3) is the first cLen = 16
//!   octets of SHA-512(suite || 0x02 || Y || H || Gamma || U || V || 0x00).
//! - proof_to_hash (RFC 9381 section 5.4.4) is SHA-512(suite || 0x03 ||
//!   8*Gamma || 0x00), a full 64-octet beta.
//! - Verification enforces validate_key = TRUE (RFC 9381 section 5.4.5):
//!   non-canonical point encodings and public keys of small order are
//!   rejected.
//!
//! Conformance is pinned against the official RFC 9381 Appendix B test
//! vectors for this ciphersuite; the internal test module reproduces the
//! published public keys, proofs and outputs byte for byte. Any future
//! deviation in the transcript order, the nonce formula or the challenge
//! composition changes the pinned bytes and fails those tests immediately.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// Ciphersuite identifier: suite_string = 0x03 selects
/// ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 section 5.5).
const SUITE_STRING: u8 = 0x03;

/// Challenge length in octets for this ciphersuite (cLen = 16).
const CHALLENGE_LEN: usize = 16;

/// Field modulus p = 2^255 - 19 serialized as a 32-octet little-endian
/// string. Point decoding rejects encodings with y >= p as required by
/// RFC 8032 section 5.1.3 before delegating to the library decompressor,
/// because the decompressor itself reduces its input modulo p and would
/// silently accept a non-canonical encoding.
const P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// A VRF keypair: 32-octet seed, derived secret scalar and public point.
/// The seed and the scalar are secret material and are wiped when the
/// keypair is dropped; the public point is kept alongside them so proving
/// never recomputes it.
#[derive(Zeroize)]
pub struct VrfKeypair {
    seed: [u8; 32],
    secret: Scalar,
    public: EdwardsPoint,
}

impl VrfKeypair {
    /// Derive a keypair from a raw 32-octet secret seed using the RFC 8032
    /// secret-scalar derivation.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = secret_scalar_from_seed(seed);
        let public = secret * ED25519_BASEPOINT_POINT;
        Self {
            seed: *seed,
            secret,
            public,
        }
    }

    /// Return the RFC 8032 encoding of the public key (32 octets).
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.compress().to_bytes()
    }

    /// Produce a VRF proof for `alpha` together with the 64-octet output
    /// beta. The proof is deterministic: the same (key, alpha) pair always
    /// yields byte-identical results.
    pub fn prove(&self, alpha: &[u8]) -> ([u8; 64], VrfProof) {
        let public_bytes = self.public_bytes();

        // H = ECVRF_encode_to_curve(PK, alpha). The 256-value counter space
        // finds a valid point with overwhelming probability; exhaustion would
        // indicate a broken transcript hash rather than bad luck.
        let h = encode_to_curve(&public_bytes, alpha)
            .expect("ECVRF_encode_to_curve counter space exhausted");
        let h_string = h.compress().to_bytes();

        let gamma = self.secret * h;

        let mut k = nonce_generation(&self.seed, &h_string);
        let u = k * ED25519_BASEPOINT_POINT;
        let v = k * h;

        // The challenge commits to the full transcript. Only the first cLen
        // octets of the digest are used; they fit a u128 in little-endian
        // order per RFC 8032.
        let c = challenge_generation(&public_bytes, &h_string, &gamma, &u, &v);

        // s = (k + c * x) mod q. The challenge is zero-padded to the scalar
        // width; from_bytes_mod_order reduces it modulo the group order.
        let mut c_wide = [0u8; 32];
        c_wide[..CHALLENGE_LEN].copy_from_slice(&c.to_le_bytes());
        let c_scalar = Scalar::from_bytes_mod_order(c_wide);
        let s = k + c_scalar * self.secret;

        // The response nonce is secret-derived and no longer needed once s
        // is computed; it must not survive in memory.
        k.zeroize();

        let beta = proof_to_hash(&gamma);
        (
            beta,
            VrfProof {
                gamma,
                c: c.to_le_bytes(),
                s,
            },
        )
    }
}

/// Prove a VRF from a raw 32-octet secret seed. Returns the 64-octet output
/// and the proof.
pub fn prove(secret: &[u8; 32], alpha: &[u8]) -> ([u8; 64], VrfProof) {
    VrfKeypair::from_seed(secret).prove(alpha)
}

/// Verify a proof against a raw 32-octet public key. Returns the 64-octet
/// output on success, or None when any check fails.
pub fn verify(public_bytes: &[u8; 32], alpha: &[u8], proof: &VrfProof) -> Option<[u8; 64]> {
    // validate_key (RFC 9381 section 5.4.5, default TRUE): the public key
    // must decode canonically and must not be a point of small order, so
    // that full collision resistance holds.
    let public = decode_point(public_bytes)?;
    if public.mul_by_cofactor().is_identity() {
        return None;
    }

    let h = encode_to_curve(public_bytes, alpha)?;
    let h_string = h.compress().to_bytes();

    // Re-derive the challenge scalar committed to by the proof and recompute
    // the nonce commitments U = s*B - c*Y and V = s*H - c*Gamma.
    let mut c_wide = [0u8; 32];
    c_wide[..CHALLENGE_LEN].copy_from_slice(&proof.c);
    let c_scalar = Scalar::from_bytes_mod_order(c_wide);
    let u = proof.s * ED25519_BASEPOINT_POINT - c_scalar * public;
    let v = proof.s * h - c_scalar * proof.gamma;

    // A proof is valid only when the recomputed challenge equals the
    // committed one; comparing the raw u128 values avoids any scalar
    // reduction ambiguity.
    let c_prime = challenge_generation(public_bytes, &h_string, &proof.gamma, &u, &v);
    if c_prime != u128::from_le_bytes(proof.c) {
        return None;
    }

    Some(proof_to_hash(&proof.gamma))
}

/// A VRF proof: gamma (curve point), the 16-octet challenge c and the
/// 32-octet response scalar s.
#[derive(Clone, Debug)]
pub struct VrfProof {
    gamma: EdwardsPoint,
    c: [u8; CHALLENGE_LEN],
    s: Scalar,
}

impl VrfProof {
    /// Serialize the proof: 32-octet gamma || 16-octet challenge ||
    /// 32-octet response, 80 octets in total.
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[..32].copy_from_slice(&self.gamma.compress().to_bytes());
        out[32..48].copy_from_slice(&self.c);
        out[48..].copy_from_slice(self.s.as_bytes());
        out
    }

    /// Deserialize a proof from exactly 80 octets. Returns None for a wrong
    /// length, a non-canonical or undecodable gamma, or a response scalar
    /// that is not canonically reduced (s >= q is invalid per RFC 9381).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 80 {
            return None;
        }
        let gamma = decode_point(bytes[..32].try_into().unwrap())?;
        let c = bytes[32..48].try_into().unwrap();
        let s = Option::from(Scalar::from_canonical_bytes(
            bytes[48..80].try_into().unwrap(),
        ))?;
        Some(Self { gamma, c, s })
    }
}

/// Derive the secret scalar from a seed using RFC 8032 section 5.1.5: the
/// first half of SHA-512(seed), pruned (three low bits of octet 0 cleared,
/// high bit of octet 31 cleared, second-highest bit set), then reduced
/// modulo the group order. The pruned buffer is wiped after use.
fn secret_scalar_from_seed(seed: &[u8; 32]) -> Scalar {
    let digest = Sha512::digest(seed);
    let mut pruned = [0u8; 32];
    pruned.copy_from_slice(&digest[..32]);
    pruned[0] &= 248;
    pruned[31] &= 127;
    pruned[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(pruned);
    pruned.zeroize();
    scalar
}

/// Decode a 32-octet RFC 8032 point encoding. The sign bit of x occupies the
/// most significant bit of the last octet and is not part of the field
/// element, so it is masked off before the range check: an encoding whose
/// sign bit is set still decodes whenever y < p. Encodings with y >= p are
/// non-canonical and rejected before decompression; the decompressor's
/// square-root check then enforces that the encoding is a valid curve point.
fn decode_point(encoding: &[u8; 32]) -> Option<EdwardsPoint> {
    let mut y_bytes = *encoding;
    y_bytes[31] &= 0x7f;
    // Lexicographic little-endian comparison against the field modulus. An
    // encoding equal to P_LE encodes y = p and is also rejected.
    let mut canonical = false;
    for i in (0..32).rev() {
        if y_bytes[i] != P_LE[i] {
            canonical = y_bytes[i] < P_LE[i];
            break;
        }
    }
    if !canonical {
        return None;
    }
    CompressedEdwardsY(*encoding).decompress()
}

/// ECVRF_encode_to_curve (try-and-increment, RFC 9381 section 5.4.1.1.1):
/// hash the suite transcript with a running counter, decode the first 32
/// digest octets as a point, and advance the counter while the decode fails,
/// yields the identity, or yields a point of small order after cofactor
/// clearing. Returns None only if all 256 counter values fail.
fn encode_to_curve(public_bytes: &[u8; 32], alpha: &[u8]) -> Option<EdwardsPoint> {
    for ctr in 0..=u8::MAX {
        let mut hasher = Sha512::new();
        hasher.update([SUITE_STRING, 0x01]);
        hasher.update(public_bytes);
        hasher.update(alpha);
        hasher.update([ctr, 0x00]);
        let digest = hasher.finalize();
        let mut hash_bytes = [0u8; 64];
        hash_bytes.copy_from_slice(&digest);
        let decoded = decode_point(hash_bytes[..32].try_into().unwrap());
        hash_bytes.zeroize();
        if let Some(h) = decoded {
            if h.is_identity() {
                continue;
            }
            let h = h.mul_by_cofactor();
            if !h.is_identity() {
                return Some(h);
            }
        }
    }
    None
}

/// ECVRF_nonce_generation with the RFC 8032 hash function (RFC 9381 section
/// 5.4.2.2): k = int(SHA-512(SHA-512(SK)[32..64] || H_string)) mod q via the
/// wide reduction. All intermediate buffers holding seed-derived material
/// are wiped before returning.
fn nonce_generation(seed: &[u8; 32], h_string: &[u8; 32]) -> Scalar {
    let digest = Sha512::digest(seed);
    let mut hashed_seed = [0u8; 64];
    hashed_seed.copy_from_slice(&digest);
    let k_string = Sha512::digest([&hashed_seed[32..], &h_string[..]].concat());
    hashed_seed.zeroize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&k_string);
    let nonce = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    nonce
}

/// ECVRF_challenge_generation (RFC 9381 section 5.4.3): the first cLen = 16
/// octets of SHA-512(suite || 0x02 || Y || H || Gamma || U || V || 0x00),
/// interpreted as a little-endian integer per RFC 8032.
fn challenge_generation(
    public_bytes: &[u8; 32],
    h_string: &[u8; 32],
    gamma: &EdwardsPoint,
    u: &EdwardsPoint,
    v: &EdwardsPoint,
) -> u128 {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING, 0x02]);
    hasher.update(public_bytes);
    hasher.update(h_string);
    hasher.update(gamma.compress().to_bytes());
    hasher.update(u.compress().to_bytes());
    hasher.update(v.compress().to_bytes());
    hasher.update([0x00]);
    let digest = hasher.finalize();
    u128::from_le_bytes(digest[..CHALLENGE_LEN].try_into().unwrap())
}

/// ECVRF_proof_to_hash (RFC 9381 section 5.4.4): the full 64-octet
/// SHA-512(suite || 0x03 || 8*Gamma || 0x00).
fn proof_to_hash(gamma: &EdwardsPoint) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING, 0x03]);
    hasher.update(gamma.mul_by_cofactor().compress().to_bytes());
    hasher.update([0x00]);
    let digest = hasher.finalize();
    let mut beta = [0u8; 64];
    beta.copy_from_slice(&digest);
    beta
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One official RFC 9381 Appendix B test vector for
    /// ECVRF-EDWARDS25519-SHA512-TAI.
    struct RfcVector {
        secret: &'static str,
        public: &'static str,
        alpha: &'static [u8],
        proof: &'static str,
        beta: &'static str,
    }

    /// The three official vectors. The proofs encode gamma (32 octets) ||
    /// c (16 octets) || s (32 octets); the expected public key, proof and
    /// output must reproduce byte for byte.
    const RFC9381_VECTORS: &[RfcVector] = &[
        RfcVector {
            secret: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            alpha: b"",
            proof: "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26\
                     f8a57ccaed74ee1b190bed1f479d9727\
                     d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
            beta: "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff\
                   66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
        },
        RfcVector {
            secret: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            alpha: b"\x72",
            proof: "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933\
                     bf0864a62558b3ed7f2fea45c92a4653\
                     01b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
            beta: "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb\
                   5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
        },
        RfcVector {
            secret: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            alpha: &[0xaf, 0x82],
            proof: "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccb\
                     f8096bb474e53895c362d8628ee9f9ea3\
                     c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
            beta: "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45\
                   2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
        },
    ];

    #[test]
    fn rfc9381_cross_vectors() {
        // Conformance gate: the derived public key, the serialized proof and
        // the output must match the official RFC 9381 vectors exactly, and
        // each proof must verify to its published output. Any change to the
        // transcript order, the nonce formula or the challenge composition
        // diverges from these bytes and fails here.
        for v in RFC9381_VECTORS {
            let secret: [u8; 32] = hex::decode(v.secret).unwrap().try_into().unwrap();
            let public: [u8; 32] = hex::decode(v.public).unwrap().try_into().unwrap();
            let expected_proof = hex::decode(v.proof).unwrap();
            let expected_beta: [u8; 64] = hex::decode(v.beta).unwrap().try_into().unwrap();

            let kp = VrfKeypair::from_seed(&secret);
            assert_eq!(kp.public_bytes(), public, "public key for {}", v.secret);

            let (beta, proof) = kp.prove(v.alpha);
            assert_eq!(
                proof.to_bytes(),
                expected_proof.as_slice(),
                "proof for {}",
                v.secret
            );
            assert_eq!(beta, expected_beta, "output for {}", v.secret);
            assert_eq!(verify(&public, v.alpha, &proof), Some(expected_beta));
        }
    }

    #[test]
    fn prove_verify_roundtrip() {
        let kp = VrfKeypair::from_seed(&[7u8; 32]);
        let pk = kp.public_bytes();
        let (beta, proof) = kp.prove(b"treasury selection round 1");
        assert_eq!(
            verify(&pk, b"treasury selection round 1", &proof),
            Some(beta)
        );
    }

    #[test]
    fn proof_is_deterministic() {
        // The RFC 8032 nonce derivation makes proofs reproducible: identical
        // (key, alpha) inputs produce byte-identical proofs and outputs.
        let kp = VrfKeypair::from_seed(&[7u8; 32]);
        let (beta_a, proof_a) = kp.prove(b"determinism check");
        let (beta_b, proof_b) = kp.prove(b"determinism check");
        assert_eq!(beta_a, beta_b);
        assert_eq!(proof_a.to_bytes(), proof_b.to_bytes());
    }

    #[test]
    fn wrong_alpha_is_rejected() {
        // The challenge binds alpha into the transcript, so a proof lifted
        // onto a different message must fail verification.
        let kp = VrfKeypair::from_seed(&[7u8; 32]);
        let pk = kp.public_bytes();
        let (_, proof) = kp.prove(b"message one");
        assert_eq!(verify(&pk, b"message two", &proof), None);
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let kp = VrfKeypair::from_seed(&[7u8; 32]);
        let other = VrfKeypair::from_seed(&[8u8; 32]);
        let (_, proof) = kp.prove(b"key separation check");
        assert_eq!(
            verify(&other.public_bytes(), b"key separation check", &proof),
            None
        );
    }

    #[test]
    fn tampered_proof_is_rejected() {
        // Flipping any bit of the serialized proof must invalidate it. A
        // corruption in gamma or in the response scalar can make the proof
        // undecodable (from_bytes returns None) — that is a rejection, not
        // a test error; a surviving proof must fail verification.
        let kp = VrfKeypair::from_seed(&[7u8; 32]);
        let pk = kp.public_bytes();
        for offset in [0usize, 32, 48, 79] {
            let mut bytes = kp.prove(b"tamper check").1.to_bytes();
            bytes[offset] ^= 0x01;
            match VrfProof::from_bytes(&bytes) {
                None => {}
                Some(proof) => assert!(
                    verify(&pk, b"tamper check", &proof).is_none(),
                    "tampered proof accepted at offset {}",
                    offset
                ),
            }
        }
    }

    #[test]
    fn short_and_long_proofs_are_rejected() {
        let kp = VrfKeypair::from_seed(&[7u8; 32]);
        let bytes = kp.prove(b"size check").1.to_bytes();
        assert!(VrfProof::from_bytes(&bytes[..79]).is_none());
        // An over-length proof is built by appending one octet; slicing an
        // 80-octet array to 81 is a range error, so the longer buffer is
        // constructed explicitly.
        let mut long = bytes.to_vec();
        long.push(0u8);
        assert!(VrfProof::from_bytes(&long).is_none());
    }

    #[test]
    fn non_canonical_encodings_are_rejected() {
        // y = p encodes a non-canonical field element and must be rejected
        // by string_to_point even though the library decompressor alone
        // would reduce it modulo p.
        let kp = VrfKeypair::from_seed(&[7u8; 32]);
        let pk = kp.public_bytes();
        let mut bytes = kp.prove(b"canonical check").1.to_bytes();
        bytes[..32].copy_from_slice(&P_LE);
        assert!(VrfProof::from_bytes(&bytes).is_none());
        // Flipping the sign bit of the public key changes which square root
        // the encoding selects, so verification must fail: the challenge
        // recomputed against the negated point cannot match the committed
        // one.
        let mut bad_pk = pk;
        bad_pk[31] ^= 0x80;
        let (_, proof) = kp.prove(b"canonical check");
        assert_eq!(verify(&bad_pk, b"canonical check", &proof), None);
    }
}
