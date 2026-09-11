use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A VRF keypair over the Ristretto255 group.
/// The secret scalar is automatically cleared from memory when the struct is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VrfKeypair {
    secret: Scalar,
    public: RistrettoPoint,
}

impl Clone for VrfKeypair {
    fn clone(&self) -> Self {
        Self {
            secret: self.secret,
            public: self.public,
        }
    }
}

impl VrfKeypair {
    /// Generate a new random VRF keypair.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let secret = Scalar::from_bytes_mod_order_wide(&bytes);
        let public = secret * RISTRETTO_BASEPOINT_POINT;
        Self { secret, public }
    }

    /// Construct a keypair from a 32-byte secret seed.
    /// The seed is reduced modulo the group order to produce a valid scalar.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = Scalar::from_bytes_mod_order(*seed);
        let public = secret * RISTRETTO_BASEPOINT_POINT;
        Self { secret, public }
    }

    /// Return the 32-byte compressed public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.compress().as_bytes()
    }

    /// Return the 32-byte canonical encoding of the secret scalar.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Produce a VRF output and proof for the given message.
    /// Returns (beta, proof) where beta is the 32-byte pseudorandom output.
    pub fn prove(&self, alpha: &[u8]) -> ([u8; 32], VrfProof) {
        let h = hash_to_curve(alpha, &self.public);
        let gamma = self.secret * h;

        let mut rng = OsRng;
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let k = Scalar::from_bytes_mod_order_wide(&bytes);

        let u = k * RISTRETTO_BASEPOINT_POINT;
        let v = k * h;

        let c = hash_points(&[self.public, h, gamma, u, v]);
        let s = k + c * self.secret;

        let beta = proof_to_hash(&gamma);
        let proof = VrfProof {
            gamma,
            c: c.to_bytes(),
            s,
        };
        (beta, proof)
    }
}

/// Convenience free function that proves a VRF from a raw 32-byte secret seed.
/// This matches the API expected by the integration test suite.
pub fn prove(secret: &[u8; 32], alpha: &[u8]) -> ([u8; 32], VrfProof) {
    let kp = VrfKeypair::from_seed(secret);
    kp.prove(alpha)
}

/// Convenience free function that verifies a VRF proof from a raw 32-byte public key.
/// Returns the 32-byte output if valid, or None if invalid.
pub fn verify(public_bytes: &[u8; 32], alpha: &[u8], proof: &VrfProof) -> Option<[u8; 32]> {
    let public = CompressedRistretto(*public_bytes).decompress()?;
    let h = hash_to_curve(alpha, &public);

    let c_scalar = Option::from(Scalar::from_canonical_bytes(proof.c))?;
    let u = proof.s * RISTRETTO_BASEPOINT_POINT - c_scalar * public;
    let v = proof.s * h - c_scalar * proof.gamma;

    let c_prime = hash_points(&[public, h, proof.gamma, u, v]);
    if c_prime != c_scalar {
        return None;
    }

    Some(proof_to_hash(&proof.gamma))
}

/// A VRF proof consisting of gamma (curve point), challenge scalar c, and response scalar s.
#[derive(Clone, Debug)]
pub struct VrfProof {
    gamma: RistrettoPoint,
    c: [u8; 32],
    s: Scalar,
}

impl VrfProof {
    /// Serialize the proof to a compact 96-byte representation.
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[..32].copy_from_slice(self.gamma.compress().as_bytes());
        out[32..64].copy_from_slice(&self.c);
        out[64..].copy_from_slice(self.s.as_bytes());
        out
    }

    /// Deserialize a proof from exactly 96 bytes.
    /// Returns None if any component is malformed or non-canonical.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 96 {
            return None;
        }
        let gamma = CompressedRistretto(bytes[..32].try_into().unwrap()).decompress()?;
        let c = bytes[32..64].try_into().unwrap();
        let s = Option::from(Scalar::from_canonical_bytes(
            bytes[64..96].try_into().unwrap(),
        ))?;
        Some(Self { gamma, c, s })
    }
}

/// Hash a message and public key to a curve point using the Ristretto255 hash-to-curve.
fn hash_to_curve(alpha: &[u8], public: &RistrettoPoint) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"ECVRF_RISTRETTO255_SHA512");
    hasher.update(alpha);
    hasher.update(public.compress().as_bytes());
    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 64];
    hash_bytes.copy_from_slice(&hash);
    RistrettoPoint::from_uniform_bytes(&hash_bytes)
}

/// Hash a sequence of curve points to a scalar.
fn hash_points(points: &[RistrettoPoint]) -> Scalar {
    let mut hasher = Sha512::new();
    for p in points {
        hasher.update(p.compress().as_bytes());
    }
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    Scalar::from_bytes_mod_order(bytes)
}

/// Convert a gamma point to the VRF output hash.
fn proof_to_hash(gamma: &RistrettoPoint) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"ECVRF_proof_to_hash");
    hasher.update(gamma.compress().as_bytes());
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    out
}
