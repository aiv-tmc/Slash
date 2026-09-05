use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::Aead, KeyInit};
use argon2::Argon2;
use zeroize::Zeroize;

/// Generate a new Ed25519 signing keypair.
/// Returns (secret_bytes, public_bytes). The caller should wrap the secret in Zeroizing.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut csprng = OsRng;
    let sk = SigningKey::generate(&mut csprng);
    (sk.to_bytes(), sk.verifying_key().to_bytes())
}

/// Sign `msg` with the provided 32-byte Ed25519 secret key.
pub fn sign(secret: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let sk = SigningKey::from_bytes(secret);
    sk.sign(msg).to_bytes().to_vec()
}

/// Verify an Ed25519 signature.
pub fn verify(public: &[u8; 32], msg: &[u8], sig_bytes: &[u8]) -> bool {
    let vk = match VerifyingKey::from_bytes(public) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match ed25519_dalek::Signature::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(msg, &sig).is_ok()
}

/// Generate a new X25519 static keypair for onion routing.
/// Returns (StaticSecret, public_bytes). The caller should wrap the secret in Zeroizing.
pub fn x25519_generate() -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (secret, public.to_bytes())
}

/// Compute a shared X25519 secret from a local static secret and a remote public key.
pub fn x25519_shared(secret: &StaticSecret, public_bytes: &[u8; 32]) -> [u8; 32] {
    let public = X25519PublicKey::from(*public_bytes);
    *secret.diffie_hellman(&public).as_bytes()
}

/// Encrypt `plaintext` with AES-256-GCM using the provided 32-byte key.
/// Returns (ciphertext, nonce).
pub fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = rand::random::<[u8; 12]>();
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).unwrap();
    (ciphertext, nonce)
}

/// Decrypt AES-256-GCM ciphertext.
/// Returns None if authentication fails.
pub fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()
}

/// Derive a 32-byte encryption key from a user password using Argon2id.
/// The salt must be unique per encryption and stored alongside the ciphertext.
pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).unwrap();
    key
}

/// Encrypt wallet data with AES-256-GCM using a key derived from the user password.
/// Returns (salt, nonce, ciphertext). The salt and nonce must be persisted with the ciphertext.
pub fn encrypt_wallet(plaintext: &[u8], password: &str) -> ([u8; 16], [u8; 12], Vec<u8>) {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key_bytes = derive_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).unwrap();
    key_bytes.zeroize();
    (salt, nonce, ciphertext)
}

/// Decrypt wallet data with AES-256-GCM using a key derived from the user password.
/// Returns None if the password is wrong or the ciphertext has been tampered with.
pub fn decrypt_wallet(salt: &[u8; 16], nonce: &[u8; 12], ciphertext: &[u8], password: &str) -> Option<Vec<u8>> {
    let mut key_bytes = derive_key(password, salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let result = cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok();
    key_bytes.zeroize();
    result
}
