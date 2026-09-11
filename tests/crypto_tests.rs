//! End-to-end tests for cryptographic primitives:
//! Ed25519 signatures, X25519 key exchange, AES-GCM encryption,
//! VRF prove/verify, and wallet encryption.

use slash::*;

mod common;

#[test]
fn test_ed25519_sign_and_verify() {
    let (sk, pk) = crypto::generate_keypair();
    let msg = b"hello world";
    let sig = crypto::sign(&sk, msg);
    assert!(crypto::verify(&pk, msg, &sig));
}

#[test]
fn test_ed25519_rejects_tampered_signature() {
    let (sk, pk) = crypto::generate_keypair();
    let msg = b"hello world";
    let mut sig = crypto::sign(&sk, msg);
    sig[0] ^= 0xFF;
    assert!(!crypto::verify(&pk, msg, &sig));
}

#[test]
fn test_x25519_shared_secret_symmetric() {
    let (a_sec, a_pub) = crypto::x25519_generate();
    let (b_sec, b_pub) = crypto::x25519_generate();

    let shared_a = crypto::x25519_shared(&a_sec, &b_pub);
    let shared_b = crypto::x25519_shared(&b_sec, &a_pub);

    assert_eq!(shared_a, shared_b);
}

#[test]
fn test_aes_encrypt_decrypt_roundtrip() {
    let key = [42u8; 32];
    let plaintext = b"secret message";
    let (ciphertext, nonce) = crypto::aes_encrypt(&key, plaintext);
    let decrypted = crypto::aes_decrypt(&key, &nonce, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_decrypt_rejects_tampered_ciphertext() {
    let key = [42u8; 32];
    let plaintext = b"secret message";
    let (mut ciphertext, nonce) = crypto::aes_encrypt(&key, plaintext);
    ciphertext[0] ^= 0xFF;
    assert!(crypto::aes_decrypt(&key, &nonce, &ciphertext).is_none());
}

#[test]
fn test_vrf_prove_and_verify() {
    let seed = [42u8; 32];
    let alpha = b"test message";

    // Derive the VRF public key from the same seed used for proving
    // so that the verification step has the correct public key.
    let pk = vrf::VrfKeypair::from_seed(&seed).public_bytes();
    let (output, proof) = vrf::prove(&seed, alpha);
    let verified = vrf::verify(&pk, alpha, &proof);

    assert!(verified.is_some());
    assert_eq!(verified.unwrap(), output);
}

#[test]
fn test_vrf_rejects_wrong_message() {
    let seed = [42u8; 32];
    let pk = vrf::VrfKeypair::from_seed(&seed).public_bytes();
    let (_output, proof) = vrf::prove(&seed, b"correct");
    assert!(vrf::verify(&pk, b"wrong", &proof).is_none());
}

#[test]
fn test_vrf_rejects_wrong_public_key() {
    let seed = [42u8; 32];
    let wrong_seed = [43u8; 32];
    let pk = vrf::VrfKeypair::from_seed(&wrong_seed).public_bytes();
    let (_output, proof) = vrf::prove(&seed, b"test");
    assert!(vrf::verify(&pk, b"test", &proof).is_none());
}

#[test]
fn test_vrf_proof_serialization_roundtrip() {
    let seed = [42u8; 32];
    let pk = vrf::VrfKeypair::from_seed(&seed).public_bytes();
    let (output, proof) = vrf::prove(&seed, b"roundtrip");

    let bytes = proof.to_bytes();
    let restored = vrf::VrfProof::from_bytes(&bytes).unwrap();
    let verified = vrf::verify(&pk, b"roundtrip", &restored);

    assert_eq!(verified.unwrap(), output);
}

#[test]
fn test_wallet_encryption_roundtrip() {
    let password = "super_secret_password";
    let plaintext = b"wallet data here";

    let (salt, nonce, ciphertext) = crypto::encrypt_wallet(plaintext, password);
    let decrypted = crypto::decrypt_wallet(&salt, &nonce, &ciphertext, password).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_wallet_encryption_rejects_wrong_password() {
    let password = "correct_horse_battery_staple";
    let plaintext = b"wallet data";

    let (salt, nonce, ciphertext) = crypto::encrypt_wallet(plaintext, password);
    assert!(crypto::decrypt_wallet(&salt, &nonce, &ciphertext, "wrong").is_none());
}

#[test]
fn test_key_derivation_is_deterministic() {
    let password = "my_password";
    let salt = [1u8; 16];

    let k1 = crypto::derive_key(password, &salt);
    let k2 = crypto::derive_key(password, &salt);

    assert_eq!(k1, k2);
}

#[test]
fn test_key_derivation_differs_with_different_salts() {
    let password = "my_password";
    let salt1 = [1u8; 16];
    let salt2 = [2u8; 16];

    let k1 = crypto::derive_key(password, &salt1);
    let k2 = crypto::derive_key(password, &salt2);

    assert_ne!(k1, k2);
}
