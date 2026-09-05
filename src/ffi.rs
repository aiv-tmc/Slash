use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_ulonglong};

/// Generate a new Ed25519 keypair and return the hex-encoded public key.
/// The caller must call `slash_free_string` to release the returned pointer.
/// The secret key is discarded after generation; use the wallet API for persistent keys.
#[no_mangle]
pub extern "C" fn slash_generate_keypair() -> *mut c_char {
    let (sk, pk) = crate::crypto::generate_keypair();
    // Zeroize the secret immediately since this API only exposes the public key.
    let mut sk_copy = sk;
    zeroize::Zeroize::zeroize(&mut sk_copy);
    let hex = crate::encode_key(&pk);
    match CString::new(hex) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Query the balance of an address given its hex-encoded 32-byte public key.
/// Returns the cell count or zero when the input is malformed.
#[no_mangle]
pub extern "C" fn slash_get_balance(hex_public: *const c_char) -> c_ulonglong {
    if hex_public.is_null() {
        return 0;
    }
    let c_str = unsafe { CStr::from_ptr(hex_public) };
    let hex = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let addr = match crate::decode_key(hex) {
        Ok(a) => a,
        Err(_) => return 0,
    };
    let chain = crate::load();
    chain.state.balance(addr)
}

/// Sign a 32-byte transaction hash with the provided Ed25519 secret key.
/// `hex_secret` is the 64-character hex encoding of the 32-byte secret key.
/// `hex_payload` is the 64-character hex encoding of the 32-byte blake3 hash.
/// The caller must call `slash_free_string` to release the returned pointer.
#[no_mangle]
pub extern "C" fn slash_sign_transaction(
    hex_secret: *const c_char,
    hex_payload: *const c_char,
) -> *mut c_char {
    if hex_secret.is_null() || hex_payload.is_null() {
        return std::ptr::null_mut();
    }
    let secret_str = match unsafe { CStr::from_ptr(hex_secret) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let payload_str = match unsafe { CStr::from_ptr(hex_payload) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let secret = match crate::decode_key(secret_str) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let payload = match crate::decode_key(payload_str) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    let sig = crate::crypto::sign(&secret, &payload);
    let hex_sig = hex::encode(&sig);
    match CString::new(hex_sig) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Verify a page proof against a claimed Merkle root.
/// `hex_root` is the 64-character hex encoding of the 32-byte expected root.
/// `hex_leaf_hash` is the 64-character hex encoding of the 32-byte leaf hash.
/// `siblings_json` is a JSON array of 64-character hex strings.
/// Returns 1 when the proof is valid and 0 otherwise.
#[no_mangle]
pub extern "C" fn slash_verify_page_proof(
    hex_root: *const c_char,
    hex_leaf_hash: *const c_char,
    leaf_index: c_ulonglong,
    siblings_json: *const c_char,
) -> c_int {
    if hex_root.is_null() || hex_leaf_hash.is_null() || siblings_json.is_null() {
        return 0;
    }
    let root = match decode_hex_ptr(hex_root) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let leaf_hash = match decode_hex_ptr(hex_leaf_hash) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let siblings_str = match unsafe { CStr::from_ptr(siblings_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let siblings_vec: Vec<String> = match serde_json::from_str(siblings_str) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let mut siblings = Vec::new();
    for s in siblings_vec {
        match crate::decode_key(&s) {
            Ok(h) => siblings.push(h),
            Err(_) => return 0,
        }
    }

    let proof = crate::state::PageProof {
        leaf_hash,
        siblings,
        leaf_index: leaf_index as usize,
    };

    if crate::state::verify_page_proof(&root, &proof) {
        1
    } else {
        0
    }
}

/// Free a string previously returned by any `slash_*` function.
/// Passing a null pointer is a no-op.
#[no_mangle]
pub extern "C" fn slash_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Helper to decode a hex string passed from C into a fixed 32-byte array.
fn decode_hex_ptr(ptr: *const c_char) -> anyhow::Result<[u8; 32]> {
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let hex = c_str.to_str()?;
    crate::decode_key(hex)
}
