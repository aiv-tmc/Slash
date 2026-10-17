use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_ulonglong};

/// Select the data directory that every subsequent `slash_*` call operates on.
/// The library addresses all on-chain files (`manifest.bin`, page files,
/// block storage) through relative paths, so anchoring the process working
/// directory to the chosen directory makes the whole API datadir-aware
/// without threading a path through every entry point. The embedding
/// application must call this function exactly once, before any other
/// `slash_*` function and from a moment when no other thread touches the
/// library, because the process working directory is shared state.
/// Returns 0 on success and -1 when the pointer is null, the path is not
/// valid UTF-8, the directory does not exist, or the directory switch fails.
///
/// # Safety
/// `datadir` must be a valid, NUL-terminated C string for the duration of
/// the call.
#[no_mangle]
pub unsafe extern "C" fn slash_init(datadir: *const c_char) -> c_int {
    if datadir.is_null() {
        return -1;
    }
    let text = match unsafe { CStr::from_ptr(datadir) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let path = std::path::Path::new(text);
    if !path.is_dir() {
        return -1;
    }
    match std::env::set_current_dir(path) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Generate a new Ed25519 keypair and return the hex-encoded public key.
/// The caller must call `slash_free_string` to release the returned pointer.
/// The secret key is discarded after generation; use the wallet API for persistent keys.
#[no_mangle]
pub extern "C" fn slash_generate_keypair() -> *mut c_char {
    let (sk, pk) = crate::crypto::generate_keypair();
    // Zeroize the secret immediately since this API only exposes the public key.
    let mut sk_copy = sk;
    zeroize::Zeroize::zeroize(&mut sk_copy);
    let hex_pk = hex::encode(pk);
    match CString::new(hex_pk) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Return the cell balance of the 64-character hex-encoded address.
/// Returns 0 when the pointer is null, the text is not valid UTF-8 or hex,
/// or the address is unknown.
///
/// # Safety
/// `hex_public` must be a valid, NUL-terminated C string for the duration
/// of the call.
#[no_mangle]
pub unsafe extern "C" fn slash_get_balance(hex_public: *const c_char) -> c_ulonglong {
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
    let chain = crate::cached_load();
    chain.state.balance(addr)
}

/// Sign a 32-byte transaction hash with the provided Ed25519 secret key.
/// `hex_secret` is the 64-character hex encoding of the 32-byte secret key.
/// `hex_payload` is the 64-character hex encoding of the 32-byte blake3 hash.
/// The caller must call `slash_free_string` to release the returned pointer.
///
/// # Safety
/// `hex_secret` and `hex_payload` must be valid, NUL-terminated C strings
/// for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn slash_sign_transaction(
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

    let mut secret = match crate::decode_key(secret_str) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let payload = match crate::decode_key(payload_str) {
        Ok(p) => p,
        Err(_) => {
            zeroize::Zeroize::zeroize(&mut secret);
            return std::ptr::null_mut();
        }
    };

    let sig = crate::crypto::sign(&secret, &payload);
    // The secret is only needed for the signature itself; clear it before
    // returning so no copy survives on the stack beyond this call.
    zeroize::Zeroize::zeroize(&mut secret);
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
///
/// # Safety
/// `hex_root`, `hex_leaf_hash`, and `siblings_json` must be valid,
/// NUL-terminated C strings for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn slash_verify_page_proof(
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
///
/// # Safety
/// `s` must be either NULL or a pointer previously returned by
/// `slash_generate_keypair` or `slash_sign_transaction` and not yet
/// freed; after this call the pointer must not be used again.
#[no_mangle]
pub unsafe extern "C" fn slash_free_string(s: *mut c_char) {
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
