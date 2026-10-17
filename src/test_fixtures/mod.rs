//! Shared test fixtures exposed as public library API.
//!
//! Every integration-style test crate and the benchmark suite builds the
//! library with the `test-utils` feature (through the self-referential
//! dev-dependency in `Cargo.toml`) and imports these helpers through one
//! glob. Because the items are public library API, the dead-code lint
//! never fires for the subsets a given crate does not use.
//!
//! Layout:
//! - `blocks` — the nonce search and the block builders
//! - `tx` — the transaction builders and the encrypted-secret helpers
//!
//! Every helper is deterministic: fixed keys, fixed nonces, fixed
//! timestamps, so a failing test can be replayed bit for bit.

mod blocks;
mod tx;

pub use blocks::*;
pub use tx::*;

pub use crate::chain;
pub use crate::crypto;
pub use crate::state;
use std::sync::atomic::Ordering;

/// Test directory guard: creates a unique temporary directory, moves the
/// process working directory into it for the duration of one test, and
/// restores the previous working directory (and removes the temporary
/// tree) when the guard drops. All on-chain file access in the library is
/// relative, so isolating the working directory isolates the data.
pub struct TestDir {
    previous: std::path::PathBuf,
    temp: std::path::PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let previous = std::env::current_dir().expect("current directory");
        let unique = format!(
            "slash-test-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let temp = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp).expect("create test directory");
        std::env::set_current_dir(&temp).expect("enter test directory");
        TestDir { previous, temp }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.previous);
        let _ = std::fs::remove_dir_all(&self.temp);
    }
}

/// Enter an isolated temporary working directory for the current test.
/// The returned guard restores the original directory on drop.
pub fn setup_test_dir(label: &str) -> TestDir {
    TestDir::new(label)
}

/// Reset the process-wide network flag to mainnet so signature hashing
/// uses the mainnet chain identifier.
pub fn reset_testnet() {
    crate::TESTNET_MODE.store(false, Ordering::SeqCst);
}

/// Set the process-wide network flag to testnet so signature hashing uses
/// the testnet chain identifier.
pub fn enable_testnet() {
    crate::TESTNET_MODE.store(true, Ordering::SeqCst);
}

/// Well-known treasury secret used by fixtures. Only ever used inside
/// tests; a node started with this key would mint on the mainnet.
pub const TREASURY_SK: [u8; 32] = [0x5C; 32];

/// Deterministic test keypair: the secret seed is the byte repeated 32
/// times, and the address is the real Ed25519 public key derived from it,
/// so signatures produced by the transaction builders verify through the
/// ordinary consensus path.
pub fn test_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = [seed; 32];
    let pk = crypto::public_from_secret(&sk);
    (sk, pk)
}

/// Build a genesis chain whose treasury signer is the public half of
/// `TREASURY_SK`, so treasury mints and payouts verify without any
/// additional node configuration.
pub fn treasury_genesis() -> chain::Chain {
    let mut chain = chain::Chain::genesis();
    chain.state.treasury_signer = crypto::public_from_secret(&TREASURY_SK);
    chain
}
