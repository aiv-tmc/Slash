//! Shared test utilities for the Slash integration test suite.
//! Every test receives its own temporary directory so that on-disk state
//! never leaks between concurrent runs.

use slash::chain::{verify_pow, Block, Chain, Tx};
use slash::state::Output;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

/// Create a unique temporary directory, switch the process working directory
/// into it, and return the path so the caller can clean it up on drop.
pub fn setup_test_dir(test_name: &str) -> PathBuf {
    let pid = std::process::id();
    let tmp = std::env::temp_dir().join(format!("slash_integ_{}_{}", test_name, pid));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    std::env::set_current_dir(&tmp).unwrap();
    tmp
}

/// Execute a closure inside a temporary directory, cleaning up afterwards.
pub fn with_temp_dir<F: FnOnce()>(f: F) {
    let _tmp = setup_test_dir("integration");
    f();
}

/// Reset the global testnet flag to false so tests run against
/// the mainnet genesis and chain identifier by default.
pub fn reset_testnet() {
    slash::TESTNET_MODE.store(false, Ordering::SeqCst);
}

/// Enable testnet mode for tests that require the testnet chain id.
pub fn enable_testnet() {
    slash::TESTNET_MODE.store(true, Ordering::SeqCst);
}

/// Build a valid proof-of-work block that extends the current tip of `chain`.
/// The caller supplies the miner address and an optional list of transactions.
/// The function searches for a nonce that satisfies the current difficulty target
/// and then prepares the block so that its page roots match the expected state.
pub fn mine_next_block(chain: &mut Chain, miner: [u8; 32], txs: Vec<Tx>) -> Block {
    let prev = chain.tip_hash();
    let height = chain.blocks.len() as u64 + chain.base_height;
    let diff = chain.next_difficulty();
    let mut b = Block {
        version: 1,
        prev,
        time: height.saturating_mul(100),
        height,
        nonce: 0,
        miner,
        mined_cell: 0,
        txs,
        fee_claims: vec![],
        difficulty: diff,
        page_roots: BTreeMap::new(),
    };
    loop {
        if let Some(cell) = verify_pow(b.prev, b.time, b.height, b.miner, b.nonce, b.difficulty) {
            b.mined_cell = cell;
            break;
        }
        b.nonce += 1;
    }
    chain.prepare_block(b)
}

/// Build a valid proof-of-work block at a specific height and difficulty
/// without mutating the chain. The caller must later prepare and apply the block.
pub fn mine_valid_block(chain: &Chain, height: u64, miner: [u8; 32], diff: u64) -> Block {
    let prev = chain.tip_hash();
    let mut b = Block {
        version: 1,
        prev,
        time: height.saturating_mul(100),
        height,
        nonce: 0,
        miner,
        mined_cell: 0,
        txs: vec![],
        fee_claims: vec![],
        difficulty: diff,
        page_roots: BTreeMap::new(),
    };
    loop {
        if let Some(cell) = verify_pow(b.prev, b.time, b.height, b.miner, b.nonce, b.difficulty) {
            b.mined_cell = cell;
            break;
        }
        b.nonce += 1;
    }
    b
}

/// Mine an empty block and apply it so that `owner` receives one cell.
/// Returns the global index of the mined cell.
pub fn mine_cell_for(chain: &mut Chain, owner: [u8; 32]) -> u64 {
    let b = mine_next_block(chain, owner, vec![]);
    let cell = b.mined_cell;
    chain.apply(b).unwrap();
    cell
}

/// Create a signed transaction that spends `inputs` and creates `outputs`.
/// The signature covers the chain identifier and scheme byte to enforce
/// replay protection and future scheme migration.
pub fn make_tx(
    from: [u8; 32],
    sk: &[u8; 32],
    inputs: &[(u64, u64)],
    outputs: &[Output],
    chain_id: &[u8],
) -> Tx {
    let hash = slash::chain::tx_signature_hash(&from, inputs, outputs, chain_id, 0);
    let sig = slash::crypto::sign(sk, &hash);
    Tx {
        from,
        inputs: inputs.to_vec(),
        outputs: outputs.to_vec(),
        sig,
        scheme: 0,
    }
}

/// A single entry in an encrypted wallet file.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WalletEntry {
    pub public: String,
    pub secret: String,
}

/// On-disk wrapper for an encrypted wallet payload.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct WalletFile {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Persist an encrypted wallet to disk using Argon2id + AES-256-GCM.
pub fn save_wallets(entries: &[WalletEntry], password: &str) {
    let plaintext = bincode::serialize(entries).unwrap();
    let (salt, nonce, ciphertext) = slash::crypto::encrypt_wallet(&plaintext, password);
    let file = WalletFile {
        salt,
        nonce,
        ciphertext,
    };
    let encoded = bincode::serialize(&file).unwrap();
    slash::storage::atomic_write("wallet.bin", &encoded).unwrap();
}

/// Load and decrypt a wallet from disk.
pub fn load_wallets(password: &str) -> Option<Vec<WalletEntry>> {
    let bytes = std::fs::read("wallet.bin").ok()?;
    let file: WalletFile = bincode::deserialize(&bytes).ok()?;
    let plaintext =
        slash::crypto::decrypt_wallet(&file.salt, &file.nonce, &file.ciphertext, password)?;
    bincode::deserialize(&plaintext).ok()
}

/// Treasury secrets stored in an encrypted file.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TreasurySecretFile {
    pub vrf_secret: String,
    pub signer_secret: String,
    pub onion_secret: String,
}

/// On-disk wrapper for an encrypted treasury payload.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TreasuryFile {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Persist treasury secrets to disk using Argon2id + AES-256-GCM.
pub fn save_treasury_secret(file: &TreasurySecretFile, password: &str) {
    let plaintext = bincode::serialize(file).unwrap();
    let (salt, nonce, ciphertext) = slash::crypto::encrypt_wallet(&plaintext, password);
    let wrapper = TreasuryFile {
        salt,
        nonce,
        ciphertext,
    };
    let encoded = bincode::serialize(&wrapper).unwrap();
    slash::storage::atomic_write("treasury_secret.bin", &encoded).unwrap();
}

/// Load and decrypt treasury secrets from disk.
pub fn load_treasury_secret(password: &str) -> Option<TreasurySecretFile> {
    let bytes = std::fs::read("treasury_secret.bin").ok()?;
    let wrapper: TreasuryFile = bincode::deserialize(&bytes).ok()?;
    let plaintext = slash::crypto::decrypt_wallet(
        &wrapper.salt,
        &wrapper.nonce,
        &wrapper.ciphertext,
        password,
    )?;
    bincode::deserialize(&plaintext).ok()
}
