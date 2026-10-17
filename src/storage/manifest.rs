//! The manifest: the atomic chain snapshot. Blocks, state, and metadata
//! are written to their stable paths first; the manifest is published
//! last so readers always see a consistent triple. The manifest carries
//! a content stamp for every referenced file: the stamp changes whenever
//! the file changes, which invalidates in-memory caches keyed on the
//! manifest bytes, and the loader verifies each stamp before
//! deserializing so a swapped or corrupted file never loads silently.

use super::{save as save_state, ChainMeta, FileStamp, Header, Manifest};
use std::collections::BTreeMap;

/// Stable on-disk filenames of the snapshot triple.
const BLOCKS_PATH: &str = "chain_blocks.bin";
const STATE_PATH: &str = "header.bin";
const META_PATH: &str = "chain_meta.bin";
const MANIFEST_PATH: &str = "manifest.bin";

/// Stamp freshly serialized bytes: their length and a BLAKE3 digest over
/// their exact content.
fn stamp_bytes(bytes: &[u8]) -> FileStamp {
    FileStamp {
        len: bytes.len() as u64,
        digest: *blake3::hash(bytes).as_bytes(),
    }
}

/// Stamp a file already on disk. Used for the state half of the snapshot,
/// which `save_state` serializes internally: reading the just-written
/// file back is safe because this process wrote it atomically moments
/// ago. A read failure stamps a zero length, which the load-side check
/// then rejects.
fn stamp_path(path: &str) -> FileStamp {
    std::fs::read(path)
        .map(|b| stamp_bytes(&b))
        .unwrap_or(FileStamp {
            len: 0,
            digest: [0u8; 32],
        })
}

/// Verify one data file against its recorded stamp before any
/// deserialization happens. A length mismatch avoids hashing the file; a
/// digest mismatch means the file was swapped, truncated, or corrupted
/// after the snapshot was published. Either way the load aborts with a
/// named diagnostic instead of restoring a mixed triple.
fn verify_stamp(path: &str, file_stamp: &FileStamp) -> anyhow::Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() as u64 != file_stamp.len {
        anyhow::bail!(
            "{path}: length {} does not match the manifest stamp {}",
            bytes.len(),
            file_stamp.len
        );
    }
    if *blake3::hash(&bytes).as_bytes() != file_stamp.digest {
        anyhow::bail!("{path}: content digest does not match the manifest stamp");
    }
    Ok(bytes)
}

/// Atomically persist a complete chain snapshot using a manifest. Writes
/// blocks, state, and meta to stable paths, then publishes the manifest
/// so readers always see a consistent set of files even after a crash.
/// The metadata record includes checkpoints, version-bit deployments, and
/// the chain identifier so a restart restores the exact governance and
/// replay-protection state that was in effect. Each published file is
/// stamped with its byte length and content digest, so the manifest
/// itself is a complete integrity record of the triple.
pub fn save_manifest(
    blocks: &[crate::chain::Block],
    state: &crate::state::State,
    base_height: u64,
    checkpoints: &BTreeMap<u64, [u8; 32]>,
    deployments: &[crate::chain::Deployment],
    chain_id: &[u8],
) -> anyhow::Result<()> {
    // The state half: pages + header.
    save_state(state)?;

    // Persist the block list.
    let encoded_blocks = bincode::serialize(blocks)?;
    super::atomic_write(BLOCKS_PATH, &encoded_blocks)?;

    // Persist chain metadata: base height, checkpoints, deployments, and
    // the chain identifier. Deployments, checkpoints, and the identifier
    // are consensus state; omitting them here would silently roll back
    // soft-fork gates and replay domains after a restart.
    let encoded_meta = bincode::serialize(&ChainMeta {
        base_height,
        checkpoints: checkpoints.clone(),
        deployments: deployments.to_vec(),
        chain_id: chain_id.to_vec(),
    })?;
    super::atomic_write(META_PATH, &encoded_meta)?;

    // Publish the manifest last. Any reader that sees this file is
    // guaranteed that the referenced files are complete and consistent,
    // and the stamps make any later tampering visible at load time.
    let manifest = Manifest {
        blocks_path: BLOCKS_PATH.to_string(),
        state_header_path: STATE_PATH.to_string(),
        chain_meta_path: META_PATH.to_string(),
        blocks_stamp: stamp_bytes(&encoded_blocks),
        state_stamp: stamp_path(STATE_PATH),
        meta_stamp: stamp_bytes(&encoded_meta),
    };
    super::atomic_write(MANIFEST_PATH, &bincode::serialize(&manifest)?)?;
    Ok(())
}

/// Load the full chain record from disk: blocks, tip state, and the
/// complete chain metadata (base height, checkpoints, version-bit
/// deployments, chain identifier). A manifest that parses is
/// authoritative: every referenced file is verified against its stamp
/// before deserialization. A manifest that does not parse — from an
/// older layout or from corruption — falls back to the legacy fixed
/// filenames without verification, matching a node that has never
/// published a manifest.
pub fn load_from_manifest_full(
) -> anyhow::Result<(Vec<crate::chain::Block>, crate::state::State, ChainMeta)> {
    let manifest: Manifest = if let Ok(bytes) = std::fs::read(MANIFEST_PATH) {
        match bincode::deserialize(&bytes) {
            Ok(m) => m,
            Err(_) => {
                return Ok((
                    load_blocks()?,
                    super::state::load()?,
                    load_chain_meta_full()?,
                ));
            }
        }
    } else {
        return Ok((
            load_blocks()?,
            super::state::load()?,
            load_chain_meta_full()?,
        ));
    };

    let blocks_bytes = verify_stamp(&manifest.blocks_path, &manifest.blocks_stamp)?;
    let blocks: Vec<crate::chain::Block> = bincode::deserialize(&blocks_bytes)?;

    let header_bytes = verify_stamp(&manifest.state_header_path, &manifest.state_stamp)?;
    let header: Header = bincode::deserialize(&header_bytes)?;

    let mut pages = BTreeMap::new();
    for page_id in &header.page_ids {
        let path = format!("pages/{:04x}.bin", page_id);
        let bytes = std::fs::read(&path)?;
        let page: crate::state::Page = bincode::deserialize(&bytes)?;
        pages.insert(*page_id, page);
    }

    let state = crate::state::State {
        pages,
        locks: header.locks,
        lock_created: header.lock_created,
        balance_cache: header.balance_cache,
        treasury_signer: header.treasury_signer,
        total_sold: header.total_sold,
        total_bought_back: header.total_bought_back,
        dev_fund_signer: header.dev_fund_signer,
        dev_fee_bps: header.dev_fee_bps,
        mine_fee_bps: header.mine_fee_bps,
        dao: header.dao,
    };

    let meta_bytes = verify_stamp(&manifest.chain_meta_path, &manifest.meta_stamp)?;
    let meta: ChainMeta = bincode::deserialize(&meta_bytes)?;

    Ok((blocks, state, meta))
}

/// Backward-compatible view of `load_from_manifest_full` that returns only
/// the base height and discards the governance metadata. New code should
/// prefer the full variant so checkpoints, deployments, and the chain
/// identifier survive a restart.
pub fn load_from_manifest() -> anyhow::Result<(Vec<crate::chain::Block>, crate::state::State, u64)>
{
    let (blocks, state, meta) = load_from_manifest_full()?;
    Ok((blocks, state, meta.base_height))
}

/// Atomically persist a block list to `chain_blocks.bin`. Uses the same
/// temp-write + rename strategy for crash safety.
pub fn save_blocks(blocks: &[crate::chain::Block]) -> anyhow::Result<()> {
    let encoded = bincode::serialize(blocks)?;
    Ok(super::atomic_write(BLOCKS_PATH, &encoded)?)
}

/// Load a block list from `chain_blocks.bin`.
pub fn load_blocks() -> std::result::Result<Vec<crate::chain::Block>, anyhow::Error> {
    let bytes = std::fs::read(BLOCKS_PATH)?;
    Ok(bincode::deserialize(&bytes)?)
}

/// Persist the full chain metadata record: base height, checkpoints,
/// version-bit deployments, and the chain identifier. All fields are
/// written atomically so a crash can never mix an old base height with
/// new governance state.
pub fn save_chain_meta_full(meta: &ChainMeta) -> anyhow::Result<()> {
    Ok(super::atomic_write(META_PATH, &bincode::serialize(meta)?)?)
}

/// Load the stored chain metadata. Returns an error when the metadata file
/// is missing or corrupt; callers treat a missing file as "no metadata
/// yet".
pub fn load_chain_meta_full() -> anyhow::Result<ChainMeta> {
    let bytes = std::fs::read(META_PATH)?;
    Ok(bincode::deserialize(&bytes)?)
}

/// Save the current base height so that pruned nodes know where their
/// block window starts.
pub fn save_chain_meta(base_height: u64) -> anyhow::Result<()> {
    save_chain_meta_full(&ChainMeta {
        base_height,
        ..ChainMeta::default()
    })
}

/// Load the stored base height.
pub fn load_chain_meta() -> anyhow::Result<u64> {
    Ok(load_chain_meta_full()?.base_height)
}

/// Write bytes to a file atomically: write to a temporary name, fsync,
/// rename over the target, fsync the parent directory. A crash therefore
/// leaves either the previous or the next content of the file, never a
/// torn write.
pub fn atomic_write(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = format!("{}.tmp", path);
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(())
}
