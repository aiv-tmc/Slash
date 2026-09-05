use serde::{Serialize, Deserialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write;

/// On-disk header: lists dirty pages plus auxiliary global state.
#[derive(Serialize, Deserialize)]
struct Header {
    page_ids: Vec<u16>,
    locks: BTreeMap<u64, u64>,
    balance_cache: HashMap<[u8; 32], u64>,
}

/// On-disk chain metadata: stores the current base height for pruned chains.
#[derive(Serialize, Deserialize)]
struct ChainMeta {
    base_height: u64,
}

/// Write data to a temporary file, fsync it to disk, then rename it to the target path.
/// This guarantees that readers always see either the old file or the complete new file,
/// never a partially-written or corrupt file, even if the process crashes.
pub fn atomic_write(path: &str, data: &[u8]) -> anyhow::Result<()> {
    let tmp = format!("{}.tmp", path);
    let mut file = File::create(&tmp)?;
    file.write_all(data)?;
    // Force the operating system to flush file data to the physical storage medium.
    file.sync_all()?;
    drop(file);
    // Atomic rename makes the new data visible to all readers instantly.
    std::fs::rename(&tmp, path)?;
    // Sync the parent directory so the rename itself is durable.
    if let Some(parent) = std::path::Path::new(path).parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Atomically persist a State to header.bin + pages/*.bin.
/// Uses write-to-temp + fsync + rename so an interrupted write never leaves a corrupt file.
pub fn save(state: &crate::state::State) -> anyhow::Result<()> {
    std::fs::create_dir_all("pages")?;
    for (page_id, page) in &state.pages {
        let path = format!("pages/{:04x}.bin", page_id);
        let encoded = bincode::serialize(page)?;
        atomic_write(&path, &encoded)?;
    }
    let header = Header {
        page_ids: state.pages.keys().cloned().collect(),
        locks: state.locks.clone(),
        balance_cache: state.balance_cache.clone(),
    };
    atomic_write("header.bin", &bincode::serialize(&header)?)?;
    Ok(())
}

/// Load a State from disk. Returns an error if any expected file is missing or corrupt.
pub fn load() -> anyhow::Result<crate::state::State> {
    let header_bytes = std::fs::read("header.bin")?;
    let header: Header = bincode::deserialize(&header_bytes)?;
    let mut pages = BTreeMap::new();
    for page_id in &header.page_ids {
        let path = format!("pages/{:04x}.bin", page_id);
        let bytes = std::fs::read(&path)?;
        let page: crate::state::Page = bincode::deserialize(&bytes)?;
        pages.insert(*page_id, page);
    }
    Ok(crate::state::State {
        pages,
        locks: header.locks,
        balance_cache: header.balance_cache,
    })
}

/// Atomically persist a block list to chain_blocks.bin.
/// Uses the same temp-write + rename strategy for crash safety.
pub fn save_blocks(blocks: &[crate::chain::Block]) -> anyhow::Result<()> {
    let encoded = bincode::serialize(blocks)?;
    atomic_write("chain_blocks.bin", &encoded)
}

/// Load a block list from chain_blocks.bin.
pub fn load_blocks() -> anyhow::Result<Vec<crate::chain::Block>> {
    let bytes = std::fs::read("chain_blocks.bin")?;
    Ok(bincode::deserialize(&bytes)?)
}

/// Save the current base height so that pruned nodes know where their block window starts.
pub fn save_chain_meta(base_height: u64) -> anyhow::Result<()> {
    let meta = ChainMeta { base_height };
    atomic_write("chain_meta.bin", &bincode::serialize(&meta)?)
}

/// Load the stored base height. Returns zero if no metadata file exists yet.
pub fn load_chain_meta() -> anyhow::Result<u64> {
    let bytes = std::fs::read("chain_meta.bin")?;
    let meta: ChainMeta = bincode::deserialize(&bytes)?;
    Ok(meta.base_height)
}

/// Save a full state snapshot at a specific block height.
/// Snapshots allow pruned nodes to recover state without replaying from genesis.
pub fn save_snapshot(state: &crate::state::State, height: u64) -> anyhow::Result<()> {
    std::fs::create_dir_all("snapshots")?;
    let path = format!("snapshots/state_{}.bin", height);
    let encoded = bincode::serialize(state)?;
    atomic_write(&path, &encoded)?;
    Ok(())
}

/// Load the most recent snapshot with height less than or equal to max_height.
/// Returns the snapshot height and the reconstructed state.
pub fn load_latest_snapshot(max_height: u64) -> anyhow::Result<(u64, crate::state::State)> {
    let mut best: Option<(u64, crate::state::State)> = None;
    if let Ok(entries) = std::fs::read_dir("snapshots") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(num) = name.strip_prefix("state_").and_then(|s| s.strip_suffix(".bin")) {
                if let Ok(h) = num.parse::<u64>() {
                    if h <= max_height {
                        if best.as_ref().map_or(true, |(bh, _)| h > *bh) {
                            let bytes = std::fs::read(entry.path())?;
                            let state: crate::state::State = bincode::deserialize(&bytes)?;
                            best = Some((h, state));
                        }
                    }
                }
            }
        }
    }
    best.ok_or_else(|| anyhow::anyhow!("no snapshot found up to height {}", max_height))
}

/// Retain only the three most recent snapshots and delete all older ones.
/// This prevents unbounded growth of the snapshots directory.
pub fn prune_snapshots() -> anyhow::Result<()> {
    let mut snapshots: Vec<(u64, std::path::PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("snapshots") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(num) = name.strip_prefix("state_").and_then(|s| s.strip_suffix(".bin")) {
                if let Ok(h) = num.parse::<u64>() {
                    snapshots.push((h, entry.path()));
                }
            }
        }
    }
    snapshots.sort_by_key(|(h, _)| *h);
    if snapshots.len() > 3 {
        for (_, path) in &snapshots[..snapshots.len() - 3] {
            let _ = std::fs::remove_file(path);
        }
    }
    Ok(())
}
