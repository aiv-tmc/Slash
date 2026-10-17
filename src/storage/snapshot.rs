//! Full-state snapshots for pruned recovery: one file per retained
//! height, pruned to the three most recent so the directory cannot grow
//! without bound.

use super::atomic_write;

/// Save a full state snapshot at a specific block height. Snapshots allow
/// pruned nodes to recover state without replaying from genesis.
pub fn save_snapshot(state: &crate::state::State, height: u64) -> anyhow::Result<()> {
    std::fs::create_dir_all("snapshots")?;
    let path = format!("snapshots/state_{}.bin", height);
    let encoded = bincode::serialize(state)?;
    atomic_write(&path, &encoded)?;
    Ok(())
}

/// Load the most recent snapshot with height less than or equal to
/// `max_height`. Candidates are examined newest first: the first file
/// that reads and deserializes cleanly wins, so a torn newest snapshot
/// degrades gracefully to the previous consistent anchor instead of
/// failing the whole load. Only the winning file is ever deserialized.
pub fn load_latest_snapshot(max_height: u64) -> anyhow::Result<(u64, crate::state::State)> {
    let mut candidates: Vec<(u64, std::path::PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("snapshots") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(num) = name
                .strip_prefix("state_")
                .and_then(|s| s.strip_suffix(".bin"))
            {
                if let Ok(h) = num.parse::<u64>() {
                    if h <= max_height {
                        candidates.push((h, entry.path()));
                    }
                }
            }
        }
    }
    // Newest first: a snapshot that fails to read or parse is skipped, so
    // damage to the most recent file falls through to the previous anchor.
    candidates.sort_by_key(|(h, _)| std::cmp::Reverse(*h));
    for (h, path) in candidates {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(state) = bincode::deserialize::<crate::state::State>(&bytes) else {
            continue;
        };
        return Ok((h, state));
    }
    Err(anyhow::anyhow!(
        "no readable snapshot found up to height {}",
        max_height
    ))
}

/// Retain only the three most recent snapshots and delete all older ones.
/// This prevents unbounded growth of the snapshots directory.
pub fn prune_snapshots() -> anyhow::Result<()> {
    let mut snapshots: Vec<(u64, std::path::PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("snapshots") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(num) = name
                .strip_prefix("state_")
                .and_then(|s| s.strip_suffix(".bin"))
            {
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
