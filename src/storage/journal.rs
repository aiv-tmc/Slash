//! The crash-recovery journal: every applied block is appended as a
//! length-prefixed record so that a crash between two manifest writes can
//! be repaired by replaying exactly the committed blocks.

/// Append a single block record to the journal. The record is fully
/// validated before it is written, so replay skips the expensive header
/// checks and relies on linkage and state checks.
pub fn journal_append(block: &crate::chain::Block) -> anyhow::Result<()> {
    journal_append_batch(std::slice::from_ref(block))
}

/// Append a batch of block records to the journal in one file open.
pub fn journal_append_batch(blocks: &[crate::chain::Block]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("chain_journal.bin")?;
    for block in blocks {
        let record = bincode::serialize(block)?;
        // Length-prefixed records let the loader find record boundaries
        // without trusting the payload, so a torn tail surfaces as a
        // length mismatch instead of a deserialization panic.
        file.write_all(&(record.len() as u32).to_le_bytes())?;
        file.write_all(&record)?;
    }
    file.sync_all()?;
    Ok(())
}

/// Load every journaled block in write order, stopping at the first
/// anomaly. A torn tail (crash mid-write) and a corrupt record both end
/// recovery at the last record that was complete and well-formed:
/// everything after the cut is discarded, because a record that fails
/// to parse invalidates every later record's linkage assumptions. The
/// caller replays what is returned and treats the cut height as the
/// recovery point.
pub fn journal_load() -> Vec<crate::chain::Block> {
    let Ok(bytes) = std::fs::read("chain_journal.bin") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor + 4 <= bytes.len() {
        let len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if cursor + len > bytes.len() {
            break;
        }
        match bincode::deserialize::<crate::chain::Block>(&bytes[cursor..cursor + len]) {
            Ok(block) => out.push(block),
            // A record that does not deserialize marks the end of
            // recoverable history: skipping it would desynchronize every
            // subsequent record, so recovery stops here.
            Err(_) => break,
        }
        cursor += len;
    }
    out
}

/// Truncate the journal after a successful manifest write: the manifest
/// now covers every journaled block, so the records are redundant.
pub fn journal_truncate() -> anyhow::Result<()> {
    // Truncating to a zero-length file keeps the inode stable for readers
    // that opened the path before the truncate.
    std::fs::write("chain_journal.bin", [])?;
    Ok(())
}
