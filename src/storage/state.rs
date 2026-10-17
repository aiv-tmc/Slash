//! The state files themselves: the header index plus one file per dirty
//! page. Saving writes every dirty page and then the header; loading
//! reconstructs the state from the header's page list.

use super::{atomic_write, Header};
use std::collections::BTreeMap;

/// Persist the full state: every dirty page under `pages/`, then the
/// header that indexes them. The header carries both lock maps so the
/// snapshot-pinned governance weight is restored exactly, not rebuilt.
pub fn save(state: &crate::state::State) -> anyhow::Result<()> {
    std::fs::create_dir_all("pages")?;
    // Persist every dirty page before the header references it.
    for (page_id, page) in &state.pages {
        let path = format!("pages/{:04x}.bin", page_id);
        let encoded = bincode::serialize(page)?;
        atomic_write(&path, &encoded)?;
    }
    // Build and write the state header that indexes all persisted pages.
    let header = Header {
        page_ids: state.pages.keys().cloned().collect(),
        locks: state.locks.clone(),
        lock_created: state.lock_created.clone(),
        balance_cache: state.balance_cache.clone(),
        treasury_signer: state.treasury_signer,
        total_sold: state.total_sold,
        total_bought_back: state.total_bought_back,
        dev_fund_signer: state.dev_fund_signer,
        dev_fee_bps: state.dev_fee_bps,
        mine_fee_bps: state.mine_fee_bps,
        dao: state.dao.clone(),
    };
    atomic_write("header.bin", &bincode::serialize(&header)?)?;
    Ok(())
}

/// Load the state from `header.bin` and the page files it lists. Missing
/// or corrupt files are hard errors: a state that cannot be reconstructed
/// must never be silently replaced with a fabricated one.
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
        lock_created: header.lock_created,
        balance_cache: header.balance_cache,
        treasury_signer: header.treasury_signer,
        total_sold: header.total_sold,
        total_bought_back: header.total_bought_back,
        dev_fund_signer: header.dev_fund_signer,
        dev_fee_bps: header.dev_fee_bps,
        mine_fee_bps: header.mine_fee_bps,
        dao: header.dao,
    })
}
