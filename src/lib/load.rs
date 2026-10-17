//! The startup recovery path: manifest load with domain gates, snapshot
//! fallback, journal replay, and the bounded state-history rebuild. Every
//! entry point funnels into [`load_pruned`], which never operates on
//! fabricated history: when no exact anchor exists for the reorg window
//! the history stays empty and reorgs fail closed.

use crate::{active_chain_id, chain, state, storage};

/// Enforce that on-disk chain data belongs to the replay domain the node
/// was started for. The persisted identifier is authoritative: a node
/// started with the wrong network flag must refuse to operate on the data
/// instead of silently reinterpreting every signature hash under the other
/// domain, which would otherwise open a cross-network replay path.
/// An empty persisted identifier marks legacy data written before the
/// field existed; such data is adopted under the active mode.
fn enforce_chain_id(persisted: &[u8], active: &[u8]) {
    if !persisted.is_empty() && persisted != active {
        panic!(
            "[load] chain data belongs to '{}' but the node was started for '{}'; \
             refusing to cross replay domains",
            String::from_utf8_lossy(persisted),
            String::from_utf8_lossy(active)
        );
    }
}

/// Validate a restored version-bit deployment table before it drives
/// consensus. The table comes from local on-disk metadata; an entry whose
/// bit position leaves the 32-bit version field would make the
/// signal-count shift overflow — a panic in debug builds and a silently
/// masked shift amount in release builds — and an entry whose threshold
/// exceeds the retarget window can never accumulate the required signal
/// count inside one window, so either defect means the metadata is
/// corrupt. The node refuses to operate on a corrupt table rather than
/// reinterpret the activation schedule.
fn enforce_deployment_table(deployments: &[chain::Deployment]) {
    for d in deployments {
        if d.bit >= 32 || d.threshold as u64 > chain::DIFFICULTY_ADJUSTMENT_INTERVAL {
            panic!(
                "[load] corrupt deployment table: entry '{}' has bit {} / threshold {}; \
                 refusing to load",
                d.name, d.bit, d.threshold
            );
        }
    }
}

/// Replay the crash-recovery journal into a freshly loaded chain. Every
/// record was fully validated before it was written, so replay skips the
/// header checks (including the RandomX proof) and relies on the linkage
/// and state checks in apply_recovered: stale or torn records fail the
/// height/prev linkage, and corrupted payloads fail the state transition
/// or the page-root verification. The committed tip is reconstructed
/// exactly without a per-block proof-of-work pass during startup.
fn recover(mut chain: chain::Chain) -> chain::Chain {
    for b in storage::journal_load() {
        let _ = chain.apply_recovered(b);
    }
    let tip_len = chain.blocks.len() as u64;
    let tip = tip_len.saturating_add(chain.base_height).saturating_sub(1);
    chain.state.prune_locks(tip);
    chain
}

/// Rebuild the state history on a freshly loaded chain. The manifest
/// persists only the tip state, so the reorg machinery would otherwise have
/// no historical states to restore. An exact anchor is required: the genesis
/// state for a short chain, the snapshot taken exactly before the first
/// stored block of a pruned chain, or the newest snapshot at or below the
/// reorg window of a long chain.
///
/// The replay is always bounded by HISTORY_REBUILD_MAX_REPLAY so recovery
/// time stays proportional to the snapshot spacing instead of the full
/// chain length. When no exact anchor exists within the bound the history is
/// deliberately left empty, which makes every reorg attempt fail closed with
/// BlockError::CannotReorgBeyondHistory instead of rolling back to a
/// fabricated state that would corrupt balances.
fn restore_history(chain: &mut chain::Chain) {
    let tip = (chain.blocks.len() as u64)
        .saturating_add(chain.base_height)
        .saturating_sub(1);
    let anchor = if chain.base_height == 0 && tip <= chain::HISTORY_REBUILD_MAX_REPLAY {
        // Short full chain: replaying from genesis stays inside the bound.
        Some((state::State::genesis(), 0u64))
    } else if chain.base_height > 0 {
        // The state right after block base_height - 1 is the only valid
        // replay start for the stored block window; the window never
        // exceeds the replay bound by construction. Snapshot records are
        // stored as (height, state), while rebuild_state_history consumes
        // (state, height), so the tuple is reordered here.
        let want = chain.base_height - 1;
        storage::load_latest_snapshot(want).ok().and_then(|(h, s)| {
            if h == want {
                Some((s, h))
            } else {
                None
            }
        })
    } else {
        // Long full chain: the newest snapshot at or below the reorg
        // window is the only anchor cheap enough to replay from.
        storage::load_latest_snapshot(tip.saturating_sub(chain::MAX_REORG_DEPTH))
            .ok()
            .map(|(h, s)| (s, h))
    };
    if let Some((anchor_state, anchor_height)) = anchor {
        if chain
            .rebuild_state_history(anchor_state, anchor_height)
            .is_err()
        {
            // A replay failure indicates on-disk corruption of the block
            // list or the state. Without a trustworthy history every reorg
            // must be rejected, so the partial result is discarded.
            chain.state_history.clear();
        }
    }
    // With no anchor available the history stays empty by design: reorgs
    // are refused until enough new blocks extend the window.
}

/// Load chain, recovering from snapshot when live state files are damaged.
/// First attempts a manifest-based load; if that fails, uses the latest
/// snapshot and replays any blocks that exist after the snapshot height.
///
/// Governance state (checkpoints, version-bit deployments) is always restored
/// from the persisted metadata, and the state history is either rebuilt from
/// an exact anchor or left empty so that reorgs fail closed. The persisted
/// chain identifier is authoritative: a node started with the wrong network
/// flag refuses to operate on the data instead of silently switching replay
/// domains. The node never operates on fabricated history after a restart.
pub fn load_pruned() -> chain::Chain {
    // Attempt a manifest-based load first for crash consistency.
    if let Ok((blocks, state, meta)) = storage::load_from_manifest_full() {
        let active = active_chain_id();
        enforce_chain_id(&meta.chain_id, &active);
        // The deployment table drives the signal-count shifts and the
        // window thresholds of every future block; load it only after
        // the structural gate above has certified it.
        enforce_deployment_table(&meta.deployments);
        let mut chain = chain::Chain {
            blocks,
            base_height: meta.base_height,
            state,
            // History is rebuilt from an exact anchor below; it starts
            // empty so a failed rebuild can never leave fabricated
            // entries behind.
            state_history: std::collections::HashMap::new(),
            deployments_history: std::collections::HashMap::new(),
            checkpoints: meta.checkpoints,
            version_bits: chain::VersionBits {
                deployments: meta.deployments,
            },
            chain_id: if meta.chain_id.is_empty() {
                String::from_utf8_lossy(&active).into_owned()
            } else {
                // The persisted identifier is stored as raw bytes; the
                // in-memory chain carries it as an owned string.
                String::from_utf8_lossy(&meta.chain_id).into_owned()
            },
            // The testnet flag mirrors the process-wide network selector
            // so the rebuilt chain signs and validates against the same
            // chain identifier the rest of the node uses.
            testnet: crate::TESTNET_MODE.load(Ordering::Relaxed),
            orphan_blocks: std::collections::HashMap::new(),
            side_forks: std::collections::HashMap::new(),
            reorg_disconnected: Vec::new(),
        };
        restore_history(&mut chain);
        return recover(chain);
    }

    // Normal load failed: recover from the most recent snapshot.
    let (snap_height, state) =
        storage::load_latest_snapshot(u64::MAX).unwrap_or_else(|_| (0, state::State::genesis()));
    let active = active_chain_id();
    let mut chain = chain::Chain {
        blocks: Vec::new(),
        base_height: snap_height,
        state,
        state_history: std::collections::HashMap::new(),
        deployments_history: std::collections::HashMap::new(),
        checkpoints: std::collections::BTreeMap::new(),
        version_bits: chain::VersionBits {
            // The snapshot carries no governance state: the deployment
            // list starts empty and re-learns activations from new blocks.
            deployments: Vec::new(),
        },
        chain_id: String::from_utf8_lossy(&active).into_owned(),
        // The testnet flag mirrors the process-wide network selector
        // so the rebuilt chain signs and validates against the same
        // chain identifier the rest of the node uses.
        testnet: crate::TESTNET_MODE.load(Ordering::Relaxed),
        orphan_blocks: std::collections::HashMap::new(),
        side_forks: std::collections::HashMap::new(),
        reorg_disconnected: Vec::new(),
    };

    // Replay any blocks stored after the snapshot height. These are local
    // records written by this node (the live list was damaged, not the
    // blocks), so they replay through the recovered path: the cheap
    // height/prev linkage check plus the full state transition with page
    // roots. Re-running complete network validation (including RandomX
    // proofs and checkpoint logic aimed at untrusted peers) would add
    // startup cost without adding security on top of the trust already
    // placed in local records, exactly as the journal replay does.
    if let Ok(all_blocks) = storage::load_blocks() {
        for b in all_blocks {
            if b.height > snap_height {
                let _ = chain.apply_recovered(b);
            }
        }
    }
    // Restore the governance metadata saved alongside the blocks so that
    // checkpoints and soft-fork gates survive the recovery path as well, and
    // enforce that the data belongs to the replay domain of this node. The
    // identifier is cloned into the chain above so the enforcement check can
    // still borrow it here. The deployment table is structurally validated
    // before it drives the signal-count shifts of the replayed chain.
    if let Ok(meta) = storage::load_chain_meta_full() {
        enforce_chain_id(&meta.chain_id, &active);
        enforce_deployment_table(&meta.deployments);
        chain.checkpoints = meta.checkpoints;
        chain.version_bits.deployments = meta.deployments;
    }
    recover(chain)
}

use std::sync::atomic::Ordering;
