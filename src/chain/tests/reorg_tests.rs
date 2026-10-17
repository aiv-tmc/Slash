//! Reorg tests: the deployment table must roll back with the state when
//! a fork replaces the suffix.

use super::*;
use crate::chain::*;

#[test]
fn reorg_rolls_back_version_bit_activations() {
    // A deployment state reached only on the abandoned suffix must not
    // persist across a reorg: the deployment table is restored from the
    // snapshot recorded at the fork point, and the fork's replay
    // contributes no signals to the restored table. The window is
    // positioned at era 9 so the blocks carry no coinbase.
    //
    // Era 9 does not make a block state-independent. The slot mint still
    // runs on every block and materializes its cell's page, and the
    // page-root commitment binds the full dirty-page map of the exact
    // state the block executed against: a block prepared against one
    // state references pages that any other state never dirties, and
    // validation rejects it. Every fork block must therefore be prepared
    // against the same post-state its parent produced — the state the
    // reorg rewinds to at the fork point and then advances through the
    // ordinary apply path, one block at a time.
    let mut chain = Chain::genesis();
    chain.base_height = 9 * HALVING_INTERVAL - 1;
    let miner = [9u8; 32];
    mine_tip_block(&mut chain, miner);
    let fork_base = mine_tip_block(&mut chain, miner);
    // Snapshot the deployment table as of the fork point.
    let fork_point_status = chain.version_bits.deployments[0].status;
    // Build the competing branch before any suffix exists, while the
    // chain tip is still the fork base. The template's height, parent,
    // and difficulty therefore derive from the fork-base state, and the
    // scratch state below advances through each prepared fork block so
    // every subsequent sibling is prepared against the same post-state
    // the reorg replay reconstructs. Installing the scratch state under
    // the chain during preparation keeps the nonce search's ownership
    // check and the executed transition identical to the replay without
    // committing anything to the main chain.
    let mut fork = Vec::new();
    let mut prev = chain.block_hash(&fork_base);
    let mut scratch = chain.state.clone();
    for h in (fork_base.height + 1)..=(fork_base.height + 2) {
        let mut b = test_block(&chain, miner, 0);
        b.height = h;
        b.prev = prev;
        // Install the parent's post-state so the nonce search checks
        // treasury ownership, and preparation executes, against the
        // state this block meets during the replay.
        let tip_state = std::mem::replace(&mut chain.state, scratch.clone());
        // The nonce search ran against the pre-rewrite header; the
        // fork rewrites height and parent, so the search runs again
        // for the rewritten header before the block is prepared.
        grind(&chain, &mut b);
        b = chain.prepare_block(b);
        chain.state = tip_state;
        // The scratch state advances through the prepared block so the
        // next sibling is prepared against the same post-state the
        // replay derives from applying this block.
        scratch = chain
            .execute_block_state(&scratch, &b)
            .expect("prepared fork block executes against the scratch state");
        prev = chain.block_hash(&b);
        fork.push(b);
    }
    // A suffix block arrives and the deployment locks in on the suffix.
    mine_tip_block(&mut chain, miner);
    chain.version_bits.deployments[0].status = DeploymentStatus::LockedIn;
    assert!(matches!(
        chain.version_bits.deployments[0].status,
        DeploymentStatus::LockedIn
    ));
    chain.reorg_to_fork(&fork).unwrap();
    // The deployment is back to its fork-point state: the suffix's
    // lock-in was discarded with the snapshot, and the replayed fork
    // contributes no signals.
    assert_eq!(chain.version_bits.deployments[0].status, fork_point_status);
}
