//! The version-bit deployment lifecycle: per-window signal counting,
//! threshold evaluation at window ends, and deferred activation.
//!
//! Every deployment tracks a BIP-9-style lifecycle
//! (Defined → Started → LockedIn → Active, or Failed) driven by the
//! version bits of the blocks inside each retarget window.

use super::chain::Chain;
use super::params::DIFFICULTY_ADJUSTMENT_INTERVAL;
use super::types::Block;
use super::version_bits::{DeploymentStatus, VersionBits};

impl Chain {
    /// Advance the version-bit deployment tables for a newly applied
    /// block. The commit path calls this exactly once per block so the
    /// table state always matches the height the history records. Public
    /// because the window-semantics suite drives signaling directly
    /// against a constructed chain, block by block.
    pub fn update_version_bits(&mut self, block: &Block) {
        self.version_bits.update(block);
    }
}

impl VersionBits {
    /// Update the deployment table for a newly applied block. A deployment
    /// starts counting signals when the chain reaches its start height,
    /// counts signals per retarget window, and locks in at the end of any
    /// window that reaches the required threshold. The active height is
    /// always one full interval past the window that locked the deployment
    /// in, so every node observes the lock-in and its scheduled activation
    /// before the rules change.
    pub(crate) fn update(&mut self, block: &Block) {
        let height = block.height;
        for d in &mut self.deployments {
            // Activation is evaluated before the timeout guard. Lock-in is
            // a commitment made at window end, so the scheduled activation
            // height is honored even when it falls past the timeout; a
            // deployment that locked in late therefore reaches Active
            // instead of freezing forever between the timeout and its
            // scheduled height.
            if d.status == DeploymentStatus::LockedIn {
                if d.activation_height.is_some_and(|h| height >= h) {
                    d.status = DeploymentStatus::Active;
                }
                continue;
            }
            if height < d.start_height || height >= d.timeout_height {
                continue;
            }
            let signaling = block.version & (1u32 << d.bit) != 0;
            match d.status {
                DeploymentStatus::Defined => {
                    // The block that opens the signaling period belongs to
                    // the first window and counts toward that window's
                    // threshold.
                    d.status = DeploymentStatus::Started;
                    d.signals = u32::from(signaling);
                }
                DeploymentStatus::Started => {
                    d.signals = d.signals.saturating_add(u32::from(signaling));
                    if height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
                        if d.signals >= d.threshold {
                            d.status = DeploymentStatus::LockedIn;
                            d.activation_height =
                                Some(height.saturating_add(DIFFICULTY_ADJUSTMENT_INTERVAL));
                        }
                        d.signals = 0;
                    }
                }
                // LockedIn is handled by the activation guard above and
                // never reaches this match; the arm keeps the match
                // exhaustive. Active and Failed deployments are terminal.
                DeploymentStatus::LockedIn
                | DeploymentStatus::Active
                | DeploymentStatus::Failed => {}
            }
        }
    }
}
