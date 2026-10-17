use crate::chain::{Deployment, DeploymentStatus};
use serde::{Deserialize, Serialize};

/// A single consensus rule that can be activated through a soft fork.
/// Each variant represents a concrete change to block or transaction validation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Rule {
    /// Require a minimum total output value per transaction.
    MinTxAmount { min: u64 },
    /// Restrict the maximum serialized block size to a lower value than the
    /// hard-coded protocol limit.
    MaxBlockSize { max_bytes: usize },
    /// Permit transactions that use signature scheme identifier 1 in addition
    /// to the default scheme 0. This serves as a migration path for future
    /// post-quantum signature algorithms.
    AllowScheme1,
    /// Require that every block uses version 2 or higher.
    RequireBlockVersion2,
    /// Require every user transaction to carry a dev-fund output of at
    /// least the configured basis points of the total output, and require
    /// the coinbase to carry its configured share to the dev fund when the
    /// subsidy is positive.
    DevFund,
    /// Enable the DAO governance layer: transactions may carry governance
    /// operations in their memo field, and passed proposals execute at
    /// their scheduled height.
    DaoV1,
}

/// Compute the set of rules that are active at the given block height based
/// on the deployments tracked by the version bits state.
/// A rule becomes active once its corresponding deployment reaches the
/// Active status and the current height is greater than or equal to the
/// activation height recorded in the deployment.
pub fn active_rules(deployments: &[Deployment], height: u64) -> Vec<Rule> {
    let mut rules = Vec::new();
    for d in deployments {
        if let Some(act) = d.activation_height {
            if height >= act && d.status == DeploymentStatus::Active {
                rules.extend(rules_for_deployment(d));
            }
        }
    }
    rules
}

/// Deployment names reserved for future soft forks. Registering the names in
/// one visible list documents upgrade intent and keeps external tooling from
/// squatting the corresponding version bits. "treasury_key_rotation" is the
/// vehicle for rotating the treasury signer key, and it shares its effect
/// with the DAO rotation payload once both paths are live.
pub const RESERVED_DEPLOYMENTS: &[&str] = &["treasury_key_rotation"];

/// Map a deployment name to the concrete rules it activates.
/// This is the central registry of all known soft-fork upgrades.
fn rules_for_deployment(d: &Deployment) -> Vec<Rule> {
    match d.name.as_str() {
        "min_tx_v2" => vec![Rule::MinTxAmount { min: 100 }],
        "smaller_blocks" => vec![Rule::MaxBlockSize { max_bytes: 524_288 }],
        "scheme1_ready" => vec![Rule::AllowScheme1],
        "require_v2" => vec![Rule::RequireBlockVersion2],
        "dev_fund" => vec![Rule::DevFund],
        "dao_v1" => vec![Rule::DaoV1],
        _ => Vec::new(),
    }
}

/// Validate a block against all active soft-fork rules.
/// Returns true only when every active rule is satisfied.
pub fn validate_block_rules(block: &crate::chain::Block, rules: &[Rule]) -> bool {
    for rule in rules {
        match rule {
            Rule::MaxBlockSize { max_bytes } => {
                // Measure the block's wire size using bincode, which is the same
                // format used for all on-disk and P2P serialization. This
                // guarantees that the size limit is checked against the actual
                // bytes that would be transmitted or stored.
                let size = bincode::serialize(block).map_or(usize::MAX, |v| v.len());
                if size > *max_bytes {
                    return false;
                }
            }
            Rule::RequireBlockVersion2 if block.version < 2 => {
                return false;
            }
            _ => {}
        }
    }
    true
}

/// Validate a single transaction against all active soft-fork rules.
/// The scheme gate depends on whether the scheme-1 deployment is active:
/// only scheme 0 exists before activation, and schemes 0 and 1 are both
/// accepted afterwards, with no other identifier defined. The minimum
/// amount rule bounds the total output width while active. This function
/// is the single rule implementation shared by mempool admission and
/// block execution.
pub fn validate_tx_rules(tx: &crate::chain::Tx, rules: &[Rule]) -> bool {
    let allow_scheme1 = rules.iter().any(|r| matches!(r, Rule::AllowScheme1));
    if allow_scheme1 {
        if tx.scheme > 1 {
            return false;
        }
    } else if tx.scheme != 0 {
        return false;
    }
    for rule in rules {
        if let Rule::MinTxAmount { min } = rule {
            let total_out: u64 = tx.outputs.iter().map(|o| o.end - o.start).sum();
            if total_out < *min {
                return false;
            }
        }
    }
    true
}
