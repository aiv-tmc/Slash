//! Governance types and constants: the DAO timing and quorum parameters,
//! the executable payload variants, the proposal lifecycle and record,
//! and the memo-carried operations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Minimum lock duration, in blocks, that a cell must carry for its owner
/// to accrue voting weight. Locks shorter than this horizon are treated as
/// operational (staking, escrow) rather than governance commitments.
pub const DAO_LOCK_MIN: u64 = 10_000;

/// Quorum expressed in basis points of the total locked supply. A proposal
/// that does not attract at least this share of the total possible weight
/// cannot pass, regardless of the yes/no split.
pub const DAO_QUORUM_BPS: u64 = 500;

/// Approval threshold in basis points of the weight that actually voted.
/// Passing requires strictly more yes weight than this value allows to be
/// no weight, which implements a simple majority of 50 percent plus one.
pub const DAO_THRESHOLD_BPS: u64 = 5000;

/// Length of the voting period in blocks. A proposal submitted at height H
/// accepts votes from height H until height H + DAO_VOTING_PERIOD.
pub const DAO_VOTING_PERIOD: u64 = 4032;

/// Delay between the end of voting and executable height. Passed proposals
/// sit in a public queue for this many blocks so that voters can observe
/// the outcome and, if necessary, migrate funds before any state change.
pub const DAO_EXEC_DELAY: u64 = 1008;

/// Maximum number of concurrently open proposals. The bound keeps the
/// per-block tally walk cheap and prevents proposal-spam from growing the
/// consensus state without limit.
pub const DAO_MAX_PROPOSALS: usize = 64;

/// A typed, executable decision. Every variant names the exact state
/// transition the DAO is authorized to perform; consensus executes the
/// payload verbatim, so the payload itself is the single source of truth
/// for what a passed proposal does.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DaoPayload {
    /// Mint treasury cells to a recipient. Executed through the canonical
    /// treasury selection so every node reproduces the identical input
    /// ranges and page roots.
    TreasuryMint { amount: u64, to: [u8; 32] },
    /// Pay a recipient out of the treasury vault. Fails at execution time
    /// if the vault balance cannot cover the amount.
    TreasuryPayout { amount: u64, to: [u8; 32] },
    /// Replace the public key that authorizes spending from the dev fund.
    /// Rotation takes effect at the executable height.
    RotateDevFundSigner { public: [u8; 32] },
    /// Replace the treasury signer key. Used for planned key rotation and
    /// as the recovery path for a compromised signer.
    RotateTreasurySigner { public: [u8; 32] },
    /// Set the dev fee on user transfers, in basis points of total output.
    /// A value of zero disables the transfer-level dev fee.
    SetDevFee { bps: u64 },
    /// Set the dev fee on the coinbase subsidy, in basis points of the
    /// subsidy. A value of zero disables the mining-level dev fee.
    SetMineFee { bps: u64 },
}

/// Lifecycle of a governance proposal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Open for votes.
    Voting,
    /// Voting ended with quorum and majority yes; waiting for the
    /// executable height.
    Passed,
    /// The payload transition was applied to state.
    Executed,
    /// Voting ended without quorum or without a majority.
    Rejected,
    /// The proposal was superseded or its payload became unexecutable
    /// before the executable height.
    Expired,
}

/// A single governance proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    /// Monotonic identifier, unique across the lifetime of the chain.
    pub id: u64,
    /// The decision this proposal carries.
    pub payload: DaoPayload,
    /// First height at which votes are accepted.
    pub start_height: u64,
    /// First height at which votes are no longer accepted.
    pub end_height: u64,
    /// Cached weight snapshot height. Voting weight is evaluated at this
    /// height, so weight earned or lost inside the voting window cannot
    /// influence the outcome.
    pub snapshot_height: u64,
    /// Accumulated yes weight.
    pub yes_weight: u64,
    /// Accumulated no weight.
    pub no_weight: u64,
    /// Addresses that already voted on this proposal. One address casts at
    /// most one vote; the first vote is recorded and later votes from the
    /// same address are rejected.
    pub voters: BTreeSet<[u8; 32]>,
    /// Current lifecycle state.
    pub status: ProposalStatus,
    /// Height at which a passed proposal becomes executable.
    pub exec_height: u64,
}

/// A governance operation carried by a transaction memo. The memo bytes
/// commit into the transaction signature hash, so a signed transaction
/// cannot be repurposed as a governance operation after signing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DaoOp {
    /// Open a new proposal with the given payload.
    SubmitProposal { payload: DaoPayload },
    /// Cast one vote on an existing proposal.
    Vote { proposal_id: u64, approve: bool },
}
