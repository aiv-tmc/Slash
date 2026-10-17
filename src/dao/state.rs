//! The authoritative on-chain DAO state and the proposal lifecycle:
//! submission under the open-proposal cap, first-vote-wins voting,
//! snapshot-pinned tallying, close, and execution.

use super::payload::{execute_payload, payload_valid};
use super::types::{
    DaoOp, DaoPayload, Proposal, ProposalStatus, DAO_MAX_PROPOSALS, DAO_VOTING_PERIOD,
};
use super::weight::{close_outcome, locked_weight, total_locked_weight};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Authoritative on-chain DAO state, persisted as part of the state header.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DaoState {
    /// All proposals ever submitted, keyed by id. Pruned entries retain
    /// their terminal status so historical ids are never reused.
    pub proposals: BTreeMap<u64, Proposal>,
    /// Next proposal id to assign.
    pub next_id: u64,
}

impl DaoState {
    /// Empty DAO state: no proposals and the first id reserved.
    pub fn genesis() -> Self {
        Self {
            proposals: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Count proposals that are currently open for votes.
    pub fn open_count(&self) -> usize {
        self.proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Voting)
            .count()
    }

    /// Submit a proposal. Returns the assigned id, or None when the open
    /// proposal cap is reached or the payload is structurally invalid.
    pub fn submit(&mut self, payload: DaoPayload, height: u64) -> Option<u64> {
        if self.open_count() >= DAO_MAX_PROPOSALS {
            return None;
        }
        if !payload_valid(&payload) {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        let proposal = Proposal {
            id,
            payload,
            start_height: height,
            end_height: height.saturating_add(DAO_VOTING_PERIOD),
            snapshot_height: height,
            yes_weight: 0,
            no_weight: 0,
            voters: BTreeSet::new(),
            status: ProposalStatus::Voting,
            exec_height: 0,
        };
        self.proposals.insert(id, proposal);
        Some(id)
    }

    /// Record a vote. The voter's weight is supplied by the caller, which
    /// evaluates the locked-cell snapshot at the proposal snapshot height.
    /// Returns false when the proposal is not open, the address already
    /// voted, or the weight is zero.
    pub fn vote(
        &mut self,
        proposal_id: u64,
        voter: [u8; 32],
        weight: u64,
        approve: bool,
        height: u64,
    ) -> bool {
        if weight == 0 {
            return false;
        }
        let Some(p) = self.proposals.get_mut(&proposal_id) else {
            return false;
        };
        if p.status != ProposalStatus::Voting {
            return false;
        }
        if height < p.start_height || height >= p.end_height {
            return false;
        }
        if !p.voters.insert(voter) {
            return false;
        }
        if approve {
            p.yes_weight = p.yes_weight.saturating_add(weight);
        } else {
            p.no_weight = p.no_weight.saturating_add(weight);
        }
        true
    }

    /// Advance every open proposal whose voting window has ended against a
    /// single quorum denominator. Kept for callers that know the total
    /// locked weight out of band; the consensus path prefers `tally_at`,
    /// which pins the denominator to each proposal's own snapshot height.
    pub fn tally(&mut self, total_locked_weight: u64, height: u64) {
        for p in self.proposals.values_mut() {
            if p.status != ProposalStatus::Voting || height < p.end_height {
                continue;
            }
            let (status, exec_height) = close_outcome(p, total_locked_weight);
            p.status = status;
            p.exec_height = exec_height;
        }
    }

    /// Advance every open proposal whose voting window has ended, using the
    /// locked supply at each proposal's snapshot height as its quorum
    /// denominator. Snapshot-pinned denominators make the outcome a pure
    /// function of the snapshot state, so a long-running proposal cannot be
    /// swayed by lock movements that happened after voting opened.
    pub fn tally_at(&mut self, state: &crate::state::State, height: u64) {
        let snapshotted: Vec<(u64, u64)> = self
            .proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Voting && height >= p.end_height)
            .map(|p| (p.id, p.snapshot_height))
            .collect();
        for (id, snapshot_height) in snapshotted {
            let total = total_locked_weight(state, snapshot_height);
            let p = self.proposals.get_mut(&id).expect("id collected above");
            let (status, exec_height) = close_outcome(p, total);
            p.status = status;
            p.exec_height = exec_height;
        }
    }

    /// Close every proposal whose voting window has ended at `height` and
    /// schedule the passed ones for execution after the public delay. The
    /// quorum denominator is the locked supply at the proposal snapshot
    /// height, so the outcome is a pure function of the snapshot state
    /// and cannot be influenced by weight movements inside the voting
    /// window. Passed proposals sit in the queue for the execution delay
    /// so voters can observe the outcome before any state change.
    pub fn close_due(&mut self, state: &crate::state::State, height: u64) {
        for proposal in self.proposals.values_mut() {
            if !matches!(proposal.status, ProposalStatus::Voting) {
                continue;
            }
            if height < proposal.end_height {
                continue;
            }
            let total = total_locked_weight(state, proposal.snapshot_height);
            let (status, exec_height) = close_outcome(proposal, total);
            if matches!(status, ProposalStatus::Passed) {
                proposal.exec_height = exec_height;
            }
            proposal.status = status;
        }
    }

    /// Execute every passed proposal that reached its executable height.
    /// Execution is applied against the provided state so mint and payout
    /// transitions flow through the same ownership engine as treasury
    /// pairs; unexecutable payloads expire instead of blocking the queue.
    pub fn execute_due(&mut self, state: &mut crate::state::State, height: u64) {
        let due: Vec<u64> = self
            .proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Passed && height >= p.exec_height)
            .map(|p| p.id)
            .collect();
        for id in due {
            let payload = match self.proposals.get(&id) {
                Some(p) => p.payload.clone(),
                None => continue,
            };
            let ok = execute_payload(state, &payload, height);
            let p = self.proposals.get_mut(&id).expect("id collected above");
            p.status = if ok {
                ProposalStatus::Executed
            } else {
                ProposalStatus::Expired
            };
        }
    }

    /// Apply one governance operation carried by a transaction memo. The
    /// caller has already executed the transfer itself, so a rejected
    /// operation never invalidates the transaction: the transfer stands and
    /// the operation is silently dropped. Voting weight is evaluated at the
    /// target proposal's snapshot height, so votes ride ordinary transfers
    /// and pay the standard fee and dev-fund shares like any other
    /// transaction.
    pub fn apply_op(
        &mut self,
        state: &crate::state::State,
        voter: [u8; 32],
        op: &DaoOp,
        height: u64,
    ) -> bool {
        match op {
            DaoOp::SubmitProposal { payload } => self.submit(payload.clone(), height).is_some(),
            DaoOp::Vote {
                proposal_id,
                approve,
            } => {
                let snapshot = self
                    .proposals
                    .get(proposal_id)
                    .map(|p| p.snapshot_height)
                    .unwrap_or(height);
                let weight = locked_weight(state, voter, snapshot);
                self.vote(*proposal_id, voter, weight, *approve, height)
            }
        }
    }
}

use std::collections::BTreeSet;
