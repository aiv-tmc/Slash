//! src/dao/payload.rs — payload structural validation (at submission
//! time) and payload execution (at the executable height). Bounds at
//! submission keep a passed proposal from requesting a transition that
//! would be guaranteed to expire; execution routes treasury movements
//! through the canonical selection so every node reproduces identical
//! ranges.

use super::types::DaoPayload;

/// Structural validation for a payload, evaluated at submission time.
/// Numeric bounds keep a passed proposal from requesting an absurd state
/// transition that would be guaranteed to expire at execution.
pub fn payload_valid(payload: &DaoPayload) -> bool {
    match payload {
        DaoPayload::TreasuryMint { amount, to } => *amount >= crate::state::MIN && *to != [0u8; 32],
        DaoPayload::TreasuryPayout { amount, to } => {
            *amount >= crate::state::MIN && *to != [0u8; 32]
        }
        DaoPayload::RotateDevFundSigner { public } => *public != [0u8; 32],
        DaoPayload::RotateTreasurySigner { public } => *public != [0u8; 32],
        DaoPayload::SetDevFee { bps } => *bps <= 100,
        DaoPayload::SetMineFee { bps } => *bps <= 1000,
    }
}

/// Execute a passed payload against the state. Mint and payout flow through
/// the canonical treasury selection so every node reproduces identical
/// input ranges and page roots; rotations and fee adjustments are direct
/// field writes. Returns false when the transition cannot be applied, in
/// which case the caller marks the proposal expired.
pub fn execute_payload(state: &mut crate::state::State, payload: &DaoPayload, height: u64) -> bool {
    match payload {
        DaoPayload::TreasuryMint { amount, to } => {
            let Some((start, end)) = state.select_single(crate::state::TREASURY, *amount) else {
                return false;
            };
            state.mint(
                &[(start, end)],
                &[crate::state::Output {
                    start,
                    end,
                    to: *to,
                    lock: None,
                }],
                height,
            )
        }
        DaoPayload::TreasuryPayout { amount, to } => {
            let Some((start, end)) = state.select_single(crate::state::TREASURY_VAULT, *amount)
            else {
                return false;
            };
            state.payout(
                &[(start, end)],
                &[crate::state::Output {
                    start,
                    end,
                    to: *to,
                    lock: None,
                }],
                height,
            )
        }
        DaoPayload::RotateDevFundSigner { public } => {
            state.dev_fund_signer = *public;
            true
        }
        DaoPayload::RotateTreasurySigner { public } => {
            state.treasury_signer = *public;
            true
        }
        DaoPayload::SetDevFee { bps } => {
            state.dev_fee_bps = *bps;
            true
        }
        DaoPayload::SetMineFee { bps } => {
            state.mine_fee_bps = *bps;
            true
        }
    }
}
