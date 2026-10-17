//! The transaction list and the fee claims of a block, executed against a
//! speculative state with the treasury pairing gates applied on both
//! sides of the bonding curve through the shared pairing tables.

use super::super::chain::Chain;
use super::super::pairing::{self, Funding, PairingTables};
use super::super::subsidy::subsidy_at;
use super::super::types::{Block, BlockError};
use crate::state;

impl Chain {
    /// Execute the transaction list and the fee claims of a block against
    /// a speculative state, applying the treasury pairing rules on both
    /// sides of the bonding curve through the shared pairing tables. Buy
    /// side: a signed treasury mint at index i > 0 is valid only when an
    /// earlier ordinary transaction in the same block pays at least the
    /// curve buy price into the treasury vault, and each payment may fund
    /// only one mint. Sell side: an ordinary transaction that pays cells
    /// back to the treasury address is a sell, and a signed treasury
    /// payout funded from the vault must refund exactly one earlier sell
    /// at the curve sell price. Returns the error code of the first
    /// failing transaction.
    pub(super) fn execute_block_txs(
        &self,
        temp: &mut crate::state::State,
        block: &Block,
    ) -> Result<(), BlockError> {
        // Enforce the transaction-count cap before any execution work.
        if block.txs.len() > super::super::params::MAX_TX_PER_BLOCK {
            return Err(BlockError::InvalidTx);
        }
        let rules = crate::governance::active_rules(&self.version_bits.deployments, block.height);
        let allow_scheme1 = rules
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::AllowScheme1));
        let dao_active = rules
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::DaoV1));
        let mut tables = PairingTables::new();
        let mut dev_fund_spends = 0usize;
        // Sell refunds are priced at the curve position the block started
        // with, so an intra-block buy cannot inflate the refund of a sell
        // inside the same block.
        let total_sold_at_start = temp.total_sold;
        // Position 0 is the coinbase while the subsidy is positive: it was
        // already minted by execute_block_meta_inner and is skipped here.
        // From era 9 onward the subsidy is zero, no coinbase exists, and
        // an ordinary user transaction at position 0 — the only shape
        // `validate_coinbase` admits there — must execute like every other
        // transaction, so nothing is skipped.
        let start_index = if subsidy_at(block.height) > 0 { 1 } else { 0 };
        for (i, tx) in block.txs.iter().enumerate().skip(start_index) {
            if tx.from == state::TREASURY {
                // Sunset parity: once governance is live, signer-authorized
                // treasury transactions lose their authority in block
                // execution exactly as they do in mempool admission.
                if dao_active {
                    return Err(BlockError::InvalidTx);
                }
                if !allow_scheme1 && tx.scheme != 0 {
                    return Err(BlockError::InvalidTx);
                }
                match PairingTables::classify(temp, tx, block.height)? {
                    Funding::Mint => {
                        // A mint routing any output back into the vault
                        // would move treasury cells without paying the
                        // curve and would escape the pairing price
                        // entirely, so it is rejected outright.
                        if tx.outputs.iter().any(|o| o.to == state::TREASURY_VAULT) {
                            return Err(BlockError::InvalidTx);
                        }
                        // The minted amount is everything the treasury
                        // sends; a malformed range width fails closed.
                        let minted =
                            pairing::total_width(&tx.outputs).ok_or(BlockError::InvalidTx)?;
                        if minted > 0 {
                            let price = crate::treasury::buy_price(minted, temp.total_sold);
                            if !tables.pair_buy(block, i, price) {
                                return Err(BlockError::InvalidTx);
                            }
                            temp.total_sold = temp.total_sold.saturating_add(minted);
                        }
                        // The mint executes through the ordinary
                        // transaction pipeline: the treasury signer
                        // signature is verified and the canonical treasury
                        // range is debited.
                        if !temp.tx(
                            tx.from,
                            &tx.inputs,
                            &Self::to_state_outputs(&tx.outputs),
                            &tx.sig,
                            block.height,
                            self.chain_id.as_bytes(),
                            tx.scheme,
                            &tx.memo,
                        ) {
                            return Err(BlockError::InvalidTx);
                        }
                    }
                    Funding::Payout => {
                        // The payout amount is the total width of its
                        // outputs; a malformed range width fails closed.
                        let payout =
                            pairing::total_width(&tx.outputs).ok_or(BlockError::InvalidTx)?;
                        let sold = tables
                            .match_payout(payout, total_sold_at_start)
                            .ok_or(BlockError::InvalidTx)?;
                        // The payout moves buyer funds out of the vault, so
                        // it must carry a valid treasury signer signature
                        // like any other treasury transaction. An
                        // unconfigured all-zero signer key refuses the
                        // spend outright: the zero point is a valid
                        // small-order curve point, so signature
                        // verification alone would not be a sufficient
                        // barrier.
                        if temp.treasury_signer == [0u8; 32] {
                            return Err(BlockError::InvalidTx);
                        }
                        // Hash the payout exactly like any other treasury
                        // transaction: sender, inputs, outputs, chain
                        // identifier, scheme, and memo all commit to the
                        // signature.
                        let hash = Self::tx_signature_hash(
                            &tx.from,
                            &tx.inputs,
                            &Self::to_state_outputs(&tx.outputs),
                            self.chain_id.as_bytes(),
                            tx.scheme,
                            &tx.memo,
                        );
                        if !crate::crypto::verify(&temp.treasury_signer, &hash, &tx.sig) {
                            return Err(BlockError::InvalidTx);
                        }
                        // The matched sold count moves back out of
                        // total_sold and into the buy-back counter, so
                        // the curve price recovers after a sale.
                        temp.total_sold = temp.total_sold.saturating_sub(sold);
                        temp.total_bought_back = temp.total_bought_back.saturating_add(sold);
                        // The payout executes through the vault spend
                        // primitive, which requires every input to be
                        // vault-owned and unlocked and packs the outputs
                        // exactly over the inputs.
                        if !temp.payout(
                            &tx.inputs,
                            &Self::to_state_outputs(&tx.outputs),
                            block.height,
                        ) {
                            return Err(BlockError::InvalidTx);
                        }
                    }
                }
            } else {
                if !allow_scheme1 && tx.scheme > 0 {
                    return Err(BlockError::InvalidTx);
                }
                if tx.from == state::DEV_FUND {
                    // Dev fund spends are signer-authorized and limited to
                    // one per block, matching the mempool policy.
                    dev_fund_spends += 1;
                    if dev_fund_spends > 1 {
                        return Err(BlockError::InvalidTx);
                    }
                }
                if !temp.tx(
                    tx.from,
                    &tx.inputs,
                    &Self::to_state_outputs(&tx.outputs),
                    &tx.sig,
                    block.height,
                    self.chain_id.as_bytes(),
                    tx.scheme,
                    &tx.memo,
                ) {
                    return Err(BlockError::InvalidTx);
                }
                // Record any payment back to the treasury address as a
                // pending sell; a later payout in this block may refund
                // it.
                tables.record_sell(i, pairing::treasury_returned(tx));
            }
            // Apply a governance operation riding this transaction's memo
            // after the transfer itself has executed, so a rejected
            // operation never invalidates an otherwise valid transfer.
            if let Some(memo_bytes) = &tx.memo {
                if dao_active {
                    if let Ok(op) = bincode::deserialize::<crate::dao::DaoOp>(memo_bytes) {
                        // The operation needs the proposal tables (a field
                        // of the state) and the state itself for treasury
                        // execution and weight lookups. The tables are
                        // moved out through a temporary genesis value so
                        // the two mutable borrows stay disjoint, and are
                        // moved back immediately after the call.
                        let mut dao =
                            std::mem::replace(&mut temp.dao, crate::dao::DaoState::genesis());
                        dao.apply_op(temp, tx.from, &op, block.height);
                        temp.dao = dao;
                    }
                }
            }
        }
        // Execute the miner's fee claims: the sweep credits the miner and
        // debits the vault, rejecting any claim that fails ownership,
        // lock, or miner-destination checks. An empty claim set is valid.
        if !temp.claim_fees(
            block.miner,
            &Self::to_state_outputs(&block.fee_claims),
            block.height,
        ) {
            return Err(BlockError::InvalidTx);
        }
        Ok(())
    }
}
