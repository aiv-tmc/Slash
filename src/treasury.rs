use serde::{Deserialize, Serialize};

/// Base price of one treasury cell at the start of the bonding curve.
pub const BASE_PRICE: u64 = 1;
/// Curve steepness parameter. Higher K means a flatter price curve.
pub const K: u64 = 1_000_000;

/// Cost in cells to buy `amount` treasury cells when `total_sold` cells have
/// already been sold. This is the discrete integral of the linear curve
/// price_per_cell = BASE_PRICE * (1 + total_sold / K), computed with 128-bit
/// arithmetic so that large amounts never overflow. The formula is part of
/// the consensus rules: every node must evaluate the identical price.
pub fn buy_price(amount: u64, total_sold: u64) -> u64 {
    if amount == 0 {
        return 0;
    }
    let a = amount as u128;
    let s = total_sold as u128;
    let k = K as u128;
    let base = BASE_PRICE as u128;
    // Sum of the arithmetic progression of per-cell prices:
    // amount * base + base * (2 * total_sold + amount - 1) * amount / (2 * K).
    let cost = a * base + (base * (2 * s + a - 1) * a) / (2 * k);
    cost as u64
}

/// Refund in cells for selling `amount` treasury cells back when `total_sold`
/// cells have been sold. The refund is 98 percent of the current buy price;
/// the 2 percent spread remains in TREASURY_VAULT and slowly seeds it.
pub fn sell_price(amount: u64, total_sold: u64) -> u64 {
    let buy = buy_price(amount, total_sold) as u128;
    ((buy * 98) / 100) as u64
}

/// Treasury key material and non-consensus bookkeeping.
///
/// The on-disk treasury record stores the three separated public keys
/// (verifiable randomness, transaction signer, onion endpoint). The pricing
/// counters that consensus actually evaluates live in State (total_sold and
/// total_bought_back) and are persisted with the state header; the copies
/// kept on this struct are legacy bookkeeping for external tooling and are
/// never consulted by block validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreasuryState {
    /// Legacy fiat-denomination field retained for compatibility with
    /// existing tools. Consensus pricing is cell-denominated and never
    /// reads this value.
    #[serde(default)]
    pub reserve_fiat: u64,
    /// Legacy mirror of the consensus sell counter. Block validation reads
    /// State::total_sold instead.
    #[serde(default)]
    pub total_sold: u64,
    /// Legacy mirror of the consensus buy-back counter. Block validation
    /// reads State::total_bought_back instead.
    #[serde(default)]
    pub total_bought_back: u64,
    /// Public VRF key used for verifiable randomness in cell selection.
    pub vrf_public: [u8; 32],
    /// Public Ed25519 key used for administrative treasury transactions.
    pub signer_public: [u8; 32],
    /// Public X25519 key used for treasury onion routing.
    pub onion_public: [u8; 32],
}

impl TreasuryState {
    /// Load treasury state from disk using the compact bincode format.
    pub fn load() -> Option<Self> {
        if let Ok(bytes) = std::fs::read("treasury.bin") {
            if let Ok(t) = bincode::deserialize(&bytes) {
                return Some(t);
            }
        }
        None
    }

    /// Atomically write treasury state to disk in compact bincode format.
    pub fn save(&self) {
        let encoded = bincode::serialize(self).unwrap();
        crate::storage::atomic_write("treasury.bin", &encoded).unwrap();
    }

    /// Legacy convenience wrapper: prices against this struct's own
    /// total_sold mirror. Consensus code calls the free functions with
    /// State::total_sold instead.
    pub fn buy_price(&self, amount: u64) -> u64 {
        buy_price(amount, self.total_sold)
    }

    /// Legacy convenience wrapper for the 98 percent refund. Consensus code
    /// calls the free function with State::total_sold instead.
    pub fn sell_price(&self, amount: u64) -> u64 {
        sell_price(amount, self.total_sold)
    }
}
