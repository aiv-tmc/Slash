use serde::{Serialize, Deserialize};

/// Base price in fiat cents per cell at the very start of the bonding curve.
pub const BASE_PRICE: u64 = 1;
/// Curve steepness parameter. Higher K = flatter curve.
pub const K: u64 = 1_000_000;

/// Persistent treasury parameters and statistics.
/// Stage 7 introduces key separation: vrf, signer, and onion keys are distinct.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreasuryState {
    /// Fiat reserve held by the treasury, in cents.
    pub reserve_fiat: u64,
    /// Total cells ever sold via the bonding curve.
    pub total_sold: u64,
    /// Total cells ever bought back by the treasury.
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

    /// Calculate the total cost in fiat cents to buy `amount` cells from the treasury.
    /// Uses the integral of the linear bonding curve: price per cell increases as total_sold grows.
    pub fn buy_price(&self, amount: u64) -> u64 {
        if amount == 0 { return 0; }
        let a = amount as u128;
        let s = self.total_sold as u128;
        let k = K as u128;
        let base = BASE_PRICE as u128;
        // Sum of arithmetic progression: amount * base + base * (2*total_sold + amount - 1) * amount / (2*K)
        let cost = a * base + (base * (2 * s + a - 1) * a) / (2 * k);
        cost as u64
    }

    /// Calculate the refund in fiat cents when selling `amount` cells back to the treasury.
    /// The sell price is 98% of the current buy price for that amount (2% spread stays in reserve).
    pub fn sell_price(&self, amount: u64) -> u64 {
        let buy = self.buy_price(amount) as u128;
        ((buy * 98) / 100) as u64
    }
}
