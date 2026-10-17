//! Unit tests of the load-path gates: the replay-domain check and the
//! deployment-table structural validation that run before a restored
//! chain drives consensus.

use super::load::enforce_deployment_table_for_test as enforce_deployment_table;

/// The built-in deployment table of a fresh chain: the live schedule
/// every loader path is checked against.
fn built_in_table() -> Vec<crate::chain::Deployment> {
    crate::chain::Chain::genesis().version_bits.deployments
}

#[test]
fn deployment_table_enforcement_accepts_built_ins() {
    // The built-in table drives the live activation schedule and must
    // pass the load-time gate unchanged.
    enforce_deployment_table(&built_in_table());
}

#[test]
fn deployment_table_enforcement_rejects_out_of_range_bits() {
    // A deployment whose bit position leaves the 32-bit version field
    // would overflow the signal-count shift; the load gate refuses
    // the table instead of driving consensus with it.
    let mut table = built_in_table();
    table[0].bit = 32;
    assert!(std::panic::catch_unwind(|| enforce_deployment_table(&table)).is_err());
}

#[test]
fn deployment_table_enforcement_rejects_impossible_thresholds() {
    // A threshold beyond the retarget window can never reach the
    // required signal count inside one window; the load gate refuses
    // the table.
    let mut table = built_in_table();
    table[0].threshold = (crate::chain::DIFFICULTY_ADJUSTMENT_INTERVAL + 1) as _;
    assert!(std::panic::catch_unwind(|| enforce_deployment_table(&table)).is_err());
}
