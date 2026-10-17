# Slash Protocol — Test Coverage Matrix

**Version:** 0.5.0
**Status:** authoritative. A documented rule without a row in this matrix is treated as not implemented. Every consensus change must update this matrix in the same pull request.

## Legend

| Mark | Meaning |
|---|---|
| Covered | A test exercising the rule exists in the tree and runs in CI. |
| Specified | The rule is implemented; the named test pins it. |
| Partial | The rule is implemented and partially tested; the gap is tracked. |
| Planned | The rule is designed but the implementation or test is pending. |

## 1. Consensus: blocks and headers

| Rule | Implementation | Test | Status |
|---|---|---|---|
| Chain identifier pins the signature domain per network | `chain.rs::MAINNET_ID`, `chain.rs::TESTNET_ID` | `chain_tests.rs::test_genesis_chain_id` | Covered |
| Block extends the tip by height and previous hash | `chain.rs::Chain::check_block_meta` | `chain_tests.rs` reorg/side-fork cases | Covered |
| Median-time rule over the last 11 blocks | `chain.rs::Chain::check_block_meta` | `chain_tests.rs` timestamp cases | Covered |
| Difficulty equals the retargeted value | `chain.rs::Chain::next_difficulty`, `difficulty_for_height` | `chain_tests.rs::test_difficulty_retargets_every_interval` | Specified |
| Retarget clamps to 4x and never below 1 | `chain.rs::Chain::difficulty_for_height` | `chain_tests.rs` retarget cases | Specified |
| Zero difficulty never satisfies proof-of-work | `chain.rs::verify_pow` | `chain_tests.rs::test_verify_pow_rejects_zero_difficulty` | Covered |
| PoW slot cell treasury-owned, never confiscates user cells | `chain.rs::verify_pow` callers; `state.rs::State::mint_slot` | `chain_tests.rs::test_mine_respects_locked_cells`; `state.rs::mint_slot_refuses_non_treasury_cells` | Covered |
| Checkpoint mismatch is a permanent rejection | `chain.rs::Chain::check_block_meta` | `chain_tests.rs` checkpoint cases | Covered |
| Reorg depth limited to the retained history window | `chain.rs::Chain::reorg_to_fork`, `MAX_REORG_DEPTH` | `reorg_persistence_tests` | Covered |
| Orphan adoption bounded per pass | `chain.rs::Chain::process_orphans`, `MAX_ORPHAN_ADOPTION` | `chain.rs::process_orphans_adopts_chains_up_to_the_cap` | Covered |
| Side forks retained up to a bounded pool | `chain.rs::Chain::process_block`, `MAX_SIDE_FORKS` | `reorg_persistence_tests` | Covered |
| Recovery replay refuses broken linkage | `chain.rs::Chain::apply_recovered` | `chain.rs::apply_recovered_rejects_broken_linkage` | Covered |
| Side-fork pool rejects garbage heights/difficulties | `chain.rs::Chain::validate_side_fork_entry` | `chain.rs::side_fork_pool_rejects_garbage` | Covered |
| Header batch validates linkage, median time, retarget, slot | `chain/validation.rs::Chain::validate_headers_batch` | `chain/tests.rs::validate_headers_batch_walks_the_full_window` | Specified |
| Deployment table validated at load (bit < 32, threshold ≤ window) | `lib.rs::enforce_deployment_table` | `lib.rs::tests::deployment_table_enforcement_*` | Specified |

## 2. Emission and coinbase

| Rule | Implementation | Test | Status |
|---|---|---|---|
| Subsidy schedule exact at every era boundary | `chain.rs::subsidy_at` | `emission_harness_tests` boundary vectors | Covered |
| Coinbase mandatory and first while subsidy positive | `chain.rs::Chain::validate_coinbase` | `emission_harness_tests` coinbase shape cases | Covered |
| Coinbase outputs only to miner plus exact dev share | `chain.rs::Chain::validate_coinbase` | `emission_harness_tests` coinbase shape cases | Covered |
| Coinbase amount equals `subsidy_at(height)` | `chain.rs::Chain::validate_coinbase` | `chain_tests.rs::test_coinbase_amount_matches_schedule` | Specified |
| Coinbase inputs are the canonical treasury range | `chain.rs::Chain::validate_coinbase` | `emission_harness_tests::test_coinbase_canonical_inputs` | Specified |
| Era 9 omits coinbase, empty payload valid | `chain.rs::Chain::validate_coinbase` | `chain_tests.rs::test_era_eight_to_nine_transition` | Specified |
| Perpetual slot tail one cell per block at every height | `state.rs::State::mint_slot` | `chain_tests.rs::test_tail_slot_emission_is_perpetual` | Specified |
| Tail preserves conservation | `state.rs::State::mint_slot` | `state.rs::conservation_invariant` | Specified |
| Cumulative emission never exceeds 417_957_120 | `chain.rs::subsidy_at` | `emission_harness_tests` cap checks | Covered |

## 3. Transactions and PMIS

| Rule | Implementation | Test | Status |
|---|---|---|---|
| Conservation of cells per transaction | `state.rs::State::tx` | `state.rs::conservation_invariant` | Covered |
| Minimum 50 cells per transaction | `state.rs::State::tx` | `chain_tests.rs` minimum cases | Covered |
| Mandatory fee ≥ total_out / 200 | `state.rs::State::tx`; `chain.rs::Chain::validate_tx` | `chain_tests.rs::test_min_relay_fee_enforced` | Specified |
| Exact output packing | `state.rs::State::apply_transfer`; `chain.rs::tx_structure_valid` | `state.rs::rejection_leaves_no_partial_mutation` | Covered |
| Per-page balance for cross-page transfers | `state.rs::State::apply_transfer` | `state.rs::multi_input_cross_page` | Covered |
| Per-transaction range and page amplification caps | `chain/params.rs::MAX_RANGES_PER_TX`, `MAX_PAGES_PER_TX`; `chain/validation.rs::Chain::tx_caps_valid` | `chain/tests.rs::tx_caps_reject_range_and_page_amplification` | Specified |
| Ownership and lock checks before spend | `state.rs::State::owns`, `remove_for_spend` | `state.rs::lock_prevents_spending` | Covered |
| Locked output binds every cell of its range | `state/transfer.rs::apply_transfer` (per-cell registration) | `state/lock_range_tests.rs::locked_range_tail_cannot_be_spent_before_expiry` | Specified |
| Locked range spendable once the height is reached | `state.rs::State::owns` (expiry predicate) | `state/lock_range_tests.rs::full_locked_range_spend_succeeds_after_expiry` | Specified |
| Pruning releases every cell of an expired range | `state/locks.rs::State::prune_locks` (expiry filter) | `state/lock_range_tests.rs::prune_locks_filters_by_expiry_not_cell_index` | Specified |
| Governance weight accrues over the full locked range | `dao.rs::locked_weight`, `total_locked_weight` | `state/lock_range_tests.rs::locked_range_weight_counts_every_cell` | Specified |
| Global lock cap bounds the live map | `state/transfer.rs::apply_transfer` (live count + new width) | `state/lock_range_tests.rs::global_lock_cap_rejects_transfers_past_the_live_map` | Specified |
| Per-transaction locked-width bound | `chain.rs::tx_structure_valid` | `state.rs::lock_cap_is_enforced` | Covered |
| Mempool/consensus structural parity | `chain.rs::Chain::validate_tx` | `p2p_tests` policy cases | Covered |
| Slot mint releases lock only after reassignment | `state.rs::State::mint_slot` | `state.rs::mine_expired_lock_releases_only_after_reassignment` | Covered |
| Fee claims select only unlocked vault cells | `p2p.rs::build_fee_claims` | `p2p.rs::fee_claims_skip_locked_vault_cells` | Covered |
| Empty fee vault yields no claims | `p2p.rs::build_fee_claims` | `p2p.rs::fee_claims_empty_vault_yields_no_claims` | Covered |
| Treasury mint debits unissued supply | `state.rs::State::mint` | `state.rs::treasury_mint_without_prior_mine_uses_unissued_supply` | Covered |
| Unsigned treasury tx rejected | `state.rs::State::tx` | `state.rs::unsigned_treasury_tx_is_rejected` | Covered |
| Wrong-signer treasury tx rejected | `state.rs::State::tx` | `state.rs::treasury_tx_with_wrong_signer_is_rejected` | Covered |
| Treasury tx refused without configured signer | `state.rs::State::tx` | `state.rs::treasury_tx_rejected_without_configured_signer` | Covered |
| Dev-fund tx refused without configured signer | `state.rs::State::tx` | `dao_tests` spend setup | Covered |
| Rejection leaves no partial mutation | `state.rs::State::apply_transfer` | `state.rs::rejection_leaves_no_partial_mutation` | Covered |

## 4. Treasury and bonding curve

| Rule | Implementation | Test | Status |
|---|---|---|---|
| Buy pair mints exact amount, updates total_sold | `chain.rs::Chain::execute_block_txs` | `treasury_tests` buy-pair cases | Covered |
| Mint without earlier payment rejected | `chain.rs::Chain::execute_block_txs` | `treasury_tests.rs::test_mint_without_payment_rejected` | Specified |
| Underpayment rejected | `chain.rs::Chain::execute_block_txs` | `treasury_tests` underpayment case | Specified |
| Sell pair pays 98% | `chain.rs::Chain::execute_block_txs`; `treasury.rs::sell_price` | `treasury_tests.rs::test_sell_pair_payout_98pct` | Specified |
| Sell without vault balance rejected | `chain.rs::Chain::execute_block_txs` | `treasury_tests` vault case | Specified |
| Curve strictly monotonic | `treasury.rs::buy_price` | `treasury_tests.rs::test_curve_monotonic_in_cells` | Specified |
| Treasury sig required at any non-coinbase position | `chain.rs::Chain::execute_block_txs` | `era_nine_boundary_tests` position-zero case | Covered |
| Signed unpaired mint rejected (era 9, position 0) | `chain.rs::Chain::execute_block_txs` | `era_nine_boundary_tests` signed-unpaired case | Covered |

## 5. Governance and dev fund

| Rule | Implementation | Test | Status |
|---|---|---|---|
| Windowed signaling; reset at boundaries | `chain.rs::Chain::update_version_bits` | `version_bits_window_tests` | Covered |
| Lock-in only at window end, threshold in one window | `chain.rs::Chain::update_version_bits` | `version_bits_window_tests::single_window_reaching_threshold_locks_in_at_window_end` | Covered |
| Activation deferred one interval | `chain.rs::Chain::update_version_bits` | `version_bits_window_tests::locked_in_deployment_activates_at_scheduled_height` | Covered |
| Dev-fund required when active (mempool and consensus) | `state.rs::State::tx` gated in `chain.rs` | `dev_fee_tests` mempool and block cases | Covered |
| No dev-fee obligation before activation | `chain.rs::Chain::execute_block_txs` | `dev_fee_tests::dev_fee_not_required_before_activation` | Covered |
| Rounding max(total_out*bps/10000, 1) | `state.rs::State::tx` | `dev_fee_tests::dev_fee_rounding_pins_minimum_one_cell` | Covered |
| Treasury and pairing exempt | `state.rs::State::tx` | `dev_fee_tests::treasury_and_pairing_paths_exempt_from_dev_fee` | Covered |
| Dev-fund spend cap one per block | `chain.rs::Chain::execute_block_txs` | `dev_fee_tests::dev_fund_spends_capped_at_one_per_block` | Covered |
| DAO ops ride memo, apply after transfer | `dao.rs::DaoState::apply_op`; `chain.rs` | `dao_tests.rs::memo_submit_and_vote_flow_through_blocks` | Covered |
| Snapshot-pinned voting weight | `dao.rs::locked_weight`, `tally_at` | `dao_tests.rs::vote_weight_uses_snapshot_not_current_height` | Covered |
| One vote per address | `dao.rs::DaoState::vote` | `dao_tests.rs::proposal_lifecycle_submit_vote_close_execute` | Covered |
| Quorum against snapshot locked supply | `dao.rs::close_outcome` | `dao_tests.rs::quorum_failure_rejects_proposal` | Covered |
| Execution at end + delay via canonical selection | `dao.rs::execute_due`, `execute_payload` | `dao_tests` lifecycle and treasury cases | Covered |
| Payload structural bounds | `dao.rs::payload_valid` | `dao_tests.rs::payload_validation_bounds_submission` | Covered |
| Legacy treasury txs rejected while DaoV1 active | `chain.rs` both paths | `dao_tests.rs::treasury_transactions_rejected_while_dao_active` | Covered |
| Key rotation executes at scheduled height | `dao.rs::execute_payload` | `dao_tests.rs::rotation_payload_replaces_signer_at_execution` | Covered |

## 6. Privacy and networking

| Rule | Implementation | Test | Status |
|---|---|---|---|
| Onion build requires ≥3 relays, typed error | `onion.rs::create_onion` | `onion_tests` relay-count cases | Covered |
| Peel order and exit decryption | `onion.rs::peel`, `decrypt_inner` | `onion_tests` peel cases | Covered |
| Replay cache FIFO + persistence | `p2p.rs::OnionReplayCache` | `p2p.rs` replay cache tests | Covered |
| Onion keys only with verified attestation | `p2p.rs` `GetOnionKeyV2` | `p2p.rs::peer_id_ed25519_key_feeds_attestation_verification` | Covered |
| Per-peer token buckets | `p2p.rs` bucket constants | `p2p_tests` rate-limit cases | Covered |
| Per-subnet and node-wide inbound limits | `p2p/conn.rs::ConnectionBudgets` | `p2p/conn.rs::subnet_cap_blocks_further_inbound_until_a_slot_releases`; `p2p/conn.rs::node_wide_cap_counts_all_subnets_together` | Specified |
| Inbound slots release on close | `p2p/conn.rs::ConnectionBudgets::on_closed` | `p2p/conn.rs::inbound_slots_release_when_the_connection_closes` | Specified |
| Outbound dials never consume inbound budget | `p2p/conn.rs::ConnectionBudgets::on_established` | `p2p/conn.rs::outbound_dials_never_consume_inbound_budget` | Specified |
| Strikes and exponential backoff bans | `p2p.rs::ban_duration_secs` | `p2p.rs::ban_duration_escalates_and_saturates` | Covered |
| Sampled sync polling | `p2p.rs::SYNC_SAMPLE_SIZE` | `p2p_tests` sync cases | Covered |
| Wire frames bounded | `p2p.rs::MAX_FRAME` | `wire_format_tests` | Covered |

## 7. Storage, persistence, cryptography

| Rule | Implementation | Test | Status |
|---|---|---|---|
| Atomic writes (tmp, fsync, rename) | `storage.rs::atomic_write` | `storage_tests` | Covered |
| Manifest + crash-recovery journal | `storage.rs` | `storage_tests`; `reorg_persistence_tests` | Covered |
| Pruned recovery replay bounded | `chain.rs::HISTORY_REBUILD_MAX_REPLAY` | `reorg_persistence_tests` | Covered |
| Dev-fund/DAO state survives restart | `storage.rs::Header` | `storage_tests` round-trip | Specified |
| VRF proofs 80 octets, RFC 9381 vectors | `vrf.rs` | `vrf.rs` vector tests | Covered |
| Ed25519 round-trip | `crypto.rs` | `crypto_tests` | Covered |
| Wallet encryption Argon2id + AES-GCM | `crypto.rs` | `integration_tests` wallet cases | Covered |
| Page proofs verify | `state.rs::verify_page_proof` | `state.rs::merkle_root_and_proof` | Covered |
| FFI datadir selection | `ffi.rs::slash_init` | Planned (needs cwd-isolated harness) | Planned |

## Maintenance rules

- Every new consensus rule enters with both validation paths (mempool and block execution) named.
- Every bug fix enters with its regression test named.
- Rows are never deleted; closed items move to the appendix with the closing change named.

