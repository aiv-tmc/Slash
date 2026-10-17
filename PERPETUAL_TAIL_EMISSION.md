# Slash Protocol — Perpetual Tail Emission (Decision Record)

**Status:** accepted (v0.3.1), supersedes the "fee-only tail" claims in
`wiki.md` and the emission table in `README.md`.
**Scope:** `chain.rs`, `state.rs`, `mining.rs`, tests, documentation.

---

## Decision

The proof-of-work slot cell (`block.mined_cell`, one treasury-owned cell
minted to the miner per block) continues to be paid at every height,
including all heights from era 9 onward where `subsidy_at(height) == 0`.

From era 9 the miner revenue per block is therefore exactly one cell from
the slot mint, forever. There is no height at which the slot emission
stops.

## Rationale

1. The design document (§4.3, "mined_cell stays") mandates keeping the PoW
   slot as part of the difficulty game: `verify_pow` derives the slot from
   the hash output (`value % N`), so removing the slot would change the
   consensus input semantics of every historical and future block.
2. Zeroing the slot in era 9 would be a consensus rule change: it alters
   the executed state transition (no treasury debit / miner credit) and the
   incentives of the nonce search. By the project's own rules such a change
   ships only as a new era / DAO decision, not as a patch.
3. The perpetual tail is economically negligible at the target block time:
   one cell per 300 seconds is about 105,120 cells per year, roughly
   0.0105% of the unissued treasury supply per year. It does not threaten
   the conservation invariant: the cell is debited from the treasury entry
   of the balance cache, so `sum(balance_cache) == N` holds after every
   block (pinned by `test_tail_slot_emission_is_perpetual` and the soak
   invariant checks).

## Consequences

- Total miner compensation after era 8 is `1 cell/block` (slot only); the
  era table in the design document and `wiki.md` remains exact for the
  coinbase subsidy, which is what `subsidy_at` computes.
- The treasury depletion horizon under pure slot emission is
  `N - EMISSION_CAP` cells at one cell per block, i.e. about 582 million
  blocks (~5,500 years at the 300-second target). This is considered out of
  engineering scope for v0.3; any adjustment belongs to a future era.
- Documentation that previously claimed "from era 9 security is funded
  purely by transaction fees" is inaccurate and must be read as "purely by
  fees plus the one-cell slot tail". Documentation corrections are tracked
  as a docs-drift item in the Phase 3 documentation pass.
- Changing or removing the tail (including the treasury depletion
  horizon) requires a DAO decision per the governance design, followed by
  a new network identifier.

## Pinned behavior

The following tests lock this decision into CI; changing any of them is a
consensus fork and must follow the consensus-change process in
CONTRIBUTING.md:

- `test_era_eight_to_nine_transition` — coinbase required at 3_784_319,
  omitted at 3_784_320, empty era-9 payload block valid, unsigned treasury
  tx rejected at zero subsidy.
- `test_tail_slot_emission_is_perpetual` — deep-tail block pays exactly one
  slot cell and preserves the conservation invariant.
- `simulate_fee_only_tail` in `simulation.rs` — the subsidy-only view of
  the tail.

