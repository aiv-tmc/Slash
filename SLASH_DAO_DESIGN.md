# Slash Protocol — DAO Governance Design

**Version:** 0.4.2 · **Status:** implemented (this document precedes and pins the implementation)
**Scope:** `dao.rs`, `chain.rs`, `state.rs` (parameters), `storage.rs` (persistence), tests.

## 1. Model

Voting weight is locked supply. A cell owned by an address accrues weight when its lock expires no earlier than `snapshot_height + DAO_LOCK_MIN` (10 000 blocks). The snapshot height is fixed at proposal submission, so weight earned or burned inside the voting window cannot influence the outcome. Pristine (treasury-owned) cells never carry weight.

| Parameter | Value |
|---|---|
| `DAO_LOCK_MIN` | 10 000 blocks |
| `DAO_QUORUM_BPS` | 500 (5% of locked supply at snapshot) |
| `DAO_THRESHOLD_BPS` | 5000 (strict majority of cast weight) |
| `DAO_VOTING_PERIOD` | 4032 blocks |
| `DAO_EXEC_DELAY` | 1008 blocks |
| `DAO_MAX_PROPOSALS` | 64 open at once |

## 2. Operations and payloads

Governance rides the transaction `memo` field (DaoV1 soft fork). A memo carries a `DaoOp`: `SubmitProposal { payload }` or `Vote { proposal_id, approve }`. The memo bytes are committed into the transaction signature hash, so a signed transaction cannot be re-purposed as a vote. Operations execute only after the carrying transfer succeeds; a rejected operation (duplicate vote, closed proposal, zero weight) never invalidates the transfer — it is dropped silently. Governance transactions pay the standard fee and dev-fund shares: governance costs the same as any transfer, which is the spam control.

Executable payloads (`DaoPayload`): `TreasuryMint`, `TreasuryPayout`, `RotateDevFundSigner`, `RotateTreasurySigner`, `SetDevFee`, `SetMineFee`. Mint and payout execute through the canonical `select_single` selection so every node reproduces identical ranges and page roots. `payload_valid` bounds every payload at submission time (amounts ≥ MIN, non-zero targets, bps caps: 100 transfer / 1000 coinbase) so a passed proposal can only request transitions that can actually execute.

## 3. Lifecycle

1. Submit at height H: proposal opens with `snapshot_height = H`, votes accepted in `[H, H + 4032)`.
2. Votes: one address casts at most one vote; the first vote is recorded, later votes from the same address are rejected. Weight is evaluated at the proposal snapshot height, supplied by `locked_weight`.
3. Close at `end_height`: `tally_at` computes the quorum denominator as `total_locked_weight(state, snapshot_height)` per proposal. Passing needs quorum (cast weight ≥ 5% of snapshot locked supply) and a strict majority of cast weight. Passed proposals receive `exec_height = end_height + 1008`.
4. Execute at `exec_height`: `execute_due` applies the payload through the ordinary state transition engine (`State::mint` / `State::payout` / direct field assignment). Unexecutable payloads expire instead of blocking the queue.

## 4. Treasury sunset

While the DaoV1 rule is active, non-coinbase treasury transactions are rejected at both validation paths (`Chain::validate_tx` and `Chain::execute_block_txs`): the legacy signer loses its authority at activation, and every treasury movement afterwards flows exclusively through passed proposals. This removes the single point of failure the moment governance is live; the recovery path for a compromised signer is `RotateTreasurySigner`. The coinbase carve-out is unchanged — it is the scheduled subsidy mint, not a signer-authorized spend.

## 5. Threat model and mitigations

- **Vote buying:** acquiring cells on the curve and locking them is the only weight source; `DAO_LOCK_MIN` and the snapshot freeze make weight movements slow and observable over ~10 000 blocks.
- **Snapshot grinding:** weight is pinned at submission; locking during the voting window buys no influence on that proposal.
- **Proposal spam:** 64-open cap, per-op transfer cost, and structural payload validation bound the state growth.
- **Quorum denominator drift:** per-proposal snapshot denominators keep outcomes a pure function of snapshot state.
- **Replayed votes:** memo commitment in the signature hash plus the first-vote-wins set make double voting unprofitable and detectable.
- **Unbounded execution:** payloads are validated at submission and expire unexecutable; execution order is proposal id order via `BTreeMap`.

## 6. Out of scope (v1)

Curve parameters (`K`, `BASE_PRICE`) and emission changes require a new era, not a proposal. Multisig treasury execution, delegation, and vote abstention are future work. The `treasury_key_rotation` deployment remains the non-DAO rotation vehicle until sunset completes on a live network.

## 7. Activation and rollback

Activation follows the standard version-bits path (`dao_v1`, bit 5, threshold 1512 per retarget window). Before activation, memo payloads are inert: transfers with memos execute as ordinary transfers. Rollback of the deployment follows the project soft-fork process (new network identifier); no automatic on-chain rollback path exists, which is why `DAO_EXEC_DELAY` provides a public observation window.

