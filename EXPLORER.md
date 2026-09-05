# Block Explorer Schema

This document defines the indexing formats used by block explorers
and external indexers that reconstruct a searchable database from
on-chain data.

## 1. Address Index

For every address (32-byte public key), the indexer records:

| Field | Type | Description |
|---|---|---|
| `address` | hex string | The 32-byte public key encoded as 64 hex characters. |
| `balance` | u64 | Current cell count owned by this address. |
| `tx_count` | u64 | Total number of transactions involving this address. |
| `first_seen` | u64 | Block height of the first transaction. |
| `last_seen` | u64 | Block height of the most recent transaction. |

### Transaction History Entry

Each address points to an ordered list of history entries:

```json
{
  "block_height": 12345,
  "tx_index": 2,
  "direction": "in" | "out",
  "cell_start": 1000,
  "cell_end": 1050,
  "counterparty": "aabbcc...",
  "lock": null | 20000
}
```

## 2. Cell Index

For every cell index (0 .. 999,999,999), the indexer records:

| Field | Type | Description |
|---|---|---|
| `cell` | u64 | Global cell index. |
| `current_owner` | hex string | Address that currently owns this cell. |
| `lock_until` | u64 | Block height until which the cell is locked, or null. |
| `mined_at` | u64 | Block height when this cell was first mined out of the treasury. |
| `transfer_count` | u64 | Number of times this cell has changed ownership. |

### Ownership History Entry

```json
{
  "block_height": 12345,
  "tx_index": 0,
  "from": "0000...",
  "to": "aabbcc...",
  "range_start": 1000,
  "range_end": 1001
}
```

## 3. Block Index

For every block, the indexer records:

| Field | Type | Description |
|---|---|---|
| `height` | u64 | Absolute block height. |
| `hash` | hex string | Blake3 hash of the block header. |
| `prev_hash` | hex string | Hash of the previous block. |
| `time` | u64 | Unix timestamp. |
| `miner` | hex string | Address of the miner. |
| `mined_cell` | u64 | Cell index claimed as the mining reward. |
| `difficulty` | u64 | Difficulty target for this block. |
| `nonce` | u64 | RandomX nonce. |
| `tx_count` | usize | Number of transactions in the block. |
| `fee_claim_count` | usize | Number of fee-claim outputs. |
| `total_fees` | u64 | Sum of all fee claims. |
| `page_roots` | map | `page_id -> hex(root)` for every dirty page. |

## 4. Reconstruction Algorithm

A reference Python indexer can rebuild the entire explorer database
by iterating blocks in height order and applying state transitions:

1. Load the chain from `chain_blocks.bin` and `header.bin` + `pages/*.bin`.
2. For each block, in order:
   a. Apply `mine(mined_cell, miner, height)`.
   b. Apply `claim_fees(miner, fee_claims, height)`.
   c. For each transaction, apply `tx(from, inputs, outputs, sig, height)`.
   d. After each state change, emit index records for affected addresses and cells.
3. After the full scan, write the address, cell, and block indexes to the database.

## 5. Light-Client Verification

Light clients do not need the full index. They only need:

1. The latest block header (from any trusted node or header chain).
2. The `page_root` for the page containing the cell of interest.
3. A `PageProof` from `getPageProof(cell)`:
   - `leaf_hash`: blake3(start || end || owner)
   - `siblings`: list of sibling hashes from leaf to root.
   - `leaf_index`: position of the leaf in the sorted range list.

Verification steps:
1. Hash `leaf_hash` with its siblings using the same bottom-up blake3(left || right) construction.
2. Compare the recomputed root with the `page_root` from the block header.
3. If they match, the cell ownership is proven without downloading the full page.
