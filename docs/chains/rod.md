# SpaceXpanse ROD

| Field | Value |
|---|---|
| Ticker | ROD |
| PowData evidence start | Earliest retained SHA256d PowData observation at child height 2, timestamped 2022-06-09 18:00:26 UTC |
| Network status | Active at the 2026-09-08 archival snapshot |
| Chronological position | 25 of 27 (after Electric Cash; before Lyncoin) |
| In Stifter et al. 2018 baseline | **No** (ROD launched after the paper's measurement window) |
| PowData chain ID | `1899` |
| Source tag (in code) | `rod` |
| Public evidence | One independently reviewed canonical Bitcoin-parent observation; no accepted direct stale |

ROD uses a multi-algorithm `PowData` wrapper. The pure 80-byte child header
stores zero in its `nBits` field, while the adjacent wrapper supplies the
effective target. Algorithm byte `0x81` carries a SHA256d AuxPoW proof and
algorithm byte `0x02` carries a standalone NeoScrypt proof. The first
post-genesis block is eligible for this wrapper, but genesis itself is a
standalone NeoScrypt block. The registry's height and chronology values do not
claim that every early block was merge-mined.

## 1. Provenance and scope

The recovery pins SpaceXpanse ROD source commit
`248f1af050579a369af527288f5773a021ae8492`. A fully synchronized, unpruned
node supplied every active-chain block from height 0 through the declared
terminal height 4,127,689, whose hash was
`4a16afd2df5efd2ae7db5e07ba83820bf3174914efe2754da618a150c3df6b0a`.
The final extraction contains 4,127,690 rows: 1,058,017 SHA256d proofs and
3,069,673 standalone NeoScrypt proofs. The final private audit checks every
retained pure child header and envelope encoding, child hash, predecessor edge,
algorithm byte, effective-target field and chunk receipt. It also reconciles
the extraction's recorded proof and full-body verdict fields. The separate
candidate review recomputes the full proof and body checks used for publication.

The ROD source deserializer discards two AuxPoW compatibility fields,
`hashBlock` and the serialized parent index, and outbound RPC serialization
normalizes them. The extracted bytes are exact node RPC serialization, not a
claim about the original historical disk encoding. Proof envelopes remain
distinct evidence even when they commit the same pure child header.

## 2. Bitcoin classification and publication result

| Bitcoin context | SHA256d observations |
|---|---:|
| Exact canonical Bitcoin parent | **1** |
| Extends an active Bitcoin predecessor; fails Bitcoin self-target PoW | 68,246 |
| Extends a known noncanonical Bitcoin predecessor; fails Bitcoin self-target PoW | 1 |
| Parent and predecessor unresolved by the Bitcoin node | 989,769 |
| Total | **1,058,017** |

The one canonical observation is ROD height 2,697,753, child hash
`4707fda9b70993a867cf9026a4c977a5fc8ebf8c4bb3b3512596357520bae21b`.
Its proof commits Bitcoin height 886,688, hash
`00000000000000000001822dc3db70b75d281687f8baa10d1818d0703f49fec0`,
on 2025-03-07. Independent full-body review verifies the 25-transaction
Bitcoin Merkle tree, the exact parent coinbase transaction and script, the ROD
block Merkle tree and minimally encoded child coinbase height, and the complete
PowData AuxPoW commitment. The proof envelope agrees byte for byte with the
audited extraction.

The private canonical producer rechecks those identities and digests before
writing `rod_canonical_blocks.csv`. It uses the wrapper's effective target as
`child_nbits`, keeps the pure zero-header-bits fact in the bound source
evidence, and leaves `validation_status` and `expected_nbits` empty because a
canonical parent is outside the direct-stale validation profile. No empty
`rod_validated_stales.csv` is fabricated.

## 3. Reproducibility and limits

Activate the project virtual environment, then run the producer only against
the digest-bound complete extraction, final
audit, candidate inventory, full-body review and exact frozen extraction
dependencies:

```bash
source .venv/bin/activate
just build-rod-canonical \
  --extraction-root <private-rod-extraction> \
  --audit-root <private-final-audit> \
  --candidates <private-special-candidates.json> \
  --candidates-sha256 <pinned-sha256> \
  --review-root <private-candidate-review> \
  --review-receipt-sha256 <pinned-sha256> \
  --framing <private-frozen-framing.py> \
  --extractor <private-frozen-extractor.py> \
  --output-dir <fresh-private-output>
```

The output directory must be absent. The producer stages the CSV and receipt,
then installs them together. Any source digest, child identity, effective
target, parent header, coinbase or proof contradiction stops the run.

The active-chain extraction authenticates native ROD placement and child
heights for this snapshot. It does not turn lower-work or unresolved Bitcoin
templates into publication candidates. Separate dated P2P acquisition records
remain in the private source-event ledger. The completed join found all 261,224
prior event rows matched the active-chain extraction by exact child header and
PowData envelope. Their source provenance remains distinct and is not collapsed
into the canonical companion.
