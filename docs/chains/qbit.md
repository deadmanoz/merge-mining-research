# Qbit historical acquisition

The first acquisition assignment completed on 10 September 2026. A fresh,
fully validating native archive supplied every active-chain block from genesis
through height 80,986. Replay auditing authenticated all 80,987 blocks and
16,418 AuxPoW observations. Bitcoin classification found 2,536
canonical parents and four direct-stale header candidates that pass the
existing available-evidence profile. The Research publication includes those
2,540 observations. All 24 unknown parents are excluded by the Bitcoin epoch
target gates; application import remains separate.

## Ongoing Monitor integration

Qbit is an ongoing merge-mined source to track alongside the Monitor's six
existing live merge-mined sources. The completed historical publication is
the baseline for that integration. The live producer and service activation
have not been implemented by this Research assignment.

The Monitor integration should reuse its shared bitcoind-family polling,
backfill, cursor and storage paths with an explicit Qbit proof decoder.
Register the source with `Live` lifecycle when that producer is available,
so historical publication imports are additive. Development acceptance must
bridge the pinned child endpoint 80,986 to the current tip with deliberate
overlap, verify idempotency and restart/reorg handling, and check source health
and the retained proof controls. Reviewed node and poller activation then
establish continuous capture.

## Source and network identity

The source checkout was fetched and fast-forward checked on 10 September 2026
and remained at `70fea84f5becfb57463247af09790df5ddd424f8` (Qbit 1.0.0).
Mainnet genesis is
`0000000000004d60aa5d46013991d0a0e2995d89ee98e53068ae196d763e79f2`;
message-start bytes are `44 4f 24 a8`, P2P port is 8355 and AuxPoW chain ID
is 47. The pinned native source controls deployed rules. Its genesis is dated
15 July 2026, but this does not establish the first AuxPoW observation or the
first authenticated Bitcoin-parent witness.

The [archival workspace](../../node-infra/qbit/README.md) builds from a
digest-verified local source archive without consensus patches. It explicitly
disables ordinary and witness pruning, sets `assumevalid=0` and `txindex=1`,
uses internal RPC and disables automatic restart. The VM had no Qbit datadir
or container at initial inspection, so acquisition used a fresh sync. The node
reached height 81,086 with a synced transaction index before the settled
endpoint was selected. Historical reads and the endpoint survived a graceful
stop and cold start. The retained archive is stopped with automatic restart
disabled. The initial image startup test identified a missing `libevent_extra`
runtime library; the corrected Dockerfile passed startup before syncing.
No consensus workaround was needed.

## Proof adapter

`qbit.py` parses Qbit's explicit wire layout using the existing bounded wire
cursor and Bitcoin transaction decoder: pure child header, non-witness parent
coinbase, parent Merkle branch and signed index, chain Merkle branch and signed
index, then the pure parent header. There is no classic CAuxPow `hashBlock`
field. The classic parser is unchanged.

The adapter checks mainnet's version floor, top-bit shape, reserved bits and
AuxPoW chain ID. Bit 8 is meaningful only with top bits `001`; the chain ID is
bits 13 through 28. Direct mining may roll those chain-ID bits. Mainnet's
height-zero commitment activation requires display-order chain commitments,
including the native legacy no-marker rule. Branch limits, signed indices,
coinbase identity, parent Merkle inclusion, tree size, chain slot and child
target are checked. The child target is always its own pure header `nBits`.

The exact-header API rejects trailing bytes. The full-block API validates
that header/proof prefix and retains the complete native RPC block separately;
it does not reimplement Qbit body or contextual consensus. Native chain
placement must be established separately by the acquisition scan.

## Retained controls

The public fixture `tests/fixtures/qbit_controls.json` records the four
AuxPoW headers from the saved 8 September explorer response. Its reported
child heights were subsequently corroborated by native active-chain lookups.

| Authenticated child height | Bitcoin self-target PoW | Control |
|---|---|---|
| 78,053 | Fails | Retain privately as lower-work evidence |
| 78,058 | Passes | Embedded header matches saved Bitcoin block 966,017 |
| 78,061 | Fails | Retain privately as lower-work evidence |
| 78,064 | Fails | Retain privately as lower-work evidence |

All four pass the pinned Qbit proof-envelope checks. The positive parent is
`0000000000000000000099c87c5d482e3aa11824a22c101c5f0a0f1b96d987a5`.
Every native extended header/proof matches the saved explorer bytes exactly.
Bitcoin Core (`bitcoin-01`) independently supplied the positive parent's full
3,983-transaction block. Its exact header, non-witness coinbase and coinbase
Merkle branch match the proof, and recomputing the body's transaction Merkle
root matches the header. The three lower-work controls remain in the private
`near` inventory and never enter the accepted direct-stale set.

## Audited scope and classification

The inclusive endpoint is child height **80,986**, hash
`000000000000000464d255d39a0c29ddb05987dc6d8809f34a537a17541a1de1`.
The acquisition and post-scan native checks agree on both endpoints. Every
height has a full raw block and a native verbose block view; Qbit rejects that
verbose view for witness-pruned historical blocks. Every predecessor edge,
raw-block digest, output digest and captured response digest passed replay.

| Acquired population | Count |
|---|---:|
| Active-chain blocks, including genesis | 80,987 |
| Directly mined blocks | 64,569 |
| AuxPoW observations and distinct parent headers | 16,418 |
| Parents passing their own encoded PoW target | 2,564 |
| Lower-work parents retained privately | 13,854 |

The shared classifier, queried against `bitcoin-01`, partitions the 2,564
self-target-passing parents into **2,536 canonical, 4 direct stale and 24
unknown**. All four direct candidates have `validation_status=VALID`, with no
header-context rejection or canonical error-catalogue conflict. No error
block was produced by this pass. The complete Research publication retains
all canonical and accepted stale observations. These verdicts do not assert
full Bitcoin body validity.

| Child height | Bitcoin height | Expected Bitcoin nBits |
|---:|---:|---|
| 9,732 | 959,137 | `1702369d` |
| 45,460 | 962,722 | `1702353d` |
| 56,716 | 963,828 | `17023cc1` |
| 60,276 | 964,181 | `17023cc1` |

The earliest observed AuxPoW block is child **916**, at
**16 July 2026, 14:22:59 UTC**. The earliest Bitcoin-Core-confirmed canonical
parent witness is child **2,450**, at **17 July 2026, 11:46:40 UTC**, committing
Bitcoin block **958,405**. Height-zero consensus activation, first observed
AuxPoW and first authenticated Bitcoin-parent evidence are different facts.

The sealed acquisition is retained privately under
`<private-archive>/chains/qbit/recovery-20260910-80986/acquisition/`.
Build receipts, native controls, exact Bitcoin RPC classification responses,
classifier outputs and the replay audit are under
`<private-archive>/manifests/qbit-recovery-20260910/`. The acquisition receipt
SHA256 is `cde5e306dfb3f73cdf6ca699d06978d12f7e87f26fe564f8bc148ef2f9b96c64`.
The retained source bundle binds the acquisition implementation and shared
dependencies. Original explorer captures were copied with matching digests
and remain unchanged.

This is a complete pinned active-chain scan, not recovery of every historical
Qbit fork. The last 100 blocks present at endpoint selection and subsequent
growth are outside its declared scope. All four accepted stale headers are
already present upstream and witnessed by RSK; Qbit contributes independent
observations, not new stale identities. Application import remains separate.

## Investigation of the 24 unknown parents

Every zero-predecessor parent in the complete scan belongs to this group.
The authenticated child heights are 1739, 1769, 1780, 1791, 1800, 1807, 1837,
1905, 1907, 1911, 1912, 1913, 1921, 1923, 1935, 1940, 1948, 1953, 1966, 1967,
2038, 2044, 2047 and 2096. Their parent timestamps span 17 July 2026,
03:13:38 to 08:49:04 UTC, before the earliest canonical Bitcoin witness.

All 24 proofs have an empty parent Merkle branch, empty chain branch, zero
indices, one zero-value `OP_TRUE` output and a leading 44-byte merged-mining
commitment. Their parent `nBits` equals the Qbit child's target. Eleven parent
timestamps match the child exactly; the other thirteen are 2 to 41 seconds
ahead. The parent header hashes pass these encoded targets, but every hash
fails the contemporaneous Bitcoin target `1702369d`. Their targets also fail
the normal neighboring-epoch allowance (`17021a42|1702369d|17023ad4`).
The relevance classifier therefore emits `excluded` / `non_btc_epoch_bits`
for every row, with no strict, weak or pending result.

These are consistent with synthetic parent templates used to mine Qbit.
Their zero predecessor cannot link to a trusted Bitcoin stale root, and
their work does not qualify them for the consensus-invalid full-work error
catalogue. The pinned native source's `src/test/auxpow_tests.cpp` demonstrates
the same construction pattern, including an empty predecessor, single
coinbase and child-target proof. That is a structural comparison, not proof
that the test helper or any particular miner produced these mainnet blocks.
The generating software and operator remain unidentified.

The first extraction interpreted the 44-byte commitment as an enormous
script number and filled `btc_height` with a false value. Height inference now
rejects oversized or negative numbers. A fresh replay clears those 24 cells;
the canonical, accepted stale and lower-work classifier CSVs remain byte-for-byte
identical to the first classification. Original captures and first-generation
outputs remain intact. `tests/fixtures/qbit_synthetic_parent.json` preserves
an exact native control, and regression tests require its empty height and
excluded relevance verdict.

## Acquisition contract

`just acquire-qbit` runs `scripts/extract/extract_qbit_auxpow.py`, which
delegates to `qbit_acquisition.py`. Run `just test-qbit` in the activated
development environment for the format and acquisition failure-gate tests.
The operator supplies a settled terminal height/hash. Every active-chain
height from genesis is fetched as full native RPC bytes, authenticated against
its height lookup, and linked to the preceding serialized child header.
Direct and AuxPoW coverage are counted separately. Endpoint rechecks and
complete row counts are mandatory before a completion receipt is written.
Failures retain an incomplete run; a rerun uses a fresh private destination.

Exact JSON response bytes are retained with encoding provenance and digests.
Coverage records bind the decoded raw blocks. The receipt binds the standard
`qbit_auxpow.csv`, parser dependencies and source revision. Lower-work parents
stay in this private inventory. The normal shared classifier writes the
canonical companion and compact `qbit_validated_stales.csv`; the standard
publication exports every available canonical observation and the four stales.

Pass `--from-acquisition <sealed-directory>` instead of live RPC credentials
to authenticate and replay the captured calls, using the original endpoint
and batch size. Replay checks all retained digests and exact call order, then
reruns every normal coverage and proof gate into a fresh generation. It binds
the source receipt and current implementation without modifying original bytes.
The reviewed replay receipt SHA256 is
`f38884343e78bbe889fb5d67293148bcb1c96bcbd5820887568980699733d816`.

Classify the resulting `qbit_auxpow.csv` with the shared
`scripts/classify/classify_stales.py --chain qbit --input <replay-csv>` CLI.
Supply `--output <fresh-directory>/qbit_stale_blocks.csv`,
`--validated-output <fresh-directory>/qbit_validated_stales.csv`, and
`--keep-near`, using the normal Bitcoin RPC configuration. Retain the entire
classifier family privately; only the accepted loader input is installed under
`data/validated-stales/`. Complete publication discovers the canonical and
unknown companions alongside the primary classifier inventory.

## Validation run

`just test-qbit` passed 37 tests, including the Python 3.10 checksum regression.
The acquisition-stage focused `python -m pytest` run
covered `test_qbit.py`, `test_qbit_acquisition.py`, `test_auxpow_parse.py`,
`test_lyncoin_header_recovery.py`, `test_extract_driver.py` and
`test_rod_canonical.py`: 152 tests passed. `python -m ruff check` on the new
Python modules, adapter and tests, and `git diff --check`, passed.
The node workspace's `just config`, `just build` and corrected `just test`
passed. Native sync, all-height acquisition, raw replay, control corroboration
and cold-start checks passed independently of the fixture tests.

The publication integration passed `just test-unit` (1,749 passed, five
skipped and nine dataset tests deselected), the focused registry, loader,
novelty and relevance checks, `just lint`, `just validate-coinbase-outputs`
and `just check-leaks`. Application tests and
production import are outside this Research publication. No new runtime
dependency was introduced into the Python package.

The complete relevance, full-evidence and Monitor publication builds passed
without partial-mode exceptions. All 30 prior Monitor payloads are
byte-for-byte unchanged. An independent audit binds every new Qbit row's
parent header, child identity and coinbase evidence to the sealed acquisition.
After local installation, `just strict-weak-orphans` preserved all existing
observations and emitted empty Qbit and ROD summaries. `just test-dataset`
passed all nine publication-dataset checks.

The corrected acquisition, classifier family, full evidence, relevance results,
complete publication, executed source and verification receipts are retained
together under `<private-archive>/runs/qbit-publication-20260910/`. The corrected
acquisition receipt SHA256 is
`f38884343e78bbe889fb5d67293148bcb1c96bcbd5820887568980699733d816`.
