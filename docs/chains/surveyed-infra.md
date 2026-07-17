# Surveyed and infrastructure-only chains

This note records chain-specific infrastructure and edge-case recovery states
that cannot be understood from the presence of a node workspace alone. It
includes blocked and source-only chains as well as completed historical or
surveyed recoveries with zero accepted direct-stale candidates.

The presence of `node-infra/<chain>/`, archived source tarballs, retired Docker
workdirs, or remote raw chain data is not enough to make a chain part of the
analysis. A chain enters the integrated set only after it has a committed
validated-stale input, including a header-only file for a supported zero-stale
result, a loader in `stale_blocks.py`, and documentation that records
provenance, filtering, and novelty results.

The detailed 2026-07-10 pass over all nine sources formerly labelled
"Catalogued (not recovered)" is recorded in
[`catalogued-recovery.md`](catalogued-recovery.md). Compact canonical rows live
with the other final Monitor outputs under `results/monitor-evidence/`, while
acquisition provenance stays beside the relevant node workspace.

## Status table

| Chain | Evidence retained | Current status | Analysis treatment |
|---|---|---|---|
| BLAST | `node-infra/blast/`; pinned recovery image; archived diagnostic logs | The node sent a version message to the only TCP-reachable candidate, received 0 bytes, and disconnected without a P2P handshake. The domains serve unrelated gambling content with TLS common name `123webtj.com`. No chain data was recovered. | Blocked with no public data. Keep catalogued, with the failed endpoint retained as a reproducible terminal blocker. |
| Bitcoin Stash | Source and protocol research | No reachable peer or block archive was found. The roughly 150 GB capacity figure is an estimate for a possible future datadir, not recovered data. | Catalogued only. No public data file, loader, or result row. |
| Fusioncoin | Private source archive retained locally and in the remote chain archive | Source-preservation record only. No node run, extraction, classifier, or result output is canonical. | Surveyed only. |
| Jax.Network | Official source and container material | Seeds, explorer, and public data routes were unavailable. Prior operator estimates of about 142 MB for the beacon and 1.9 GB for shards are not recovered files. | Catalogued only. No public data file, loader, or result row. |
| Jincoin | `node-infra/jincoin/`; remote archive material | Source builds, but all standard discovery paths were dead during the May 2026 survey. No live sync or private block archive is available. | Surveyed only. Preserve build scaffold for a future private archive or peer discovery. |
| [Lyncoin](lyncoin.md) | Raw P2P extended-header archive and `node-infra/lyncoin/p2p-capture-manifest.json`; `node-infra/lyncoin/` is the full-node fallback scaffold; compact evidence in `results/monitor-evidence/lyncoin_monitor_evidence.csv` and header-only `data/validated-stales/lyncoin_validated_stales.csv` | A live peer's `headers` messages supplied the complete AuxPoW proofs for heights 0 through 260,499 plus the validated 260,500 Flex boundary. The recovery found 0 accepted direct-stale candidates, 0 strict orphans, and 0 weak orphans. | Historical and integrated. The 11 canonical rows are committed as Monitor evidence; all 56,642 unknown candidates failed the Bitcoin epoch-`nBits` consistency gates. |
| [SixEleven](sixeleven.md) | `node-infra/sixeleven/`, pinned official `611project/611coin` image, and private 2.4 GB recovered datadir; compact evidence in `results/monitor-evidence/sixeleven_monitor_evidence.csv` and header-only `data/validated-stales/sixeleven_validated_stales.csv` | The node synced from six live peers through the observed height-999,406 tip. A complete legacy `blkNNNN.dat` scan, excluding `blkindex.dat`, found 0 accepted direct-stale candidates, 0 strict orphans, and 0 weak orphans after exact child identity validation. | Historical and integrated. The 7 canonical rows are committed as Monitor evidence; all 80,357 unknown candidates failed the Bitcoin epoch-`nBits` consistency gates. |
| Doichain | `node-infra/doichain/`; private recovered datadir and aggregate characterization; header-only validated, strict/weak, and Monitor outputs | The observed-tip survey covered child heights 0 through 430,684. It found 0 accepted direct-stale candidates and 0 strict or weak observations. Separately, 300,625 canonical-tip commitments matched exact expected Bitcoin `nBits` and BIP34 height. | Integrated zero-stale loader result. The aggregate supports Bitcoin-derived work-template use, but no row-level canonical export is committed, so Doichain remains non-selectable in the Monitor. |
| VCash | `results/monitor-evidence/vcash_monitor_evidence.csv`; private explorer mapping archive | 68 canonical mappings are fully hydrated from a 767-row archive, but no VCash blockchain was recovered and 699 mappings remain unresolved. | Canonical-only partial evidence. Import the 68 recovered rows, but do not report stale or strict/weak totals from this subset. |

## Archive policy

These artifacts are intentionally retained because they preserve recovery
context: source provenance, build recipes, node-operation notes, or evidence
that a live network path is unavailable. Lyncoin and SixEleven have completed
that path and publish only their compact evidence and zero-stale files. For the
partial, blocked, source-only, and excluded rows, infrastructure or private
archives should not be copied into public `data/` or counted in public results
unless a future task completes the normal extraction, classification,
validation, and documentation path.
