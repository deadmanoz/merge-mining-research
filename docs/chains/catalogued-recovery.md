# Catalogued-source recovery survey

This note records the 2026-07-10 recovery pass over every source previously
labelled "Catalogued (not recovered)" for Merge Mining Monitor. It separates
recovered child blockchains from partial mappings, source-code preservation,
terminal public-data blockers, and a negative consensus audit. Those states are
not interchangeable.

The survey is final for this pass: all nine sources have either a validated
recovery result or a reproducible terminal status. This document and the
individual chain or infrastructure notes are the coverage record; the former
campaign-specific JSON manifest was removed rather than maintaining the same
facts in parallel. A chain remains outside the integrated stale census until
its final extract, Bitcoin classification, validation gates, compact data
artifact, and loader documentation all agree.

## Outcome summary

| Source | Recovery state on 2026-07-10 | Data obtained | Monitor treatment |
|---|---|---|---|
| VCash | Partial canonical recovery | 68 fully hydrated canonical VCash-to-Bitcoin mappings from a 767-row private explorer archive; no VCash blockchain | Canonical-only partial source. Import the 68 recovered rows, but do not report stale or strict/weak totals from this subset. |
| Lyncoin | Historical recovery complete | Raw P2P extended-header capture from a live peer covers the complete pre-Flex chain; 56,653 Bitcoin-difficulty candidates, 11 canonical Bitcoin parents, and 0 stales | Historical and import-ready. The 11 canonical evidence rows remain useful even though the validated stale file is empty. |
| Jax.Network | Blocked, no public chain data recovered | Official code and container material only; seeds and explorer routes are unavailable | Catalogued only. |
| SixEleven | Historical recovery complete | Pinned official node image synced from six live peers, then scanned through height 999,406; 80,364 Bitcoin-difficulty candidates, 7 canonical Bitcoin parents, and 0 stales | Historical and import-ready. The 7 canonical evidence rows remain useful even though the validated stale file is empty. |
| BLAST | Blocked, no public chain data recovered | Pinned node reached networking and sent a version message to the only TCP-reachable candidate, which returned 0 bytes and disconnected | Catalogued only. The endpoint is unrelated web infrastructure, not a usable BLAST peer. |
| Doichain | Observed-tip survey complete, zero admissible rows | Recovered active chain through the height-430,684 tip observed on 2026-06-24, plus a complete AuxPoW characterization | Surveyed-window negative result. Do not expose as a selectable evidence source. |
| Fusioncoin | Source preservation only | Source archive, with no canonical node run or block archive | Surveyed infrastructure only. |
| Jincoin | Blocked, no public chain data recovered | Buildable source and node scaffold, but no reachable peers or block archive | Surveyed infrastructure only. |
| Bitcoin Stash | Blocked, no public chain data recovered | Source and protocol research only; no reachable peers or block archive | Catalogued only. |

## VCash: partial canonical recovery

The recovered private explorer scrape contains 767 VCash-to-Bitcoin mapping
rows. Bitcoin Core confirms 68 of those parent hashes as canonical Bitcoin
blocks. The remaining 699 are unresolved by the available archive and must not
be called stale, unknown, or rejected without the missing source-chain evidence.

`results/monitor-evidence/vcash_monitor_evidence.csv` publishes the 68 confirmed
rows with the full Bitcoin header and coinbase evidence, VCash child hash and
height, and the actual VCash child timestamp.
Every row is explicitly marked `artifact_scope=partial_canonical_subset` and
`classification=canonical`.

No VCash blockchain, block database, complete RPC export, or full explorer dump
was recovered. In particular, the 68-row file is not a substitute for the
VCash chain. It cannot measure VCash coverage, recover VCash-witnessed Bitcoin
stales, or prove that no such stales exist.

The strongest remaining recovery routes are:

1. Contact the original maintainer or explorer operator at
   `jdwldnqi837@protonmail.com` for a datadir, block export, or explorer backup.
2. Ask the former BTC.com or Bitmain AuxPoW service operators about the
   historical endpoint `39.100.112.3:3517/v1/pool/getauxblock`. The address no
   longer serves the original system and appears reassigned. Public contacts
   retained with the service research are `jasper.li@bitmain.com`,
   `hanjiang.yu@bitmain.com`, `hu60.cn@gmail.com`, and `admin@btc.com`.
3. Ask Mixin for the archived adapter or node data associated with chain record
   `c3b9153a-7fab-4138-a3a4-99849cadc073`. Public snapshots record a terminal
   height of 682,355 but do not expose block bodies. The public contact is
   `contact@mixin.one`, and the published developer group identifier is
   `7000104112`.
4. Ask the operator of `wshshra/my-vcash:v4.1.1`, at
   `wshshra@live.cn`, whether the image was paired with a retained datadir.

The historical genesis anchor is
`569ed9e4a5463896190447e6ffe37c394c4d77ce470aa29ad762e0286b896832`.
All known seeds now return NXDOMAIN, two candidate endpoints failed the
official node handshake, and inspected BTC.com VCash images contained software
but no chain data. No outreach was sent during this pass.

## Runtime recovery outcomes

### BLAST

The recovery build pins source commit
`c5c231398bd1d74dce2f465db049ce4a43e811e8` and image digest
`sha256:7cbd47b0d4cb8b6ec20ecd79f75cacaffac82b540f0460a6688db2df3c07c2a0`.
An upstream `disablewallet` startup segfault was diagnosed and fixed for the
recovery run, allowing the node to reach networking.

All six BLAST project domains resolved to `45.142.152.75`, and TCP 64640 was
open from `<archival-host>`. The node sent its BLAST version message but
received 0 bytes before the endpoint disconnected. No P2P handshake occurred.
The same domains serve unrelated Chinese gambling content, and their TLS
certificate has common name `123webtj.com`. The endpoint is not a usable BLAST
peer.

No chain data, block archive, extract, or Monitor-ready artifact was recovered.
The diagnostic logs are retained in the private archive and the container is
stopped. BLAST returns to `blocked_no_public_data`.

### Lyncoin

Lyncoin's scoped historical recovery is complete. Instead of waiting for a
full block-body sync, the recovery captured a live peer's raw P2P `headers`
stream; Lyncoin serializes the complete AuxPoW proof in each extended header.
The archive contains the continuous pre-Flex sequence from child height 0
through 260,499 and validates the next Flex boundary header at 260,500. The
capture manifest records 132 atomic batches and `complete=true`. The retained
archive is about 215 MB.

The 260,500 pre-Flex headers comprise 249,640 AuxPoW headers and 10,860 solo
headers. Validation retained 56,653 Bitcoin-difficulty parent candidates. The
candidate CSV SHA-256 is
`83eb5c13419eedddfe7040b7fe1d4506f217f4f636f47b6b3563b25c872bea56`.
Bitcoin Core classification produced 11 canonical parents, 0 stales, and
56,642 unknowns.

The compact Monitor evidence file is
`results/monitor-evidence/lyncoin_monitor_evidence.csv`, with 11 canonical rows.
The capture manifest is committed as
`node-infra/lyncoin/p2p-capture-manifest.json`, SHA-256
`5afa37dd8b788c2c0fffdbbf52d80944486f808f239f0c972d4412365ee2020e`.
The zero-stale result is preserved as the header-only
`data/validated-stales/lyncoin_validated_stales.csv`, SHA-256
`54feae508585061c47474ee4b4c1e3325da0e5cba68e6e90d1f1e652f7f4dc89`.

Lyncoin is historical and import-ready rather than surveyed. The 11 canonical
rows are admissible evidence for Merge Mining Monitor even though no stale
Bitcoin parent was found. The subsequent relevance pass assessed all 56,642
unknown candidates and found 0 strict and 0 weak BTC orphans. Every unknown
failed the Bitcoin epoch-`nBits` consistency gates.

### SixEleven

SixEleven's blockchain recovery is complete through its canonical height
999,406 tip. The node finished with six connected peers and a 2.4 GB datadir.
The runtime pinned the official `611project/611coin` OCI index digest
`sha256:e4448b4c626288e257eb28399c8d1ec85828ab49b46cc94978d1096a645752cc`
and linux/amd64 manifest digest
`sha256:64a174792a4a2112d06c895a72bfcb70c8d25b2ab19bfe624d235cc75a156283`.
Consensus inspection and live blocks establish chain ID 1 and an AuxPoW
activation floor at child height 19,200.

The complete legacy `blkNNNN.dat` pass explicitly excluded `blkindex.dat`
and scanned 999,407 blocks: 30,090 non-AuxPoW blocks and 969,317 AuxPoW blocks,
with 0 parse errors and 0 chain-ID mismatches. It retained 80,364 parents that
clear Bitcoin difficulty. Exact child heights, hashes, versions, and timestamps
were then validated through the legacy RPC. Each row required nonnegative
confirmations and `getblockhash(height)` equality before classification.

Against Bitcoin Core at tip 957,432, the 80,364 candidates classify as 7
canonical parents, 0 stales, and 80,357 unknowns. The raw candidate CSV SHA-256
is `7641d1dda75b2fed4bc280063a57317ea54c1863147198bdf14aa6cde5e9381c`;
the exact-height-normalized candidate CSV SHA-256 is
`5b32ef52777ca4465bcffacb312e8116b83227cc55fd13c33ba9ae9a90ee886a`.

The compact Monitor evidence file is
`results/monitor-evidence/sixeleven_monitor_evidence.csv`, with 7 canonical rows.
The zero-stale result is preserved as the header-only
`data/validated-stales/sixeleven_validated_stales.csv`, SHA-256
`54feae508585061c47474ee4b4c1e3325da0e5cba68e6e90d1f1e652f7f4dc89`.
SixEleven is historical and import-ready rather than surveyed.
The subsequent relevance pass assessed all 80,357 unknown candidates and found
0 strict and 0 weak BTC orphans. Every unknown failed the Bitcoin epoch-`nBits`
consistency gates.

## Completed negative and exclusion audits

### Doichain

Doichain's recovery is now documented independently in
[`doichain.md`](doichain.md). The synced node, blkdat extraction, exact-height
normalizer, Bitcoin classifier, population characterization, strict/weak
review, and compact zero-row outputs are documented in the repository. The
recovered window through the active-chain tip observed at child height 430,684
produced 0 accepted direct-stale candidates, 0 strict BTC orphans, and 0 weak
BTC orphans.

## Blocked and source-only records

- Jax.Network has official code and image material, but its seeds, explorer,
  and public data routes are unavailable. A prior operator estimated backups
  at about 142 MB for the beacon and 1.9 GB for shards. Those are estimates,
  not recovered files or verified current chain sizes.
- Fusioncoin has retained source material only. No node run, extraction,
  classifier, or canonical result exists.
- Jincoin builds from its retained source, but all standard peer discovery
  routes were dead and no block archive was found.
- Bitcoin Stash has no reachable peer or recovered archive. Reserve roughly
  150 GB if a full datadir becomes available. This is an estimate based on
  prior chain research, not a measured artifact.

## Storage and archive boundaries

| Source | Capacity guidance | Basis |
|---|---:|---|
| VCash | 20 to 50 GB | Inferred estimate for a possible full datadir. No chain data was recovered. |
| Lyncoin | About 215 MB recovered | Raw extended-header archive. A full-node fallback still needs an estimated 5 to 10 GB. |
| Jax.Network | About 2.0 GB combined | Prior operator estimate of about 142 MB beacon plus 1.9 GB shards. No files recovered. |
| SixEleven | About 2.4 GB recovered | Complete datadir through canonical height 999,406. |
| Bitcoin Stash | About 150 GB | Prior research estimate for a possible full datadir. No files recovered. |
| BLAST | No chain-data estimate | The recovery image and diagnostic logs are retained, but no datadir or block archive was recovered. |
| Doichain, Fusioncoin, Jincoin | No new estimate recorded | Either no recoverable data route was found or the completed datadir is already retained. |

Raw datadirs, block archives, source dumps, extractor intermediates, and
classifier scratch outputs remain outside the public repository. Only compact,
auditable artifacts belong in `data/` or `results/`.
