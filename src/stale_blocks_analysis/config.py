"""Configuration for the acquisition/recovery side of the package.

Paths, protocol constants, the per-chain validated-CSV locations, the
relevance-bucket vocabulary shared with the merge-mining-monitor, chain
chronology, and the CHAIN_SPECS registry. Imported by every other module
in the package; depends on nothing internal (stdlib only).

Importing this module has one side effect: creating the output directories
(RESULTS_DIR, CACHE_DIR) if they don't exist. Other modules assume these
directories exist at import time, so don't remove the mkdir loop below.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

# Project root: repo root containing data/, results/, and cache/.
# This file lives at src/stale_blocks_analysis/config.py, so parents[2]
# is the repo root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Input data: the bitcoin-data/stale-blocks repository. Default location is
# data/stale-blocks under the project root (cloned by scripts/fetch-data.sh).
# Override with the STALE_BLOCKS_DIR environment variable.
DATA_DIR = PROJECT_ROOT / "data"
# Committed per-chain VALID-only stale loader inputs
# (<chain>_validated_stales.csv). Nested under data/ for layout clarity; this
# path is a published cross-repo contract consumed by merge-mining-monitor's
# historical-source manifest, so changes here must land in lockstep there.
VALIDATED_STALES_DIR = DATA_DIR / "validated-stales"
VALIDATED_STALES_DIR.mkdir(parents=True, exist_ok=True)
STALE_DIR = Path(os.environ.get("STALE_BLOCKS_DIR", DATA_DIR / "stale-blocks"))
STALE_CSV = STALE_DIR / "stale-blocks.csv"
BLOCKS_DIR = STALE_DIR / "blocks"

# Compact, committed Bitcoin retarget-epoch reference data fetched from a
# public Esplora-compatible API. Unlike CACHE_DIR, this is reproducible input
# data and is safe to consume in CI without access to an operator's node.
BITCOIN_EPOCH_REFERENCE_DIR = DATA_DIR / "bitcoin-epoch-reference"

# Compact repo-owned overlay for upstream or per-chain rows that later
# available evidence proved consensus-invalid or misclassified as direct
# stales. This is applied
# to every public stale loader until the corresponding source dataset is
# corrected and the pinned revision is updated.
STALE_EXCLUSIONS_CSV = DATA_DIR / "stale_block_exclusions.csv"

# Output locations (all relative to the project root).
RESULTS_DIR = PROJECT_ROOT / "results"
CACHE_DIR = PROJECT_ROOT / "cache"
for _d in (RESULTS_DIR, CACHE_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# AuxPoW-recovered stale blocks (Namecoin merged mining side channel).
# See docs/chains/namecoin.md for methodology.
AUXPOW_CSV = VALIDATED_STALES_DIR / "namecoin_validated_stales.csv"

# AuxPoW-recovered stale blocks (Geistgeld merged mining side channel).
# Geistgeld is a dead 2011 merge-mined chain with no surviving public
# infrastructure; the recovery source is Nicholas Stifter's complete
# `getblock`-JSON sneakernet dump (one JSONL record per Geistgeld block).
# `auxpow.coinbasetx` in the dump has no `vout` field, so the validated
# CSV's `coinbase_outputs` column is always empty — pool ID downstream
# relies on scriptsig markers only (same as Terracoin's pre-fix state).
# Chronological position 2: catalogue activation date 2011-10-08, tied
# with Namecoin and broken alphabetically. The dump shows AuxPoW activity
# from GG height 14,092 (parent_block.time 2011-09-16), ~22 days earlier
# than the catalogue date, but those pre-Oct-2011 commitments come from
# Geistgeld's own copy of Durham's AuxPoW implementation (Lolcust's fork of
# sacarlson's MultiCoin-exp) used at relaxed difficulty — parent headers
# don't resolve to BTC mainchain and zero validated BTC stales survive
# classification. See docs/chains/geistgeld.md for methodology.
GEISTGELD_CSV = VALIDATED_STALES_DIR / "geistgeld_validated_stales.csv"

# AuxPoW-recovered stale blocks (Syscoin merged mining side channel).
# See docs/chains/syscoin.md for methodology.
SYSCOIN_CSV = VALIDATED_STALES_DIR / "syscoin_validated_stales.csv"

# AuxPoW-recovered stale blocks (Devcoin merged mining side channel).
# See docs/chains/devcoin.md for methodology.
DEVCOIN_CSV = VALIDATED_STALES_DIR / "devcoin_validated_stales.csv"

# AuxPoW-recovered stale blocks (ixcoin merged mining side channel).
# See docs/chains/ixcoin.md for methodology.
IXCOIN_CSV = VALIDATED_STALES_DIR / "ixcoin_validated_stales.csv"

# AuxPoW-recovered stale blocks (i0coin merged mining side channel).
# Offline blk*.dat parse of 2018 snapshot on <archival-host>.
I0COIN_CSV = VALIDATED_STALES_DIR / "i0coin_validated_stales.csv"

# AuxPoW-recovered stale blocks (CoiledCoin merged mining side channel).
# Offline blk*.dat parse of a P2P-synced node on <archival-host> (pre-0.6
# Bitcoin Core fork; see node-infra/coiledcoin/). Chronological position
# 5: AuxPoW activation 2012-01-05 (genesis). 27 stales, narrow window
# BTC 161,761 -> 187,452 (Jan 2012 -> Jul 2012). Includes a flag column
# `eligius_attack_window` marking records in the 2012-01-05..2012-01-15 window.
# See docs/chains/coiledcoin.md for methodology.
COILEDCOIN_CSV = VALIDATED_STALES_DIR / "coiledcoin_validated_stales.csv"

# AuxPoW-recovered stale blocks (Groupcoin merged mining side channel).
# Groupcoin is a dead 2012-2018 merge-mined chain with no surviving public
# infrastructure; the recovery source is Nicholas Stifter's complete
# `getblock`-JSON sneakernet dump (one JSONL record per Groupcoin block;
# 235,752 total / 218,494 AuxPoW-bearing, 93% AuxPoW share).
# Chronological position 7: AuxPoW activation 2012-02-16 (verified from
# the dump — first AuxPoW block at GPC height 17,187 with parent_block.time
# 2012-02-16 10:56:16 UTC, matching the catalogue date).
# Quirk: `coinbasetx.vout[*].scriptPubKey.addresses` in the dump are
# Groupcoin-base58-encoded (e.g. `2h…`), NOT BTC mainnet; the classifier
# emits raw `scriptPubKey.hex` semicolon-joined into `coinbase_outputs`
# (Unobtanium / Huntercoin pattern), preserved for later attribution research.
# See docs/chains/groupcoin.md for methodology.
GROUPCOIN_CSV = VALIDATED_STALES_DIR / "groupcoin_validated_stales.csv"

# AuxPoW-recovered stale blocks (Huntercoin SHA-256d branch merged mining
# side channel). Huntercoin is dead with no reachable live node; data
# sourced via fetch_huntercoin_arweave.py from the domob1812/arblockstore
# permaweb archive (first ~100k HUC blocks). Chronological position 8:
# AuxPoW activation 2014-01-31. 13 validated stales (Feb-Mar 2014, BTC
# 285,130 -> 290,178). AuxPoW chain ID = 6 for the SHA-256 branch
# (BTC parent); 2 for the Scrypt branch (LTC parent) which is out of scope.
# See docs/chains/huntercoin.md for methodology.
HUNTERCOIN_CSV = VALIDATED_STALES_DIR / "huntercoin_validated_stales.csv"

# AuxPoW-recovered stale blocks (Elastos merged mining side channel).
# Hybrid extraction: local node on <archival-host> for heights 177,000..1,817,250
# (covered by chaindata), public RPC at api.elastos.io/ela for 1,817,251..tip.
# See docs/chains/elastos.md for methodology.
ELASTOS_CSV = VALIDATED_STALES_DIR / "elastos_validated_stales.csv"

# AuxPoW-recovered stale blocks (Unobtanium merged mining side channel).
# Bitcoin Core 0.11 fork; getblock JSON has no decoded auxpow field, so
# extraction reads raw block hex and parses the Namecoin-style CAuxPow
# binary in Python. AuxPoW activates at UNO height 600,000 (May 2015).
# See docs/chains/unobtanium.md for methodology.
UNOBTANIUM_CSV = VALIDATED_STALES_DIR / "unobtanium_validated_stales.csv"

# AuxPoW-recovered stale blocks (Crown merged mining side channel).
# Crown is a 2014 Bitcoin/Dash-derived chain with standard Namecoin-style
# AuxPoW (chain ID 20, fStrictChainId=true). AuxPoW activates at Crown
# height 453,273 (block timestamp 1440546428 = 2015-08-25 UTC). Crown
# went PoS-hybrid at height 2,330,000 — PoS blocks carry no AuxPoW, and
# in the PoS era the nVersion chain-ID field rotated 20→22 (irrelevant
# since PoS blocks never set the AuxPoW flag). getblock exposes no
# decoded auxpow JSON field, so extraction reads raw block hex and
# parses the CAuxPow binary in Python (extract_crown_auxpow.py); the
# only gate is the AuxPoW version bit (no per-algo filter — Crown is
# single-algo SHA-256d). Recovery 2026-05-20: chain synced on <archival-host>
# from a Wayback-harvested live peer; 1,868,911 AuxPoW commitments over
# the PoW window (453,273 → ~2,330,000) → 23 validated BTC stales.
CROWN_CSV = VALIDATED_STALES_DIR / "crown_validated_stales.csv"

# AuxPoW-recovered stale blocks (Myriadcoin SHA-256d branch).
# Multi-algo PoW chain (SHA-256d / Scrypt / Groestl / Yescrypt / Argon2d;
# Yescrypt replaced Qubit at XMY 1,764,000 in 2016 and Argon2d replaced
# Skein at 2,772,000 in ~2019). Only the SHA-256d branch is Bitcoin-parent
# merge-mined; the extractor (extract_myriadcoin_auxpow.py) filters on
# nVersion bits 9-11 (BLOCK_VERSION_ALGO = 7<<9) to keep only algo==0
# (SHA-256d) before parsing the Namecoin-style CAuxPow. AuxPoW activates
# at XMY height 1,402,000 (block timestamp 1443262763 = 2015-09-26 UTC).
# fStrictChainId=false, so the SHA-256d branch accepts AuxPoW from any
# SHA-256d parent; the classify_myriadcoin_stales.py phase-1 filter only
# checks each parent header against its own encoded target, and Bitcoin
# parentage is established by Bitcoin Core lookup plus the nBits gate.
MYRIADCOIN_CSV = VALIDATED_STALES_DIR / "myriadcoin_validated_stales.csv"

# AuxPoW-recovered stale blocks (Bitmark SHA-256d branch -- multi-algo).
# Bitmark is an 8-algo PoW chain with all algorithms merge-mineable since
# Fork 1. Only the SHA-256d branch is Bitcoin-parent in this project scope;
# the extractor filters on nVersion bits 9-11 (ALGO_SHA256D = 1 on
# Bitmark, unlike Myriadcoin where SHA-256d encodes as 0) and the AuxPoW
# flag before parsing the Namecoin-style CAuxPow tail. Fork 1 activation is
# pinned at BTMK height 450,947 (2018-06-07 04:18:55 UTC). The single
# validated stale is cross-confirmation only: it is already in the
# Unobtanium and Myriadcoin validated sets.
BITMARK_CSV = VALIDATED_STALES_DIR / "bitmark_validated_stales.csv"

# AuxPoW-recovered stale blocks (Argentum SHA-256d branch — multi-algo).
# Argentum is a multi-algo PoW chain (pre-2018-03 fork: Scrypt + SHA-256d
# only; post-fork height >= 2,977,000: Scrypt + SHA-256d + Lyra2REv2 +
# Myriad-Groestl + Argon2d + Yescrypt). Only the SHA-256d branch carries
# Bitcoin-parent AuxPoW. The extractor (extract_argentum_auxpow.py)
# filters on (nVersion & 0x0E00) == 0x0200 — note this differs from
# Myriadcoin where SHA-256d is the default 0 algo; in Argentum SHA-256d
# is explicit (1<<9) and Scrypt is the default. AuxPoW activates at ARG
# height 1,825,000; activation_date in CHAINS_BY_AUXPOW_ACTIVATION uses
# the 2016-04-10 multi-algo relaunch ANN date (per chronological-ordering
# convention) rather than the 2013-05-22 standalone-Scrypt genesis.
# fStrictChainId=false on Argentum (identical to Myriadcoin) — the
# defensive self-target PoW filter in
# classify_argentum_stales.py enforces Bitcoin-only parents in practice.
ARGENTUM_CSV = VALIDATED_STALES_DIR / "argentum_validated_stales.csv"

# AuxPoW-recovered stale blocks (Terracoin merged mining side channel).
# JSON-decoded RPC extraction (decoded `auxpow` object as for Syscoin,
# via boolean-verbose `getblock`) over TRC heights 833,000 → tip.
# See docs/chains/terracoin.md for methodology. The `coinbase_outputs`
# column carries decoded `addr:value|...` entries: terracoind
# (Dash-Core-0.12.x-derived) exposes parent-coinbase addresses via the
# legacy plural `scriptPubKey.addresses` field, and the 2026-05-29 backfill
# re-fetched the 35 validated rows with that shape after the original
# extractor had read only the modern singular `.address` field and stored
# type labels.
TERRACOIN_CSV = VALIDATED_STALES_DIR / "terracoin_validated_stales.csv"

# Recovered stale blocks from the RSK / Rootstock merge-mining side channel.
# The committed file preserves historical labels derived from RSK miner
# addresses because the extractor preserves the BTC header and compressed proof
# material, not a reconstructable full BTC coinbase transaction. Those labels
# may remain stored in `pool_label` for provenance, but load_rsk_stales ignores
# them. Like every other chain the committed file is VALID-stales-only;
# the full stale/unknown inventory stays in the private chain archive.
RSK_CSV = VALIDATED_STALES_DIR / "rsk_validated_stales.csv"

# Recovered stale blocks from Hathor's merge-mining side channel.
# Hathor uses an RFC-0006 split-header proof with a "Hath" coinbase tag,
# distinct from Namecoin-family CAuxPow. The tag can appear in scriptSig or an
# output. The classifier reconstructs the BTC-format parent header from
# funds+graph bytes, applies its encoded target, and retains rows whose
# predecessor resolves on Bitcoin's active chain. RPC misses remain unresolved;
# the production classifier does not identify their parent chain.
HATHOR_CSV = VALIDATED_STALES_DIR / "hathor_validated_stales.csv"

# Derived BTC stale-fork descendants recovered from the unknown inventories.
# Generated by scripts/analysis/reconcile_unknown_stale_ancestry.py. These
# rows preserve the raw classifier's one-hop `unknown` semantics while
# promoting only entries whose backward header walk reaches a known stale and
# whose validation_status is VALID_STALE_DESCENDANT.
STALE_DESCENDANTS_CSV = DATA_DIR / "stale_descendants.csv"

# AuxPoW-recovered stale blocks (Emercoin merged mining side channel).
# Hybrid PoW/PoS chain in the Peercoin lineage — only PoW blocks carry
# the Namecoin-style AuxPoW commitment, and only ~15.5% of post-MMHeight
# blocks are PoW (the rest are PoS and have no parent-header proof).
# The extractor (extract_emercoin_auxpow.py) filters PoS via the RPC
# ``flags`` field ("proof-of-work" vs "proof-of-stake") which mirrors
# nFlags & BLOCK_PROOF_OF_STAKE (src/primitives/block.h:36).
# AUXPOW_CHAIN_ID = 666; MMHeight = 219,809 (2017-03-17 UTC).
# Parent-header reconstruction is done from RPC JSON (no binary CAuxPow
# parse needed — Emercoin RPC exposes the full parent_block object).
EMERCOIN_CSV = VALIDATED_STALES_DIR / "emercoin_validated_stales.csv"

# AuxPoW-recovered stale blocks (Fractal Bitcoin merged mining side channel).
# Raw header extraction over FB heights 1 -> tip via
# `getblockheader <hash> false true`, which returns the compact Fractal block
# header with the CAuxPow tail but without full Fractal transaction data.
# Cadence Mining targets roughly one-third AuxPoW blocks. The extractor must
# not test only version bit 0x100: the 0x20260100 Indexer class sets the flag
# but carries a different proof. The protocol predicate combines that flag
# with chain ID 0x2024; 0x20240100 is the observed encoding in this recovery.
# Chronological latest chain in scope; post-genesis launch 2024-09-09.
# See docs/chains/fractal.md for methodology.
FRACTAL_CSV = VALIDATED_STALES_DIR / "fractal_validated_stales.csv"

# AuxPoW-recovered stale blocks (Bitcoin Vault merged mining side channel).
# Namecoin-byte-identical AuxPoW wire format under a refactored class layout
# (CAuxPow validator separate from CAuxBlockHeader data carrier — see
# src/primitives/block.h in bitcoinvault/bitcoinvault). The chain is dormant
# (tip h=228,360 stalled since 2024-03-10), so Phase 2 extraction went via
# Blockbook REST (btcvexplorer.com /api/rawblock/<hash>) rather than a live
# node — a first in the project. Coverage h=58,420 → 228,360 (99.99%, only
# 2 blocks legitimately solo-mined-without-AuxPoW). Of 169,939 commitments,
# 167,364 (98.5%) meet only BTCV's lower aux-difficulty target — weak-share
# submissions, especially in the Binance era post-Sep 2021. 9 stale
# BTC blocks recovered (original run 8; the June 2026 refresh added the
# already-upstream h=665,005) - 6 novel vs upstream, zero overlap with
# earlier chain CSVs. After BTC h=699,616 / BTCV h=100,670 (2021-09-08),
# zero additional accepted direct-stale candidates were produced despite
# ~128k more BTCV AuxPoW blocks. Chain ID 0x0666 (1638 dec) — DO NOT confuse with
# Emercoin's 666 dec (0x029A hex), different by an order of magnitude.
# See docs/chains/bitcoin-vault.md for methodology.
BITCOIN_VAULT_CSV = VALIDATED_STALES_DIR / "bitcoin-vault_validated_stales.csv"

# AuxPoW-recovered stale blocks (Electric Cash / ELCASH merged mining side
# channel). Bitcoin Core 0.20.2 fork with strict chain ID 0x2137 (8503),
# merge-mined from its fresh 2020-12-20 genesis (nAuxpowStartHeight=1).
# Recovered from a self-synced elcashd node; the three VALID stale parents
# (BTC 688,349 / 693,118 / 699,616, Jun-Sep 2021) all re-observe headers
# first-claimed by Bitcoin Vault. Real-difficulty merge-mining ran Jan 2021
# to Nov 2024 (peak Sep-Oct 2021). The full canonical-plus-stale classified
# set lives in the private chain archive (no unknown rows).
ELCASH_CSV = VALIDATED_STALES_DIR / "elcash_validated_stales.csv"

# Complete zero-stale recoveries. Lyncoin's full evidence came from its raw P2P
# extended-header stream; SixEleven and Doichain came from complete legacy
# blkNNNN.dat scans of pinned source builds.
LYNCOIN_CSV = VALIDATED_STALES_DIR / "lyncoin_validated_stales.csv"
SIXELEVEN_CSV = VALIDATED_STALES_DIR / "sixeleven_validated_stales.csv"
DOICHAIN_CSV = VALIDATED_STALES_DIR / "doichain_validated_stales.csv"

# AuxPoW-recovered stale blocks (Xaya / CHI merged mining side channel).
# Xaya is multi-algo: blocks are mined either with NEOSCRYPT (solo) or
# SHA256D-AuxPoW (merge-mined with Bitcoin). The source enforces "SHA256D must
# be merge-mined", so every SHA256D Xaya block carries a Bitcoin-parent CAuxPow
# and NEOSCRYPT blocks carry none. The on-disk block prepends a PowData wrapper
# after the 80-byte header (algo:uint8 + nBits:uint32 + CAuxPow|fakeHeader);
# the extractor (extract_xaya_auxpow.py) parses that wrapper and reuses the
# shared Namecoin-style CAuxPow parser, keying purely on the 0x80 merge-mined
# flag. AuxPoW chain ID 1829 (0x0725); SHA256D-AuxPoW active from genesis
# (2018-07-13; the genesis block itself is NEOSCRYPT). Recovered offline from
# Xaya's open blocks.zip dump (2024-11-15 snapshot, ~6.34M blocks):
# 1,695,912 merge-mined blocks -> 38,483 self-target-PoW-valid parent headers
# -> classified. The legacy P2P network is fully down (see
# node-infra/xaya/peers.list), so the snapshot, not a live node, is the data
# path; the 6.34M -> ~7.3M deprecation-height tail is a documented coverage gap.
XAYA_CSV = VALIDATED_STALES_DIR / "xaya_validated_stales.csv"

# Chronological ordering by earliest evidenced Bitcoin merge mining. Most
# entries use the chain's AuxPoW activation date; custom proof formats use the
# earliest source-confirmed production evidence.
#
# Used by per-chain documentation and the chain-novelty helper to attribute
# "first-seen" credit when the same BTC stale appears in multiple chains'
# validated sets. The rule: earlier-born chain has novelty precedence. This
# is a simplifying convention for reproducible attribution — NOT a claim
# that the earlier-born chain literally observed the stale first in real
# time (a chain only "sees" a BTC stale when its miners actually embed
# AuxPoW proofs, so a younger chain could in principle have observed any
# given stale earlier than an older one). Chain age is intrinsic and stable;
# integration order in the merge pipeline is not.
#
# Dates mark the start of the recoverable merge-mining mechanism, not chain
# genesis. For a chain like Unobtanium (genesis Oct 2013, AuxPoW activation May
# 2015), the proof-activation date is the meaningful one for stale observability.
#
# Source: see docs/auxpow-recovery.md for methodology. The authoritative
# catalogue itself draws on Stifter et al. 2018 plus per-chain source-code
# verification of chainparams + auxpow.cpp.
#
# Geistgeld and Namecoin share the catalogue activation date 2011-10-08.
# The Stifter sneakernet Geistgeld dump (arrived 2026-05-15) shows AuxPoW
# commitments from GG height 14,092 / 2011-09-16 — ~22 days before the
# catalogue date (25 days before Namecoin's own height-19200 block on
# 2011-10-11) — but those early blocks come from Geistgeld's own copy of
# Durham's AuxPoW implementation used at relaxed difficulty, not real BTC
# merge-mining: parent headers don't resolve to BTC mainchain, Geistgeld's
# aux chain id is operator-configurable (-OurChainID, default 0, not fixed
# from the public record), and Geistgeld produces zero validated BTC stales
# after classification. We therefore use the catalogue 2011-10-08 production
# date for both chains and break the tie alphabetically — Geistgeld at
# position 2, Namecoin at position 1. See docs/chains/geistgeld.md §2
# for the reasoning.
CHAINS_BY_AUXPOW_ACTIVATION: list[tuple[str, str]] = [
    ("namecoin", "2011-10-08"),
    (
        "geistgeld",
        "2011-10-08",
    ),  # catalogue tie with Namecoin; alphabetical tie-break to second
    ("i0coin", "2011-12-20"),
    ("ixcoin", "2011-12-31"),
    ("coiledcoin", "2012-01-05"),  # source genesis nTime 1325782557 (2012-01-05)
    ("devcoin", "2012-01-07"),
    ("groupcoin", "2012-02-16"),
    ("huntercoin", "2014-01-31"),
    ("unobtanium", "2015-05-08"),
    (
        "crown",
        "2015-08-25",
    ),  # AuxPoW activation block 453,273 (timestamp 1440546428); PoW window only — chain went PoS-hybrid at h=2,330,000
    ("myriadcoin", "2015-09-26"),  # SHA-256d branch; AuxPoW from XMY height 1,402,000
    ("sixeleven", "2015-11-03"),  # chain ID 1; AuxPoW from child height 19,200
    (
        "argentum",
        "2016-04-10",
    ),  # SHA-256d branch; multi-algo relaunch ANN date (chain born 2013-05-22 standalone-Scrypt)
    (
        "terracoin",
        "2016-09-23",
    ),  # hard fork 1 (DGW + merged mining) at TRC 833,000, block time 2016-09-23;
    # the catalogue's 2017-10 month belongs to the later Dash-features fork
    # at TRC 1,087,500 (2017-10-02)
    (
        "emercoin",
        "2017-03-17",
    ),  # MMHeight=219,809 (PoW blocks only; chain is hybrid PoW/PoS, ~15.5% PoW)
    ("rsk", "2018-01-01"),  # catalogue records month-precision only
    ("doichain", "2018-05-23"),  # first mined block; AuxPoW accepted from height 1
    ("bitmark", "2018-06-07"),  # SHA-256d branch; Fork 1 multi-algo/AuxPoW activation
    (
        "xaya",
        "2018-07-13",
    ),  # SHA256D-AuxPoW from genesis (genesis block itself is NEOSCRYPT)
    ("elastos", "2018-08-26"),
    ("syscoin", "2019-06-03"),  # Syscoin chain 2 (fresh-genesis 2019 launch)
    ("hathor", "2020-01-24"),  # earliest source-confirmed version-3 block
    ("bitcoin-vault", "2020-11-17"),  # BTCV mainnet AuxPoW activation block h=58420
    ("elcash", "2020-12-20"),  # fresh genesis nTime; AuxPoW permitted from height 1
    (
        "lyncoin",
        "2022-12-30",
    ),  # strict chain ID 0x0b0d; pre-Flex AuxPoW through height 260,499
    ("fractal", "2024-09-09"),
]


# BIP34's historical mainnet transition. The coinbase-height rule applied to
# version 2 or newer blocks from height 224,413. Version 1 became invalid at
# height 227,931, making the height prefix mandatory for every later block.
BIP34_VERSION_2_HEIGHT = 224_413
BIP34_HEIGHT = 227_931
BIP66_HEIGHT = 363_725
BIP65_HEIGHT = 388_381

# Derived BTC-stale-relevance bucket vocabulary, emitted by
# scripts/analysis/classify_btc_stale_relevance.py in the
# `btc_stale_relevance` column. This is the shared refinement taxonomy:
# `unknown` in the primary `classification` axis stays a single evidence
# state (legacy artifacts wrote `orphan`; readers accept both), and these
# buckets refine it. "Orphan" is used ONLY in this strict/weak sense
# repo-wide. The merge-mining-monitor's BTC-orphan classifier is a port of
# that script and its importer reads these exact strings — renames must land
# in lockstep with the monitor.
#
# There is no "confirmed" bucket here: `stale`/`stale_descendant` rows carry
# a VALID validation status on the primary `classification` axis already, so
# a confirmed row is written with an EMPTY `btc_stale_relevance` and a
# `relevance_reason` of `valid_direct_stale` / `valid_stale_descendant`. The
# derived axis holds only the unknown-row refinement values below.
RELEVANCE_STRICT_BTC_ORPHAN = "strict_btc_orphan"
RELEVANCE_WEAK_BTC_ORPHAN = "weak_btc_orphan"
RELEVANCE_EXCLUDED = "excluded"
# Verdict for rows whose height/time lies beyond the committed nBits
# table's coverage: no final verdict yet, re-classifiable once the table
# is extended. Mirrors the monitor's `pending` horizon semantics.
RELEVANCE_PENDING = "pending"

# Default height floor for the loader functions in stale_blocks.py,
# snapped to a DAA (2016-block) epoch start: epoch 209 (421,344), one full
# epoch after the BIP 152 activation at 420,000. Acquisition-side callers that
# want everything pass min_height=0 explicitly.
MIN_HEIGHT = 421_344  # epoch 209 (first DAA ≥ BIP 152 activation at 420,000)


# ── Per-chain integration specs ────────────────────────────────────────────
#
# A single declarative record per integrated merge-mined chain, consolidating
# the values that today live scattered across each chain's
# scripts/classify_<chain>_stales.py (height column, CSV paths), its
# scripts/extract_<chain>_auxpow.py (chain ID, proof activation or extraction floor), and
# the per-chain provenance docs (docs/chains/<chain>.md). These specs are the
# live source of truth: run_classifier(CHAIN_SPECS[...]) drives the ~19 thin
# classify wrappers and full_evidence reads them directly, so edits here change
# runtime behaviour.
#
# Field provenance and conventions:
#   - key: the canonical chain key, matching CHAINS_BY_AUXPOW_ACTIVATION
#     (hyphenated for "bitcoin-vault" / "fractal").
#   - height_column: the chain's OWN height column in its raw/classified CSVs
#     (e.g. "sys_height"), not the BTC parent height ("btc_height").
#   - chain_id: the AuxPoW chain ID embedded in the child block nVersion high
#     16 bits. None where the value is not needed for our recovery and
#     not confirmed from source (the JSON-dump chains Geistgeld and Groupcoin),
#     or where the proof format does not use a numeric AuxPoW chain ID at all
#     (RSK miner-address evidence, Hathor split-header marker).
#   - activation_height: the chain's own AuxPoW activation height when known.
#     None when the recovery uses a format-specific acquisition floor rather
#     than a verified activation, including RSK, Hathor, and Elastos.
#   - attribution_mode: the evidence source preserved for possible later
#     attribution: "coinbase" for the default Namecoin-family path,
#     "miner_address" for RSK, or "rest" for Hathor REST extraction.
#   - input_csv / output_csv / validated_csv: defaults follow the established
#     scripts/classify_<chain>_stales.py argument defaults under data/. The
#     validated_csv reuses the existing module-level *_CSV constants so the
#     two never drift.


@dataclass(frozen=True)
class ChainSpec:
    """Declarative integration spec for one merge-mined chain."""

    key: str
    display_name: str
    height_column: Optional[str]
    chain_id: Optional[int]
    activation_height: Optional[int]
    attribution_mode: Literal["coinbase", "miner_address", "rest"]
    input_csv: Path
    output_csv: Path
    validated_csv: Path


def _chain_input_csv(key: str) -> Path:
    """Default raw-extraction CSV path for a chain (data/<key>_auxpow_raw.csv)."""
    return DATA_DIR / f"{key}_auxpow_raw.csv"


def _chain_output_csv(key: str) -> Path:
    """Default classifier inventory path for a chain (data/<key>_stale_blocks.csv)."""
    return DATA_DIR / f"{key}_stale_blocks.csv"


CHAIN_SPECS: dict[str, ChainSpec] = {
    "namecoin": ChainSpec(
        key="namecoin",
        display_name="Namecoin",
        height_column="nmc_height",
        chain_id=1,
        activation_height=19_200,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("namecoin"),
        output_csv=_chain_output_csv("namecoin"),
        validated_csv=AUXPOW_CSV,
    ),
    "geistgeld": ChainSpec(
        key="geistgeld",
        display_name="Geistgeld",
        height_column="geistgeld_height",
        chain_id=None,  # JSON-dump chain; AuxPoW chain ID not confirmed from source
        activation_height=14_092,  # dump's first AuxPoW-bearing GG block
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("geistgeld"),
        output_csv=_chain_output_csv("geistgeld"),
        validated_csv=GEISTGELD_CSV,
    ),
    "i0coin": ChainSpec(
        key="i0coin",
        display_name="i0coin",
        height_column="child_height",  # i0coin validated CSV uses "child_height", not "i0c_height"
        chain_id=2,
        activation_height=160_000,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("i0coin"),
        output_csv=_chain_output_csv("i0coin"),
        validated_csv=I0COIN_CSV,
    ),
    "coiledcoin": ChainSpec(
        key="coiledcoin",
        display_name="CoiledCoin",
        height_column="clc_height",
        chain_id=16,  # collides with Syscoin chain 2; harmless at runtime
        activation_height=1,  # AuxPoW accepted from genesis (height 1)
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("coiledcoin"),
        output_csv=_chain_output_csv("coiledcoin"),
        validated_csv=COILEDCOIN_CSV,
    ),
    "ixcoin": ChainSpec(
        key="ixcoin",
        display_name="ixcoin",
        height_column="ixc_height",
        chain_id=3,
        activation_height=45_001,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("ixcoin"),
        output_csv=_chain_output_csv("ixcoin"),
        validated_csv=IXCOIN_CSV,
    ),
    "devcoin": ChainSpec(
        key="devcoin",
        display_name="Devcoin",
        height_column="dvc_height",
        chain_id=4,
        activation_height=25_000,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("devcoin"),
        output_csv=_chain_output_csv("devcoin"),
        validated_csv=DEVCOIN_CSV,
    ),
    "groupcoin": ChainSpec(
        key="groupcoin",
        display_name="Groupcoin",
        height_column="groupcoin_height",
        chain_id=None,  # JSON-dump chain; AuxPoW chain ID not confirmed from source
        activation_height=17_187,  # dump's first AuxPoW-bearing GPC block
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("groupcoin"),
        output_csv=_chain_output_csv("groupcoin"),
        validated_csv=GROUPCOIN_CSV,
    ),
    "huntercoin": ChainSpec(
        key="huntercoin",
        display_name="Huntercoin",
        height_column="huc_height",
        chain_id=6,  # SHA-256d branch; Scrypt branch (chain ID 2 / LTC) out of scope
        activation_height=None,  # Arweave-archive parse; no numeric activation constant
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("huntercoin"),
        output_csv=_chain_output_csv("huntercoin"),
        validated_csv=HUNTERCOIN_CSV,
    ),
    "unobtanium": ChainSpec(
        key="unobtanium",
        display_name="Unobtanium",
        height_column="uno_height",
        chain_id=117,  # 0x75
        activation_height=600_000,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("unobtanium"),
        output_csv=_chain_output_csv("unobtanium"),
        validated_csv=UNOBTANIUM_CSV,
    ),
    "crown": ChainSpec(
        key="crown",
        display_name="Crown",
        height_column="crown_height",
        chain_id=20,  # 0x14 (PoW era); cosmetically rotates to 22 in PoS era
        activation_height=453_273,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("crown"),
        output_csv=_chain_output_csv("crown"),
        validated_csv=CROWN_CSV,
    ),
    "myriadcoin": ChainSpec(
        key="myriadcoin",
        display_name="Myriadcoin",
        height_column="xmy_height",
        chain_id=90,  # 0x005A; fStrictChainId=false (SHA-256d branch)
        activation_height=1_402_000,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("myriadcoin"),
        output_csv=_chain_output_csv("myriadcoin"),
        validated_csv=MYRIADCOIN_CSV,
    ),
    "sixeleven": ChainSpec(
        key="sixeleven",
        display_name="SixEleven",
        height_column="child_height",
        chain_id=1,
        activation_height=19_200,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("sixeleven"),
        output_csv=_chain_output_csv("sixeleven"),
        validated_csv=SIXELEVEN_CSV,
    ),
    "argentum": ChainSpec(
        key="argentum",
        display_name="Argentum",
        height_column="arg_height",
        chain_id=1187,  # 0x004A3; fStrictChainId=false (SHA-256d branch)
        activation_height=1_825_000,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("argentum"),
        output_csv=_chain_output_csv("argentum"),
        validated_csv=ARGENTUM_CSV,
    ),
    "emercoin": ChainSpec(
        key="emercoin",
        display_name="Emercoin",
        height_column="emc_height",
        chain_id=666,  # 0x29A; strict via raw conditional (not fStrictChainId flag)
        activation_height=219_809,  # MMHeight
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("emercoin"),
        output_csv=_chain_output_csv("emercoin"),
        validated_csv=EMERCOIN_CSV,
    ),
    "terracoin": ChainSpec(
        key="terracoin",
        display_name="Terracoin",
        height_column="trc_height",
        chain_id=50,  # 0x0032, strict
        activation_height=833_000,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("terracoin"),
        output_csv=_chain_output_csv("terracoin"),
        validated_csv=TERRACOIN_CSV,
    ),
    "rsk": ChainSpec(
        key="rsk",
        display_name="RSK / Rootstock",
        height_column="rsk_height",
        chain_id=None,  # RSK proof format; no numeric Namecoin-style chain ID
        activation_height=None,  # extraction starts at 139,999, but earlier proofs exist
        attribution_mode="miner_address",
        input_csv=_chain_input_csv("rsk"),
        output_csv=_chain_output_csv("rsk"),
        validated_csv=RSK_CSV,
    ),
    "doichain": ChainSpec(
        key="doichain",
        display_name="Doichain",
        height_column="doi_height",
        chain_id=2,
        activation_height=1,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("doichain"),
        output_csv=_chain_output_csv("doichain"),
        validated_csv=DOICHAIN_CSV,
    ),
    "bitmark": ChainSpec(
        key="bitmark",
        display_name="Bitmark",
        height_column="btmk_height",
        chain_id=91,  # 0x005B, fStrictChainId=true (SHA-256d branch)
        activation_height=450_947,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("bitmark"),
        output_csv=_chain_output_csv("bitmark"),
        validated_csv=BITMARK_CSV,
    ),
    "xaya": ChainSpec(
        key="xaya",
        display_name="Xaya",
        height_column="child_height",  # synthetic disk-order counter (i0coin precedent), not a consensus height
        chain_id=1829,  # 0x0725; no fStrictChainId flag (AuxPoW parent carries no chain ID)
        activation_height=1,  # SHA256D-AuxPoW accepted from genesis (genesis block itself is NEOSCRYPT)
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("xaya"),
        output_csv=_chain_output_csv("xaya"),
        validated_csv=XAYA_CSV,
    ),
    "elastos": ChainSpec(
        key="elastos",
        display_name="Elastos",
        height_column="ela_height",
        chain_id=1224,
        activation_height=None,  # first real proof is observed at 177,153; no coded activation
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("elastos"),
        output_csv=_chain_output_csv("elastos"),
        validated_csv=ELASTOS_CSV,
    ),
    "syscoin": ChainSpec(
        key="syscoin",
        display_name="Syscoin",
        height_column="sys_height",
        chain_id=16,  # with legacy 4096; strict (fStrictChainId=true)
        activation_height=1973,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("syscoin"),
        output_csv=_chain_output_csv("syscoin"),
        validated_csv=SYSCOIN_CSV,
    ),
    "hathor": ChainSpec(
        key="hathor",
        display_name="Hathor",
        height_column="hathor_height",
        chain_id=None,  # RFC-0006 "Hath"-tagged proof; no Namecoin chain ID
        activation_height=None,  # exact first merge-mined height is not established
        attribution_mode="rest",
        input_csv=DATA_DIR / "hathor" / "hathor_auxpow_raw.csv",
        output_csv=DATA_DIR / "hathor" / "hathor_phase_a.csv",
        validated_csv=HATHOR_CSV,
    ),
    "bitcoin-vault": ChainSpec(
        key="bitcoin-vault",
        display_name="Bitcoin Vault",
        height_column="btcv_height",
        chain_id=1638,  # 0x0666 (NOT Emercoin's 666 dec / 0x029A), strict
        activation_height=58_420,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("bitcoin-vault"),
        output_csv=_chain_output_csv("bitcoin-vault"),
        validated_csv=BITCOIN_VAULT_CSV,
    ),
    "elcash": ChainSpec(
        key="elcash",
        display_name="Electric Cash",
        height_column="elc_height",
        chain_id=8503,  # 0x2137, strict
        activation_height=None,  # AuxPoW permitted from height 1 (source nAuxpowStartHeight=1); no extraction floor needed
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("elcash"),
        output_csv=_chain_output_csv("elcash"),
        validated_csv=ELCASH_CSV,
    ),
    "lyncoin": ChainSpec(
        key="lyncoin",
        display_name="Lyncoin",
        height_column="child_height",
        chain_id=0x0B0D,
        activation_height=1,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("lyncoin"),
        output_csv=_chain_output_csv("lyncoin"),
        validated_csv=LYNCOIN_CSV,
    ),
    "fractal": ChainSpec(
        key="fractal",
        display_name="Fractal Bitcoin",
        height_column="fb_height",
        chain_id=8228,  # 0x2024
        activation_height=1,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("fractal"),
        output_csv=_chain_output_csv("fractal"),
        validated_csv=FRACTAL_CSV,
    ),
}
