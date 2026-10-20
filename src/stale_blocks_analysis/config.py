"""Paths, protocol constants, validated-CSV locations, monitor vocabulary, and CHAIN_SPECS.

Stdlib only. Importing this registry must not create directories.
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
STALE_DIR = Path(os.environ.get("STALE_BLOCKS_DIR", DATA_DIR / "stale-blocks"))
STALE_CSV = STALE_DIR / "stale-blocks.csv"
BLOCKS_DIR = STALE_DIR / "blocks"

# Current native foundations publish one complete split classifier family.
COHERENT_CLASSIFIER_FAMILY_CHAINS = frozenset({"huntercoin", "xaya"})

# Native Huntercoin dump framing, corroborated with the retained Arweave genesis.
HUNTERCOIN_NETWORK_MAGIC = bytes.fromhex("f9beb4fe")
HUNTERCOIN_SCRYPT_CHAIN_ID = 2
HUNTERCOIN_GENESIS_HASH = (
    "00000000db7eb7a9e1a06cf995363dcdc4c28e8ae04827a961942657db9a1631"
)

# Reviewed body-invalid evidence, fetched at the data-sources.tsv pin.
INVALID_BLOCKS_DIR = Path(
    os.environ.get("INVALID_BLOCKS_DIR", DATA_DIR / "invalid-blocks")
)
ERROR_BLOCK_BODIES_DIR = INVALID_BLOCKS_DIR / "blocks"

# bitcoin-data/mining-pools, pinned in data-sources.tsv. Override with
# LOCAL_MINING_POOLS_DIR. Lineage: blockchain/Blockchain-Known-Pools ->
# btccom/Blockchain-Known-Pools -> 0xB10C/known-mining-pools ->
# bitcoin-data/mining-pools. Reads pools/ from the working tree, including
# uncommitted edits. No cache and no network fetch; a missing clone fails.
LOCAL_MINING_POOLS_DIR = Path(
    os.environ.get("LOCAL_MINING_POOLS_DIR", DATA_DIR / "mining-pools")
)

# Compact, committed Bitcoin retarget-epoch reference data fetched from a
# public Esplora-compatible API. Unlike CACHE_DIR, this is reproducible input
# data and is safe to consume in CI without access to an operator's node.
BITCOIN_EPOCH_REFERENCE_DIR = DATA_DIR / "bitcoin-epoch-reference"

# Historical Namecoin-family pipelines whose refreshed rows must carry a
# complete authenticated child-header bundle. The order is the recovery
# priority used by the coverage report and source preflight.
HISTORICAL_CHILD_HEADER_CHAINS = (
    "devcoin",
    "ixcoin",
    "i0coin",
    "groupcoin",
    "coiledcoin",
    "geistgeld",
    "huntercoin",
    "bitmark",
    "terracoin",
    "emercoin",
    "myriadcoin",
    "unobtanium",
    "argentum",
    "crown",
    "elcash",
    "xaya",
    "rod",
    "bitcoin-vault",
)

# Committed error-blocks dataset: consensus-invalid full-proof-of-work
# Bitcoin blocks. The file is committed, so the directory is not created at
# import time; the loader fails closed if the file is missing.
ERROR_BLOCKS_DIR = DATA_DIR / "error-blocks"
ERROR_BLOCKS_CSV = ERROR_BLOCKS_DIR / "error_blocks.csv"
# Committed median-time-past context for time-rule error blocks: the canonical
# parent's median-time-past, keyed by (height, hash), so the validator can
# re-derive time-rule violations offline.
ERROR_BLOCKS_MTP_CONTEXT_CSV = ERROR_BLOCKS_DIR / "mtp_context.csv"
# Body-rule verdicts are externally verified; these are Core reject families.
ERROR_BLOCKS_BODY_EVIDENCE_NAME = "body_evidence.csv"
ERROR_BLOCKS_ANCESTRY_EVIDENCE_NAME = "ancestry_evidence.csv"
CONSENSUS_INVALID_PARENT_RULE = "consensus_invalid_parent"
SEGWIT_ACTIVATION_HEIGHT = 481824
BODY_ERROR_REJECTIONS = {
    "p2sh_redeem_script_failure": "block-script-verify-flag-failed",
    "missing_unconfirmed_parent": "bad-txns-inputs-missingorspent",
    "bad-txns-inputs-missingorspent": "bad-txns-inputs-missingorspent",
    "bad-cb-amount": "bad-cb-amount",
    "bad-blk-sigops": "bad-blk-sigops",
}

# Output locations (all relative to the project root).
RESULTS_DIR = PROJECT_ROOT / "results"
CACHE_DIR = PROJECT_ROOT / "cache"

# AuxPoW-recovered stale blocks (Namecoin merged mining side channel).
# See docs/chains/namecoin.md for methodology.
AUXPOW_CSV = VALIDATED_STALES_DIR / "namecoin_validated_stales.csv"

# Geistgeld: dead 2011 chain. Stifter getblock JSONL has no
# auxpow.coinbasetx.vout, so coinbase_outputs is empty and pool ID uses
# scriptSig only. Catalogue activation 2011-10-08, alphabetical tie with
# Namecoin (position 2). Dump AuxPoW from GG height 14,092 (2011-09-16) is
# Durham's AuxPoW at relaxed difficulty (Lolcust's fork of sacarlson's
# MultiCoin-exp): parents do not resolve to BTC mainchain, so zero validated
# BTC stales survive.
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

# Groupcoin: dead 2012-2018 chain. Stifter getblock JSONL, 235,752 blocks /
# 218,494 AuxPoW. Activation 2012-02-16, first AuxPoW at GPC height 17,187
# (parent_block.time 2012-02-16 10:56:16 UTC). vout addresses are Groupcoin
# base58 (`2h…`), not BTC mainnet; outputs are rendered from scriptPubKey.hex.
GROUPCOIN_CSV = VALIDATED_STALES_DIR / "groupcoin_validated_stales.csv"

# Huntercoin SHA-256d AuxPoW evidence comes from the foundational Kraft native
# dump. The Scrypt/Litecoin branch is out of scope. Measured coverage and prior
# Arweave recovery history are documented in docs/chains/huntercoin.md.
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

# Crown: chain ID 20, fStrictChainId. AuxPoW at height 453,273
# (timestamp 1440546428 = 2015-08-25 UTC). PoS-hybrid at 2,330,000 carries
# no AuxPoW; nVersion chain ID rotated 20→22 there and is unused because PoS
# blocks never set the AuxPoW flag. Single-algo SHA-256d. 1,868,911
# commitments over 453,273 → ~2,330,000 produced 23 validated BTC stales.
CROWN_CSV = VALIDATED_STALES_DIR / "crown_validated_stales.csv"

# Myriadcoin SHA-256d only. Algos: SHA-256d / Scrypt / Groestl / Yescrypt /
# Argon2d. Yescrypt replaced Qubit at XMY 1,764,000 (2016); Argon2d replaced
# Skein at 2,772,000 (~2019). Filter nVersion bits 9-11
# (BLOCK_VERSION_ALGO = 7<<9), algo==0. AuxPoW at height 1,402,000
# (timestamp 1443262763 = 2015-09-26 UTC). fStrictChainId=false: self-target
# is header consistency; Bitcoin parentage is Core lookup plus the nBits gate.
MYRIADCOIN_CSV = VALIDATED_STALES_DIR / "myriadcoin_validated_stales.csv"

# Bitmark: 8-algo, all merge-mineable since Fork 1. SHA-256d is nVersion
# bits 9-11 with ALGO_SHA256D = 1 (Myriadcoin encodes it as 0). Fork 1 at
# BTMK height 450,947 (2018-06-07 04:18:55 UTC). The one validated stale is
# already in the Unobtanium and Myriadcoin sets.
BITMARK_CSV = VALIDATED_STALES_DIR / "bitmark_validated_stales.csv"

# Argentum SHA-256d is (nVersion & 0x0E00) == 0x0200 (1<<9); Scrypt is the
# default (Myriadcoin's SHA-256d is algo 0). Pre-2018-03 fork: Scrypt +
# SHA-256d. Height >= 2,977,000 adds Lyra2REv2, Myriad-Groestl, Argon2d,
# Yescrypt. AuxPoW at ARG height 1,825,000. Activation date is the
# 2016-04-10 multi-algo relaunch, not the 2013-05-22 Scrypt genesis.
# fStrictChainId=false. Parentage is Core lookup plus the expected-nBits gate.
ARGENTUM_CSV = VALIDATED_STALES_DIR / "argentum_validated_stales.csv"

# Terracoin: decoded auxpow JSON over heights 833,000 → tip. coinbase_outputs
# is addr:value|... from terracoind's legacy scriptPubKey.addresses (Dash
# Core 0.12.x). The 2026-05-29 backfill re-fetched 35 rows after the first
# extractor stored type labels from the singular .address field.
TERRACOIN_CSV = VALIDATED_STALES_DIR / "terracoin_validated_stales.csv"

# Recovered stale blocks from the RSK / Rootstock merge-mining side channel.
# The committed file preserves historical labels derived from RSK miner
# addresses because the extractor preserves the BTC header and compressed proof
# material, not a reconstructable full BTC coinbase transaction. Those labels
# may remain stored in `pool_label` for provenance, but load_rsk_stales ignores
# them. Like every other chain the committed file is VALID-stales-only;
# the full stale/unknown inventory stays in the private chain archive.
RSK_CSV = VALIDATED_STALES_DIR / "rsk_validated_stales.csv"

# RSKj fallback signatures encode [v, r, s] as RLP, with signed-positive Java
# BigInteger byte arrays for the scalars. Their widths are variable.
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
RSK_FALLBACK_MIN_PROOF_BYTES = 4
RSK_FALLBACK_MAX_PROOF_BYTES = 70

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
STALE_DESCENDANT_OBSERVATIONS_CSV = DATA_DIR / "stale_descendant_observations.csv"

# Emercoin: only PoW blocks carry AuxPoW (~15.5% after MMHeight). PoS is
# filtered on RPC flags, mirroring nFlags & BLOCK_PROOF_OF_STAKE
# (src/primitives/block.h:36). AUXPOW_CHAIN_ID = 666; MMHeight = 219,809
# (2017-03-17 UTC). Parent header comes from RPC JSON, not a binary CAuxPow.
EMERCOIN_CSV = VALIDATED_STALES_DIR / "emercoin_validated_stales.csv"

# Fractal: `getblockheader <hash> false true` returns the compact header
# plus CAuxPow tail, not full transactions. Do not test only version bit
# 0x100: Indexer class 0x20260100 sets the flag with a different proof.
# Predicate is that flag plus chain ID 0x2024; observed encoding 0x20240100.
# Launch 2024-09-09.
FRACTAL_CSV = VALIDATED_STALES_DIR / "fractal_validated_stales.csv"

# Bitcoin Vault: Namecoin-identical AuxPoW wire format; CAuxPow validator is
# separate from CAuxBlockHeader (src/primitives/block.h). Dormant, tip
# h=228,360 since 2024-03-10. Blockbook REST (btcvexplorer.com
# /api/rawblock/<hash>), h=58,420 → 228,360. Of 169,939 commitments, 167,364
# meet only BTCV's lower aux target. 9 accepted stales (June 2026 refresh
# added h=665,005). After BTC h=699,616 / BTCV h=100,670 (2021-09-08), no
# further accepted direct stales. Chain ID 0x0666 (1638); Emercoin's 666
# decimal is 0x029A.
BITCOIN_VAULT_CSV = VALIDATED_STALES_DIR / "bitcoin-vault_validated_stales.csv"

# AuxPoW-recovered stale blocks (Electric Cash / ELCASH merged mining side
# channel). Bitcoin Core 0.20.2 fork with strict chain ID 0x2137 (8503),
# merge-mined from its fresh 2020-12-20 genesis (nAuxpowStartHeight=1).
# Recovered from a self-synced elcashd node; the three VALID stale parents
# (BTC 688,349 / 693,118 / 699,616, Jun-Sep 2021) all re-observe headers
# also witnessed by Bitcoin Vault. Real-difficulty merge-mining ran Jan 2021
# to Nov 2024 (peak Sep-Oct 2021). The full canonical-plus-stale classified
# set lives in the private chain archive (no unknown rows).
ELCASH_CSV = VALIDATED_STALES_DIR / "elcash_validated_stales.csv"

# Complete zero-stale recoveries. Lyncoin's full evidence came from its raw P2P
# extended-header stream; SixEleven and Doichain came from complete legacy
# blkNNNN.dat scans of pinned source builds.
LYNCOIN_CSV = VALIDATED_STALES_DIR / "lyncoin_validated_stales.csv"
SIXELEVEN_CSV = VALIDATED_STALES_DIR / "sixeleven_validated_stales.csv"
DOICHAIN_CSV = VALIDATED_STALES_DIR / "doichain_validated_stales.csv"

# Xaya: NEOSCRYPT is solo; SHA256D must be merge-mined. PowData follows the
# 80-byte header (algo:uint8 + nBits:uint32 + CAuxPow|fakeHeader), keyed on
# the 0x80 merge-mined flag. Chain ID 1829 (0x0725). SHA256D-AuxPoW from
# genesis 2018-07-13; genesis itself is NEOSCRYPT. Kraft native dump is the
# ancestry source past the migration height. No live node.
XAYA_CSV = VALIDATED_STALES_DIR / "xaya_validated_stales.csv"

# SpaceXpanse ROD stores the effective target beside the pure child header in
# PowData, like Xaya.  The full historical recovery currently publishes a
# canonical companion only; this conventional path is deliberately absent
# until a direct stale is admitted by the normal validation workflow.
ROD_CSV = VALIDATED_STALES_DIR / "rod_validated_stales.csv"
QBIT_CSV = VALIDATED_STALES_DIR / "qbit_validated_stales.csv"

# Integrated chains whose reviewed result currently consists only of a
# canonical companion. They stay in chronology and loader rosters, but a
# missing validated-stales file is intentional until a direct stale is admitted.
CANONICAL_ONLY_CHAINS = frozenset({"rod"})

# Order is AuxPoW activation, or the earliest source-confirmed production
# proof. An entry does not establish that the parent is Bitcoin. Novelty
# gives the earlier-born chain first-seen credit. That is a stable
# convention, not a claim the older chain observed the stale first: a chain
# sees a BTC stale only when its miners embed a proof. Dates are
# proof-activation, not genesis (Unobtanium: genesis Oct 2013, AuxPoW May
# 2015).
# Geistgeld and Namecoin share catalogue date 2011-10-08. The Geistgeld dump
# shows AuxPoW from GG height 14,092 / 2011-09-16, before Namecoin height
# 19200 on 2011-10-11, but those blocks are Durham's AuxPoW at relaxed
# difficulty: parents do not resolve to BTC mainchain, -OurChainID defaults
# to 0 and is not fixed in the public record, and classification yields zero
# validated BTC stales. Tie-break is alphabetical: Namecoin position 1,
# Geistgeld position 2.
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
        "rod",
        "2022-06-09",
    ),  # earliest retained SHA256d PowData observation: child height 2
    (
        "lyncoin",
        "2022-12-30",
    ),  # strict chain ID 0x0b0d; pre-Flex AuxPoW through height 260,499
    ("fractal", "2024-09-09"),
    ("qbit", "2026-07-16"),  # earliest authenticated native AuxPoW observation
]


# BIP34's historical mainnet transition. The coinbase-height rule applied to
# version 2 or newer blocks from height 224,413. Version 1 became invalid at
# height 227,931, making the height prefix mandatory for every later block.
BIP34_VERSION_2_HEIGHT = 224_413
BIP34_HEIGHT = 227_931
BIP66_HEIGHT = 363_725
BIP65_HEIGHT = 388_381

# Core's maximum key count for inaccurate legacy CHECKMULTISIG counting.
MAX_PUBKEYS_PER_MULTISIG = 20

# btc_stale_relevance vocabulary. Primary classification stays a single
# `unknown` (legacy artifacts wrote `orphan`; readers accept both). "Orphan"
# is only the strict/weak sense below. Monitor imports these exact strings.
# There is no "confirmed" bucket: VALID stale and stale_descendant rows carry
# an empty btc_stale_relevance and relevance_reason valid_direct_stale or
# valid_stale_descendant.
ACCEPTED_STALE_VALIDATION_STATUSES = frozenset(
    {
        "VALID",
        "VALID (post-BCH, difficulty matches BTC)",
    }
)
RELEVANCE_STRICT_BTC_ORPHAN = "strict_btc_orphan"
RELEVANCE_WEAK_BTC_ORPHAN = "weak_btc_orphan"
RELEVANCE_EXCLUDED = "excluded"
# Verdict for rows whose height/time lies beyond the committed nBits
# table's coverage: no final verdict yet, re-classifiable once the table
# is extended. Mirrors the monitor's `pending` horizon semantics.
RELEVANCE_PENDING = "pending"

# Machine-readable publication contracts shared by the exporter and the full
# transactional monitor-evidence validator. Keep this protocol data in config
# so metadata consumers do not depend on an exporter implementation module.
MONITOR_VALIDATION_CONTRACTS = {
    "ordinary_monitor_evidence": {
        "profile": "direct_stale_header_context_v1",
        "valid_token_scope": "publication_gate_accepted_not_full_block_validity",
        "full_block_consensus_validity_asserted": False,
        "required_checks": [
            "candidate_header_hash_and_self_pow",
            "active_chain_parent_and_expected_height",
            "expected_nbits",
            "median_time_past",
            "historical_minimum_block_version",
            "coinbase_scriptsig_length_when_available",
            "bip34_coinbase_height_when_available",
        ],
        "known_exception": {
            "rsk": "coinbase-dependent checks unavailable from compressed proof"
        },
        "documentation": "docs/data-validity.md",
    },
    "error-block-observations": {
        "profile": "error_observation_consensus_invalid_v1",
        "valid_tokens": ["VALID_ERROR_BLOCK"],
        "valid_token_scope": "authenticated_witness_of_consensus_invalid_parent",
        "parent_consensus_invalidity_asserted": True,
        "required_checks": [
            "parent_header_hash_and_fields",
            "catalogued_consensus_rejection_reason",
            "authenticated_child_identity",
            "source_observation_coordinates",
        ],
        "documentation": "docs/data-validity.md",
    },
}

# Default height floor for the loader functions in stale_blocks.py,
# snapped to a DAA (2016-block) epoch start: epoch 209 (421,344), one full
# epoch after the BIP 152 activation at 420,000. Acquisition-side callers that
# want everything pass min_height=0 explicitly.
MIN_HEIGHT = 421_344  # epoch 209 (first DAA ≥ BIP 152 activation at 420,000)


# CHAIN_SPECS is the live source for classifiers, raw-hex extractors, and
# full_evidence. Edits here change runtime behaviour.
# key matches CHAINS_BY_AUXPOW_ACTIVATION (hyphenated for bitcoin-vault and
# fractal). height_column is the chain's own height, not btc_height; an
# unauthenticated source leaves it blank. chain_id is the high 16 bits of
# child nVersion, or None for Geistgeld, Groupcoin, RSK, and Hathor.
# activation_height is None when the recovery uses an acquisition floor
# (RSK, Hathor, Elastos). attribution_mode is coinbase, miner_address (RSK),
# or rest (Hathor). validated_csv reuses the module-level *_CSV constants.
# child_nbits_from_header is false only when the target sits outside the
# 80-byte child header (Xaya PowData). bits_source_is_decimal is true only
# for Bitcoin Vault's decimal btc_bits; otherwise lowercase 8-char hex.


@dataclass(frozen=True)
class ChainSpec:
    """Declarative integration spec for one merge-mined chain."""

    key: str
    display_name: str
    height_column: str
    chain_id: Optional[int]
    activation_height: Optional[int]
    attribution_mode: Literal["coinbase", "miner_address", "rest"]
    input_csv: Path
    output_csv: Path
    validated_csv: Path
    child_nbits_from_header: bool = True
    bits_source_is_decimal: bool = False


def _chain_input_csv(key: str) -> Path:
    """Default raw-extraction CSV path for a chain (data/<key>_auxpow_raw.csv)."""
    return DATA_DIR / f"{key}_auxpow_raw.csv"


def _chain_output_csv(key: str) -> Path:
    """Default classifier inventory path for a chain (data/<key>_stale_blocks.csv)."""
    return DATA_DIR / f"{key}_stale_blocks.csv"


CHAIN_SPECS: dict[str, ChainSpec] = {
    "qbit": ChainSpec(
        key="qbit",
        display_name="Qbit",
        height_column="qbit_height",
        chain_id=47,
        activation_height=0,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("qbit"),
        output_csv=_chain_output_csv("qbit"),
        validated_csv=QBIT_CSV,
    ),
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
        height_column="child_height",  # blank when the snapshot cannot prove it
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
        height_column="clc_height",  # blank when the archive cannot prove it
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
        activation_height=None,  # native dual-algo scan; no RPC activation gate
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
        height_column="xaya_height",  # exact BIP34 height from the native child coinbase
        chain_id=1829,  # 0x0725; no fStrictChainId flag (AuxPoW parent carries no chain ID)
        activation_height=1,  # SHA256D-AuxPoW accepted from genesis (genesis block itself is NEOSCRYPT)
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("xaya"),
        output_csv=_chain_output_csv("xaya"),
        validated_csv=XAYA_CSV,
        child_nbits_from_header=False,
    ),
    "rod": ChainSpec(
        key="rod",
        display_name="SpaceXpanse ROD",
        height_column="child_height",
        chain_id=1899,
        # Height 1 is the first post-genesis block eligible for a PowData
        # proof. Mainnet genesis is standalone NeoScrypt; the first retained
        # SHA256d observation is height 2, dated 2022-06-09.
        activation_height=1,
        attribution_mode="coinbase",
        input_csv=_chain_input_csv("rod"),
        output_csv=_chain_output_csv("rod"),
        validated_csv=ROD_CSV,
        child_nbits_from_header=False,
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
        input_csv=DATA_DIR / "hathor" / "hathor_acquisition.csv",
        output_csv=DATA_DIR / "hathor" / "classified" / "hathor_stale_blocks.csv",
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
        bits_source_is_decimal=True,
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
