"""Stale block loaders.

Reads the upstream bitcoin-data/stale-blocks CSV and the per-chain
AuxPoW-recovered validated CSVs (Geistgeld, Namecoin, CoiledCoin, Syscoin,
Devcoin, ixcoin, i0coin, Groupcoin, Huntercoin, Elastos, Unobtanium, Doichain,
Myriadcoin, Bitmark, Argentum, Terracoin, RSK, Xaya, Bitcoin Vault,
Electric Cash, Lyncoin, SixEleven, and Fractal Bitcoin; see docs/ for
methodology), returning the established
row shape (`height`, `hash`, `source`, and where available
`_scriptsig_hex` / `_outputs_str`). Merging across sources is handled
separately. The loaders do not import a pool registry or perform pool
attribution.

Depends on: config (STALE_CSV, MIN_HEIGHT, ARGENTUM_CSV, AUXPOW_CSV,
BITCOIN_VAULT_CSV, BITMARK_CSV, COILEDCOIN_CSV, DEVCOIN_CSV, ELASTOS_CSV, FRACTAL_CSV,
GEISTGELD_CSV, GROUPCOIN_CSV, HUNTERCOIN_CSV, I0COIN_CSV, IXCOIN_CSV,
LYNCOIN_CSV, RSK_CSV, SIXELEVEN_CSV, STALE_DESCENDANTS_CSV, SYSCOIN_CSV, TERRACOIN_CSV,
UNOBTANIUM_CSV, ELCASH_CSV), bitcoin_binary (_b58_decode_to_hash160,
_bech32_decode_to_program).
"""

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .bitcoin_binary import (
    _b58_decode_to_hash160,
    _bech32_decode_to_program,
)
from .config import (
    MIN_HEIGHT,
    RSK_CSV,
    STALE_CSV,
    STALE_DESCENDANT_CORRECTIONS_CSV,
    STALE_DESCENDANTS_CSV,
)
from .error_blocks import exclude_consensus_invalid_rows, exclude_stale_rows

# The per-chain *_CSV path constants below are referenced only indirectly, via
# globals()[spec.csv_attr] at load time (see the LoaderSpec docstring), so a test
# that does monkeypatch.setattr(stale_blocks, "<CHAIN>_CSV", ...) still takes
# effect. They are imported for that name binding but never used by name here;
# keep them and silence F401 rather than dropping them.
from .config import (  # noqa: F401
    ARGENTUM_CSV,
    AUXPOW_CSV,
    BITCOIN_VAULT_CSV,
    BITMARK_CSV,
    COILEDCOIN_CSV,
    CROWN_CSV,
    DEVCOIN_CSV,
    DOICHAIN_CSV,
    ELASTOS_CSV,
    ELCASH_CSV,
    EMERCOIN_CSV,
    FRACTAL_CSV,
    GEISTGELD_CSV,
    GROUPCOIN_CSV,
    HATHOR_CSV,
    HUNTERCOIN_CSV,
    I0COIN_CSV,
    IXCOIN_CSV,
    LYNCOIN_CSV,
    MYRIADCOIN_CSV,
    SIXELEVEN_CSV,
    SYSCOIN_CSV,
    TERRACOIN_CSV,
    UNOBTANIUM_CSV,
    XAYA_CSV,
)


def load_stale_csv(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load stale block records at height >= *min_height*, sorted by height."""
    rows = []
    with open(STALE_CSV, newline="") as f:
        for row in csv.DictReader(f):
            h = int(row["height"])
            if h >= min_height:
                rows.append(
                    {"height": h, "hash": row["hash"], "source": "stale-blocks"}
                )
    rows = exclude_consensus_invalid_rows(rows)
    rows.sort(key=lambda r: r["height"])
    return rows


def _addr_to_spk(addr: str) -> bytes | None:
    """Convert a Bitcoin address string to its scriptPubKey bytes.

    Supports P2PKH (1...), P2SH (3...), and P2WPKH/P2WSH/P2TR (bc1...).
    Returns None if the address can't be decoded.
    """
    if addr.startswith(("bc1", "nc1")):
        # nc1 = Namecoin bech32. The HRP only affects the (skipped) checksum,
        # so normalize to bc1 and decode the identical data part.
        program = _bech32_decode_to_program("bc1" + addr[3:])
        if program is None:
            return None
        if len(program) == 20:
            return bytes([0x00, 0x14]) + program  # P2WPKH
        elif len(program) == 32:
            return bytes([0x51, 0x20]) + program  # P2TR
        return None
    h160 = _b58_decode_to_hash160(addr)
    if h160 is None:
        return None
    # P2PKH (N prefix = Namecoin, S prefix = Syscoin; the base58 version
    # byte is chain cosmetics, the hash160 payload is the same)
    if addr.startswith(("1", "N", "S")):
        return bytes([0x76, 0xA9, 0x14]) + h160 + bytes([0x88, 0xAC])
    # P2SH (M and 6 prefixes = Namecoin)
    elif addr.startswith(("3", "M", "6")):
        return bytes([0xA9, 0x14]) + h160 + bytes([0x87])
    return None


OutputsMode = Literal["raw", "addr", "addr_nonstandard"]


@dataclass(frozen=True)
class LoaderSpec:
    """Declarative description of one AuxPoW validated-stale loader.

    Captures only the loader-level (CSV-reading) variation between the
    near-identical per-chain load_<chain>_stales functions:

      - csv_attr: name of the module-level *_CSV path constant. Resolved by
        attribute lookup at call time (NOT captured at import) so tests that
        monkeypatch e.g. stale_blocks.HATHOR_CSV still take effect.
      - source: the record `source` label.
      - height_col / hash_col: the BTC parent height / hash column names in
        that chain's validated CSV.
      - require_stale: gate rows on classification == "stale" (the default;
        every normalized validated CSV is stale-only).
      - every committed input row must have a validation_status beginning with
        "VALID". This preserves legacy Namecoin/i0coin ``VALID (...)`` verdicts
        while failing closed on blank or unvalidated rows.
      - outputs: coinbase_outputs handling — "raw" (passthrough),
        "addr" (parse "addr:value|..." to "addr;addr", dropping OP_RETURN),
        or "addr_nonstandard" (as "addr" but also dropping "nonstandard*").
      - skip_empty_height: skip rows whose height column is empty (Terracoin).

    Loader-level concerns deliberately live here rather than on
    config.ChainSpec: ChainSpec documents extraction/classification provenance
    (chain ID, activation height, raw/output CSV paths) and is shared with the
    extractor/classifier scripts, whereas these fields (hash column, source
    label, output-encoding mode) describe only how this module reads the
    already-validated CSV.
    """

    csv_attr: str
    source: str
    height_col: str = "btc_height"
    hash_col: str = "btc_header_hash"
    require_stale: bool = True
    outputs: OutputsMode = "raw"
    skip_empty_height: bool = False


def _parse_addr_outputs(raw_outputs: str, *, drop_nonstandard: bool = False) -> str:
    """Convert "addr:value|addr:value|OP_RETURN:value" to "addr;addr"."""
    addrs = []
    for part in raw_outputs.split("|"):
        addr = part.split(":")[0].strip()
        if not addr or addr == "OP_RETURN":
            continue
        if drop_nonstandard and addr.startswith("nonstandard"):
            continue
        addrs.append(addr)
    return ";".join(addrs)


def load_auxpow_validated_stales(
    spec: LoaderSpec, min_height: int = MIN_HEIGHT
) -> list[dict]:
    """Spec-driven loader for AuxPoW-recovered validated stale CSVs.

    Reads the CSV named by ``spec.csv_attr`` (resolved against this module's
    globals at call time), applies the spec's classification/validation gates
    and height floor, normalizes coinbase outputs per ``spec.outputs``, and
    emits canonical records ({height, hash, source, _scriptsig_hex,
    _outputs_str}) sorted by height. Returns [] if the CSV is absent.
    """
    csv_path = globals()[spec.csv_attr]
    if not csv_path.exists():
        return []

    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            if spec.require_stale and row.get("classification") != "stale":
                continue
            if not row.get("validation_status", "").startswith("VALID"):
                continue
            height_str = row.get(spec.height_col, "")
            if spec.skip_empty_height and not height_str:
                continue
            h = int(row[spec.height_col])
            if h < min_height:
                continue
            raw_outputs = row.get("coinbase_outputs", "")
            if spec.outputs == "addr":
                outputs_str = _parse_addr_outputs(raw_outputs)
            elif spec.outputs == "addr_nonstandard":
                outputs_str = _parse_addr_outputs(raw_outputs, drop_nonstandard=True)
            else:
                outputs_str = raw_outputs
            rows.append(
                {
                    "height": h,
                    "hash": row[spec.hash_col],
                    "source": spec.source,
                    "_scriptsig_hex": row.get("coinbase_scriptsig_hex", ""),
                    "_outputs_str": outputs_str,
                }
            )
    rows = exclude_stale_rows(rows)
    rows.sort(key=lambda r: r["height"])
    return rows


# Per-chain loader specs. Each thin load_<chain>_stales wrapper below binds
# one of these to load_auxpow_validated_stales while preserving the public
# function name and signature so all existing callers keep working.
_LOADER_SPECS: dict[str, LoaderSpec] = {
    "namecoin": LoaderSpec(
        # Normalized to the shared schema in the data pass (legacy file used
        # btc_stale_height / btc_hash / btc_bits_hex). The common VALID-prefix
        # gate preserves the documented "VALID (post-BCH ...)" contract.
        csv_attr="AUXPOW_CSV",
        source="namecoin",
    ),
    "geistgeld": LoaderSpec(
        csv_attr="GEISTGELD_CSV",
        source="geistgeld",
    ),
    "syscoin": LoaderSpec(
        csv_attr="SYSCOIN_CSV",
        source="syscoin",
        outputs="addr",
    ),
    "devcoin": LoaderSpec(
        csv_attr="DEVCOIN_CSV",
        source="devcoin",
        outputs="addr",
    ),
    "i0coin": LoaderSpec(
        # Normalized to the shared schema in the data pass (legacy file used
        # btc_stale_height / btc_hash / btc_bits_hex). The common VALID-prefix
        # gate preserves the documented "VALID (post-BCH ...)" contract.
        csv_attr="I0COIN_CSV",
        source="i0coin",
    ),
    "coiledcoin": LoaderSpec(
        csv_attr="COILEDCOIN_CSV",
        source="coiledcoin",
    ),
    "ixcoin": LoaderSpec(
        csv_attr="IXCOIN_CSV",
        source="ixcoin",
        outputs="addr",
    ),
    "groupcoin": LoaderSpec(
        csv_attr="GROUPCOIN_CSV",
        source="groupcoin",
    ),
    "huntercoin": LoaderSpec(
        csv_attr="HUNTERCOIN_CSV",
        source="huntercoin",
    ),
    "unobtanium": LoaderSpec(
        csv_attr="UNOBTANIUM_CSV",
        source="unobtanium",
    ),
    "myriadcoin": LoaderSpec(
        csv_attr="MYRIADCOIN_CSV",
        source="myriadcoin",
    ),
    "sixeleven": LoaderSpec(
        csv_attr="SIXELEVEN_CSV",
        source="sixeleven",
    ),
    "bitmark": LoaderSpec(
        csv_attr="BITMARK_CSV",
        source="bitmark",
    ),
    "argentum": LoaderSpec(
        csv_attr="ARGENTUM_CSV",
        source="argentum",
    ),
    "crown": LoaderSpec(
        csv_attr="CROWN_CSV",
        source="crown",
    ),
    "xaya": LoaderSpec(
        csv_attr="XAYA_CSV",
        source="xaya",
    ),
    "terracoin": LoaderSpec(
        csv_attr="TERRACOIN_CSV",
        source="terracoin",
        outputs="addr",
        skip_empty_height=True,
    ),
    "emercoin": LoaderSpec(
        csv_attr="EMERCOIN_CSV",
        source="emercoin",
    ),
    "doichain": LoaderSpec(
        csv_attr="DOICHAIN_CSV",
        source="doichain",
    ),
    "elcash": LoaderSpec(
        csv_attr="ELCASH_CSV",
        source="elcash",
    ),
    "lyncoin": LoaderSpec(
        csv_attr="LYNCOIN_CSV",
        source="lyncoin",
    ),
    "elastos": LoaderSpec(
        csv_attr="ELASTOS_CSV",
        source="elastos",
    ),
    "hathor": LoaderSpec(
        csv_attr="HATHOR_CSV",
        source="hathor",
        outputs="addr",
    ),
    "fractal": LoaderSpec(
        csv_attr="FRACTAL_CSV",
        source="fractal",
    ),
    "bitcoin_vault": LoaderSpec(
        csv_attr="BITCOIN_VAULT_CSV",
        source="bitcoin-vault",
        outputs="addr_nonstandard",
    ),
}


def load_namecoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Namecoin merged mining data.

    Returns records in the same shape as load_stale_csv() but with the
    coinbase data pre-parsed from the AuxPoW extraction (no .bin file
    needed). Only loads entries with classification "stale" and
    validation_status starting with "VALID".
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["namecoin"], min_height=min_height
    )


def load_auxpow_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Backward-compatible alias for Namecoin AuxPoW stales."""
    return load_namecoin_stales(min_height=min_height)


def load_geistgeld_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Geistgeld merged mining data.

    Returns records in the same shape as load_coiledcoin_stales() with
    source="geistgeld". Only loads entries with classification "stale".

    Geistgeld's source dump (a complete `getblock`-JSON archival dump shared
    by Nicholas Stifter) lacks `auxpow.coinbasetx.vout` entirely, so the
    validated CSV's `coinbase_outputs` column is always empty.
    `_scriptsig_hex` still preserves the intact BTC parent coinbase scriptSig
    for any later attribution research.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["geistgeld"], min_height=min_height
    )


def load_syscoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Syscoin merged mining data.

    Returns records in the same shape as load_namecoin_stales() with
    source="syscoin". Only loads entries with classification "stale".

    Syscoin `coinbase_outputs` use `addr:value|addr:value` format; this
    function converts them to the established semicolon-separated bare-address
    representation preserved by all loaders.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["syscoin"], min_height=min_height)


def load_devcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Devcoin merged mining data.

    Returns records in the same shape as load_syscoin_stales() with
    source="devcoin". Only loads entries with classification "stale".

    Devcoin coinbases often have many outputs (50k DVC split between the
    miner and project funds). The loader preserves every address, including
    the leading miner payout, as evidence for later attribution research.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["devcoin"], min_height=min_height)


def load_i0coin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from i0coin merged mining data.

    Returns records in the same shape as load_namecoin_stales() with
    source="i0coin". Only loads entries with validation_status
    starting with "VALID". The committed CSV uses the shared normalized
    validated-stales schema, including ``btc_height`` and
    ``btc_header_hash``. Coinbase outputs remain raw scriptPubKey hex.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["i0coin"], min_height=min_height)


def load_coiledcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from CoiledCoin merged mining data.

    Returns records in the same shape as load_devcoin_stales() with
    source="coiledcoin". Only loads entries with classification "stale".
    CoiledCoin's `coinbase_outputs` column is the raw scriptPubKey-hex
    semicolon-joined form (matches i0coin/ixcoin/elastos blkdat format),
    so values are preserved unchanged for later attribution research. The CSV
    also carries an `eligius_attack_window` flag column
    marking records in the Jan 2012 Eligius 51% attack window
    (BTC ~160,000-163,000); this column is preserved for diagnostic use
    but does not affect the loader filter.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["coiledcoin"], min_height=min_height
    )


def load_ixcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from ixcoin merged mining data.

    Returns records in the same shape as load_devcoin_stales() with
    source="ixcoin". Only loads entries with classification "stale".
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["ixcoin"], min_height=min_height)


def load_groupcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Groupcoin merged mining data.

    Returns records in the same shape as load_huntercoin_stales() with
    source="groupcoin". Only loads entries with classification "stale".

    Groupcoin's data was sourced from a complete `getblock`-JSON archival
    dump shared by Nicholas Stifter; the network is dead and has no surviving
    public infrastructure. `coinbase_outputs` is raw scriptPubKey hex
    semicolon-joined (matches i0coin/Unobtanium/Huntercoin format) and is
    preserved for later attribution research. The dump's pre-decoded
    `vout[*].scriptPubKey.addresses` are Groupcoin-base58-encoded (e.g.
    `2h…`) rather than BTC mainnet and must NOT be used — the classifier
    deliberately emits the raw pkscript hex instead.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["groupcoin"], min_height=min_height
    )


def load_huntercoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Huntercoin (SHA-256d branch)
    merged mining data.

    Returns records in the same shape as load_unobtanium_stales() with
    source="huntercoin". Only loads entries with classification "stale".

    Huntercoin's data was sourced via Arweave from the domob1812/arblockstore
    permaweb archive — the network itself is dead. The validated CSV holds
    only the SHA-256d branch (chain ID 6, BTC parent); the Scrypt branch
    (chain ID 2, LTC parent) is out of scope. coinbase_outputs is the raw
    scriptPubKey hex semicolon-joined form (matches i0coin/ixcoin/Unobtanium
    blkdat format), so it is preserved unchanged for later attribution.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["huntercoin"], min_height=min_height
    )


def load_unobtanium_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Unobtanium merged mining data.

    Returns records in the same shape as load_elastos_stales() with
    source="unobtanium". Only loads entries with classification "stale".
    Unobtanium coinbase_outputs are raw pkscript hex semicolon-joined (matches
    i0coin/ixcoin/elastos blkdat format), so they are preserved unchanged for
    later attribution research.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["unobtanium"], min_height=min_height
    )


def load_myriadcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Myriadcoin (SHA-256d branch).

    Returns records in the same shape as load_unobtanium_stales() with
    source="myriadcoin". Only loads entries with classification "stale".
    Myriadcoin's multi-algo PoW (SHA-256d / Scrypt / Groestl / Yescrypt /
    Argon2d) means only the SHA-256d branch is Bitcoin-parent merge-mined;
    the extractor filters on nVersion bits 9-11 before parsing. Myriadcoin
    coinbase_outputs are raw pkscript hex semicolon-joined (matches the
    i0coin/ixcoin/elastos/unobtanium blkdat format), so they are preserved for
    later attribution research.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["myriadcoin"], min_height=min_height
    )


def load_sixeleven_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load the header-only SixEleven validated-stale publication input.

    The complete recovery found no accepted direct-stale candidates. A normal
    loader keeps the zero-row artifact inside chronology and novelty checks and
    will admit future VALID stale rows without a second integration path.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["sixeleven"], min_height=min_height
    )


def load_bitmark_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Bitmark (SHA-256d branch).

    Returns records in the same shape as load_myriadcoin_stales() with
    source="bitmark". Only loads entries with classification "stale".

    Bitmark is an 8-algo PoW chain where all branches are merge-mineable,
    but only the SHA-256d branch is Bitcoin-parent in this project scope.
    The extractor filters on nVersion bits 9-11 (ALGO_SHA256D = 1 on
    Bitmark) and the AuxPoW flag before parsing the Namecoin-style CAuxPow
    payload. `coinbase_outputs` is raw pkscript hex semicolon-joined and is
    preserved unchanged for later attribution research.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["bitmark"], min_height=min_height)


def load_argentum_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Argentum (SHA-256d branch).

    Returns records in the same shape as load_myriadcoin_stales() with
    source="argentum". Only loads entries with classification "stale".

    Argentum is a multi-algo PoW chain — only the SHA-256d branch is
    Bitcoin-parent merge-mined. The extractor filters on
    (nVersion & 0x0E00) == 0x0200 (BLOCK_VERSION_SHA256D = 1 << 9)
    BEFORE parsing the Namecoin-style CAuxPow. Note this differs from
    Myriadcoin where SHA-256d is the default 0; in Argentum SHA-256d is
    explicit (1<<9) and Scrypt is the default. fStrictChainId=false on
    Argentum (identical to Myriadcoin). The self-target PoW filter establishes
    header consistency; Bitcoin Core parent lookup plus the expected-nBits
    gate establish Bitcoin parentage for accepted stales.

    The completed extraction recovered two accepted direct-stale candidates.
    As with every shared loader, an absent CSV returns an empty list.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["argentum"], min_height=min_height
    )


def load_crown_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Crown merged mining data.

    Returns records in the same shape as load_myriadcoin_stales() with
    source="crown". Only loads entries with classification "stale".

    Crown is a 2014 Bitcoin/Dash-derived chain with standard Namecoin-style
    AuxPoW (chain ID 20, fStrictChainId=true). Single-algo SHA-256d — no
    per-algo filter. AuxPoW activates at Crown height 453,273; the chain
    went PoS-hybrid at 2,330,000 (PoS blocks carry no AuxPoW). The
    extractor (extract_crown_auxpow.py) gates on the AuxPoW version bit
    and parses the Namecoin-style CAuxPow from raw block hex. Crown
    coinbase_outputs are raw pkscript hex semicolon-joined (matches the
    myriadcoin/argentum/ixcoin format), so they are preserved unchanged for
    later attribution research.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["crown"], min_height=min_height)


def load_xaya_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Xaya (CHI) merged mining data.

    Returns records in the same shape as load_crown_stales() with
    source="xaya". Only loads entries with classification "stale".

    Xaya is a multi-algo chain (NEOSCRYPT solo-mined or SHA256D merge-mined);
    the source enforces "SHA256D must be merge-mined", so every SHA256D block
    carries a Bitcoin-parent CAuxPow and NEOSCRYPT blocks carry none (chain ID
    1829; Xaya has no fStrictChainId flag). SHA256D-AuxPoW is active from genesis
    (2018-07-13). The extractor (extract_xaya_auxpow.py) parses Xaya's PowData
    block-header wrapper, keys on the 0x80 merge-mined flag, and reuses the
    shared Namecoin-style CAuxPow parser. Xaya coinbase_outputs are raw pkscript
    hex semicolon-joined (matches the crown/myriadcoin/ixcoin format), so they
    are preserved unchanged for later attribution research.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["xaya"], min_height=min_height)


def load_terracoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Terracoin merged mining data.

    Returns records in the same shape as load_syscoin_stales() with
    source="terracoin". Only loads entries with classification "stale".

    `coinbase_outputs` is "addr:value|..." matching the other AuxPoW-derived
    loaders. terracoind exposes addresses via the legacy `scriptPubKey.addresses`
    plural array (pre-Bitcoin-Core-0.18 shape); the extractor reads both that
    and the modern singular `address` field.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["terracoin"], min_height=min_height
    )


def load_emercoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Emercoin merged mining data.

    Returns records in the same shape as load_myriadcoin_stales() with
    source="emercoin". Only loads entries with classification "stale".

    Emercoin is a hybrid PoW/PoS chain (Peercoin lineage). Only PoW blocks
    carry the Namecoin-style AuxPoW commitment; the PoS branch is filtered
    at extraction time (~15.5% of post-MMHeight EMC blocks are PoW).
    `coinbase_outputs` is raw pkscript hex semicolon-joined, matching the
    myriadcoin/i0coin/ixcoin format, and is preserved unchanged for later
    attribution research.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["emercoin"], min_height=min_height
    )


def load_doichain_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load validated Bitcoin-parent stales recovered from Doichain AuxPoW.

    The complete height 1 through 430,684 survey yielded no stale rows, so the
    committed CSV is header-only. Keeping a normal loader makes reruns and any
    future extension follow the same integration contract as other chains.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["doichain"], min_height=min_height
    )


def load_elastos_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Elastos merged mining data.

    Returns records in the same shape as load_i0coin_stales() with
    source="elastos". Only loads entries with classification "stale"
    and validation_status "VALID" — rejected (BCH/BSV contamination) and
    unknown rows are excluded. Elastos coinbase_outputs are raw pkscript hex
    semicolon-joined (matches i0coin/ixcoin blkdat format) and are preserved
    unchanged for later attribution research.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["elastos"], min_height=min_height)


def load_rsk_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load stale blocks recovered from RSK merge-mining data.

    RSK extraction differs from the Namecoin-family chains: the full BTC parent
    coinbase transaction is not reconstructable from the compressed proof.
    The CSV preserves the BTC header, limited proof-tail diagnostics, and
    historical label columns from an earlier RSK miner-address analysis, but
    this loader ignores everything except the accepted header identity.

    Like every other chain, the committed loader input is VALID-stales-only
    (`data/validated-stales/rsk_validated_stales.csv`, carrying the shared validated-stales layout plus
    RSK's historical miner-label columns). The full stale/unknown
    inventory stays in the private chain archive.
    """
    if not RSK_CSV.exists():
        return []

    rows = []
    with open(RSK_CSV, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("classification") != "stale":
                continue
            if not row.get("validation_status", "").startswith("VALID"):
                continue
            h = int(row["btc_height"])
            if h < min_height:
                continue
            rows.append(
                {
                    "height": h,
                    "hash": row["btc_header_hash"],
                    "source": "rsk",
                }
            )
    rows = exclude_stale_rows(rows)
    rows.sort(key=lambda r: r["height"])
    return rows


def load_hathor_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load stale blocks recovered from Hathor merge-mining data.

    Returns records in the same shape as load_devcoin_stales() with
    source="hathor". Only loads entries with classification "stale" and
    validation_status "VALID".

    Hathor uses an RFC-0006 split-header proof with the coinbase tag "Hath"
    (not Namecoin-family CAuxPow). The classifier pipeline
    (classify_hathor_stales.py + phase_b + phase_c) handles funds+graph
    reconstruction, Bitcoin predecessor linkage, and BIP34 height parsing.
    RPC-miss rows remain unresolved and never enter this loader. By the time
    this loader sees the data, only self-target-PoW-passing stales remain.

    coinbase_outputs is raw pkscript_hex format (the same pattern as
    Unobtanium / Fractal Bitcoin / Devcoin) because the classifier parses
    the BTC parent coinbase directly from the reconstructed bytes without
    routing through an RPC's address decoder.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["hathor"], min_height=min_height)


def load_fractal_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Fractal Bitcoin merged mining data.

    Returns records in the same shape as load_unobtanium_stales() with
    source="fractal". Only loads entries with classification "stale"
    and validation_status "VALID".

    Fractal Bitcoin's Cadence Mining splits blocks across three classes;
    only the merge-mined class carries an AuxPoW proof. The classifier CSV
    contains only that subset. The extractor requires the AuxPoW flag together
    with chain ID 0x2024, excluding the 0x2026 Indexer class that shares the
    flag but serializes a different proof. The shared publication gate rejects
    parent headers that fail the available Bitcoin context checks before rows
    reach the committed loader input.

    `coinbase_outputs` is the Unobtanium-pattern semicolon-joined raw
    scriptPubKey hex emitted by the binary CAuxPow parser. Fractald's compact
    `getblockheader <hash> false true` response includes the CAuxPow tail but
    does not decode the embedded BTC parent coinbase into JSON, so the
    extractor outputs raw pkscript hex rather than decoded mainnet addresses.
    The scriptsig markers and pkscript hex are retained for a later
    attribution phase.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["fractal"], min_height=min_height)


def load_bitcoin_vault_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Bitcoin Vault merged mining data.

    Returns records in the same shape as load_syscoin_stales() with
    source="bitcoin-vault". Only loads entries with classification "stale".

    BTCV is dormant — extraction was REST-driven via Blockbook
    (`scripts/extract/extract_bitcoin_vault_auxpow.py`) rather than a live
    node. `coinbase_outputs` uses the Syscoin-pattern "addr:value|addr:value|
    OP_RETURN:value" format, with mainnet addresses decoded via the shared
    `stale_blocks_analysis.bitcoin_binary` bech32+base58 helper
    (`format_outputs_addr`; no `requests` / `bitcoinlib` dependency on the
    4-host extraction fleet).
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["bitcoin_vault"], min_height=min_height
    )


def load_elcash_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load AuxPoW-recovered stale blocks from Electric Cash merged mining data.

    Returns records in the same shape as load_i0coin_stales() with
    source="elcash". Only loads entries with classification "stale" and
    validation_status "VALID". The extraction did not preserve decoded
    coinbase outputs, so pool identification downstream relies on scriptsig
    markers only.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["elcash"], min_height=min_height)


def load_lyncoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load the header-only Lyncoin validated-stale publication input.

    The complete pre-Flex recovery found no accepted direct-stale candidates.
    A normal loader keeps the zero-row artifact inside chronology and novelty
    checks and will admit future VALID stale rows without a second path.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["lyncoin"], min_height=min_height)


def _outputs_for_tagging(raw_outputs: str) -> str:
    """Normalize mixed output encodings to the established semicolon form."""
    if not raw_outputs:
        return ""
    out = []
    for part in raw_outputs.replace(";", "|").split("|"):
        entry = part.strip()
        if not entry:
            continue
        if ":" in entry:
            label, _value = entry.split(":", 1)
            if label == "OP_RETURN":
                continue
            entry = label
        out.append(entry)
    return ";".join(out)


def load_stale_descendants(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load derived BTC stale-fork descendants from the unknown inventories.

    `scripts/analysis/reconcile_unknown_stale_ancestry.py` writes this file
    after walking unknown-row `btc_prev_hash` ancestry back to known BTC
    stale headers. Raw classifier rows remain `unknown`; this loader admits
    only rows with `classification == "stale_descendant"` and
    `validation_status == "VALID_STALE_DESCENDANT"` so downstream consumers get
    valid stale-fork continuation headers without weakening the one-hop stale
    classifier semantics.
    """
    if not STALE_DESCENDANTS_CSV.exists():
        return []

    rows = []
    with open(STALE_DESCENDANTS_CSV, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("classification") != "stale_descendant":
                continue
            if row.get("validation_status") != "VALID_STALE_DESCENDANT":
                continue
            h = int(row["btc_height"])
            if h < min_height:
                continue
            rows.append(
                {
                    "height": h,
                    "hash": row["btc_header_hash"],
                    "source": "stale-descendant",
                    "_scriptsig_hex": row.get("coinbase_scriptsig_hex", ""),
                    "_outputs_str": _outputs_for_tagging(
                        row.get("coinbase_outputs", "")
                    ),
                }
            )
    rows.sort(key=lambda r: r["height"])
    return exclude_consensus_invalid_rows(rows)


def load_stale_descendant_observation_keys(
    path: Path = STALE_DESCENDANTS_CSV,
) -> frozenset[tuple[str, int, str]]:
    """Return accepted source observations as ``(chain, BTC height, hash)`` keys.

    These keys join exact source rows to the independently validated
    stale-descendant sidecar. Unknown source rows retain their primary
    classification; a direct-stale source row corrected by the exact-key
    overlay can be projected into its final ``stale_descendant`` state.
    """
    if not path.exists():
        return frozenset()

    observations: set[tuple[str, int, str]] = set()
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "classification",
            "validation_status",
            "btc_height",
            "btc_header_hash",
            "source_rows",
        }
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{path}: missing stale-descendant columns: "
                + ", ".join(sorted(missing))
            )
        for row_number, row in enumerate(reader, start=2):
            if row["classification"] != "stale_descendant" or (
                row["validation_status"] != "VALID_STALE_DESCENDANT"
            ):
                continue
            try:
                height = int(row["btc_height"])
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"{path}:{row_number}: btc_height must be an integer"
                ) from exc
            if height < 0:
                raise ValueError(
                    f"{path}:{row_number}: btc_height must be non-negative"
                )
            block_hash = row["btc_header_hash"].strip().lower()
            if len(block_hash) != 64:
                raise ValueError(
                    f"{path}:{row_number}: btc_header_hash must be 32 bytes"
                )
            try:
                bytes.fromhex(block_hash)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{row_number}: btc_header_hash must be hexadecimal"
                ) from exc
            for source_row in row["source_rows"].split("|"):
                chain, separator, _source = source_row.strip().partition(":")
                if not separator or not chain:
                    raise ValueError(
                        f"{path}:{row_number}: malformed source_rows entry"
                    )
                observations.add((chain, height, block_hash))
    return frozenset(observations)


def load_stale_descendant_correction_keys(
    path: Path = STALE_DESCENDANT_CORRECTIONS_CSV,
) -> frozenset[tuple[int, str]]:
    """Return exact keys explicitly corrected from direct stales.

    The compact correction overlay is distinct from the accepted descendant
    sidecar. A source row must match both this exact Bitcoin identity and its
    chain-specific sidecar observation before the monitor export projects it as
    a descendant.
    """
    if not path.exists():
        return frozenset()

    correction_keys: set[tuple[int, str]] = set()
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "btc_height",
            "btc_header_hash",
            "correction_reason",
        }
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{path}: missing stale-descendant correction columns: "
                + ", ".join(sorted(missing))
            )
        for row_number, row in enumerate(reader, start=2):
            if row["correction_reason"] != "reclassified_from_direct_stale":
                raise ValueError(f"{path}:{row_number}: unsupported correction_reason")
            try:
                height = int(row["btc_height"])
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"{path}:{row_number}: btc_height must be an integer"
                ) from exc
            if height < 0:
                raise ValueError(
                    f"{path}:{row_number}: btc_height must be non-negative"
                )
            block_hash = row["btc_header_hash"].strip().lower()
            if len(block_hash) != 64:
                raise ValueError(
                    f"{path}:{row_number}: btc_header_hash must be 32 bytes"
                )
            try:
                bytes.fromhex(block_hash)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{row_number}: btc_header_hash must be hexadecimal"
                ) from exc
            key = (height, block_hash)
            if key in correction_keys:
                raise ValueError(
                    f"{path}:{row_number}: duplicate stale-descendant correction key"
                )
            correction_keys.add(key)
    return frozenset(correction_keys)
