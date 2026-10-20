"""Loaders for the upstream stale-blocks CSV and per-chain validated CSVs.

Records are ``height``, ``hash``, ``source``, and where available
``_scriptsig_hex`` / ``_outputs_str``. Merging and pool attribution are
separate passes.
"""

import csv
from dataclasses import dataclass

from .coinbase_output_claims import (
    parse_coinbase_output_claims,
    render_coinbase_output_claims,
)
from .config import (
    ACCEPTED_STALE_VALIDATION_STATUSES,
    MIN_HEIGHT,
    RSK_CSV,
    STALE_CSV,
    STALE_DESCENDANT_OBSERVATIONS_CSV,
    STALE_DESCENDANTS_CSV,
)
from .error_blocks import exclude_error_block_rows
from .stale_descendants import (
    load_stale_descendant_observations,
    load_stale_descendant_parents,
)

# Bound for LoaderSpec's globals()[csv_attr] lookup and for
# monkeypatch.setattr(stale_blocks, "<CHAIN>_CSV", ...). Unused by name.
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
    ROD_CSV,
    QBIT_CSV,
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
    rows = exclude_error_block_rows(rows)
    rows.sort(key=lambda r: r["height"])
    return rows


@dataclass(frozen=True)
class LoaderSpec:
    """CSV-reading differences among the per-chain loaders.

    ``csv_attr`` is resolved at call time, not import, so a monkeypatch of
    the path constant still applies. Committed rows must be exactly ``VALID``
    or ``VALID (post-BCH, difficulty matches BTC)``. These fields stay off
    ``ChainSpec``, which is the extraction registry shared with the scripts.
    """

    csv_attr: str
    source: str
    height_col: str = "btc_height"
    hash_col: str = "btc_header_hash"
    require_stale: bool = True
    skip_empty_height: bool = False


def load_auxpow_validated_stales(
    spec: LoaderSpec, min_height: int = MIN_HEIGHT
) -> list[dict]:
    """Read ``spec.csv_attr`` at call time. An absent CSV returns ``[]``.

    The ``coinbase_outputs`` cell is passed through unchanged.
    """
    csv_path = globals()[spec.csv_attr]
    if not csv_path.exists():
        return []

    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            if spec.require_stale and row.get("classification") != "stale":
                continue
            if (
                row.get("validation_status", "")
                not in ACCEPTED_STALE_VALIDATION_STATUSES
            ):
                continue
            height_str = row.get(spec.height_col, "")
            if spec.skip_empty_height and not height_str:
                continue
            h = int(row[spec.height_col])
            if h < min_height:
                continue
            # Pass the committed cell through. Rewriting dropped placeholders
            # and stripped amounts.
            outputs_str = row.get("coinbase_outputs", "")
            rows.append(
                {
                    "height": h,
                    "hash": row[spec.hash_col],
                    "source": spec.source,
                    "_scriptsig_hex": row.get("coinbase_scriptsig_hex", ""),
                    "_outputs_str": outputs_str,
                }
            )
    rows = exclude_error_block_rows(rows)
    rows.sort(key=lambda r: r["height"])
    return rows


# Public load_<chain>_stales wrappers bind these specs.
_LOADER_SPECS: dict[str, LoaderSpec] = {
    "qbit": LoaderSpec(csv_attr="QBIT_CSV", source="qbit"),
    "namecoin": LoaderSpec(
        # Legacy columns were btc_stale_height / btc_hash / btc_bits_hex.
        # Exact statuses still include "VALID (post-BCH, difficulty matches BTC)".
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
    ),
    "devcoin": LoaderSpec(
        csv_attr="DEVCOIN_CSV",
        source="devcoin",
    ),
    "i0coin": LoaderSpec(
        # Legacy columns were btc_stale_height / btc_hash / btc_bits_hex.
        # Exact statuses still include "VALID (post-BCH, difficulty matches BTC)".
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
    "rod": LoaderSpec(
        csv_attr="ROD_CSV",
        source="rod",
    ),
    "elastos": LoaderSpec(
        csv_attr="ELASTOS_CSV",
        source="elastos",
    ),
    "hathor": LoaderSpec(
        csv_attr="HATHOR_CSV",
        source="hathor",
    ),
    "fractal": LoaderSpec(
        csv_attr="FRACTAL_CSV",
        source="fractal",
    ),
    "bitcoin_vault": LoaderSpec(
        csv_attr="BITCOIN_VAULT_CSV",
        source="bitcoin-vault",
    ),
}


def load_namecoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Namecoin coinbase evidence comes from the AuxPoW CSV, not a .bin."""
    return load_auxpow_validated_stales(
        _LOADER_SPECS["namecoin"], min_height=min_height
    )


def load_geistgeld_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Geistgeld's dump has no ``auxpow.coinbasetx.vout``, so outputs are empty.

    ``_scriptsig_hex`` still keeps the parent coinbase scriptSig.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["geistgeld"], min_height=min_height
    )


def load_syscoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Syscoin address-derived payouts are recipient-only ``pkh`` claims.

    The child node decoded version-63 base58 / ``sys1``. The cell is passed
    through unchanged.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["syscoin"], min_height=min_height)


def load_devcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Devcoin keeps every output, including the leading miner payout."""
    return load_auxpow_validated_stales(_LOADER_SPECS["devcoin"], min_height=min_height)


def load_i0coin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    return load_auxpow_validated_stales(_LOADER_SPECS["i0coin"], min_height=min_height)


def load_coiledcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """``eligius_attack_window`` marks BTC ~160,000-163,000 and is not a filter."""
    return load_auxpow_validated_stales(
        _LOADER_SPECS["coiledcoin"], min_height=min_height
    )


def load_ixcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    return load_auxpow_validated_stales(_LOADER_SPECS["ixcoin"], min_height=min_height)


def load_groupcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Groupcoin ``addresses`` are Groupcoin base58 (``2h…``), not BTC mainnet.

    Outputs are rendered from ``scriptPubKey.hex``. Those decoded addresses
    must not be used.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["groupcoin"], min_height=min_height
    )


def load_huntercoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Kraft native dump, SHA-256d chain ID 6 only.

    The Scrypt branch (chain ID 2, LTC parent) is out of scope.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["huntercoin"], min_height=min_height
    )


def load_unobtanium_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    return load_auxpow_validated_stales(
        _LOADER_SPECS["unobtanium"], min_height=min_height
    )


def load_myriadcoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Only the SHA-256d branch (nVersion bits 9-11, algo 0) is Bitcoin-parent."""
    return load_auxpow_validated_stales(
        _LOADER_SPECS["myriadcoin"], min_height=min_height
    )


def load_sixeleven_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Header-only until a VALID stale row is admitted. No second path."""
    return load_auxpow_validated_stales(
        _LOADER_SPECS["sixeleven"], min_height=min_height
    )


def load_bitmark_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """SHA-256d is nVersion bits 9-11 with ``ALGO_SHA256D = 1``, not Myriadcoin's 0."""
    return load_auxpow_validated_stales(_LOADER_SPECS["bitmark"], min_height=min_height)


def load_argentum_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """SHA-256d is ``(nVersion & 0x0E00) == 0x0200`` (``1 << 9``), not algo 0.

    Scrypt is the default. ``fStrictChainId`` is false. Parentage is Bitcoin
    Core lookup plus the expected-nBits gate, not the self-target check.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["argentum"], min_height=min_height
    )


def load_crown_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Chain ID 20, ``fStrictChainId``. AuxPoW from height 453,273.

    PoS-hybrid at 2,330,000 carries no AuxPoW. No per-algo filter.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["crown"], min_height=min_height)


def load_xaya_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Chain ID 1829. SHA256D must be merge-mined; NEOSCRYPT carries no AuxPoW.

    PowData is keyed on the ``0x80`` merge-mined flag. Active from genesis
    (2018-07-13). No ``fStrictChainId`` flag.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["xaya"], min_height=min_height)


def load_terracoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Terracoin decoded addresses collapse P2PK to P2PKH-form ``pkh`` claims.

    The cell is passed through unchanged.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["terracoin"], min_height=min_height
    )


def load_emercoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Only PoW blocks carry AuxPoW. PoS is filtered at extraction."""
    return load_auxpow_validated_stales(
        _LOADER_SPECS["emercoin"], min_height=min_height
    )


def load_doichain_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Header-only through height 430,684 until a stale row is admitted."""
    return load_auxpow_validated_stales(
        _LOADER_SPECS["doichain"], min_height=min_height
    )


def load_elastos_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Rejected BCH/BSV-contamination rows and unknown rows stay out."""
    return load_auxpow_validated_stales(_LOADER_SPECS["elastos"], min_height=min_height)


def load_rsk_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """RSK's compressed proof does not reconstruct the BTC parent coinbase.

    Historical ``pool_label`` columns stay in the CSV. This loader returns
    only the accepted header identity.
    """
    if not RSK_CSV.exists():
        return []

    rows = []
    with open(RSK_CSV, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("classification") != "stale":
                continue
            if (
                row.get("validation_status", "")
                not in ACCEPTED_STALE_VALIDATION_STATUSES
            ):
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
    rows = exclude_error_block_rows(rows)
    rows.sort(key=lambda r: r["height"])
    return rows


def load_hathor_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """RFC-0006 split-header proof, coinbase tag ``Hath``, not CAuxPow.

    RPC-miss rows stay unresolved and never enter this loader.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["hathor"], min_height=min_height)


def load_fractal_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """AuxPoW flag plus chain ID ``0x2024``. ``0x2026`` Indexer is a different proof.

    Compact ``getblockheader`` does not decode the parent coinbase, so outputs
    are rendered from the script bytes.
    """
    return load_auxpow_validated_stales(_LOADER_SPECS["fractal"], min_height=min_height)


def load_bitcoin_vault_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Dormant chain; outputs come from raw block hex, not a live node.

    Nulldata survives only as the legacy ``OP_RETURN`` label.
    """
    return load_auxpow_validated_stales(
        _LOADER_SPECS["bitcoin_vault"], min_height=min_height
    )


def load_elcash_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """No decoded coinbase outputs. Attribution can use scriptSig markers only."""
    return load_auxpow_validated_stales(_LOADER_SPECS["elcash"], min_height=min_height)


def load_lyncoin_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Header-only pre-Flex recovery. No second path for a later VALID row."""
    return load_auxpow_validated_stales(_LOADER_SPECS["lyncoin"], min_height=min_height)


def load_rod_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Canonical companion only. The absent validated-stales path returns ``[]``."""
    return load_auxpow_validated_stales(_LOADER_SPECS["rod"], min_height=min_height)


def load_qbit_stales(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Load native-archive Qbit direct stales through the shared verdict gate."""
    return load_auxpow_validated_stales(_LOADER_SPECS["qbit"], min_height=min_height)


def _outputs_for_tagging(raw_outputs: str) -> str:
    """Return canonical output claims for downstream pool tagging."""
    return render_coinbase_output_claims(parse_coinbase_output_claims(raw_outputs))


def load_stale_descendants(min_height: int = MIN_HEIGHT) -> list[dict]:
    """Admit only ``stale_descendant`` / ``VALID_STALE_DESCENDANT`` parents.

    Source classifications stay in the observation ledger. A missing,
    malformed, or parent-inconsistent witness ledger fails closed before any
    parent is admitted.
    """
    load_stale_descendant_observations(
        STALE_DESCENDANT_OBSERVATIONS_CSV,
        parents_path=STALE_DESCENDANTS_CSV,
    )
    rows = []
    for parent in load_stale_descendant_parents(STALE_DESCENDANTS_CSV).values():
        if parent.height < min_height:
            continue
        rows.append(
            {
                "height": parent.height,
                "hash": parent.block_hash,
                "source": "stale-descendant",
                "_scriptsig_hex": parent.row.get("coinbase_scriptsig_hex", ""),
                "_outputs_str": _outputs_for_tagging(
                    parent.row.get("coinbase_outputs", "")
                ),
            }
        )
    rows.sort(key=lambda r: r["height"])
    return exclude_error_block_rows(rows)
