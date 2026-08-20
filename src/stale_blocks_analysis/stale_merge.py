"""Merging and pool-tagging of loaded stale-block records.

Analysis-side companions to the loaders in `stale_blocks.py`:
`merge_stale_sources` combines the upstream bitcoin-data/stale-blocks
baseline with AuxPoW-recovered records (deduplicating by (height, hash)),
and `tag_stale_blocks` attributes each record to a mining pool via
`identify_pool`. The loaders themselves stay free of pool attribution so
the acquisition/recovery pipeline never imports the pool dataset.

Depends on: config (BLOCKS_DIR), bitcoin_binary (parse_coinbase),
pool_identification (identify_pool), stale_blocks (_addr_to_spk).
"""

from .bitcoin_binary import parse_coinbase
from .config import BLOCKS_DIR
from .pool_identification import identify_pool
from .stale_blocks import _addr_to_spk


def merge_stale_sources(
    primary: list[dict],
    auxpow: list[dict],
) -> list[dict]:
    """Merge stale block lists, deduplicating by (height, hash).

    Primary (bitcoin-data/stale-blocks) wins on exact duplicates; AuxPoW
    records at new (height, hash) pairs are added. Records at the same
    height but with different hashes are both kept (multi-way forks).

    For exact duplicates, the AuxPoW coinbase fields (_scriptsig_hex,
    _outputs_str) are carried over to the primary record so
    tag_stale_blocks() can use them as a fallback when the .bin file is
    missing.
    """
    primary_idx = {(b["height"], b["hash"]): b for b in primary}
    merged = list(primary)
    added = 0
    enriched = 0
    for b in auxpow:
        key = (b["height"], b["hash"])
        if key in primary_idx:
            # Carry AuxPoW coinbase data to the primary record as fallback.
            # Both observations witness the same Bitcoin coinbase, so the
            # scriptSig and the outputs are filled independently: a record
            # that already has one field can still gain the other from a
            # later observation. Non-empty fields are never overwritten.
            pri = primary_idx[key]
            filled = False
            if not pri.get("_scriptsig_hex") and b.get("_scriptsig_hex"):
                pri["_scriptsig_hex"] = b["_scriptsig_hex"]
                filled = True
            if not pri.get("_outputs_str") and b.get("_outputs_str"):
                pri["_outputs_str"] = b["_outputs_str"]
                filled = True
            if filled:
                pri.setdefault("_outputs_str", "")
                enriched += 1
        else:
            primary_idx[key] = b
            merged.append(b)
            added += 1
    merged.sort(key=lambda r: r["height"])
    print(
        f"  Merged stale sources: {len(primary)} primary + {added} new from AuxPoW "
        f"= {len(merged)} total ({enriched} primary enriched with AuxPoW coinbase)"
    )
    return merged


def tag_stale_blocks(blocks: list[dict]) -> list[dict]:
    """Parse .bin files and tag each block with its pool name.

    For AuxPoW-sourced blocks (no .bin file), uses the pre-parsed coinbase
    scriptsig hex and output addresses carried in the record. Records that
    arrive pre-tagged (pool already set, as for RSK rows whose attribution
    comes from a miner-address registry rather than the BTC coinbase) skip
    identify_pool entirely.
    """
    for b in blocks:
        # Pre-tagged source (e.g., RSK with miner-address pool resolution).
        if b.get("pool"):
            b.setdefault("has_bin", False)
            b.pop("_scriptsig_hex", None)
            b.pop("_outputs_str", None)
            continue

        # Try .bin file first (primary source)
        path = BLOCKS_DIR / f"{b['height']}-{b['hash']}.bin"
        has_bin = path.exists()
        if has_bin:
            cb = parse_coinbase(path.read_bytes())
            if cb:
                b["pool"] = identify_pool(cb["scriptsig"], cb["outputs"])
                b["has_bin"] = True
                continue
            # Unparseable binary: fall through to the carried AuxPoW coinbase
            # (when present) so an unusable file never makes attribution
            # worse than having no binary at all. has_bin still records that
            # the file exists.

        # AuxPoW source: use pre-parsed coinbase data
        sig_hex = b.pop("_scriptsig_hex", "")
        outputs_str = b.pop("_outputs_str", "")

        if sig_hex:
            scriptsig = bytes.fromhex(sig_hex)
            # Build (value, scriptPubKey) tuples. Each entry is either a
            # base58/bech32 address (NMC, Syscoin loaders) or a raw
            # scriptPubKey hex string (Devcoin, ixcoin loaders, whose
            # source CSVs carry scripts not addresses). Try address first,
            # fall back to hex.
            outputs = []
            if outputs_str:
                for entry in outputs_str.split(";"):
                    entry = entry.strip()
                    if not entry:
                        continue
                    spk = _addr_to_spk(entry)
                    if spk is None:
                        try:
                            spk = bytes.fromhex(entry)
                        except ValueError:
                            continue
                    outputs.append((0, spk))
            b["pool"] = identify_pool(scriptsig, outputs or None)
        else:
            b["pool"] = "Unknown"

        b["has_bin"] = has_bin

    return blocks
