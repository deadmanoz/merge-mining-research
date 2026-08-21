"""Merging and pool-tagging of loaded stale-block records.

Analysis-side companions to the loaders in `stale_blocks.py`:
`merge_stale_sources` combines the upstream bitcoin-data/stale-blocks
baseline with AuxPoW-recovered records (deduplicating by (height, hash)),
and `tag_stale_blocks` attributes each record to a mining pool via
`identify_pool`. The loaders themselves stay free of pool attribution so
the acquisition/recovery pipeline never imports the pool dataset.

Depends on: config (BLOCKS_DIR), bitcoin_binary (parse_coinbase),
pool_identification (identify_pool_detailed), stale_blocks (_addr_to_spk).
"""

from .bitcoin_binary import parse_coinbase, sha256d
from .config import BLOCKS_DIR
from .pool_identification import identify_pool_detailed
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
    # Deduplicate exact keys inside the primary list itself (first row
    # wins), so a duplicated upstream row can never double-count a stale
    # event or split its AuxPoW enrichment across copies. The upstream
    # census currently has no exact-key duplicates; this is the doctrine
    # (dedupe by (height, hash)) enforced rather than assumed.
    primary_idx: dict = {}
    merged: list[dict] = []
    primary_dupes = 0
    for b in primary:
        key = (b["height"], b["hash"])
        if key in primary_idx:
            primary_dupes += 1
            continue
        primary_idx[key] = b
        merged.append(b)
    if primary_dupes:
        print(f"  {primary_dupes} exact-duplicate primary rows dropped")
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
            # Outputs are unioned, not just filled. Chains describe the
            # same coinbase differently: a Namecoin RPC yields decoded
            # payout addresses (dropping OP_RETURN and P2PK), while ixcoin
            # and i0coin yield complete raw scripts. Keeping only the first
            # observation's list discards a tag another chain preserved.
            if b.get("_outputs_str"):
                existing = [
                    e for e in (pri.get("_outputs_str") or "").split(";") if e.strip()
                ]
                incoming = [e for e in b["_outputs_str"].split(";") if e.strip()]
                unioned = existing + [e for e in incoming if e not in existing]
                if unioned != existing:
                    pri["_outputs_str"] = ";".join(unioned)
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


def tag_stale_blocks(blocks: list[dict], allow_partial: bool = False) -> list[dict]:
    """Parse .bin files and tag each block with its pool name.

    For AuxPoW-sourced blocks (no .bin file), uses the pre-parsed coinbase
    scriptsig hex and output addresses carried in the record. A tracked
    binary that holds the wrong block, or whose coinbase will not parse,
    stops the run unless *allow_partial* permits the AuxPoW fallback. Records that
    arrive pre-tagged (pool already set by a caller that labels before
    tagging) skip identification entirely; in this repo's own assembly no
    record arrives pre-tagged — RSK rows enter untagged and receive their
    historical registry labels in a later attribution pass, so coinbase
    evidence wins.
    """
    for b in blocks:
        # A caller-supplied label bypasses identification, but the "Unknown"
        # sentinel is not a label: a row carrying it still has its coinbase
        # evidence read, exactly as if the key were absent.
        if b.get("pool") and b["pool"] != "Unknown":
            b.setdefault("has_bin", False)
            b.pop("_scriptsig_hex", None)
            b.pop("_outputs_str", None)
            continue

        # Try .bin file first (primary source)
        path = BLOCKS_DIR / f"{b['height']}-{b['hash']}.bin"
        has_bin = path.exists()
        if has_bin:
            raw = path.read_bytes()
            # The file name claims a block; the bytes must agree. A
            # misplaced but parseable binary would otherwise label an
            # unrelated stale row from the wrong coinbase.
            header_hash = sha256d(raw[:80])[::-1].hex() if len(raw) >= 80 else None
            if header_hash != b["hash"]:
                raise ValueError(
                    f"Block archive file {path.name} does not contain the "
                    f"block it names (header hashes to {header_hash}). "
                    "Re-fetch the pinned bitcoin-data/stale-blocks clone; "
                    "attribution refuses to label a row from another "
                    "block's coinbase."
                )
            cb = parse_coinbase(raw)
            if cb:
                b["pool"], b["_pool_match"] = identify_pool_detailed(
                    cb["scriptsig"], cb["outputs"]
                )
                b["has_bin"] = True
                continue
            # A tracked file whose body will not parse is a corrupt
            # archive, not an absent one: the filename inventory still
            # reports it present, so falling back silently would hide it
            # behind provenance that claims a complete archive. Partial
            # mode is the deliberate way to proceed on the carried AuxPoW
            # coinbase instead.
            if not allow_partial:
                raise ValueError(
                    f"Block archive file {path.name} contains the right "
                    "block but its coinbase will not parse. Re-fetch the "
                    "pinned bitcoin-data/stale-blocks clone, or pass "
                    "--allow-partial to attribute from the carried AuxPoW "
                    "evidence instead."
                )

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
            b["pool"], b["_pool_match"] = identify_pool_detailed(
                scriptsig, outputs or None
            )
        else:
            b["pool"] = "Unknown"
            b["_pool_match"] = "none"

        b["has_bin"] = has_bin

    return blocks
