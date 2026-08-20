"""Runtime pool identification.

Loads the canonical mining-pools dataset from $LOCAL_MINING_POOLS_DIR,
merges it with any LOCAL_POOL_TAGS / LOCAL_OUTPUT_ADDR_POOLS overrides,
and exposes identify_pool() as the single entry point used by both
stale-block tagging and main-chain resolution.

Depends on: config (for LOCAL_MINING_POOLS_DIR), bitcoin_binary (for the
base58/bech32 address decoders). No dependency on analysis-layer code,
so this module can be imported early without pulling matplotlib, RPC, or
enrichment dependencies.
"""

import hashlib
import json

from .bitcoin_binary import _b58_decode_to_hash160, _bech32_decode_to_program
from .config import LOCAL_MINING_POOLS_DIR

# ── Local pool overrides ──────────────────────────────────────────────────
#
# LOCAL_POOL_TAGS is reserved for patterns that cannot live in upstream as
# "pools" — right now that's just a single catchall for individual miners
# (scriptsigs containing "Mined by <something>" that don't match any specific
# pool). At runtime, upstream tags run first; this entry catches whatever
# falls through.
#
# A pool-tag audit against the clone is a later milestone in the companion
# analysis repo; that flag does not exist here.

LOCAL_POOL_TAGS: list[tuple[bytes, str]] = []


# Hand-curated coinbase output address (hash160) overrides for pools the
# upstream canonical dataset doesn't cover. Runs after upstream in
# identify_pool(), so upstream wins on conflicts.
#
# Contract: an entry here must cite committed, publicly auditable evidence.
# Overrides whose research trail lives outside this repo are not carried;
# the preferred route for new identifications is an upstream contribution to
# bitcoin-data/mining-pools, which lands here on the next pin bump.
LOCAL_OUTPUT_ADDR_POOLS: dict[bytes, str] = {}


# ── KIT pool name mapping ────────────────────────────────────────────────
# Maps blockchain.info miner names (used in KIT forks.gpd) to canonical names.

KIT_POOL_MAP: dict[str, str] = {
    # Direct matches
    "AntPool": "AntPool",
    "F2Pool": "F2Pool",
    "ViaBTC": "ViaBTC",
    "BTC.com": "BTC.com",
    "BTC.TOP": "BTC.TOP",
    "Bixin": "Bixin",
    "ConnectBTC": "ConnectBTC",
    "GBMiners": "GBMiners",
    "GHash.IO": "GHash.IO",
    "Eligius": "Eligius",
    "KnCMiner": "KnCMiner",
    "BATPOOL": "BATPOOL",
    "Bitcoin.com": "Bitcoin.com",
    "BitMinter": "BitMinter",
    "Solo CKPool": "Solo CKPool",
    "58COIN": "58COIN",
    # Name variations
    "BitFury": "Bitfury",
    "BTCC Pool": "BTCC",
    "BW.COM": "BW.com",
    "BitClub Network": "BitClub",
    "SlushPool": "Braiins Pool",
    "KanoPool": "Kano CKPool",
    # KIT-only pools
    "21 Inc.": "21 Inc.",
    "Telco 214": "Telco 214",
    "GoGreenLight": "GoGreenLight",
    "EkanemBTC": "EkanemBTC",
    "EclipseMC": "EclipseMC",
    "myBTCcoin Pool": "myBTCcoin Pool",
    "shawnp0wers": "Individual Miner",
    "xbtc.exx.com&bw.com;": "BW.com",
    "185.24.97.11": "Unknown",
    "52.8.223.185": "Unknown",
    "1Hash": "1hash.com",
}


def map_kit_pool(kit_name: str) -> str:
    """Map a KIT/blockchain.info pool name to our canonical pool name."""
    return KIT_POOL_MAP.get(kit_name, kit_name)


def _norm_pool_name(name: str) -> str:
    """Canonicalise a pool name for fuzzy comparison.

    Trivial styling differences (case, whitespace, punctuation, "Pool"
    suffix) shouldn't trigger a name-disagreement report. Real disagreements
    survive normalisation.
    """
    s = name.lower().strip()
    for ch in " .-_/":
        s = s.replace(ch, "")
    if s.endswith("pool"):
        s = s[:-4]
    return s


def _decode_payout_address(addr: str) -> bytes | None:
    """Witness program or hash160 for a payout address, None if it is junk.

    A well-formed address that is not hash160-shaped (P2WSH, P2TR) decodes
    fine and is simply unusable for the 20-byte lookup; the pinned registry
    contains such an address, so "decodes" and "is usable" are deliberately
    different questions.
    """
    if addr.startswith("bc1"):
        return _bech32_decode_to_program(addr)
    return _b58_decode_to_hash160(addr)


def fetch_known_pools() -> dict:
    """Load the pool identification dataset from $LOCAL_MINING_POOLS_DIR.

    Walks <dir>/pools/*.json and folds each pool's tags and addresses into
    the same {coinbase_tags, payout_addresses} shape as the upstream
    `generated` branch's pools.json. Reads whatever is currently on disk —
    including uncommitted and untracked files — so your in-progress work
    in the clone is immediately visible to the analysis.

    This is the single source of truth for pool identification. Raises
    FileNotFoundError with instructions if the clone is missing.
    """
    pools_dir = LOCAL_MINING_POOLS_DIR / "pools"
    if not pools_dir.is_dir():
        raise FileNotFoundError(
            f"\n\n  Pool data source missing: {pools_dir}\n"
            f"\n  The analysis reads pool tags and payout addresses directly"
            f" from a local\n  clone of bitcoin-data/mining-pools. Clone it with:\n"
            f"\n      git clone https://github.com/bitcoin-data/mining-pools.git"
            f" {LOCAL_MINING_POOLS_DIR}\n"
            f"\n  Or set $LOCAL_MINING_POOLS_DIR to point at an existing clone.\n"
        )

    coinbase_tags: dict[str, dict] = {}
    payout_addresses: dict[str, dict] = {}
    pool_files = sorted(pools_dir.glob("*.json"))
    if not pool_files:
        raise FileNotFoundError(
            f"Pool data source empty: {pools_dir} contains no .json files. "
            f"Is this really a clone of bitcoin-data/mining-pools?"
        )

    # Two different pool files claiming the same tag or address would make
    # the exported label depend on filename order, so conflicts stop the run
    # instead of being resolved silently.
    tag_conflicts: list[tuple[str, str, str]] = []
    addr_conflicts: list[tuple[str, str, str]] = []

    for pool_file in pool_files:
        try:
            pool = json.loads(pool_file.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            # Fail closed: a skipped file would silently demote its pool's
            # blocks to Unknown (or weaker matches) while the export still
            # looks complete. This bites hardest in the supported dirty
            # local-registry workflow, where an in-progress edit must not
            # turn into partial experimental results.
            raise ValueError(
                f"Malformed pool registry file {pool_file}: {exc}. Fix or "
                "remove the file; attribution refuses to run from a partial "
                "registry."
            ) from exc
        for field in ("tags", "addresses"):
            value = pool.get(field)
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                # A string value would be iterated per character and register
                # overbroad one-character tags (a "/" tag matches almost
                # every coinbase), and an empty-string tag encodes to b"",
                # which occurs in every scriptSig and would claim every
                # otherwise-unmatched row. Schema errors fail closed like
                # unparseable JSON does.
                raise ValueError(
                    f"Malformed pool registry file {pool_file}: {field!r} "
                    "must be present and an array of non-empty strings "
                    "(null and missing both hide markers). Fix or remove "
                    "the file; attribution refuses to run from a partial "
                    "registry."
                )
        for tag in pool["tags"]:
            # Tags are matched as UTF-8 bytes, so the rule is on encoded
            # length, not characters: a single byte like "/" appears in
            # almost every coinbase and would claim every otherwise
            # unmatched row, while F2Pool's one-character emoji tag is four
            # bytes and perfectly specific.
            if len(tag.encode("utf-8")) < 2:
                raise ValueError(
                    f"Malformed pool registry file {pool_file}: tag {tag!r} "
                    "encodes to a single byte, which matches almost every "
                    "coinbase. Use a more specific tag; attribution refuses "
                    "to run from a registry that would over-claim."
                )

        for addr in pool["addresses"]:
            # An address that does not decode would be dropped from the
            # runtime table, quietly weakening that pool's attribution.
            if _decode_payout_address(addr) is None:
                raise ValueError(
                    f"Malformed pool registry file {pool_file}: payout "
                    f"address {addr!r} does not decode as base58check or "
                    "bech32. Fix or remove the file; attribution refuses to "
                    "run from a registry whose markers it cannot read."
                )

        name = pool.get("name")
        link = pool.get("link", "") or ""
        if not isinstance(name, str) or not name.strip():
            # Skipping would silently drop the file's tags and addresses
            # from the runtime tables while the export still looks
            # complete: fail closed like the other schema defects.
            raise ValueError(
                f"Malformed pool registry file {pool_file}: 'name' must be "
                "a non-empty string. Fix or remove the file; attribution "
                "refuses to run from a partial registry."
            )
        entry = {"name": name, "link": link}
        for tag in pool["tags"]:
            if tag in coinbase_tags and coinbase_tags[tag]["name"] != name:
                tag_conflicts.append((tag, coinbase_tags[tag]["name"], name))
            coinbase_tags[tag] = entry
        for addr in pool["addresses"]:
            if addr in payout_addresses and payout_addresses[addr]["name"] != name:
                addr_conflicts.append((addr, payout_addresses[addr]["name"], name))
            payout_addresses[addr] = entry

    if tag_conflicts or addr_conflicts:
        details = [f"tag {x!r}: {a} vs {b}" for x, a, b in tag_conflicts[:5]]
        details += [f"address {x}: {a} vs {b}" for x, a, b in addr_conflicts[:5]]
        raise ValueError(
            "Conflicting pool markers in the registry: "
            + "; ".join(details)
            + ". Two pool files claim the same marker, so the exported label "
            "would depend on filename order. Resolve the conflict (ideally "
            "upstream) before attributing."
        )

    print(
        f"  Pool data: {LOCAL_MINING_POOLS_DIR} "
        f"({len(coinbase_tags)} tags, {len(payout_addresses)} addresses, working tree)"
    )
    return {"coinbase_tags": coinbase_tags, "payout_addresses": payout_addresses}


# ── Runtime pool tables (upstream + local additions) ─────────────────────
#
# Built lazily on the first identify_pool() call. The combined tables are
# (upstream first, local additions second) so upstream canonical names win
# on any tag/address present in both. Module import does not touch the
# network; the cache is only consulted when identify_pool() is invoked.

_RUNTIME_POOL_TAGS: list[tuple[bytes, str]] | None = None
_RUNTIME_OUTPUT_ADDR_POOLS: dict[bytes, str] | None = None


def _build_runtime_pool_tables() -> tuple[list[tuple[bytes, str]], dict[bytes, str]]:
    """Decode upstream JSON + concatenate local additions for runtime use."""
    data = fetch_known_pools()

    # Coinbase tags: encode str -> bytes (UTF-8 preserves emoji and Chinese
    # characters), sort by length descending so longer / more specific
    # patterns are checked first (matches the existing first-match-wins
    # convention).
    upstream_tags: list[tuple[bytes, str]] = sorted(
        (
            (tag.encode("utf-8"), entry["name"])
            for tag, entry in data["coinbase_tags"].items()
        ),
        key=lambda x: -len(x[0]),
    )
    runtime_tags = upstream_tags + LOCAL_POOL_TAGS

    # Payout addresses: decode each base58check (P2PKH/P2SH) or bech32
    # (P2WPKH only — P2WSH/P2TR don't fit the 20-byte hash160 lookup) into
    # a {hash160: name} dict.
    upstream_addrs: dict[bytes, str] = {}
    for addr, entry in data["payout_addresses"].items():
        # Every address here decoded during loading; only hash160-shaped
        # ones can back the 20-byte output lookup, so P2WSH/P2TR payout
        # addresses are carried in the registry but not in this table.
        program = _decode_payout_address(addr)
        if program is not None and len(program) == 20:
            upstream_addrs[program] = entry["name"]

    # Local additions only catch h160s upstream missed: upstream is the
    # later (winning) operand of the merge, so a colliding local override
    # can never displace an upstream mapping.
    runtime_addrs = {**LOCAL_OUTPUT_ADDR_POOLS, **upstream_addrs}
    return runtime_tags, runtime_addrs


def _ensure_runtime_pool_tables() -> tuple[list[tuple[bytes, str]], dict[bytes, str]]:
    """Lazily build and cache the merged runtime pool tables."""
    global _RUNTIME_POOL_TAGS, _RUNTIME_OUTPUT_ADDR_POOLS
    if _RUNTIME_POOL_TAGS is None or _RUNTIME_OUTPUT_ADDR_POOLS is None:
        _RUNTIME_POOL_TAGS, _RUNTIME_OUTPUT_ADDR_POOLS = _build_runtime_pool_tables()
    return _RUNTIME_POOL_TAGS, _RUNTIME_OUTPUT_ADDR_POOLS


def reset_runtime_pool_tables() -> None:
    """Drop the cached runtime tables so the next call rebuilds from disk.

    The tables are cached per process for identification speed. A long-lived
    process (notebook, the companion analysis library) that edits or checks
    out the mining-pools clone between runs would otherwise identify against
    stale tables while the meta sidecar records the NEW dataset fingerprint;
    every attribution run resets the cache first so labels always match the
    recorded provenance.
    """
    global _RUNTIME_POOL_TAGS, _RUNTIME_OUTPUT_ADDR_POOLS
    _RUNTIME_POOL_TAGS = None
    _RUNTIME_OUTPUT_ADDR_POOLS = None


def pool_dataset_fingerprint() -> str:
    """Stable SHA-256 fingerprint of the full pool identification dataset.

    Covers the upstream mining-pools/*.json files, LOCAL_POOL_TAGS, and
    LOCAL_OUTPUT_ADDR_POOLS. Used by the layer-2 assignments cache to
    detect when pool tables have changed and a rebuild is needed.
    """
    h = hashlib.sha256()
    # Upstream pool JSON files (sorted for determinism).
    pools_dir = LOCAL_MINING_POOLS_DIR / "pools"
    if pools_dir.is_dir():
        for f in sorted(pools_dir.glob("*.json")):
            h.update(f.name.encode())
            h.update(f.read_bytes())
    # Local overrides — changes here must also invalidate.
    h.update(repr(LOCAL_POOL_TAGS).encode())
    h.update(repr(sorted(LOCAL_OUTPUT_ADDR_POOLS.items())).encode())
    return h.hexdigest()


def identify_pool_detailed(
    sig: bytes | None, outputs: list[tuple[int, bytes]] | None = None
) -> tuple[str, str]:
    """Identify a pool and report what kind of evidence matched.

    Returns ``(name, method)`` with method one of ``"tag"`` (scriptSig tag),
    ``"op_return"`` (tag found in a coinbase OP_RETURN output),
    ``"address"`` (payout-address hash160 match), or ``"none"``. Downstream
    consumers that make tag-evidence-only claims (the template-producer
    fold) gate on the method.
    """
    if not sig:
        return "Unknown", "none"

    pool_tags, addr_pools = _ensure_runtime_pool_tables()

    # 1. ScriptSig tag matching
    for tag, name in pool_tags:
        if tag in sig:
            return name, "tag"

    # 2. OP_RETURN data in coinbase outputs (e.g. "Mined by 1hash.com")
    if outputs:
        for _value, spk in outputs:
            if len(spk) >= 3 and spk[0] == 0x6A:  # OP_RETURN
                for tag, name in pool_tags:
                    if tag in spk:
                        return name, "op_return"
                # Check for "1hash.com" in OP_RETURN specifically
                if b"1hash.com" in spk:
                    return "1hash.com", "op_return"

        # 3. Output address matching (last resort for tagless miners)
        for _value, spk in outputs:
            h160 = None
            if len(spk) == 25 and spk[0] == 0x76:  # P2PKH
                h160 = spk[3:23]
            elif len(spk) == 23 and spk[0] == 0xA9:  # P2SH
                h160 = spk[2:22]
            elif len(spk) == 22 and spk[0] == 0x00:  # P2WPKH
                h160 = spk[2:]
            if h160 and h160 in addr_pools:
                return addr_pools[h160], "address"

    return "Unknown", "none"


def identify_pool(
    sig: bytes | None, outputs: list[tuple[int, bytes]] | None = None
) -> str:
    """Identify pool from coinbase scriptSig, OP_RETURN data, and output addresses."""
    return identify_pool_detailed(sig, outputs)[0]
