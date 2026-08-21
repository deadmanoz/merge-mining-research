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
from .coinbase_markers import parse_op_return_payload
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


# Hand-curated coinbase output overrides, keyed by complete scriptPubKey,
# for pools the
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
    # The registry's canonical name for this pool is "1Hash", which is what
    # coinbase identification returns; mapping the KIT census name to a
    # different spelling would split one pool across two labels.
    "1Hash": "1Hash",
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


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _payout_address_problem(addr: str) -> str | None:
    """Why *addr* is unusable as a registry marker, or None if it is sound.

    The shared decoders in bitcoin_binary deliberately skip checksums,
    because their callers only need the payload bytes. A registry marker is
    different: a mistyped address that still decodes registers the wrong
    hash160, so that pool's real payouts stop matching and its rows quietly
    weaken. Checksums are therefore verified here, without changing the
    shared decoders that the recovery pipeline also uses.
    """
    if addr != addr.strip() or not addr:
        return "has surrounding whitespace"
    if addr.lower().startswith("bc1"):
        lowered = addr.lower()
        if addr != lowered and addr != addr.upper():
            return "mixes upper and lower case"
        pos = lowered.rfind("1")
        hrp, data = lowered[:pos], lowered[pos + 1 :]
        if len(data) < 6 or any(c not in _BECH32_CHARSET for c in data):
            return "is not valid bech32"
        values = (
            [ord(c) >> 5 for c in hrp]
            + [0]
            + [ord(c) & 31 for c in hrp]
            + [_BECH32_CHARSET.index(c) for c in data]
        )
        witness_version = _BECH32_CHARSET.index(data[0])
        if witness_version > 16:
            return (
                f"has witness version {witness_version}, which SegWit does not define"
            )
        checksum = _bech32_polymod(values)
        expected = 1 if witness_version == 0 else 0x2BC830A3
        if checksum != expected:
            return "fails its bech32 checksum"
        # Strict 5-to-8 bit conversion: BIP-173 forbids leftover bits that
        # form another group, and requires the padding bits to be zero. The
        # shared decoder discards them, so an address with extra or
        # non-zero padding would decode to a valid-looking program.
        payload = [_BECH32_CHARSET.index(c) for c in data[:-6]][1:]
        acc = bits = 0
        for value in payload:
            acc = (acc << 5) | value
            bits += 5
            if bits >= 8:
                bits -= 8
        if bits >= 5 or (acc & ((1 << bits) - 1)):
            return "has non-canonical SegWit padding"
        program = _bech32_decode_to_program(lowered)
        if program is None:
            return "does not decode to a witness program"
        if witness_version == 0 and len(program) not in (20, 32):
            return f"is witness v0 with a {len(program)}-byte program"
        if not 2 <= len(program) <= 40:
            return f"has a {len(program)}-byte witness program"
        return None
    num = 0
    for ch in addr:
        index = _B58_ALPHABET.find(ch)
        if index < 0:
            return "contains non-base58 characters"
        num = num * 58 + index

    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(addr) - len(addr.lstrip("1"))) + raw
    if len(raw) < 5:
        return "is too short to carry a checksum"
    body, checksum_bytes = raw[:-4], raw[-4:]
    digest = hashlib.sha256(hashlib.sha256(body).digest()).digest()
    if digest[:4] != checksum_bytes:
        return "fails its base58check checksum"
    # Registry markers are Bitcoin addresses. A checksum-valid address from
    # another chain would pass every check above and then produce no
    # runtime script, silently dropping that pool's marker.
    if body[0] not in (0, 5):
        return f"uses base58 version {body[0]}, which is not a Bitcoin address"
    return None


def _payout_script(addr: str) -> bytes | None:
    """Canonical scriptPubKey a payout address pays to, if this table can
    match it.

    Markers are keyed by the whole script rather than by the hash160,
    because the same 20 bytes under different templates are different
    payment targets: a P2PKH and a P2SH address sharing a payload must not
    overwrite each other or claim each other's outputs. Address types this
    lookup cannot match (P2WSH, P2TR, witness v1+) return None and are
    carried in the registry unused.
    """
    lowered = addr.lower()
    if lowered.startswith("bc1"):
        program = _bech32_decode_to_program(addr)
        if program is None or not lowered.startswith("bc1q") or len(program) != 20:
            return None
        return b"\x00\x14" + program  # P2WPKH: v0 <20>
    h160 = _b58_decode_to_hash160(addr)
    if h160 is None:
        return None
    if addr.startswith("1"):
        return b"\x76\xa9\x14" + h160 + b"\x88\xac"  # P2PKH
    if addr.startswith("3"):
        return b"\xa9\x14" + h160 + b"\x87"  # P2SH
    return None


def _decode_payout_address(addr: str) -> bytes | None:
    """Witness program or hash160 for a payout address, None if it is junk.

    A well-formed address that is not hash160-shaped (P2WSH, P2TR) decodes
    fine and is simply unusable for the 20-byte lookup; the pinned registry
    contains such an address, so "decodes" and "is usable" are deliberately
    different questions.

    The bech32 test is case-insensitive because BIP-173 permits an
    all-uppercase address; base58 is case-sensitive by construction and is
    left alone.
    """
    if addr.lower().startswith("bc1"):
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
    # Conflicts are detected on the DECODED payload, not the address text:
    # the same output can be written in more than one valid spelling (an
    # all-uppercase bech32 address, say), and those spellings collide only
    # once the runtime table keys them by bytes.
    addr_owner: dict[str, str] = {}

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
            # A marker that does not decode would be dropped from the
            # runtime table, and one that decodes to the wrong bytes is
            # worse: both quietly weaken that pool's attribution.
            problem = _payout_address_problem(addr)
            if problem is None and _decode_payout_address(addr) is None:
                problem = "does not decode to a usable payload"
            if problem is not None:
                raise ValueError(
                    f"Malformed pool registry file {pool_file}: payout "
                    f"address {addr!r} {problem}. Fix or remove the file; "
                    "attribution refuses to run from a registry whose "
                    "markers it cannot trust."
                )

        name = pool.get("name")
        link = pool.get("link", "") or ""
        if isinstance(name, str) and name != name.strip():
            # A trailing space makes a second, near-identical pool label
            # that splits the group in downstream analysis.
            raise ValueError(
                f"Malformed pool registry file {pool_file}: name {name!r} has "
                "surrounding whitespace. Fix or remove the file; attribution "
                "refuses to run from a registry that would split a pool."
            )
        if isinstance(name, str) and name.strip().lower() == "unknown":
            # Downstream treats this label as the no-match sentinel, so a
            # pool claiming it would have its successful matches exported
            # as unattributed.
            raise ValueError(
                f"Malformed pool registry file {pool_file}: 'Unknown' is the "
                "reserved no-match label and cannot name a pool. Fix or "
                "remove the file; attribution refuses to run from a registry "
                "that would mislabel its own matches."
            )
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
            # Case-fold bech32 so its two valid spellings are one marker;
            # the folded form still encodes the witness version, so
            # different scripts stay distinct.
            key = addr.lower() if addr.lower().startswith("bc1") else addr
            if key in addr_owner and addr_owner[key] != name:
                addr_conflicts.append((addr, addr_owner[key], name))
            addr_owner[key] = name
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
        script = _payout_script(addr)
        if script is not None:
            upstream_addrs[script] = entry["name"]

    # Local additions only catch scripts upstream missed: upstream is the
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

    # 2. OP_RETURN data in coinbase outputs (e.g. "Mined by 1hash.com").
    #    Only the pushed payload is searched: matching raw script bytes
    #    would let a push-length byte or an opcode form part of a tag.
    if outputs:
        for _value, spk in outputs:
            payload = parse_op_return_payload(spk)
            if payload:
                for tag, name in pool_tags:
                    if tag in payload:
                        return name, "op_return"

        # 3. Payout script matching (last resort for tagless miners). The
        #    table is keyed by complete canonical scripts, so only a real
        #    P2PKH, P2SH, or P2WPKH output matches, and each address type
        #    matches only its own outputs.
        for _value, spk in outputs:
            name = addr_pools.get(spk)
            if name:
                return name, "address"

    return "Unknown", "none"


def identify_pool(
    sig: bytes | None, outputs: list[tuple[int, bytes]] | None = None
) -> str:
    """Identify pool from coinbase scriptSig, OP_RETURN data, and output addresses."""
    return identify_pool_detailed(sig, outputs)[0]
