"""Pool identification from the mining-pools clone plus local overrides.

No analysis-layer imports, so this module can load before matplotlib or RPC.
"""

from collections.abc import Iterable
import hashlib
import json

from .bitcoin_binary import _b58_decode_to_hash160, _bech32_decode_to_program
from .coinbase_markers import parse_op_return_payload
from .coinbase_output_claims import (
    CoinbaseOutputClaim,
    recipient_hash160_for_script,
)
from .config import LOCAL_MINING_POOLS_DIR

# Patterns that cannot live upstream as pools. Upstream tags run first.

LOCAL_POOL_TAGS: list[tuple[bytes, str]] = []


# Complete scriptPubKey overrides. Upstream wins on conflict. An entry must
# cite committed public evidence; new identifications belong in mining-pools.
LOCAL_OUTPUT_ADDR_POOLS: dict[bytes, str] = {}


# blockchain.info miner names (KIT forks.gpd) to canonical pool names.

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
    # Registry spelling is "1Hash". A second spelling would split the pool.
    "1Hash": "1Hash",
}


def map_kit_pool(kit_name: str) -> str:
    """Map a KIT/blockchain.info pool name to our canonical pool name."""
    return KIT_POOL_MAP.get(kit_name, kit_name)


def _norm_pool_name(name: str) -> str:
    """Case, spacing, punctuation, and a trailing "Pool" are not a disagreement."""
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
    """Why *addr* is unusable as a registry marker, or None.

    Shared decoders skip checksums. A marker that decodes to the wrong
    hash160 is checked here, without changing those decoders.
    """
    if addr != addr.strip() or not addr:
        return "has surrounding whitespace"
    if addr.lower().startswith("bc1"):
        lowered = addr.lower()
        if addr != lowered and addr != addr.upper():
            return "mixes upper and lower case"
        pos = lowered.rfind("1")
        hrp, data = lowered[:pos], lowered[pos + 1 :]
        if hrp != "bc":
            # Checksum covers the HRP, so a foreign prefix must not register.
            return f"uses the {hrp!r} prefix, which is not Bitcoin mainnet"
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
        # BIP-173: leftover bits must not form a group, and padding must be
        # zero. The shared decoder discards them.
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
    # A checksum-valid foreign address would drop the marker with no script.
    if body[0] not in (0, 5):
        return f"uses base58 version {body[0]}, which is not a Bitcoin address"
    return None


def _payout_script(addr: str) -> bytes | None:
    """Whole script, not hash160: the same 20 bytes under another template differ.

    P2WSH, P2TR, and witness v1+ return None and stay unused.
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
    """Decoded payload, or None. A valid P2WSH/P2TR address can still be unusable.

    Bech32 is case-insensitive (BIP-173); base58 is not.
    """
    if addr.lower().startswith("bc1"):
        return _bech32_decode_to_program(addr)
    return _b58_decode_to_hash160(addr)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate keys. ``json.loads`` would otherwise keep the last one."""
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def fetch_known_pools() -> dict:
    """Working-tree ``pools/*.json``, including uncommitted files.

    Same ``{coinbase_tags, payout_addresses}`` shape as upstream ``pools.json``.
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

    # Same marker in two files would make the label depend on filename order.
    tag_conflicts: list[tuple[str, str, str]] = []
    addr_conflicts: list[tuple[str, str, str]] = []
    # Collisions are on the decoded payload. Bech32 has two valid spellings.
    addr_owner: dict[str, str] = {}

    for pool_file in pool_files:
        try:
            pool = json.loads(pool_file.read_text(), object_pairs_hook=_unique_keys)
        except (ValueError, OSError) as exc:
            # A skipped file would demote that pool while the export looked complete.
            raise ValueError(
                f"Malformed pool registry file {pool_file}: {exc}. Fix or "
                "remove the file; attribution refuses to run from a partial "
                "registry."
            ) from exc
        if not isinstance(pool, dict):
            # Wrong shape would otherwise raise AttributeError below.
            raise ValueError(
                f"Malformed pool registry file {pool_file}: top level is "
                f"{type(pool).__name__}, expected an object. Fix or remove "
                "the file; attribution refuses to run from a partial "
                "registry."
            )
        for field in ("tags", "addresses"):
            value = pool.get(field)
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                # A string would register per character, and ``b""`` matches
                # every scriptSig.
                raise ValueError(
                    f"Malformed pool registry file {pool_file}: {field!r} "
                    "must be present and an array of non-empty strings "
                    "(null and missing both hide markers). Fix or remove "
                    "the file; attribution refuses to run from a partial "
                    "registry."
                )
        for tag in pool["tags"]:
            # Matched as UTF-8 bytes. "/" is one byte; an emoji tag is not.
            if len(tag.encode("utf-8")) < 2:
                raise ValueError(
                    f"Malformed pool registry file {pool_file}: tag {tag!r} "
                    "encodes to a single byte, which matches almost every "
                    "coinbase. Use a more specific tag; attribution refuses "
                    "to run from a registry that would over-claim."
                )

        for addr in pool["addresses"]:
            # An undecodeable or wrong-bytes marker quietly weakens the pool.
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
            # Surrounding whitespace would split one pool into two labels.
            raise ValueError(
                f"Malformed pool registry file {pool_file}: name {name!r} has "
                "surrounding whitespace. Fix or remove the file; attribution "
                "refuses to run from a registry that would split a pool."
            )
        if isinstance(name, str) and name.strip().lower() == "unknown":
            # "Unknown" is the no-match sentinel.
            raise ValueError(
                f"Malformed pool registry file {pool_file}: 'Unknown' is the "
                "reserved no-match label and cannot name a pool. Fix or "
                "remove the file; attribution refuses to run from a registry "
                "that would mislabel its own matches."
            )
        if not isinstance(name, str) or not name.strip():
            # A missing name would drop the file's markers and still look complete.
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
            # Case-fold bech32. The witness version stays in the key.
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


# Built on the first identify_pool() call. Upstream wins a collision.
# Import does not read the clone.

_RUNTIME_POOL_TAGS: list[tuple[bytes, str]] | None = None
_RUNTIME_OUTPUT_ADDR_POOLS: dict[bytes, str] | None = None


def _build_runtime_pool_tables() -> tuple[list[tuple[bytes, str]], dict[bytes, str]]:
    """Decode upstream JSON + concatenate local additions for runtime use."""
    data = fetch_known_pools()

    # UTF-8 bytes, longest first, so a specific tag wins over a prefix.
    upstream_tags: list[tuple[bytes, str]] = sorted(
        (
            (tag.encode("utf-8"), entry["name"])
            for tag, entry in data["coinbase_tags"].items()
        ),
        key=lambda x: -len(x[0]),
    )
    runtime_tags = upstream_tags + LOCAL_POOL_TAGS

    # Keyed by script. P2WSH and P2TR do not fit this lookup.
    upstream_addrs: dict[bytes, str] = {}
    for addr, entry in data["payout_addresses"].items():
        script = _payout_script(addr)
        if script is not None:
            upstream_addrs[script] = entry["name"]

    # Upstream is the later merge operand, so a local override cannot displace it.
    runtime_addrs = {**LOCAL_OUTPUT_ADDR_POOLS, **upstream_addrs}
    return runtime_tags, runtime_addrs


def _ensure_runtime_pool_tables() -> tuple[list[tuple[bytes, str]], dict[bytes, str]]:
    """Lazily build and cache the merged runtime pool tables."""
    global _RUNTIME_POOL_TAGS, _RUNTIME_OUTPUT_ADDR_POOLS
    if _RUNTIME_POOL_TAGS is None or _RUNTIME_OUTPUT_ADDR_POOLS is None:
        _RUNTIME_POOL_TAGS, _RUNTIME_OUTPUT_ADDR_POOLS = _build_runtime_pool_tables()
    return _RUNTIME_POOL_TAGS, _RUNTIME_OUTPUT_ADDR_POOLS


def reset_runtime_pool_tables() -> None:
    """Drop the cache. A long-lived process must not label against the previous clone."""
    global _RUNTIME_POOL_TAGS, _RUNTIME_OUTPUT_ADDR_POOLS
    _RUNTIME_POOL_TAGS = None
    _RUNTIME_OUTPUT_ADDR_POOLS = None


def pool_dataset_fingerprint() -> str:
    """SHA-256 of ``pools/*.json`` plus the local tag and script overrides."""
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
    sig: bytes | None,
    outputs: list[tuple[int, bytes]] | None = None,
    *,
    output_claims: Iterable[CoinbaseOutputClaim] | None = None,
) -> tuple[str, str]:
    """``(name, method)`` with method ``tag``, ``op_return``, ``address``, or ``none``.

    The template-producer fold keeps only tag evidence.
    """
    if outputs is not None and output_claims is not None:
        raise ValueError("pass exact outputs or semantic output claims, not both")

    claims = tuple(output_claims or ())
    claimed_exact_outputs = [
        (claim.value_sats or 0, bytes.fromhex(claim.script_hex))
        for claim in claims
        if claim.script_hex
    ]
    exact_outputs = outputs or claimed_exact_outputs

    if not sig and not exact_outputs and not claims:
        return "Unknown", "none"

    pool_tags, addr_pools = _ensure_runtime_pool_tables()

    # ScriptSig and outputs are independent. Outputs-only skips this stage.
    if sig:
        for tag, name in pool_tags:
            if tag in sig:
                return name, "tag"

    # Search the OP_RETURN payload only. Raw script bytes include the push length.
    if exact_outputs:
        for _value, spk in exact_outputs:
            payload = parse_op_return_payload(spk)
            if payload:
                for tag, name in pool_tags:
                    if tag in payload:
                        return name, "op_return"

        # Exact P2PKH, P2SH, and P2WPKH scripts. P2PK may also match the
        # P2PKH address of its pubkey. P2SH and witness stay distinct.
    if outputs is not None:
        for _value, spk in outputs:
            name = addr_pools.get(spk)
            if name:
                return name, "address"
            recipient = recipient_hash160_for_script(spk.hex())
            if recipient:
                p2pkh_marker = b"\x76\xa9\x14" + bytes.fromhex(recipient) + b"\x88\xac"
                name = addr_pools.get(p2pkh_marker)
                if name:
                    return name, "address"
    else:
        for claim in claims:
            if claim.script_hex:
                script = bytes.fromhex(claim.script_hex)
                name = addr_pools.get(script)
                if name:
                    return name, "address"
                recipient = recipient_hash160_for_script(claim.script_hex)
            else:
                recipient = claim.recipient_hash160
            if recipient:
                # A decoded address proves HASH160, not P2PKH versus P2PK.
                # Match only a P2PKH marker.
                p2pkh_marker = b"\x76\xa9\x14" + bytes.fromhex(recipient) + b"\x88\xac"
                name = addr_pools.get(p2pkh_marker)
                if name:
                    return name, "address"

    return "Unknown", "none"


def identify_pool(
    sig: bytes | None,
    outputs: list[tuple[int, bytes]] | None = None,
    *,
    output_claims: Iterable[CoinbaseOutputClaim] | None = None,
) -> str:
    """Identify pool from coinbase scriptSig, OP_RETURN data, and output addresses."""
    return identify_pool_detailed(sig, outputs, output_claims=output_claims)[0]
