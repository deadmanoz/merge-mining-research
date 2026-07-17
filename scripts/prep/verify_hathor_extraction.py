#!/usr/bin/env python3
"""Sanity-check that the extracted hathor_auxpow_raw fields are sufficient
to fully reconstruct the BTC parent header, before committing to a multi-week
public-API scrape.

For a handful of sample heights, this script:
  1. Parses the aux_pow hex blob per Hathor RFC 0006 binary layout
  2. Confirms the layout boundaries make sense (lengths add up, no leftover bytes)
  3. Verifies the magic marker `Hath` (0x48 61 74 68) appears at the end of cb_head
  4. Fetches the raw transaction and extracts funds+graph bytes before aux_pow
  5. Reconstructs aux_block_hash = sha256d(sha256(funds) || sha256(graph))
  6. Reconstructs the full coinbase tx (cb_head || aux_block_hash || cb_tail)
  7. Computes coinbase txid → folds merkle path → reconstructs 80-byte BTC header
  8. Checks hashPrevBlock against Bitcoin through a public Esplora API. A miss
     leaves parent identity unresolved and is not evidence for a particular chain.
  9. Reports nTime / nBits / nNonce so a human can sanity-check plausibility

If every sample reconstructs cleanly and prevhashes resolve correctly, the
extractor's CSV columns (hathor_height, hathor_block_hash, hathor_timestamp,
aux_pow_hex) carry everything classify_hathor_stales.py will ever need.

Usage:
    python3 scripts/prep/verify_hathor_extraction.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HATHOR_API = "https://node.explorer.hathor.network/v1a"
BTC_ESPLORA = "https://blockstream.info/api"

# Spread across the merge-mining era so we hit different pool populations
# and difficulty regimes.
SAMPLE_HEIGHTS = [1_200_000, 2_500_000, 3_900_000, 5_000_000, 6_000_000, 6_400_000]

HATH_MAGIC = b"\x48\x61\x74\x68"  # "Hath" — RFC 0006 marker


def http_json(url, timeout=15):
    """GET ``url`` with the module's User-Agent and return the parsed JSON body."""
    req = Request(url, headers={"user-agent": "merge-mining-research/verify-hathor"})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def sha256d(b: bytes) -> bytes:
    """Double-SHA256, the Bitcoin block/tx hash primitive."""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def sha256(b: bytes) -> bytes:
    """Single SHA256 digest."""
    return hashlib.sha256(b).digest()


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Returns (value, new_pos). Standard Bitcoin compact-size varint."""
    n = buf[pos]
    if n < 0xFD:
        return n, pos + 1
    if n == 0xFD:
        return int.from_bytes(buf[pos + 1 : pos + 3], "little"), pos + 3
    if n == 0xFE:
        return int.from_bytes(buf[pos + 1 : pos + 5], "little"), pos + 5
    return int.from_bytes(buf[pos + 1 : pos + 9], "little"), pos + 9


def parse_aux_pow(hex_blob: str):
    """Decode the RFC 0006 binary layout. Returns dict with all fields."""
    buf = bytes.fromhex(hex_blob)
    pos = 0

    head = buf[pos : pos + 36]
    pos += 36

    cb_head_len, pos = read_varint(buf, pos)
    cb_head = buf[pos : pos + cb_head_len]
    pos += cb_head_len

    cb_tail_len, pos = read_varint(buf, pos)
    cb_tail = buf[pos : pos + cb_tail_len]
    pos += cb_tail_len

    merkle_count, pos = read_varint(buf, pos)
    merkle_path = []
    for _ in range(merkle_count):
        merkle_path.append(buf[pos : pos + 32])
        pos += 32

    tail = buf[pos : pos + 12]
    pos += 12

    leftover = buf[pos:]
    return {
        "head_36": head,
        "cb_head": cb_head,
        "cb_tail": cb_tail,
        "merkle_path": merkle_path,
        "tail_12": tail,
        "leftover": leftover,
    }


def reconstruct_header(
    parsed,
    funds_graph_hex: str,
    hathor_block_hash_hex: str,
) -> tuple[bytes, bytes, int] | None:
    """Folds the parsed AuxPoW into an 80-byte BTC header.

    RFC 0006 embeds aux_block_hash, not the Hathor block hash, in the BTC
    coinbase. The funds/graph boundary is variable, so smoke-test every split
    and accept the one whose reconstructed BTC header hash is Hathor's block
    hash.
    """
    try:
        funds_graph = bytes.fromhex(funds_graph_hex)
        expected = bytes.fromhex(hathor_block_hash_hex)
    except ValueError:
        return None

    for split in range(2, len(funds_graph)):
        funds_hash = sha256(funds_graph[:split])
        graph_hash = sha256(funds_graph[split:])
        aux_block_hash = sha256d(funds_hash + graph_hash)[::-1]
        full_coinbase = parsed["cb_head"] + aux_block_hash + parsed["cb_tail"]

        cur = sha256d(full_coinbase)
        for sibling in parsed["merkle_path"]:
            cur = sha256d(cur + sibling[::-1])

        header = parsed["head_36"] + cur + parsed["tail_12"]
        if sha256d(header)[::-1] == expected:
            return header, full_coinbase, split

    return None


def fetch_block(height: int):
    """Returns (tx_id, version) from /block_at_height."""
    d = http_json(f"{HATHOR_API}/block_at_height?height={height}")
    if not d.get("success"):
        return None, None
    b = d["block"]
    return b["tx_id"], b["version"]


def fetch_tx(tx_id: str) -> tuple[str | None, str | None]:
    """Fetch a Hathor transaction and split its raw hex at the aux_pow blob.

    Returns ``(aux_pow_hex, funds_graph_hex)`` where ``funds_graph_hex`` is
    the raw tx hex preceding the aux_pow blob (the bytes ``reconstruct_header``
    needs). Returns ``(None, None)`` on API failure, or ``(aux_pow, None)``
    if the aux_pow blob cannot be located inside ``raw``.
    """
    d = http_json(f"{HATHOR_API}/transaction?id={tx_id}")
    if not d.get("success"):
        return None, None
    tx = d.get("tx", {})
    aux_pow = tx.get("aux_pow")
    raw_hex = tx.get("raw") or ""
    if not aux_pow or not raw_hex:
        return aux_pow, None
    idx = raw_hex.find(aux_pow)
    if idx < 0:
        return aux_pow, None
    return aux_pow, raw_hex[:idx]


def lookup_btc(prevhash_hex: str):
    """Returns dict if found, None if 404, 'rate-limit' on 429, raises otherwise."""
    try:
        return http_json(f"{BTC_ESPLORA}/block/{prevhash_hex}", timeout=10)
    except HTTPError as e:
        if e.code == 404:
            return None
        if e.code == 429:
            return "rate-limit"
        raise


def verify_one(height: int):
    """Run the full parse/reconstruct/verify pipeline for one sample height.

    Prints step-by-step diagnostics and returns True if the height was
    processed without a hard parsing/reconstruction failure (a skip for a
    non-merge-mined block, or a BTC lookup miss/rate-limit, still counts as
    True); returns False only on FAIL.
    """
    print(f"\n--- Hathor height {height:,} ---")
    tx_id, version = fetch_block(height)
    if not tx_id:
        print(f"  FAIL: no block at height {height}")
        return False
    if version != 3:
        print(f"  SKIP: version {version} (not merge-mined)")
        return True
    aux_hex, funds_graph_hex = fetch_tx(tx_id)
    if not aux_hex:
        print("  FAIL: no aux_pow on v3 block (shouldn't happen)")
        return False
    if not funds_graph_hex:
        print("  FAIL: raw transaction did not expose funds+graph bytes")
        return False

    print(f"  hathor_block_hash: {tx_id}")
    print(f"  aux_pow_hex bytes: {len(aux_hex) // 2}")

    parsed = parse_aux_pow(aux_hex)
    print(
        f"  cb_head: {len(parsed['cb_head'])} B,  "
        f"cb_tail: {len(parsed['cb_tail'])} B,  "
        f"merkle_levels: {len(parsed['merkle_path'])},  "
        f"leftover: {len(parsed['leftover'])} B"
    )

    if parsed["leftover"]:
        print(
            f"  WARN: {len(parsed['leftover'])} bytes leftover after parse — "
            "layout assumption wrong?"
        )

    if not parsed["cb_head"].endswith(HATH_MAGIC):
        # Hathor RFC 0006 says cb_head ends RIGHT before the embedded Hathor
        # block hash; the magic appears just before that boundary.
        idx = parsed["cb_head"].rfind(HATH_MAGIC)
        print(
            f"  WARN: cb_head doesn't end with 'Hath' magic "
            f"(found at offset {idx} of {len(parsed['cb_head'])})"
        )
    else:
        print("  ✓ cb_head ends with 'Hath' magic marker")

    recon = reconstruct_header(parsed, funds_graph_hex, tx_id)
    if recon is None:
        print("  FAIL: no funds/graph split reconstructed the Hathor block hash")
        return False
    header, _full_coinbase, split = recon
    assert len(header) == 80, f"header is {len(header)} bytes, expected 80"
    print(f"  ✓ reconstructed header hash matches Hathor block hash (split={split})")

    prev_le = header[4:36]
    prev_be = prev_le[::-1].hex()
    n_time = int.from_bytes(header[68:72], "little")
    n_bits = header[72:76][::-1].hex()
    n_nonce = int.from_bytes(header[76:80], "little")

    print(f"  reconstructed prevhash:  {prev_be}")
    print(f"  nTime:  {n_time}  ({_iso(n_time)})")
    print(f"  nBits:  0x{n_bits}")
    print(f"  nNonce: {n_nonce}")

    btc = lookup_btc(prev_be)
    if btc == "rate-limit":
        print("  ? BTC lookup rate-limited (re-run later)")
        return True
    if btc is None:
        print("  → prevhash not found on BTC (parent identity unresolved)")
        return True
    print(
        f"  ✓ BTC parent confirmed: height {btc.get('height')}, "
        f"timestamp {_iso(btc.get('timestamp', 0))}"
    )

    return True


def _iso(ts: int) -> str:
    """Format a Unix timestamp as a UTC display string, or ``"?"`` for a falsy ``ts``."""
    from datetime import datetime, timezone

    return (
        datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if ts
        else "?"
    )


def main():
    """Run ``verify_one`` over ``SAMPLE_HEIGHTS`` and print a pass-count summary."""
    ok = 0
    for h in SAMPLE_HEIGHTS:
        try:
            if verify_one(h):
                ok += 1
        except Exception as e:
            print(f"  EXCEPTION on height {h}: {e}")
    print(f"\n{ok}/{len(SAMPLE_HEIGHTS)} samples processed without parsing failure")


if __name__ == "__main__":
    sys.exit(main())
