#!/usr/bin/env python3
"""Probe whether Hathor merge-mining yields a meaningful BTC signal.

Stratified random sample of Hathor blocks. For each version-3 (merge-mined)
block, extract bytes [4:36] of the aux_pow blob (= BTC/BCH parent prevhash)
and classify it via Esplora-style lookups: BTC, BCH, or other.

No header reconstruction or PoW validation — we only need to know which
parent chain each merge-mining hit was pointing at. That decides whether
standing up a full Hathor node + extractor is worth it.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HATHOR_API = "https://node1.mainnet.hathor.network/v1a"
BTC_ESPLORA = "https://blockstream.info/api"
BCH_DASHBOARD = "https://api.blockchair.com/bitcoin-cash/dashboards/block"
UA = "merge-mining-research/probe-hathor-btc-signal"


def http_json(url, timeout=20):
    """GET ``url`` with the module's User-Agent and return the parsed JSON body."""
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def http_ok(url, timeout=15):
    """Return True/False for a 2xx/404 response on ``url``, or None if the
    outcome is unknown (rate limiting or a network error).
    """
    req = Request(url, headers={"User-Agent": UA})
    try:
        with urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except HTTPError as e:
        return False if e.code == 404 else None  # None = unknown (rate limit etc.)
    except URLError:
        return None


def hathor_tip():
    """Return the highest height among Hathor's current best-block DAG tips."""
    s = http_json(f"{HATHOR_API}/status")
    tips = s["dag"]["best_block_tips"]
    return max(t["height"] for t in tips)


def fetch_block_meta(height):
    """Return ``(version, tx_id)`` for the Hathor block at ``height``, or
    ``(None, None)`` on any API failure.
    """
    try:
        d = http_json(f"{HATHOR_API}/block_at_height?height={height}")
        if not d.get("success"):
            return None, None
        b = d["block"]
        return b.get("version"), b.get("tx_id")
    except Exception:
        return None, None


def fetch_aux_pow(tx_id):
    """Fetch the ``aux_pow`` hex blob for Hathor transaction ``tx_id``, or None on failure."""
    try:
        d = http_json(f"{HATHOR_API}/transaction?id={tx_id}")
        if not d.get("success"):
            return None
        return d.get("tx", {}).get("aux_pow")
    except Exception:
        return None


def parse_prevhash(aux_pow_hex: str) -> str:
    """Extract the parent chain's prevhash from an aux_pow blob's first 36 bytes.

    Bytes [4:36] are the parent header's ``hashPrevBlock`` in internal
    (little-endian) order; this reverses them to display-order hex for the
    Esplora/Blockchair lookups.
    """
    head = bytes.fromhex(aux_pow_hex[: 36 * 2])
    return head[4:36][::-1].hex()


def lookup_btc(prevhash):
    """Return True/False/None for whether ``prevhash`` is a known BTC block (via Esplora)."""
    return http_ok(f"{BTC_ESPLORA}/block/{prevhash}")


def lookup_bch(prevhash):
    """Return True/False/None for whether ``prevhash`` is a known BCH block (via Blockchair).

    Returns None on a rate-limit/payment-required response (429/402) or any
    other exception, so callers can distinguish "not found" from "unknown".
    """
    try:
        d = http_json(f"{BCH_DASHBOARD}/{prevhash}", timeout=15)
        return bool(d.get("data", {}).get(prevhash))
    except HTTPError as e:
        return None if e.code in (429, 402) else False
    except Exception:
        return None


def stratified(low, high, per, strata, seed=42):
    """Sample up to ``per`` random heights from each of ``strata`` equal-width
    buckets spanning ``[low, high)``. Returns ``(sorted_heights, bucket_edges)``.
    """
    rng = random.Random(seed)
    edges = [low + i * (high - low) // strata for i in range(strata + 1)]
    out = []
    for i in range(strata):
        span = list(range(edges[i], edges[i + 1]))
        out.extend(rng.sample(span, min(per, len(span))))
    return sorted(out), edges


def main():
    """Stratified-sample Hathor v3 blocks, classify each aux_pow prevhash as
    BTC/BCH/unknown, and print a per-stratum summary (optionally to a CSV).
    """
    p = argparse.ArgumentParser()
    p.add_argument("--per-stratum", type=int, default=100)
    p.add_argument("--strata", type=int, default=12)
    p.add_argument(
        "--low",
        type=int,
        default=1_000_000,
        help="Lower bound for the stratified feasibility sample",
    )
    p.add_argument("--high", type=int, default=None)
    p.add_argument("--workers", type=int, default=6)
    p.add_argument(
        "--bch-cap",
        type=int,
        default=200,
        help="Max BCH lookups (blockchair has tight free-tier limits)",
    )
    p.add_argument("--out", default=None, help="Write per-block CSV to this path")
    args = p.parse_args()

    high = args.high or hathor_tip()
    print(f"Hathor tip: {high:,}", file=sys.stderr)

    heights, edges = stratified(args.low, high, args.per_stratum, args.strata)
    print(
        f"Sampling {len(heights)} heights across {args.low:,}..{high:,} "
        f"({args.strata} strata × {args.per_stratum})",
        file=sys.stderr,
    )

    # Phase 1: version + tx_id
    meta = {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_block_meta, h): h for h in heights}
        for f in as_completed(futs):
            h = futs[f]
            meta[h] = f.result()

    versions = Counter(v for v, _ in meta.values() if v is not None)
    print(f"Version distribution: {dict(versions)}", file=sys.stderr)

    v3 = [(h, tx) for h, (v, tx) in meta.items() if v == 3 and tx]
    print(
        f"v3 (merge-mined): {len(v3)} / {sum(versions.values())} sampled "
        f"= {100 * len(v3) / max(1, sum(versions.values())):.1f}%",
        file=sys.stderr,
    )

    # Phase 2: aux_pow blobs
    aux = {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_aux_pow, tx): h for h, tx in v3}
        for f in as_completed(futs):
            h = futs[f]
            blob = f.result()
            if blob:
                aux[h] = blob
    print(f"Fetched aux_pow for {len(aux)} blocks", file=sys.stderr)

    # Phase 3: parse prevhashes
    prevhashes = {h: parse_prevhash(b) for h, b in aux.items()}

    # Phase 4: BTC lookup
    btc = {}
    print("Looking up prevhashes on BTC (blockstream.info)...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(lookup_btc, ph): h for h, ph in prevhashes.items()}
        done = 0
        for f in as_completed(futs):
            h = futs[f]
            btc[h] = f.result()
            done += 1
            if done % 50 == 0:
                print(f"  ...{done}/{len(prevhashes)}", file=sys.stderr)

    btc_hits = {h for h, v in btc.items() if v is True}
    btc_misses = {h for h, v in btc.items() if v is False}
    btc_unknown = {h for h, v in btc.items() if v is None}

    # Phase 5: BCH lookup on the non-BTC subset
    bch = {}
    not_btc = sorted(btc_misses)[: args.bch_cap]
    print(
        f"Looking up {len(not_btc)} non-BTC prevhashes on BCH (blockchair)...",
        file=sys.stderr,
    )
    with ThreadPoolExecutor(max_workers=2) as ex:  # blockchair: gentle
        futs = {ex.submit(lookup_bch, prevhashes[h]): h for h in not_btc}
        for f in as_completed(futs):
            h = futs[f]
            bch[h] = f.result()
    bch_hits = {h for h, v in bch.items() if v is True}

    # Summary
    n = len(prevhashes)
    print()
    print("=" * 60)
    print(f"Sampled blocks (v3 with aux_pow): {n}")
    print(f"  BTC parent:        {len(btc_hits):>4}  ({100 * len(btc_hits) / n:5.1f}%)")
    print(
        f"  BCH parent:        {len(bch_hits):>4}  "
        f"({100 * len(bch_hits) / n:5.1f}%)  [of {len(not_btc)} probed]"
    )
    print(f"  Neither/unknown:   {n - len(btc_hits) - len(bch_hits):>4}")
    print(f"  BTC-lookup unknown (rate-limited / network): {len(btc_unknown)}")
    print()

    # Per-stratum
    print("Per-stratum (range, n_v3, btc%, bch% of non-BTC sampled):")
    for i in range(args.strata):
        lo, hi = edges[i], edges[i + 1]
        in_s = [h for h in prevhashes if lo <= h < hi]
        if not in_s:
            continue
        b = sum(1 for h in in_s if h in btc_hits)
        nb_in_s = [h for h in in_s if h in btc_misses]
        c = sum(1 for h in nb_in_s if h in bch_hits)
        bch_denom = sum(1 for h in nb_in_s if h in bch)
        bch_pct = 100 * c / bch_denom if bch_denom else float("nan")
        print(
            f"  {lo:>8,}..{hi:>8,}  n={len(in_s):>3}  "
            f"btc={100 * b / len(in_s):5.1f}%  bch={bch_pct:5.1f}%"
        )

    if args.out:
        import csv

        with open(args.out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["hathor_height", "prevhash", "btc", "bch"])
            for h in sorted(prevhashes):
                w.writerow([h, prevhashes[h], btc.get(h), bch.get(h, "")])
        print(f"\nWrote per-block CSV to {args.out}")


if __name__ == "__main__":
    main()
