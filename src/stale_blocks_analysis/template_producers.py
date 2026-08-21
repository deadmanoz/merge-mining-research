"""The dual-attribution fold: tag-owner labels into template-producer labels.

Proxy pooling decouples the coinbase tag from the entity that actually built
a block's template. A pool's stratum endpoint can serve jobs stamped with
another pool's coinbase tag, so the coinbase's on-chain tag identifies who
*owns* the tag, not necessarily who *built* the block. `fold_template_producer`
takes a tag-owner label (as emitted by coinbase identification against the
pinned `bitcoin-data/mining-pools` registry) and, inside the height window
its cited measurements cover, folds it into the label for the entity that
actually produced the block template. Outside any matching window the
tag-owner label is returned unchanged, so a label only ever changes where
the cited measurements support it.

See `docs/pool-attribution.md` ("Dual attribution: tag owner and template
producer") for how this fits into the broader attribution pipeline, and the
0xB10C sources for the underlying measurement:

- 0xB10C, "Block Template Similarities between Mining Pools," September 2024,
  <https://b10c.me/observations/12-template-similarity/>.
- 0xB10C, "Bitcoin Mining Centralization in 2025," April 2025,
  <https://b10c.me/blog/015-bitcoin-mining-centralization/>.
"""

from __future__ import annotations

# Table-level notes:
#
# (a) Every `tag_label` below must equal a `name` field in the pinned
#     bitcoin-data/mining-pools registry exactly — that is the string
#     `identify_pool` emits for coinbase-tag matches, and `fold_template_producer`
#     compares against it verbatim.
#
# (b) No SpiderPool row. Prior to 2024-08-23, Binance Pool's stratum endpoint
#     served jobs carrying the `SpiderPool/` coinbase tag: SpiderPool was the
#     template producer and Binance the proxy for that period, so
#     SpiderPool-tagged blocks from that window are already correctly
#     template-attributed as-is (no fold needed). Binance's hashrate hiding
#     inside those SpiderPool-tagged blocks is a hashrate-attribution caveat
#     for the companion stale-rate methodology, not a template fold this table
#     performs.
#
# (c) No rows for non-custodial-template pools (Ocean.xyz, P2Pool). Their
#     tags are left as-is: every row in this table is a measured proxy
#     relationship between two named pools, and the non-custodial
#     characterization is prose in docs/pool-attribution.md (the registry
#     also has no P2Pool entry, so that tag_label could never match).
#
# (d) Every row has an end height: `valid_to_height` is the first DAA epoch
#     start on/after the last date the cited measurement documents the
#     relationship (per data/bitcoin-epoch-reference). Nothing here knows
#     whether a proxy arrangement continued after the cited data ends, so a
#     tag from a later block is left as-is until newer published
#     measurements extend the row.
TEMPLATE_PRODUCER_MAP: tuple[dict, ...] = (
    {
        "tag_label": "AntPool",
        "template_producer": "AntPool & friends",
        "valid_from_height": 774_144,
        "valid_to_height": 895_104,
        "evidence": (
            "AntPool-Poolin 99% / AntPool-BTC.com 98% weighted Merkle-branch "
            "similarity (0xB10C obs 12, stratum data 2024-06..2024-09); cluster "
            "~40% of network hashrate through 2023-H1 2024 (0xB10C blog/015). "
            "Window opens ~Jan 2023 because blog/015 documents the cluster "
            "operating through 2023, and ends at 895104, the first DAA epoch "
            "start after April 2025, the last period blog/015 documents."
        ),
    },
    {
        "tag_label": "Poolin",
        "template_producer": "AntPool & friends",
        "valid_from_height": 774_144,
        "valid_to_height": 895_104,
        "evidence": (
            "AntPool-Poolin 99% / AntPool-BTC.com 98% weighted Merkle-branch "
            "similarity (0xB10C obs 12, stratum data 2024-06..2024-09); cluster "
            "~40% of network hashrate through 2023-H1 2024 (0xB10C blog/015). "
            "Window opens ~Jan 2023 because blog/015 documents the cluster "
            "operating through 2023, and ends at 895104, the first DAA epoch "
            "start after April 2025, the last period blog/015 documents."
        ),
    },
    {
        "tag_label": "BTC.com",
        "template_producer": "AntPool & friends",
        "valid_from_height": 774_144,
        "valid_to_height": 895_104,
        "evidence": (
            "AntPool-Poolin 99% / AntPool-BTC.com 98% weighted Merkle-branch "
            "similarity (0xB10C obs 12, stratum data 2024-06..2024-09); cluster "
            "~40% of network hashrate through 2023-H1 2024 (0xB10C blog/015). "
            "Window opens ~Jan 2023 because blog/015 documents the cluster "
            "operating through 2023, and ends at 895104, the first DAA epoch "
            "start after April 2025, the last period blog/015 documents."
        ),
    },
    {
        # Height derived, not asserted directly by a source: the switch date
        # 2024-08-23 (0xB10C obs 12) is bracketed against the committed
        # data/bitcoin-epoch-reference/btc_epoch_headers.json DAA epoch-start
        # table. Epoch start 856,800 begins 2024-08-14T23:59:21Z (before the
        # switch) and the next epoch start 858,816 begins 2024-08-28T14:31:55Z
        # (after the switch), so 858,816 is the first DAA epoch start on/after
        # the 2024-08-23 00:00 UTC switch date. Epoch-start granularity (up to
        # one retarget period, 2016 blocks / ~2 weeks) is coarser than the
        # exact switch block, and is accepted as defensible for this window.
        "tag_label": "Binance Pool",
        "template_producer": "AntPool & friends",
        "valid_from_height": 858_816,
        "valid_to_height": 895_104,
        "evidence": (
            "Binance Pool endpoint switched from SpiderPool to the "
            "AntPool-Poolin-BTC.com template on 2024-08-23 (0xB10C obs 12); "
            "height 858816 = first DAA epoch start on/after the switch date "
            "per data/bitcoin-epoch-reference. Ends at 895104 with the other "
            "cluster rows (blog/015 documents the cluster's operation into "
            "early 2025)."
        ),
    },
    {
        "tag_label": "Sigmapool.com",
        "template_producer": "SecPool",
        "valid_from_height": 840_672,
        "valid_to_height": 862_848,
        "evidence": (
            "SigmaPool stratum endpoint proxies the SecPool endpoint, "
            "publishing 'Mined by SecPool' jobs (0xB10C obs 12). No "
            "Sigmapool.com-tagged blocks observed on-chain; row documents the "
            "direction for any future tag. Ends at 862848, the first DAA epoch "
            "start after the obs-12 stratum window ends (2024-09-12)."
        ),
    },
)


def fold_template_producer(tag: str, height: int) -> str:
    """Fold a coinbase tag-owner label into its template-producer label.

    Returns the matching `TEMPLATE_PRODUCER_MAP` entry's `template_producer`
    when `tag` equals that entry's `tag_label` and `height` falls inside its
    window (`valid_from_height` inclusive, `valid_to_height`
    exclusive; `None` means open-ended). Otherwise `tag` is returned
    unchanged, including for `"Unknown"`, which never matches any row and
    always passes through as `"Unknown"`.
    """
    for entry in TEMPLATE_PRODUCER_MAP:
        if tag != entry["tag_label"]:
            continue
        valid_to = entry["valid_to_height"]
        if (
            entry["valid_from_height"]
            <= height
            < (valid_to if valid_to is not None else float("inf"))
        ):
            return entry["template_producer"]
    return tag
