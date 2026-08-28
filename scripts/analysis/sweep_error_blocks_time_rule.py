#!/usr/bin/env python3
"""Sweep stale/unknown classified rows for time-rule error blocks.

The 946213 and 957780 error-block class is a full-proof-of-work Bitcoin header
whose ``nTime`` violates a time rule. This sweep re-examines two operator-approved
candidate classes across the reachable per-chain classified inventories (the
authoritative copies live on the chain archive host, set via the
``ERROR_BLOCKS_ARCHIVE_HOST`` env var; see ``STALE_INVENTORIES`` /
``UNKNOWN_INVENTORY_GLOB``):

- every stale-classified row (``<chain>_stale_blocks.csv``), and
- every unknown row (``<chain>_unknown_blocks.csv``) that carries a parseable
  claimed height (a ``btc_height`` column that, when a coinbase scriptSig is
  present, agrees with the decoded BIP34 coinbase height).

Each candidate is re-verified from the committed bytes, never trusted on a
label:

1. Full proof of work: sha256d of the 80-byte ``btc_header_hex`` must meet
   the header's own ``btc_bits`` target via ``hash_meets_btc_difficulty``;
   ``btc_time`` is re-derived from the header bytes, not the column. A row
   failing full PoW is a share/near, not an error block.
2. ``time_below_mtp``: candidate ``nTime`` <= the canonical parent's
   median-time-past at the claimed height. The parent MTP is the
   ``mediantime`` field of the canonical block at ``height - 1``. This check
   is robust (the parent MTP is committed canonical context), so a violation
   is a promotable NEW error-block finding.
3. ``time_beyond_future_limit``: candidate ``nTime`` > the canonical
   parent's block ``time`` + 2 hours (``MAX_FUTURE_BLOCK_TIME``). Reference
   caveat: Bitcoin's real future bound is network-adjusted time + 2h, which
   is NOT reconstructable offline; the canonical parent time is only a
   neighbor-evidence approximation, and the rule is still deferred in the
   offline validator's ``TIME_RULES``. Findings under this rule are reported
   for manual review (NEEDS_CONTEXT) and are NOT auto-promoted.

Claimed-height trust: a time-rule check is only meaningful when the claimed
height is a real canonical-chain height. The 16 regen-chain stale inventories
carry an authoritative height (the classifier set ``btc_height`` =
active-chain prev height + 1 after confirming the parent is on the canonical
chain). Unknown rows and the canonical-fill-scratch stale inventories
(syscoin/elastos/fractal) carry a ``btc_height`` that is NOT verified against
the canonical chain (a share/child height or contamination), so a time-rule
check against it is uninterpretable; those full-PoW rows are tallied as
``untrustworthy height`` negatives, never as violations.

Canonical parent context (``time``/``mediantime`` per height) is batch-fetched
once per distinct claimed height among the authoritative-height candidates —
a single ssh session running a persistent
batched JSON-RPC helper on the node (see ``_REMOTE_MTP_HELPER``) — and cached
to ``cache/time_sweep_mtp.json`` (gitignored). Membership is checked against
the committed ``data/error-blocks/error_blocks.csv`` dataset by
``(height, hash)``.

Inventory access is injectable: ``main`` defaults to reading each
authoritative inventory with ``ssh -o BatchMode=yes $ERROR_BLOCKS_ARCHIVE_HOST
cat <path>``, and ``--chain-archive-root`` instead reads a local mirror
directory laid out as ``<root>/<chain>/<filename>``. Tests inject readers
directly.

FAIL CLOSED: an unreachable inventory or node is recorded and the sweep
continues; if NO inventory is reachable, or no MTP context could be fetched
at all, the script exits non-zero. The committed report is only ever written
from a COMPLETE sweep: if any inventory is unreachable, OR the canonical MTP
context does not cover every requested parent height (a partial context
would leave candidates unevaluated while the report could still claim "no
time_below_mtp violations found"), writing the committed default report
fails closed (no committed write, naming the missing heights) unless
``--allow-partial`` together with a disposable ``--output-dir`` writes the
partial report there instead.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from _sweep_common import (  # noqa: E402
    ARCHIVE_HOST,
    InventoryReader,
    MAX_PLAUSIBLE_HEIGHT,
    STALE_INVENTORIES,
    STALE_INVENTORY_BASELINE_ROWS,
    UNKNOWN_INVENTORY_BASELINE_ROWS,
    _REGEN_CHAINS,
    _REGEN_STAGING,
    header_display_hash,
    load_dataset_keys,
    load_nbits_by_epoch,
    local_mirror_reader,
    require_full_coverage_for_committed,
    resolve_output_path,
    reverify_against_canonical_target,
    ssh_inventory_reader,
    validate_partial_args,
)
from stale_blocks_analysis.auxpow_parse import (  # noqa: E402
    hash_meets_btc_difficulty,
    parse_coinbase_height,
)
from stale_blocks_analysis.config import BIP34_HEIGHT  # noqa: E402

# Bitcoin's MAX_FUTURE_BLOCK_TIME: a block's nTime must not exceed the
# network-adjusted time plus this bound. The sweep's future-limit reference
# is the canonical parent's block time (see module docstring).
MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60

# Unknown-row inventories sit next to the stale ones for the regen chains;
# the canonical-fill scratch chains (syscoin/elastos/fractal) have no
# classified unknown inventory.
UNKNOWN_INVENTORY_GLOB: dict[str, str] = {
    chain: f"{_REGEN_STAGING}/{chain}/classified/{chain}_unknown_blocks.csv"
    for chain in _REGEN_CHAINS
}

DEFAULT_REPORT = Path("results/analysis/error-blocks/time-rule-report.md")
DEFAULT_MTP_CACHE = Path("cache/time_sweep_mtp.json")

INVENTORY_BASELINE_ROWS = {
    **{f"{chain}:stale": rows for chain, rows in STALE_INVENTORY_BASELINE_ROWS.items()},
    **{
        f"{chain}:unknown": rows
        for chain, rows in UNKNOWN_INVENTORY_BASELINE_ROWS.items()
    },
}

# Heading prefix of the manually-written follow-up investigation section that
# resolves the future-limit flags (the child-chain commit-time evidence). The
# sweep cannot regenerate that investigation, so when the committed report is
# regenerated the section is carried forward verbatim from the prior report
# text (see render_report's prior_text parameter) rather than dropped.
RESOLUTION_SECTION_MARKER = "## Follow-up investigation"

# Callable that returns {height: {"time": int, "mediantime": int}} for the
# canonical blocks at the given heights, or raises.
MtpFetcher = Callable[[list[int]], dict[int, dict[str, int]]]


@dataclass
class Candidate:
    """One sweep candidate (stale or BIP34-height unknown row)."""

    chain: str
    source: str  # "stale" | "unknown"
    inventory: str
    height: int
    block_hash: str
    n_time: int  # re-derived from the header bytes
    meets_full_pow: bool
    # Whether the claimed height is authoritative: True only for stale rows
    # whose classifier set btc_height = (active-chain prev height) + 1. For
    # unknown rows and the canonical-fill-scratch stale inventories the
    # btc_height is not verified against the canonical chain, so a time-rule
    # check against it is uninterpretable.
    authoritative_height: bool = False
    # Whether the header digest meets the CANONICAL expected-nBits target at
    # the claimed height (the inventory's expected_nbits column, else the
    # epoch table at the height's epoch start). None when neither source
    # yields a parseable target. Meeting only the header's own embedded bits
    # is not enough: an easy self-declared-target header is a
    # share/contamination, not a confirmed error block (the same rule the
    # offline validator enforces).
    meets_expected_pow: bool | None = None
    parent_mtp: int | None = None
    parent_time: int | None = None
    violation: str = ""  # "time_below_mtp" | "time_beyond_future_limit" | ""
    in_dataset: bool = False

    @property
    def is_error_block_candidate(self) -> bool:
        # Only time_below_mtp is a promotable error-block finding: its parent
        # MTP is committed canonical context, so the violation re-derives
        # offline. time_beyond_future_limit uses an approximate neighbor-time
        # reference (Bitcoin's real network-adjusted-time bound is not
        # reconstructable offline) and is deferred in the validator, so those
        # rows are manual-review flags, never auto-promoted. A promotable
        # finding must ALSO meet the canonical expected-nBits target: an easy
        # self-declared-target header is a share/contamination, not a
        # confirmed error block.
        return (
            self.meets_full_pow
            and self.meets_expected_pow is True
            and self.violation == "time_below_mtp"
        )

    @property
    def is_new_finding(self) -> bool:
        return self.is_error_block_candidate and not self.in_dataset


@dataclass
class ChainReport:
    """Per-chain sweep tally."""

    chain: str
    stale_inventory: str
    unknown_inventory: str = ""
    reachable: bool = True
    error: str = ""
    stale_rows: int = 0
    unknown_rows: int = 0
    unknown_no_height: int = 0
    candidates: int = 0
    pow_pass: int = 0
    pow_fail: int = 0
    pow_unparseable: int = 0
    no_mtp_context: int = 0
    untrustworthy_height: int = 0
    time_below_mtp: int = 0
    time_beyond_future_limit: int = 0
    # Full-PoW time_below_mtp violations whose digest does NOT meet the
    # canonical expected-nBits target at the claimed height:
    # share/contamination observations, never confirmed error blocks.
    canonical_target_fail: int = 0
    already_in_dataset: int = 0
    new_findings: list[Candidate] = field(default_factory=list)
    # Distinct (height, hash) NEW-finding keys: the same new BTC error block
    # can be witnessed in several sibling-chain inventories, so the
    # new_findings observation list overcounts distinct blocks.
    new_finding_keys: set[tuple[int, str]] = field(default_factory=set)
    # time_beyond_future_limit rows (approximate reference, deferred in the
    # validator): manual-review flags, kept separate from promotable findings.
    future_limit_flags: list[Candidate] = field(default_factory=list)


def parse_header(header_hex: str) -> tuple[int, int, int] | None:
    """Return (n_time, bits, version) from an 80-byte header hex, or None."""
    try:
        raw = bytes.fromhex((header_hex or "").strip())
    except ValueError:
        return None
    if len(raw) != 80:
        return None
    version = int.from_bytes(raw[0:4], "little", signed=True)
    n_time = int.from_bytes(raw[68:72], "little")
    bits = int.from_bytes(raw[72:76], "little")
    return n_time, bits, version


def reverify_full_pow(header_hex: str) -> tuple[bool, int, int] | None:
    """Re-verify full PoW from the committed header bytes.

    Returns (meets_target, n_time, bits) with both fields re-derived from the
    header, or None when the header cannot be parsed.
    """
    parsed = parse_header(header_hex)
    if parsed is None:
        return None
    n_time, bits, _version = parsed
    header = bytes.fromhex(header_hex.strip())
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return hash_meets_btc_difficulty(digest, bits), n_time, bits


def claimed_height(row: dict[str, str]) -> tuple[int | None, str]:
    """Return the trustworthy claimed height for a row, or (None, why).

    The claimed height is the ``btc_height`` column, corroborated against the
    decoded BIP34 coinbase height when a coinbase scriptSig is present: a
    disagreement means the height is not trustworthy. Rows without a
    scriptSig (or with an unparseable one) keep the column value — the
    classifier derived it from the child-chain evidence.

    The BIP34 corroboration only applies where the BIP34 height commitment is
    in force (height >= ``BIP34_HEIGHT``). Before BIP34 activation the
    scriptSig's first push was NOT a consensus height commitment, so a
    pre-BIP34 row whose first pushed integer differs from ``btc_height`` is
    not a contradiction: the authoritative stale inventory's ``btc_height``
    is trustworthy on its own and the row is kept.
    """
    height_text = (row.get("btc_height") or "").strip()
    if not height_text:
        return None, "no btc_height"
    try:
        height = int(height_text)
    except ValueError:
        return None, f"malformed btc_height {height_text!r}"
    # Bound to the plausible canonical range: these inventories carry
    # contamination rows whose btc_height is a garbage integer (a misparsed
    # hash), and a claimed height above the canonical tip has no parent MTP
    # to check against. MAX_PLAUSIBLE_HEIGHT is a generous forward margin
    # over the ~900k tip at sweep time.
    if height <= 0 or height > MAX_PLAUSIBLE_HEIGHT:
        return None, f"implausible btc_height {height}"
    scriptsig_hex = (row.get("coinbase_scriptsig_hex") or "").strip()
    if scriptsig_hex and height >= BIP34_HEIGHT:
        try:
            scriptsig = bytes.fromhex(scriptsig_hex)
        except ValueError:
            return None, "malformed coinbase scriptSig hex"
        decoded = parse_coinbase_height(scriptsig)
        if decoded is not None and decoded != height:
            return None, f"btc_height {height} != BIP34 coinbase height {decoded}"
    return height, ""


def apply_time_rules(n_time: int, parent_mtp: int, parent_time: int) -> str:
    """Return the violated time-rule token, or "" when both rules pass.

    ``time_below_mtp``: nTime must be strictly greater than the canonical
    parent's median-time-past. ``time_beyond_future_limit``: nTime must not
    exceed the canonical parent's block time + MAX_FUTURE_BLOCK_TIME (the
    committed neighbor-evidence reference; see module docstring).
    """
    if n_time <= parent_mtp:
        return "time_below_mtp"
    if n_time > parent_time + MAX_FUTURE_BLOCK_TIME:
        return "time_beyond_future_limit"
    return ""


# Remote helper run on the archive host: reads claimed heights (one per line)
# from stdin and emits "height time mediantime" per line, resolving each
# canonical hash and header over a single persistent JSON-RPC HTTP connection
# with request batching. Per-height ``bitcoin-cli`` subprocesses would take
# ~8 hours at these inventories' ~650k distinct claimed heights; this batched
# connection does it in under a minute. RPC credentials are read from the
# node's own config on the remote host, never committed here.
_REMOTE_MTP_HELPER = r"""
import http.client, json, base64, sys
conf = {}
for line in open("/etc/bitcoin/bitcoin.conf"):
    if "=" in line:
        k, v = line.strip().split("=", 1)
        conf[k] = v
auth = base64.b64encode(
    (conf.get("rpcuser", "") + ":" + conf.get("rpcpassword", "")).encode()
).decode()
conn = http.client.HTTPConnection(
    "127.0.0.1", int(conf.get("rpcport", 8332)), timeout=120
)
headers = {"Authorization": "Basic " + auth, "Content-Type": "application/json"}
heights = [int(l) for l in sys.stdin if l.strip()]
BATCH = 500
for i in range(0, len(heights), BATCH):
    chunk = heights[i:i + BATCH]
    bh = [
        {"jsonrpc": "1.0", "id": str(h), "method": "getblockhash", "params": [h]}
        for h in chunk
    ]
    conn.request("POST", "/", json.dumps(bh), headers)
    resp = json.loads(conn.getresponse().read())
    hashes = {int(x["id"]): x["result"] for x in resp if x.get("result")}
    if not hashes:
        continue
    bh2 = [
        {"jsonrpc": "1.0", "id": str(h), "method": "getblockheader", "params": [hh]}
        for h, hh in hashes.items()
    ]
    conn.request("POST", "/", json.dumps(bh2), headers)
    for x in json.loads(conn.getresponse().read()):
        r = x.get("result")
        if r:
            print(x["id"], r["time"], r["mediantime"])
"""


def ssh_mtp_fetcher(heights: list[int]) -> dict[int, dict[str, int]]:
    """Batch-fetch canonical block time/MTP for heights via one ssh session.

    Ships a small helper to the archive host that resolves each height's
    canonical hash and header over a single persistent batched JSON-RPC
    connection (see ``_REMOTE_MTP_HELPER``), emitting ``height time
    mediantime`` lines. Heights whose fetch fails are omitted from the result
    (the caller treats a missing height as unavailable context, never as a
    pass).
    """
    if not heights:
        return {}
    stdin_text = "\n".join(str(h) for h in sorted(set(heights))) + "\n"
    # Ship the helper to a remote temp path (its source goes through this
    # call's stdin), then run it with the heights on stdin — the helper
    # source and the heights cannot share one stdin stream.
    helper_path = "/tmp/mmr_time_sweep_mtp_helper.py"
    write = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", ARCHIVE_HOST, f"cat > {helper_path}"],
        input=_REMOTE_MTP_HELPER,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if write.returncode != 0:
        raise OSError(
            f"ssh {ARCHIVE_HOST} helper upload failed (rc={write.returncode}): "
            f"{write.stderr.strip()}"
        )
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", ARCHIVE_HOST, f"python3 {helper_path}"],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
    )
    if result.returncode != 0:
        raise OSError(
            f"ssh {ARCHIVE_HOST} MTP batch failed (rc={result.returncode}): "
            f"{result.stderr.strip()}"
        )
    out: dict[int, dict[str, int]] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        try:
            height, block_time, mediantime = (int(p) for p in parts)
        except ValueError:
            continue
        out[height] = {"time": block_time, "mediantime": mediantime}
    return out


def load_mtp_cache(path: Path) -> dict[int, dict[str, int]]:
    """Load the cached canonical time/MTP context, keyed by height."""
    if not path.exists():
        return {}
    with path.open() as f:
        payload = json.load(f)
    return {
        int(height): {"time": int(ctx["time"]), "mediantime": int(ctx["mediantime"])}
        for height, ctx in payload.items()
    }


def save_mtp_cache(path: Path, context: dict[int, dict[str, int]]) -> None:
    """Persist the canonical time/MTP context cache (gitignored scratch)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump({str(h): ctx for h, ctx in sorted(context.items())}, f)


def fetch_mtp_context(
    heights: set[int],
    fetcher: MtpFetcher,
    cache_path: Path,
) -> dict[int, dict[str, int]]:
    """Return canonical time/MTP for every height, using and updating the cache.

    Only heights missing from the cache are fetched; newly fetched context is
    merged in and the cache rewritten. A fetch failure raises (the caller
    fails closed).
    """
    cached = load_mtp_cache(cache_path)
    missing = sorted(h for h in heights if h not in cached)
    if missing:
        fetched = fetcher(missing)
        cached.update(fetched)
        save_mtp_cache(cache_path, cached)
    return {h: cached[h] for h in heights if h in cached}


def collect_candidates(
    chain: str,
    stale_inventory: str,
    unknown_inventory: str,
    reader: InventoryReader,
    report: ChainReport,
    nbits_by_epoch: dict[int, int] | None = None,
) -> list[Candidate]:
    """Collect PoW-verified candidates from one chain's inventories.

    Raises OSError/subprocess errors upward so the caller marks the chain
    unreachable; per-row parse problems are tallied, never fatal.
    """
    if nbits_by_epoch is None:
        nbits_by_epoch = load_nbits_by_epoch()
    candidates: list[Candidate] = []
    sources = [("stale", stale_inventory)]
    if unknown_inventory:
        sources.append(("unknown", unknown_inventory))

    for source, inventory in sources:
        text = reader(chain, inventory)
        for row in csv.DictReader(io.StringIO(text)):
            if source == "stale":
                report.stale_rows += 1
            else:
                report.unknown_rows += 1
            height, why = claimed_height(row)
            if height is None:
                if source == "unknown":
                    report.unknown_no_height += 1
                continue
            pow_result = reverify_full_pow(row.get("btc_header_hex") or "")
            if pow_result is None:
                report.pow_unparseable += 1
                continue
            meets_pow, n_time, _bits = pow_result
            if meets_pow:
                report.pow_pass += 1
            else:
                report.pow_fail += 1
                continue  # a share/near row, not an error block
            # Candidate identity (and hence dataset membership) is keyed on
            # the display hash derived from the header bytes, never the
            # inventory's btc_header_hash column: the PoW check already
            # parsed the header, so this digest is authoritative.
            block_hash = header_display_hash(row.get("btc_header_hex") or "")
            if block_hash is None:
                report.pow_unparseable += 1
                continue
            candidates.append(
                Candidate(
                    chain=chain,
                    source=source,
                    inventory=inventory,
                    height=height,
                    block_hash=block_hash,
                    n_time=n_time,
                    meets_full_pow=True,
                    # Only the 16 regen-chain stale inventories carry an
                    # authoritative canonical height (classifier-derived from
                    # an active-chain prev). Unknown rows and the scratch
                    # stale inventories do not.
                    authoritative_height=(source == "stale" and chain in _REGEN_CHAINS),
                    meets_expected_pow=reverify_against_canonical_target(
                        row.get("btc_header_hex") or "", row, height, nbits_by_epoch
                    ),
                )
            )
    report.candidates = len(candidates)
    return candidates


def sweep_chain(
    chain: str,
    stale_inventory: str,
    unknown_inventory: str,
    reader: InventoryReader,
    mtp_context: dict[int, dict[str, int]],
    dataset_keys: set[tuple[int, str]],
    nbits_by_epoch: dict[int, int] | None = None,
) -> ChainReport:
    """Sweep one chain; unreachable inventories fail soft."""
    report = ChainReport(
        chain=chain,
        stale_inventory=stale_inventory,
        unknown_inventory=unknown_inventory,
    )
    try:
        candidates = collect_candidates(
            chain,
            stale_inventory,
            unknown_inventory,
            reader,
            report,
            nbits_by_epoch,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        report.reachable = False
        report.error = str(exc)
        return report

    for cand in candidates:
        evaluate_candidate(cand, mtp_context, dataset_keys, report)
    return report


def evaluate_candidate(
    cand: Candidate,
    mtp_context: dict[int, dict[str, int]],
    dataset_keys: set[tuple[int, str]],
    report: ChainReport,
) -> None:
    """Apply the time rules to one PoW-verified candidate and tally it.

    A candidate without an authoritative claimed height (unknown rows, and
    the canonical-fill-scratch stale inventories) carries a btc_height that
    is not verified against the canonical chain, so a time-rule check against
    it is uninterpretable — it is tallied as ``untrustworthy_height`` and
    never as a violation. Authoritative-height rows (the 16 regen-chain stale
    inventories, whose classifier set btc_height from an active-chain prev)
    are checked directly: their height is trustworthy by construction, so
    even a large nTime gap is a real, interpretable condition.
    """
    if not cand.authoritative_height:
        report.untrustworthy_height += 1
        return
    ctx = mtp_context.get(cand.height - 1)
    if ctx is None:
        report.no_mtp_context += 1
        return
    cand.parent_mtp = ctx["mediantime"]
    cand.parent_time = ctx["time"]
    cand.violation = apply_time_rules(cand.n_time, ctx["mediantime"], ctx["time"])
    if not cand.violation:
        return
    cand.in_dataset = (cand.height, cand.block_hash) in dataset_keys
    if cand.violation == "time_below_mtp":
        report.time_below_mtp += 1
        if cand.meets_expected_pow is not True:
            # The digest fails (or cannot be evaluated against) the canonical
            # expected-nBits target at the claimed height: a
            # share/contamination observation, not a confirmed error block.
            report.canonical_target_fail += 1
        elif cand.in_dataset:
            report.already_in_dataset += 1
        elif cand.is_new_finding:
            report.new_findings.append(cand)
            report.new_finding_keys.add((cand.height, cand.block_hash))
    else:
        # time_beyond_future_limit: approximate reference and a rule deferred
        # in the validator, so flag for manual review, never auto-promote.
        report.time_beyond_future_limit += 1
        if cand.in_dataset:
            report.already_in_dataset += 1
        else:
            report.future_limit_flags.append(cand)


def extract_resolution_section(report_text: str) -> str:
    """Return the follow-up investigation section of a report, or "".

    The section runs from the ``## Follow-up investigation`` heading to the
    end of the report. It is the manually-written child-chain commit-time
    resolution of the future-limit flags, which the sweep cannot regenerate;
    it is carried forward verbatim across regeneration. Returns "" when the
    report has no such section.
    """
    idx = report_text.find(RESOLUTION_SECTION_MARKER)
    if idx == -1:
        return ""
    return report_text[idx:].rstrip("\n")


def render_report(
    reports: list[ChainReport], generated_at: str, prior_text: str = ""
) -> str:
    """Render the dated Markdown sweep report, including negative results.

    When ``prior_text`` carries a follow-up investigation section (the
    manually-written future-limit resolution the sweep cannot regenerate), it
    is appended verbatim so regenerating the report does not drop that
    evidence.
    """
    reachable = [r for r in reports if r.reachable]
    unreachable = [r for r in reports if not r.reachable]
    total_stale = sum(r.stale_rows for r in reachable)
    total_unknown = sum(r.unknown_rows for r in reachable)
    total_no_height = sum(r.unknown_no_height for r in reachable)
    total_pow_pass = sum(r.pow_pass for r in reachable)
    total_below = sum(r.time_below_mtp for r in reachable)
    total_beyond = sum(r.time_beyond_future_limit for r in reachable)
    total_canonical_fail = sum(r.canonical_target_fail for r in reachable)
    total_in_dataset = sum(r.already_in_dataset for r in reachable)
    total_new = sum(len(r.new_findings) for r in reachable)
    distinct_new = len({key for r in reachable for key in r.new_finding_keys})
    total_untrustworthy = sum(r.untrustworthy_height for r in reachable)

    lines = [
        "# Error-blocks time-rule sweep",
        "",
        f"Generated: {generated_at}",
        "",
        "Re-examination of stale-classified rows and BIP34-height unknown rows",
        "across the reachable per-chain classified inventories on the chain",
        "archive host, for error blocks of the 946213 and 957780 class:",
        "full-proof-of-work Bitcoin headers whose `nTime` violates a time",
        "rule. Full PoW and the",
        "header `nTime` are re-derived from the committed header bytes via",
        "`hash_meets_btc_difficulty`, never inherited from a classification",
        "label. The canonical parent context (`time`/`mediantime` of the",
        "canonical block at `height - 1`) is batch-fetched from the Bitcoin",
        "node on the archive host and cached in the gitignored",
        "`cache/time_sweep_mtp.json`. Membership is checked against the",
        "committed `data/error-blocks/error_blocks.csv` dataset by",
        "`(height, hash)`.",
        "",
        "Time rules applied per candidate:",
        "",
        "- `time_below_mtp`: candidate `nTime` <= the canonical parent's",
        "  median-time-past (the `mediantime` of the canonical block at",
        "  `height - 1`). This check is robust: the parent MTP is committed",
        "  canonical-chain context. A confirmed finding must ALSO meet the",
        "  canonical expected-nBits target at the claimed height (the",
        "  inventory's `expected_nbits` column, else the committed epoch",
        "  table at the height's epoch start): a `time_below_mtp` violation",
        "  whose digest meets only an easy self-declared embedded target is",
        "  a share/contamination observation, tallied separately as",
        "  `canonical_target_fail`, never a confirmed error block (the same",
        "  rule the offline validator enforces).",
        "- `time_beyond_future_limit`: candidate `nTime` > the canonical",
        "  parent's block `time` + 2h (`MAX_FUTURE_BLOCK_TIME`). Reference",
        "  caveat: Bitcoin's real future bound is network-adjusted time + 2h,",
        "  which is NOT reconstructable offline. The canonical parent time is",
        "  only a neighbor-evidence approximation, so a modest excess is NOT",
        "  proof of a real violation (a block 2-7h after its parent is normal",
        "  under the real rule). Findings under this rule are reported for",
        "  manual review and are NOT auto-promoted.",
        "",
        "Claimed-height trust: a time-rule check is only meaningful when the",
        "claimed height is a real canonical-chain height. The 16 regen-chain",
        "stale inventories carry an authoritative height: the classifier set",
        "`btc_height` = (active-chain prev height) + 1 after confirming the",
        "parent is on the canonical chain. Unknown rows and the",
        "canonical-fill-scratch stale inventories (syscoin/elastos/fractal)",
        "carry a `btc_height` that is NOT verified against the canonical",
        "chain (a share/child height or contamination), so a time-rule check",
        "against it is uninterpretable; those full-PoW rows are tallied as",
        "`untrustworthy height` negatives, never as violations.",
        "",
        "## Summary",
        "",
        f"- Inventories reachable: {len(reachable)}/{len(reports)}",
        f"- Stale-classified rows examined: {total_stale}",
        f"- Unknown rows examined: {total_unknown}",
        f"- Unknown rows skipped for no parseable claimed height: {total_no_height}",
        f"- Candidates with full-PoW pass: {total_pow_pass}",
        f"- Full-PoW candidates with an untrustworthy claimed height "
        f"(no valid check possible): {total_untrustworthy}",
        f"- `time_below_mtp` violations (trustworthy heights): {total_below}",
        f"- `time_beyond_future_limit` flags (trustworthy heights, "
        f"approximate reference, manual review): {total_beyond}",
        f"- `time_below_mtp` observations failing the canonical "
        f"expected-nBits target (share/contamination, not confirmed): "
        f"{total_canonical_fail}",
        f"- Already catalogued in the dataset: {total_in_dataset}",
        f"- NEW confirmed error blocks: {total_new} "
        f"observations across {distinct_new} distinct (height, hash) "
        "blocks (the same new BTC error block can be witnessed in several "
        "sibling-chain inventories)",
        "",
    ]
    if unreachable:
        lines += ["## Unreachable inventories", ""]
        for r in unreachable:
            lines.append(f"- **{r.chain}** (`{r.stale_inventory}`): {r.error}")
        lines.append("")

    lines += [
        "## Per-chain results",
        "",
        "| chain | stale rows | unknown rows | full-PoW candidates | "
        "untrustworthy height | time_below_mtp | time_beyond_future_limit | "
        "already in dataset | NEW |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in reports:
        if not r.reachable:
            lines.append(f"| {r.chain} | — | — | — | — | — | — | — | unreachable |")
            continue
        lines.append(
            f"| {r.chain} | {r.stale_rows} | {r.unknown_rows} "
            f"| {r.candidates} | {r.untrustworthy_height} | {r.time_below_mtp} "
            f"| {r.time_beyond_future_limit} | {r.already_in_dataset} "
            f"| {len(r.new_findings)} |"
        )
    lines.append("")

    lines += ["## Negative results", ""]
    zero_violation = [
        r.chain
        for r in reachable
        if r.candidates > 0
        and r.time_below_mtp == 0
        and r.time_beyond_future_limit == 0
    ]
    if zero_violation:
        lines.append(
            "- Chains with full-PoW candidates but no time-rule violation "
            "(trustworthy heights): " + ", ".join(zero_violation) + "."
        )
    else:
        lines.append("- No reachable chain was violation-free.")
    if total_below == 0:
        lines.append(
            "- No `time_below_mtp` (time-too-old) violations among "
            "trustworthy-height candidates: the 946213 and 957780 class does "
            "not recur in these historical classified inventories. The "
            "946213 and 957780 rows themselves are recent (2026) and not "
            "present in these historical inventories, so they do not appear "
            "here as already-catalogued."
        )
    if total_no_height:
        lines.append(
            f"- {total_no_height} unknown rows were skipped for lacking a "
            "parseable claimed height (no `btc_height`, a malformed value, an "
            "implausible value above the canonical tip, or a `btc_height` "
            "disagreeing with the decoded BIP34 coinbase height)."
        )
    if total_untrustworthy:
        lines.append(
            f"- {total_untrustworthy} full-PoW candidates carried a "
            "non-authoritative claimed height (unknown rows, and the "
            "canonical-fill-scratch stale inventories): their `btc_height` is "
            "not verified against the canonical chain, so no valid time-rule "
            "check is possible. They are negatives, not violations."
        )
    no_context = sum(r.no_mtp_context for r in reachable)
    if no_context:
        lines.append(
            f"- {no_context} full-PoW candidates had no canonical parent "
            "context available (node fetch gap); they were not evaluated."
        )
    if total_canonical_fail:
        lines.append(
            f"- {total_canonical_fail} `time_below_mtp` observation(s) failed "
            "(or could not be evaluated against) the canonical expected-nBits "
            "target at the claimed height: they meet only an easy "
            "self-declared embedded target, so they are share/contamination "
            "observations, NOT confirmed error blocks."
        )
    if total_new == 0:
        lines.append(
            "- No NEW confirmed time-rule error blocks promoted: see the "
            "future-limit caveat and the review list below."
        )
    lines.append("")

    if total_beyond:
        lines += [
            "## `time_beyond_future_limit` flags (NEEDS_CONTEXT, not promoted)",
            "",
            "These trustworthy-height rows have `nTime` more than 2h beyond",
            "the canonical parent's block time. Under Bitcoin's REAL future",
            "rule (network-adjusted time + 2h) a modest excess is normal and",
            "NOT a violation — network-adjusted time tracks the wall clock,",
            "which is near the block's own `nTime`. The canonical parent time",
            "is only a neighbor-evidence approximation, so these are reported",
            "for manual review and are NOT promoted into the dataset. The",
            "`time_beyond_future_limit` rule is also still deferred in the",
            "offline validator's `TIME_RULES` (it needs a network-adjusted-",
            "time reference that is not committed).",
            "",
        ]
        # Aggregate every chain that observed each flagged block.
        chains_by_key: dict[tuple[int, str], list[str]] = {}
        cand_by_key: dict[tuple[int, str], Candidate] = {}
        for r in reachable:
            for cand in r.future_limit_flags:
                key = (cand.height, cand.block_hash)
                chains_by_key.setdefault(key, [])
                if cand.chain not in chains_by_key[key]:
                    chains_by_key[key].append(cand.chain)
                cand_by_key[key] = cand
        for key in sorted(chains_by_key):
            cand = cand_by_key[key]
            chains = "|".join(sorted(chains_by_key[key]))
            excess_h = (cand.n_time - cand.parent_time) / 3600
            lines.append(
                f"- height {cand.height} hash `{cand.block_hash}` "
                f"(seen on {chains}) — nTime {excess_h:.2f}h beyond "
                f"the canonical parent time"
            )
        lines.append("")

    if total_new:
        lines += ["## NEW confirmed `time_below_mtp` error blocks", ""]
        for r in reachable:
            for cand in r.new_findings:
                lines.append(
                    f"- {cand.chain} ({cand.source}) height {cand.height} hash "
                    f"`{cand.block_hash}` — nTime {cand.n_time} <= parent MTP "
                    f"{cand.parent_mtp} (provenance: "
                    f"`sweep-time-rule:{cand.chain}:{cand.inventory}`)"
                )
        lines.append("")

    lines += [
        "Row-level candidate detail remains in the authoritative inventories on",
        "the chain archive host; this report is the compact committed summary.",
        "",
    ]
    resolution = extract_resolution_section(prior_text)
    if resolution:
        lines += [resolution, ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chain-archive-root",
        type=Path,
        default=None,
        help="read inventories from a local mirror (<root>/<chain>/<filename>) "
        f"instead of ssh {ARCHIVE_HOST}",
    )
    parser.add_argument(
        "--mtp-cache",
        type=Path,
        default=DEFAULT_MTP_CACHE,
        help="canonical time/MTP cache path (gitignored scratch)",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    if validate_partial_args(args):
        return 2

    reader: InventoryReader = (
        local_mirror_reader(args.chain_archive_root)
        if args.chain_archive_root is not None
        else ssh_inventory_reader
    )
    dataset_keys = load_dataset_keys()

    # Pass 1: collect PoW-verified candidates per chain (fail soft per chain).
    reports: list[ChainReport] = []
    candidates_by_chain: dict[str, list[Candidate]] = {}
    for chain, stale_path in STALE_INVENTORIES.items():
        unknown_path = UNKNOWN_INVENTORY_GLOB.get(chain, "")
        report = ChainReport(
            chain=chain, stale_inventory=stale_path, unknown_inventory=unknown_path
        )
        try:
            candidates_by_chain[chain] = collect_candidates(
                chain, stale_path, unknown_path, reader, report
            )
        except (OSError, subprocess.SubprocessError) as exc:
            report.reachable = False
            report.error = str(exc)
        reports.append(report)

    reachable = [r for r in reports if r.reachable]
    if not reachable:
        for r in reports:
            print(f"error: {r.chain}: {r.error}", file=sys.stderr)
        print(
            "sweep failed: no inventories reachable (no report written)",
            file=sys.stderr,
        )
        return 1

    # A partial sweep (some inventories unreachable) must not overwrite the
    # committed report without --allow-partial.
    if require_full_coverage_for_committed(
        args,
        reports,
        expected_inventory_rows=INVENTORY_BASELINE_ROWS,
        inventory_row_counts=lambda report: {
            f"{report.chain}:stale": report.stale_rows,
            **(
                {f"{report.chain}:unknown": report.unknown_rows}
                if report.unknown_inventory
                else {}
            ),
        },
    ):
        return 1

    # Batch-fetch the canonical parent context once for all distinct claimed
    # heights, then evaluate the time rules per candidate. Only candidates
    # with an AUTHORITATIVE claimed height are ever MTP-evaluated (unknown
    # rows and the canonical-fill-scratch stale inventories are tallied as
    # untrustworthy without a time-rule check), so only their parent heights
    # are requested: fetching context for the (potentially millions of)
    # unevaluated untrustworthy-height candidates would waste the node fetch.
    all_heights = {
        cand.height - 1
        for chain in candidates_by_chain
        for cand in candidates_by_chain[chain]
        if cand.authoritative_height
    }
    try:
        mtp_context = fetch_mtp_context(all_heights, ssh_mtp_fetcher, args.mtp_cache)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"error: canonical MTP fetch failed: {exc}", file=sys.stderr)
        print("sweep failed: no canonical context (no report written)", file=sys.stderr)
        return 1
    if all_heights and not mtp_context:
        print(
            "error: canonical MTP fetch returned no context for any claimed "
            "height (no report written)",
            file=sys.stderr,
        )
        return 1
    # The committed report must only ever present a COMPLETE sweep: every
    # requested parent height must have canonical MTP context. A partial
    # context (the RPC result omitted even one requested height) would leave
    # those candidates unevaluated while the report could still state "no
    # time_below_mtp violations found" — an incomplete sweep presented as
    # complete. Refuse the committed write in that case, naming the missing
    # heights; --allow-partial --output-dir remains the diagnostic escape.
    missing_mtp = sorted(h for h in all_heights if h not in mtp_context)
    if missing_mtp and not args.allow_partial:
        print(
            "error: canonical MTP context is incomplete: "
            f"{len(missing_mtp)} requested parent height(s) missing: "
            + ", ".join(str(h) for h in missing_mtp),
            file=sys.stderr,
        )
        print(
            "sweep failed: refusing to write the committed report from an "
            "incomplete canonical MTP context; re-run with --allow-partial "
            "--output-dir <dir> for a diagnostic partial report",
            file=sys.stderr,
        )
        return 1

    for report in reports:
        if not report.reachable:
            continue
        for cand in candidates_by_chain.get(report.chain, []):
            evaluate_candidate(cand, mtp_context, dataset_keys, report)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    output = resolve_output_path(args, DEFAULT_REPORT)
    if output is None:
        return 2
    # Preserve the manually-written follow-up investigation section (the
    # future-limit resolution the sweep cannot regenerate) across the
    # overwrite: carry it forward from the report being replaced.
    prior_text = output.read_text() if output.exists() else ""
    report_text = render_report(reports, generated_at, prior_text)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report_text)
    print(f"wrote sweep report to {output}")

    total_new = sum(len(r.new_findings) for r in reachable)
    print(
        f"swept {sum(r.candidates for r in reachable)} full-PoW candidates "
        f"({sum(r.stale_rows for r in reachable)} stale + "
        f"{sum(r.unknown_rows for r in reachable)} unknown rows) across "
        f"{len(reachable)}/{len(reports)} reachable inventories: "
        f"{sum(r.untrustworthy_height for r in reachable)} untrustworthy-height, "
        f"{sum(r.time_below_mtp for r in reachable)} time_below_mtp, "
        f"{sum(r.time_beyond_future_limit for r in reachable)} "
        f"time_beyond_future_limit (review), {total_new} NEW error block(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
