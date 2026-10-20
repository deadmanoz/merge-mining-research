"""Offline re-check of committed error blocks. No live RPC.

Body rules use reviewed evidence: bodies are authenticated locally and those
failures are not re-derived here. ``consensus_invalid_parent`` authenticates
the header path and the root's minimum-version violation through
``ancestry_evidence.csv``. Predecessor placement is a reviewed RPC receipt;
serialized identity and target context are rechecked offline.

A row must meet both its embedded ``btc_bits`` target and canonical
``expected_nbits``. A declared version or length token must be the one the
height or scriptSig length determines. A BIP34 coinbase-height token also
requires a passing header version, and must match the gate's form: one gate
serves both the wrong-height and missing-height rules. ``rejection_reason``
is the first local token, or the Core reject family for a body rule
(``missing_unconfirmed_parent`` maps to ``bad-txns-inputs-missingorspent``).
Version, BIP34 height, and scriptSig-length violations must all be claimed.
MTP and retarget are not held to that exact set.

``expected_nbits`` must match the epoch table. Embedded ``btc_bits`` must
equal it except ``nbits_retarget_not_applied``, whose bits are the previous
epoch's and whose digest still meets the canonical target. That is an
epoch-boundary full-PoW failure, not a non-boundary nBits mismatch.

Audit columns must match the header: ``btc_prev_hash`` is bytes 4-36 reversed
to display order, ``btc_header_version`` is bytes 0-4 LE signed, ``btc_time``
is bytes 68-72 LE, and ``btc_bits`` is bytes 72-76 LE. ``coinbase_height`` is
checked only when a BIP34 prefix is derivable. ``time_below_mtp`` uses
``mtp_context.csv`` and nTime from those header bytes, never ``btc_time``.
``TIME_RULES`` (``time_beyond_future_limit``) fail closed. Active-parent
placement is not checked here; that gate is online.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from stale_blocks_analysis.auxpow_chainid import hash_to_display_hex
from stale_blocks_analysis.auxpow_parse import (
    hash_meets_btc_difficulty,
    parse_coinbase_height,
)
from stale_blocks_analysis.btc_stale_validation import (
    LENGTH_RULES as _LENGTH_RULE_TOKENS,
)
from stale_blocks_analysis.btc_stale_validation import (
    VERSION_RULES as _VERSION_RULE_TOKENS,
)
from stale_blocks_analysis.btc_stale_validation import (
    BIP34_HEIGHT_MISMATCH_PREFIX,
    BIP34_HEIGHT_MISSING_PREFIX,
    bip34_height_error,
    block_version_error,
    coinbase_scriptsig_length_error,
    consensus_violations,
    expected_length_rule as _expected_length_token,
    expected_version_rule as _expected_version_token,
    median_time_past_error,
    nbits_retarget_not_applied_error as _nbits_retarget_not_applied_error,
)
from stale_blocks_analysis.config import (
    BITCOIN_EPOCH_REFERENCE_DIR,
    ERROR_BLOCK_BODIES_DIR,
    BODY_ERROR_REJECTIONS,
    ERROR_BLOCKS_BODY_EVIDENCE_NAME,
    ERROR_BLOCKS_CSV,
    ERROR_BLOCKS_MTP_CONTEXT_CSV,
    ERROR_BLOCKS_ANCESTRY_EVIDENCE_NAME,
    CONSENSUS_INVALID_PARENT_RULE,
)
from stale_blocks_analysis.error_ancestry import (
    load_ancestry_evidence,
    validate_ancestry_evidence,
)
from stale_blocks_analysis.body_evidence import (
    load_body_evidence,
    validate_body_evidence,
)
from stale_blocks_analysis.error_observations import (
    ERROR_OBSERVATION_LEDGER,
    ErrorBlock,
    ErrorObservationKey,
    validate_error_observation_ledger,
)

EPOCH_LENGTH = 2016
NBITS_BY_EPOCH_JSON = BITCOIN_EPOCH_REFERENCE_DIR / "btc_nbits_by_epoch.json"

# Needs network-adjusted time, so these tokens fail closed offline.
# ``time_below_mtp`` uses the MTP sidecar and is not in this set.
TIME_RULES = frozenset(
    {
        "time_beyond_future_limit",
    }
)

Gate = Callable[[dict[str, Any], int], str | None]


class ErrorModuleValidationError(ValueError):
    """Report every failed invariant in the canonical error-block module."""

    def __init__(self, failures: list[str]) -> None:
        self.failures = tuple(failures)
        super().__init__(
            f"{len(failures)} canonical error-module validation failure(s)"
        )


def _load_nbits_by_epoch(path: Path = NBITS_BY_EPOCH_JSON) -> dict[int, int]:
    with path.open() as f:
        table = json.load(f)
    return {
        int(epoch_start): int(hexbits, 16) for epoch_start, hexbits in table.items()
    }


def _load_mtp_context(
    path: Path = ERROR_BLOCKS_MTP_CONTEXT_CSV,
) -> dict[tuple[int, str], int]:
    """Load the committed parent median-time-past sidecar, keyed by (height, hash)."""
    out: dict[tuple[int, str], int] = {}
    with path.open(newline="") as f:
        for row_number, row in enumerate(csv.DictReader(f), start=2):
            try:
                raw_height = row["height"]
                height = int(raw_height)
                block_hash = row["hash"]
                if (
                    height < 0
                    or str(height) != raw_height
                    or len(block_hash) != 64
                    or block_hash != block_hash.lower()
                    or any(char not in "0123456789abcdef" for char in block_hash)
                ):
                    raise ValueError("non-canonical MTP context key")
                key = (height, block_hash)
                parent_mtp = int(row["parent_median_time_past"])
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"invalid MTP context row {row_number} in {path}"
                ) from exc
            if key in out:
                raise ValueError(
                    f"duplicate MTP context key {key!r} at row {row_number} in {path}"
                )
            out[key] = parent_mtp
    return out


RULE_GATES: dict[str, Gate] = {
    "bip34_block_version_below_2": block_version_error,
    "bip66_block_version_below_3": block_version_error,
    "bip65_block_version_below_4": block_version_error,
    "coinbase_scriptsig_length_above_100": lambda row, height: (
        coinbase_scriptsig_length_error(row)
    ),
    "coinbase_scriptsig_length_below_2": lambda row, height: (
        coinbase_scriptsig_length_error(row)
    ),
    "bip34_coinbase_height_mismatch": bip34_height_error,
    "bip34_v2_coinbase_height_mismatch": bip34_height_error,
    "bip34_coinbase_height_missing": bip34_height_error,
    "bip34_v2_coinbase_height_missing": bip34_height_error,
}

# Version and length tokens are fixed by height and scriptSig length. REJECTED
# proves a violation, not the declared token: version-2 labelled
# ``bip66_block_version_below_3`` fires the same gate as
# ``bip65_block_version_below_4``. Vocabulary is ``btc_stale_validation``.
# ``bip34_height_error`` rejects a too-low version at BIP34+ before reading
# the coinbase, so a coinbase-height token on that header is the wrong claim.
# One gate serves mismatch and missing forms; the token must match
# ``BIP34_HEIGHT_*_PREFIX``. Other REJECTED text is unusable evidence or a
# ``btc_bip34_height`` metadata disagreement, not a consensus violation.
_BIP34_HEIGHT_MISMATCH_TOKENS = frozenset(
    {
        "bip34_coinbase_height_mismatch",
        "bip34_v2_coinbase_height_mismatch",
    }
)
_BIP34_HEIGHT_MISSING_TOKENS = frozenset(
    {
        "bip34_coinbase_height_missing",
        "bip34_v2_coinbase_height_missing",
    }
)
_BIP34_COINBASE_HEIGHT_TOKENS = (
    _BIP34_HEIGHT_MISMATCH_TOKENS | _BIP34_HEIGHT_MISSING_TOKENS
)


def _actual_violation_token(rule: str, row: dict[str, Any], height: int) -> str | None:
    """Version or length token fixed by the bytes, or None when there is none."""
    if rule in _VERSION_RULE_TOKENS:
        return _expected_version_token(height)
    if rule in _LENGTH_RULE_TOKENS:
        return _expected_length_token(row)
    return None


def _derivable_violation_tokens(row: dict[str, Any], height: int) -> list[str]:
    """Version, BIP34-height, and scriptSig-length violations, via ``consensus_violations``.

    UNKNOWN, malformed, or missing-scriptSig verdicts are not violations.
    MTP and retarget are not derived. A BIP34 height token is derived only
    when the header version already passes. No parent MTP, so this matches
    the classifier's byte-derivable set.
    """
    return consensus_violations(row, height)


def nbits_retarget_not_applied_error(
    row: dict[str, Any], nbits_by_epoch: dict[int, int]
) -> str | None:
    """Shared retarget gate, reading height from the dataset row.

    ``ValueError`` on an unevaluable claim; the validator fails closed.
    """
    try:
        height = int(str(row.get("height", "") or "").strip())
    except ValueError as exc:
        raise ValueError(
            "malformed height or btc_bits for nbits_retarget_not_applied"
        ) from exc
    return _nbits_retarget_not_applied_error(row, height, nbits_by_epoch)


def validate_row(
    row: dict[str, str],
    *,
    nbits_by_epoch: dict[int, int] | None = None,
    mtp_context: dict[tuple[int, str], int] | None = None,
    body_evidence: dict[tuple[int, str], dict[str, str]] | None = None,
    ancestry_evidence: dict[tuple[int, str], dict[str, str]] | None = None,
    blocks_dir: Path = ERROR_BLOCK_BODIES_DIR,
) -> list[str]:
    """Return local-gate or externally attested body-evidence failures."""
    if nbits_by_epoch is None:
        nbits_by_epoch = _load_nbits_by_epoch()
    if mtp_context is None:
        mtp_context = _load_mtp_context()

    failures: list[str] = []

    height_text = str(row.get("height", "") or "").strip()
    try:
        height = int(height_text)
    except ValueError:
        return [f"malformed height value {height_text!r}"]

    # (a) Full proof of work against the header's own target.
    header_hex = str(row.get("btc_header_hex", "") or "").strip()
    bits_text = str(row.get("btc_bits", "") or "").strip()
    derived_time: int | None = None
    header_digest: bytes | None = None
    embedded_bits: int | None = None
    try:
        header = bytes.fromhex(header_hex)
        bits = int(bits_text, 16)
    except ValueError:
        failures.append("malformed btc_header_hex or btc_bits")
    else:
        embedded_bits = bits
        if len(header) != 80:
            failures.append(f"btc_header_hex is {len(header)} bytes, expected 80")
        else:
            digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
            header_digest = digest
            if not hash_meets_btc_difficulty(digest, bits):
                failures.append(
                    "header hash does not meet its own target (not full PoW)"
                )
            # Audit columns must match these header bytes, or the row names
            # a different block than the header.
            derived_hash = digest[::-1].hex()
            if str(row.get("hash", "") or "").strip().lower() != derived_hash:
                failures.append("hash column does not match btc_header_hex digest")
            derived_prev_hash = hash_to_display_hex(header[4:36])
            prev_hash_text = str(row.get("btc_prev_hash", "") or "").strip().lower()
            if prev_hash_text != derived_prev_hash:
                failures.append(
                    "btc_prev_hash column does not match the header's embedded "
                    "previous-block hash"
                )
            derived_version = int.from_bytes(header[0:4], "little", signed=True)
            version_text = str(row.get("btc_header_version", "") or "").strip()
            try:
                if int(version_text) != derived_version:
                    failures.append(
                        "btc_header_version column does not match the header's "
                        "embedded nVersion"
                    )
            except ValueError:
                failures.append(f"malformed btc_header_version value {version_text!r}")
            derived_time = int.from_bytes(header[68:72], "little")
            time_text = str(row.get("btc_time", "") or "").strip()
            try:
                if int(time_text) != derived_time:
                    failures.append(
                        "btc_time column does not match the header's embedded nTime"
                    )
            except ValueError:
                failures.append(f"malformed btc_time value {time_text!r}")
            derived_bits = int.from_bytes(header[72:76], "little")
            if derived_bits != bits:
                failures.append(
                    "btc_bits column does not match the header's embedded nBits"
                )

    # ``coinbase_height`` must match a derivable BIP34 prefix. Pre-BIP34 and
    # scripts with no height push are skipped.
    scriptsig_text = str(row.get("coinbase_scriptsig_hex", "") or "").strip()
    try:
        scriptsig = bytes.fromhex(scriptsig_text)
    except ValueError:
        scriptsig = b""
        # Malformed nonempty scriptSig fails closed. An empty one is missing
        # evidence, not a parse failure.
        if scriptsig_text:
            failures.append("malformed nonempty coinbase_scriptsig_hex")
    derived_coinbase_height = parse_coinbase_height(scriptsig) if scriptsig else None
    if derived_coinbase_height is not None:
        coinbase_height_text = str(row.get("coinbase_height", "") or "").strip()
        try:
            if int(coinbase_height_text) != derived_coinbase_height:
                failures.append(
                    "coinbase_height column does not match the coinbase "
                    "scriptSig's BIP34 height prefix"
                )
        except ValueError:
            failures.append(f"malformed coinbase_height value {coinbase_height_text!r}")

    # Parsed once for the canonical-target check and the epoch table.
    expected_text = str(row.get("expected_nbits", "") or "").strip()
    expected_nbits: int | None = None
    try:
        expected_nbits = int(expected_text, 16)
    except ValueError:
        failures.append(f"malformed expected_nbits value {expected_text!r}")

    # Canonical target, not just embedded bits. A retarget-not-applied row
    # still has to meet this harder target.
    if header_digest is not None and expected_nbits is not None:
        if not hash_meets_btc_difficulty(header_digest, expected_nbits):
            failures.append(
                "header hash does not meet the canonical expected_nbits "
                "target (not full Bitcoin PoW)"
            )

    # (b) Every claimed rule needs its local gate or reviewed body evidence.
    rules_text = str(row.get("rules_violated", "") or "").strip()
    rules = [rule for rule in rules_text.split("|") if rule]
    if not rules:
        failures.append("rules_violated is empty")

    # Embedded nBits must equal the epoch value. Stricter-but-wrong bits are
    # still a consensus violation. ``nbits_retarget_not_applied`` is the
    # exception: those bits are the previous epoch's.
    if (
        embedded_bits is not None
        and expected_nbits is not None
        and "nbits_retarget_not_applied" not in rules
        and embedded_bits != expected_nbits
    ):
        failures.append(
            f"embedded btc_bits {bits_text} does not match canonical "
            f"expected_nbits {expected_text}"
        )

    # ``rejection_reason`` is the first ``rules_violated`` token, or the Core
    # reject family registered for a body rule.
    rejection_reason = str(row.get("rejection_reason", "") or "").strip()
    if not rejection_reason:
        failures.append("rejection_reason is empty")
    elif rules and rejection_reason != BODY_ERROR_REJECTIONS.get(rules[0], rules[0]):
        failures.append(
            f"rejection_reason {rejection_reason} is not the primary (first) "
            f"rule of rules_violated ({rules[0]})"
        )
    for rule in rules:
        if rule == CONSENSUS_INVALID_PARENT_RULE:
            failures.extend(
                validate_ancestry_evidence(row, ancestry_evidence or {}, nbits_by_epoch)
            )
            continue
        if rule in BODY_ERROR_REJECTIONS:
            failures.extend(
                validate_body_evidence(row, rule, body_evidence or {}, blocks_dir)
            )
            continue
        if rule in TIME_RULES:
            # No committed network-adjusted time. Fail closed.
            failures.append(
                f"rule {rule} is not offline-recheckable and cannot be a "
                "committed error block"
            )
            continue
        if rule == "time_below_mtp":
            # Not a RULE_GATES entry: parent MTP does not fit the gate
            # signature. nTime is header bytes 68-72 LE, not ``btc_time``.
            parent_mtp = mtp_context.get((height, str(row.get("hash", ""))))
            if parent_mtp is None:
                failures.append(
                    f"rule {rule} has no committed MTP context for "
                    f"({height}, {str(row.get('hash', ''))[-12:]})"
                )
                continue
            if derived_time is None:
                # The header was already flagged malformed above; the rule
                # cannot be re-derived without its nTime.
                failures.append(
                    f"rule {rule} cannot re-derive: no parseable header nTime"
                )
                continue
            mtp_result = median_time_past_error(
                {**row, "btc_time": str(derived_time)},
                parent_mtp,
                time_key="btc_time",
            )
            if mtp_result is None:
                failures.append(f"rule {rule} did not re-derive")
                continue
            # UNKNOWN is unusable evidence, not a proven violation.
            if mtp_result.startswith("UNKNOWN:"):
                failures.append(
                    f"rule {rule} could not be evaluated (gate returned UNKNOWN)"
                )
            continue
        if rule == "nbits_retarget_not_applied":
            # Epoch table does not fit the gate signature. Canonical-target
            # PoW is the shared check above; only the boundary re-derives here.
            try:
                derived = nbits_retarget_not_applied_error(row, nbits_by_epoch)
            except ValueError as exc:
                failures.append(f"rule nbits_retarget_not_applied: {exc}")
                continue
            if derived is None:
                failures.append("rule nbits_retarget_not_applied did not re-derive")
            continue
        gate = RULE_GATES.get(rule)
        if gate is None:
            failures.append(f"no gate registered for rule {rule}")
            continue
        gate_result = gate(row, height)
        if gate_result is None:
            failures.append(f"rule {rule} did not re-derive")
            continue
        # Only a rule-specific REJECTED verdict is proof. UNKNOWN, malformed
        # evidence, and a missing scriptSig are not a consensus violation: a
        # BIP34 failure needs a present, wrongly-encoded scriptSig.
        if gate_result.startswith("UNKNOWN:"):
            failures.append(
                f"rule {rule} could not be evaluated (gate returned UNKNOWN)"
            )
            continue
        if "malformed" in gate_result:
            failures.append(
                f"rule {rule} could not be evaluated (gate returned a "
                "malformed-evidence verdict, not a proven violation)"
            )
            continue
        # "missing coinbase scriptSig" is absent evidence, not a BIP34 violation.
        if "missing coinbase scriptSig" in gate_result:
            failures.append(
                f"rule {rule} could not be evaluated (gate returned a "
                "missing-evidence verdict, not a proven violation)"
            )
            continue
        # The verdict must match the declared form. One gate serves both
        # mismatch and missing-height, so "some rejection" would let one
        # verdict claim both tokens. A ``btc_bip34_height`` disagreement is
        # not either form.
        if rule in _BIP34_COINBASE_HEIGHT_TOKENS:
            declared_prefix = (
                BIP34_HEIGHT_MISSING_PREFIX
                if rule in _BIP34_HEIGHT_MISSING_TOKENS
                else BIP34_HEIGHT_MISMATCH_PREFIX
            )
            if not gate_result.startswith(declared_prefix):
                # No continue: the version check below names that cause too.
                failures.append(
                    f"rule {rule} did not re-derive in its declared form "
                    f"(gate verdict does not begin {declared_prefix!r})"
                )
        # Version and length tokens are fixed by height and scriptSig length.
        actual_token = _actual_violation_token(rule, row, height)
        if actual_token is not None and actual_token != rule:
            failures.append(
                f"declared rule {rule} inconsistent with actual violation "
                f"{actual_token}"
            )
        # At BIP34+ a too-low version is rejected before the coinbase prefix.
        # The coinbase-height token is then the wrong claim.
        if rule in _BIP34_COINBASE_HEIGHT_TOKENS and (
            block_version_error(row, height) is not None
        ):
            failures.append(
                f"declared rule {rule} inconsistent with actual violation: "
                "header version is also too low for the height (the real "
                "violation is the version, not the coinbase height)"
            )

    # Unclaimed version, BIP34-height, or scriptSig-length violations fail.
    # MTP and retarget are not part of that exact set.
    for token in _derivable_violation_tokens(row, height):
        if token not in rules:
            failures.append(f"unclaimed violation: {token}")

    # Epoch-table comparison. A malformed value was already reported.
    epoch_start = (height // EPOCH_LENGTH) * EPOCH_LENGTH
    if expected_nbits is not None:
        epoch_bits = nbits_by_epoch.get(epoch_start)
        if epoch_bits is None:
            failures.append(
                f"epoch start {epoch_start} missing from nbits reference table"
            )
        elif expected_nbits != epoch_bits:
            failures.append(
                f"expected_nbits {expected_text} does not match epoch table "
                f"value {epoch_bits:08x} at epoch start {epoch_start}"
            )

    return failures


def validate_dataset(
    path: Path = ERROR_BLOCKS_CSV,
    *,
    nbits_by_epoch_path: Path = NBITS_BY_EPOCH_JSON,
    mtp_context_path: Path = ERROR_BLOCKS_MTP_CONTEXT_CSV,
    body_evidence_path: Path | None = None,
    ancestry_evidence_path: Path | None = None,
    blocks_dir: Path = ERROR_BLOCK_BODIES_DIR,
) -> list[str]:
    """Validate every catalogue row and its matching body sidecar, if required."""
    nbits_by_epoch = _load_nbits_by_epoch(nbits_by_epoch_path)
    mtp_context = _load_mtp_context(mtp_context_path)
    if body_evidence_path is None:
        body_evidence_path = path.parent / ERROR_BLOCKS_BODY_EVIDENCE_NAME
    if ancestry_evidence_path is None:
        ancestry_evidence_path = path.parent / ERROR_BLOCKS_ANCESTRY_EVIDENCE_NAME
    try:
        body_evidence = load_body_evidence(body_evidence_path)
        ancestry_evidence = load_ancestry_evidence(ancestry_evidence_path)
    except ValueError as exc:
        return [str(exc)]
    body_keys: set[tuple[int, str]] = set()
    ancestry_keys: set[tuple[int, str]] = set()
    failures: list[str] = []
    seen_keys: set[tuple[int, str]] = set()
    row_count = 0
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            row_count += 1
            row_id = f"{row.get('height', '?')}:{str(row.get('hash', ''))[-12:]}"
            if (row.get("classification") or "").strip() != "error_block":
                failures.append(f"{row_id}: classification must be error_block")
            try:
                key = (int(row["height"]), row["hash"].strip().lower())
                if key[0] < 0 or len(key[1]) != 64:
                    raise ValueError
                bytes.fromhex(key[1])
            except (KeyError, ValueError):
                # Malformed keys are reported by ``validate_row``. Duplicates
                # are checked only for a parseable identity.
                key = None
            if key is not None:
                if key in seen_keys:
                    failures.append(
                        f"{row_id}: duplicate error-block key {key} in {path}"
                    )
                seen_keys.add(key)
            if (
                key is not None
                and set(row.get("rules_violated", "").split("|"))
                & BODY_ERROR_REJECTIONS.keys()
            ):
                body_keys.add(key)
            if key is not None and CONSENSUS_INVALID_PARENT_RULE in row.get(
                "rules_violated", ""
            ).split("|"):
                ancestry_keys.add(key)
            for failure in validate_row(
                row,
                nbits_by_epoch=nbits_by_epoch,
                mtp_context=mtp_context,
                body_evidence=body_evidence,
                ancestry_evidence=ancestry_evidence,
                blocks_dir=blocks_dir,
            ):
                failures.append(f"{row_id}: {failure}")
    for unused in sorted(body_evidence.keys() - body_keys):
        failures.append(f"body evidence has no matching catalogue body rule: {unused}")
    for unused in sorted(ancestry_evidence.keys() - ancestry_keys):
        failures.append(
            f"ancestry evidence has no matching catalogue ancestry rule: {unused}"
        )
    if row_count == 0:
        # An empty catalogue would otherwise look like success.
        failures.append(f"dataset is empty (no error-block rows in {path})")
    return failures


def validate_error_module(
    *,
    catalogue_path: Path = ERROR_BLOCKS_CSV,
    ledger_path: Path | None = None,
    nbits_by_epoch_path: Path = NBITS_BY_EPOCH_JSON,
    mtp_context_path: Path = ERROR_BLOCKS_MTP_CONTEXT_CSV,
    body_evidence_path: Path | None = None,
    blocks_dir: Path = ERROR_BLOCK_BODIES_DIR,
) -> tuple[list[ErrorBlock], dict[ErrorObservationKey, dict[str, str]]]:
    """Validate consensus claims and exact witness coverage as one module."""
    if ledger_path is None:
        ledger_path = catalogue_path.parent / ERROR_OBSERVATION_LEDGER
    failures = validate_dataset(
        catalogue_path,
        nbits_by_epoch_path=nbits_by_epoch_path,
        mtp_context_path=mtp_context_path,
        body_evidence_path=body_evidence_path,
        blocks_dir=blocks_dir,
    )
    try:
        blocks, observations = validate_error_observation_ledger(
            catalogue_path=catalogue_path,
            ledger_path=ledger_path,
        )
    except (OSError, ValueError) as exc:
        failures.append(f"error-observation ledger: {exc}")
        blocks, observations = [], {}
    if failures:
        raise ErrorModuleValidationError(failures)
    return blocks, observations


def main() -> int:
    try:
        blocks, observations = validate_error_module()
    except ErrorModuleValidationError as exc:
        print(f"{exc}:")
        for failure in exc.failures:
            print(f"  {failure}")
        return 1
    print(
        f"all {len(blocks)} committed error blocks pass evidence validation "
        f"and cover {len(observations)} child observations"
    )
    return 0
