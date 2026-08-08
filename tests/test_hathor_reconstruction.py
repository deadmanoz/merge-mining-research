from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from stale_blocks_analysis import stale_blocks
from stale_blocks_analysis.btc_nbits_validation import NBITS_MISMATCH_PREFIX
from stale_blocks_analysis.btc_stale_validation import PLACEMENT_REJECTION
from stale_blocks_analysis.config import BIP66_HEIGHT


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "classify"
    / "classify_hathor_stales.py"
)
SPEC = importlib.util.spec_from_file_location("classify_hathor_stales", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
hathor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hathor)

PHASE_C_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "classify"
    / "classify_hathor_phase_c.py"
)
PHASE_C_SPEC = importlib.util.spec_from_file_location(
    "classify_hathor_phase_c", PHASE_C_SCRIPT
)
assert PHASE_C_SPEC is not None and PHASE_C_SPEC.loader is not None
hathor_phase_c = importlib.util.module_from_spec(PHASE_C_SPEC)
PHASE_C_SPEC.loader.exec_module(hathor_phase_c)

PHASE_B_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "classify"
    / "classify_hathor_phase_b.py"
)
PHASE_B_SPEC = importlib.util.spec_from_file_location(
    "classify_hathor_phase_b", PHASE_B_SCRIPT
)
assert PHASE_B_SPEC is not None and PHASE_B_SPEC.loader is not None
hathor_phase_b = importlib.util.module_from_spec(PHASE_B_SPEC)
PHASE_B_SPEC.loader.exec_module(hathor_phase_b)


RFC_BLOCK_HASH = "00000000000000001edcb1b01154f8df97199f5fd936d8e7d553d76d01abec3c"

RFC_FUNDS = "0003010000190000001976a914bcdddee6f042c73ff4b947bc9bca929fbd4fa98588ac"
RFC_GRAPH = (
    "404dea2b25737540"
    "5ef3846b"
    "03"
    "000000000000000eab4934332c22f5db57ce7276cc76304384979ff861a5ff5a"
    "000000000706cc3cfe08ea41eb25b22d170193a8dfc0335cf3983d97f70ddbe0"
    "000000009ff1ea03f91bb20e6b2fc55bcd1f46d0564849641adb6c51f1dc6f4b"
    "00"
)
RFC_HEADER_HEAD = (
    "000000202f6636c625e1303fffbd016104041dc1e9ca1452109404000000000000000000"
)
RFC_COINBASE_HEAD = (
    "010000000001010000000000000000000000000000000000000000000000000000000000"
    "000000ffffffff33fe05b5090048617468"
)
RFC_COINBASE_TAIL = (
    "9cf38114100000000000ffffffff0140cd4f260000000016a9c384cd403c314e857d68dc"
    "96093c45914c4bbc60870120000000000000000000000000000000000000000000000000"
    "000000000000000000000000"
)
RFC_MERKLE_PATH = [
    "78d994a5f520c138408abcb2665aa39df1bbcde26aa13cce9775276371c09d22",
    "759c3d2229ea39c7740fbffdf299efaf544f5382099e9dec63b9fbdb83f141b6",
    "1c00ad5025f5d3ebb15365d42e4acb8654db3a06ace7d638be146c9ba5e5239f",
    "64efed174ad8651e05669c15ec258fd31cd1ff79927d2476b59aad5a52cf1f32",
    "2b70e3bbddb58e474402e2504c5ce13bb408d0c5066186f5796b38522cc0b9ee",
    "0965361770473985e6d7ba3417274821245898f13cd3c785a1c3cfbddb0357e4",
    "8ac9da66991f8b12cbc51fdd47768c930dde106a95672dcfb55adef505f1bdc8",
    "7c6cec9c7e548007d642495226cb0746e5500dee273bed8c40036bef13f7d671",
    "6c221b75f9904d37ed5b55e829ebe23a447847d31d33b645c8787a9eeb9f7195",
    "a845b78e5a86ede4c5591c0d741fe889a347dfba8345a6dde9e65427727c65cd",
    "0d56f17e358542cfeb3f4702e1d9f0e0e1d24e9f3a632c7b245e6311d96f1a29",
    "113709424b0f60dcc6e7e0263815792d13d53b09452db4d672d26c4d2f0dbfe2",
]
RFC_HEADER_TAIL = "6c84f35ef2d4111798bc21ca"


def rfc_aux_pow_hex() -> str:
    return (
        RFC_HEADER_HEAD
        + "35"
        + RFC_COINBASE_HEAD
        + "54"
        + RFC_COINBASE_TAIL
        + "0c"
        + "".join(RFC_MERKLE_PATH)
        + RFC_HEADER_TAIL
    )


def serialized_header(
    *, previous_hash: str = "00" * 32, timestamp: int = 1_000, bits: int = 0x170FFFFF
) -> bytes:
    return (
        (4).to_bytes(4, "little")
        + bytes.fromhex(previous_hash)[::-1]
        + b"\x00" * 32
        + timestamp.to_bytes(4, "little")
        + bits.to_bytes(4, "little")
        + (1).to_bytes(4, "little")
    )


def test_hathor_rfc_0006_reconstruction_vector() -> None:
    parsed = hathor.parse_aux_pow(rfc_aux_pow_hex())
    assert parsed is not None

    funds = bytes.fromhex(RFC_FUNDS)
    graph = bytes.fromhex(RFC_GRAPH)
    expected_aux_block_hash = hathor.sha256d(
        hathor.sha256(funds) + hathor.sha256(graph)
    )[::-1]
    reconstructed = hathor.reconstruct(
        parsed,
        funds + graph,
        RFC_BLOCK_HASH,
    )
    assert reconstructed is not None

    header, coinbase, split = reconstructed
    assert split == len(funds)
    assert expected_aux_block_hash in coinbase
    assert hathor.sha256d(header)[::-1].hex() == RFC_BLOCK_HASH


def test_hathor_phase_c_requires_parent_height_and_exact_bip34_prefix() -> None:
    height = 700_000
    prefix = b"\x03" + height.to_bytes(3, "little")
    valid_row = {
        "btc_parent_height": str(height - 1),
        "btc_parent_mediantime": "999",
        "btc_time": "1000",
        "btc_header_hex": (b"\x04\x00\x00\x00" + b"\x00" * 76).hex(),
        "validation_status": "VALID",
    }

    assert hathor_phase_c.resolved_height_and_status(valid_row, prefix.hex()) == (
        height,
        "VALID",
    )
    assert hathor_phase_c.resolved_height_and_status(
        valid_row, (b"\x4c\x03" + height.to_bytes(3, "little")).hex()
    )[1].startswith("REJECTED: BIP34")
    assert hathor_phase_c.resolved_height_and_status(
        {"btc_parent_height": "", "validation_status": "VALID"}, prefix.hex()
    ) == ("", "REJECTED: missing canonical parent height")


def test_hathor_phase_c_enforces_historical_minimum_block_version() -> None:
    height = BIP66_HEIGHT
    row = {
        "btc_parent_height": str(height - 1),
        "btc_parent_mediantime": "999",
        "btc_time": "1000",
        "btc_header_hex": (b"\x02\x00\x00\x00" + b"\x00" * 76).hex(),
        "validation_status": "VALID",
    }
    scriptsig = (b"\x03" + height.to_bytes(3, "little")).hex()

    assert (
        "required 3 after BIP66"
        in hathor_phase_c.resolved_height_and_status(row, scriptsig)[1]
    )


def test_hathor_phase_b_verdicts_mirror_the_shared_vocabulary() -> None:
    """Phase B duplicates the shared verdict strings; Phase C accepts both.

    Phase B is import-free by design, so its verdict literals are copies that
    can drift. Pin them against the named originals, and pin Phase C's
    normalization of the pre-rename tokens archived intermediates still carry.
    """
    assert hathor_phase_b.PLACEMENT_REJECTION == PLACEMENT_REJECTION
    assert hathor_phase_b.NBITS_MISMATCH_PREFIX == NBITS_MISMATCH_PREFIX
    assert hathor_phase_b.PARENT_CONTEXT_UNKNOWN.startswith("UNKNOWN:")

    scriptsig = (b"\x03" + (700_000).to_bytes(3, "little")).hex()
    legacy = {"btc_parent_height": "699999"}

    assert hathor_phase_c.resolved_height_and_status(
        {**legacy, "validation_status": "PARENT_NOT_CANONICAL"}, scriptsig
    ) == (700_000, PLACEMENT_REJECTION)
    assert hathor_phase_c.resolved_height_and_status(
        {**legacy, "validation_status": "NBITS_MISMATCH"}, scriptsig
    ) == (700_000, NBITS_MISMATCH_PREFIX)
    assert hathor_phase_c.resolved_height_and_status(
        {**legacy, "validation_status": "PARENT_CONTEXT_UNAVAILABLE"}, scriptsig
    ) == ("", hathor_phase_b.PARENT_CONTEXT_UNKNOWN)


def test_hathor_phase_b_rejects_malformed_reconstructed_header() -> None:
    row = {
        "btc_header_hex": "00",
        "btc_prev_hash": "00" * 32,
        "btc_time": "1000",
        "btc_bits": "170fffff",
    }

    with pytest.raises(ValueError, match="expected 80"):
        hathor_phase_b.process_row(row, object())


def test_hathor_phase_b_rpc_mismatch_cannot_validate_stale() -> None:
    parent_header = serialized_header(timestamp=900)
    parent_hash = hathor_phase_b.sha256d(parent_header)[::-1].hex()
    requested_canonical_hash = "11" * 32

    class FakeRPC:
        def call(self, method, params=None):
            if method == "getblockheader" and params == [parent_hash, True]:
                return {
                    "hash": parent_hash,
                    "height": 699_999,
                    "confirmations": 100,
                    "bits": "170fffff",
                    "previousblockhash": "00" * 32,
                    "time": 900,
                    "mediantime": 899,
                }
            if method == "getblockheader" and params == [parent_hash, False]:
                return parent_header.hex()
            if method == "getblockhash" and params == [700_000]:
                return requested_canonical_hash
            if method == "getblockheader" and params == [
                requested_canonical_hash,
                True,
            ]:
                return {"hash": "22" * 32}
            raise AssertionError((method, params))

    assert hathor_phase_b.validate_stale(
        {"btc_prev_hash": parent_hash, "btc_bits": "170fffff"}, FakeRPC()
    ) == (699_999, 899, "", hathor_phase_b.PARENT_CONTEXT_UNKNOWN)


def test_hathor_phase_b_preserves_output_on_worker_failure(
    tmp_path, monkeypatch
) -> None:
    input_path = tmp_path / "phase_a.csv"
    output_path = tmp_path / "phase_b.csv"
    phase_a_columns = hathor_phase_b.OUTPUT_COLUMNS[:10]
    input_path.write_text(
        ",".join(phase_a_columns)
        + "\n"
        + ",".join(["1", "", "", "00" * 32, "1000", "170fffff", "1", "00", "", "true"])
        + "\n"
    )
    output_path.write_text("existing output\n")

    class ProbeOnlyRPC:
        def __init__(self, *_args, **_kwargs):
            pass

        def call(self, method, params=None):
            assert method == "getblockcount"
            return 1

    monkeypatch.setattr(hathor_phase_b, "BitcoinRPC", ProbeOnlyRPC)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(PHASE_B_SCRIPT),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--workers",
            "1",
        ],
    )

    with pytest.raises(ValueError, match="expected 80"):
        hathor_phase_b.main()
    assert output_path.read_text() == "existing output\n"


def test_hathor_phase_b_preserves_output_on_none_result(tmp_path, monkeypatch) -> None:
    input_path = tmp_path / "phase_a.csv"
    output_path = tmp_path / "phase_b.csv"
    phase_a_columns = hathor_phase_b.OUTPUT_COLUMNS[:10]
    input_path.write_text(
        ",".join(phase_a_columns)
        + "\n"
        + ",".join(["", "", "", "", "", "", "", "", "", "true"])
        + "\n"
    )
    output_path.write_text("existing output\n")

    class ProbeOnlyRPC:
        def __init__(self, *_args, **_kwargs):
            pass

        def call(self, method, params=None):
            assert method == "getblockcount"
            return 1

    monkeypatch.setattr(hathor_phase_b, "BitcoinRPC", ProbeOnlyRPC)
    monkeypatch.setattr(hathor_phase_b, "process_row", lambda _row, _rpc: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(PHASE_B_SCRIPT),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--workers",
            "1",
        ],
    )

    with pytest.raises(RuntimeError, match="returned no result"):
        hathor_phase_b.main()
    assert output_path.read_text() == "existing output\n"


def test_hathor_phase_b_preserves_output_on_unavailable_validation(
    tmp_path, monkeypatch
) -> None:
    input_path = tmp_path / "phase_a.csv"
    output_path = tmp_path / "phase_b.csv"
    phase_a_columns = hathor_phase_b.OUTPUT_COLUMNS[:10]
    input_path.write_text(
        ",".join(phase_a_columns)
        + "\n"
        + ",".join(["", "", "", "", "", "", "", "", "", "true"])
        + "\n"
    )
    output_path.write_text("existing output\n")

    class ProbeOnlyRPC:
        def __init__(self, *_args, **_kwargs):
            pass

        def call(self, method, params=None):
            assert method == "getblockcount"
            return 1

    unavailable_row = {column: "" for column in hathor_phase_b.OUTPUT_COLUMNS}
    unavailable_row.update(
        {
            "classification": "stale",
            "validation_status": hathor_phase_b.PARENT_CONTEXT_UNKNOWN,
        }
    )
    monkeypatch.setattr(hathor_phase_b, "BitcoinRPC", ProbeOnlyRPC)
    monkeypatch.setattr(
        hathor_phase_b, "process_row", lambda _row, _rpc: unavailable_row
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(PHASE_B_SCRIPT),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--workers",
            "1",
        ],
    )

    with pytest.raises(RuntimeError, match="validation context is incomplete"):
        hathor_phase_b.main()
    assert output_path.read_text() == "existing output\n"


def test_hathor_phase_c_preserves_output_on_coinbase_parse_failure(
    tmp_path, monkeypatch
) -> None:
    input_path = tmp_path / "phase_b.csv"
    output_path = tmp_path / "validated.csv"
    columns = sorted(hathor_phase_c.PHASE_B_REQUIRED_COLUMNS)
    values = {column: "" for column in columns}
    values.update({"classification": "stale", "full_coinbase_hex": "not-hex"})
    input_path.write_text(
        ",".join(columns) + "\n" + ",".join(values[column] for column in columns) + "\n"
    )
    output_path.write_text("existing output\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(PHASE_C_SCRIPT),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(ValueError, match="invalid coinbase hex"):
        hathor_phase_c.main()
    assert output_path.read_text() == "existing output\n"


def test_hathor_phase_c_preserves_output_on_unavailable_validation(
    tmp_path, monkeypatch
) -> None:
    input_path = tmp_path / "phase_b.csv"
    output_path = tmp_path / "validated.csv"
    columns = sorted(hathor_phase_c.PHASE_B_REQUIRED_COLUMNS)
    values = {column: "" for column in columns}
    values.update(
        {
            "classification": "stale",
            "full_coinbase_hex": "00",
            # Deliberately the pre-rename token: an archived Phase B
            # intermediate must still abort the run, not slip through.
            "validation_status": "PARENT_CONTEXT_UNAVAILABLE",
        }
    )
    input_path.write_text(
        ",".join(columns) + "\n" + ",".join(values[column] for column in columns) + "\n"
    )
    output_path.write_text("existing output\n")
    monkeypatch.setattr(
        hathor_phase_c,
        "parse_coinbase_tx",
        lambda _raw: {"scriptsig": b"\x01\x01", "outputs": []},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(PHASE_C_SCRIPT),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(RuntimeError, match="validation context is incomplete"):
        hathor_phase_c.main()
    assert output_path.read_text() == "existing output\n"


def test_hathor_loader_requires_valid_validation_status(tmp_path, monkeypatch) -> None:
    csv_path = tmp_path / "hathor_validated_stales.csv"
    csv_path.write_text(
        "\n".join(
            [
                "btc_height,btc_header_hash,btc_prev_hash,btc_time,btc_bits,"
                "coinbase_scriptsig_hex,coinbase_outputs,btc_header_hex,"
                "hathor_height,classification,validation_status,expected_nbits",
                "700000,validhash,prev,1,170fffff,03a00a00,,00,1,stale,VALID,170fffff",
                "700001,badhash,prev,1,170fffff,03a10a00,,00,2,stale,NBITS_MISMATCH,170fffff",
                "700002,oldschemahash,prev,1,170fffff,03a20a00,,00,3,stale,,",
            ]
        )
        + "\n"
    )
    monkeypatch.setattr(stale_blocks, "HATHOR_CSV", csv_path)

    rows = stale_blocks.load_hathor_stales(min_height=0)

    assert [row["hash"] for row in rows] == ["validhash"]


def test_fractal_loader_requires_valid_validation_status(tmp_path, monkeypatch) -> None:
    csv_path = tmp_path / "fractal_validated_stales.csv"
    csv_path.write_text(
        "\n".join(
            [
                "btc_height,btc_header_hash,btc_prev_hash,btc_time,btc_bits,"
                "coinbase_scriptsig_hex,coinbase_outputs,btc_header_hex,"
                "fb_height,classification,validation_status,expected_nbits",
                "900000,validhash,prev,1,170fffff,03a00a00,,00,1,stale,VALID,170fffff",
                "900001,badhash,prev,1,170fffff,03a10a00,,00,2,stale,REJECTED_NBITS,170fffff",
                "900002,oldschemahash,prev,1,170fffff,03a20a00,,00,3,stale,,",
            ]
        )
        + "\n"
    )
    monkeypatch.setattr(stale_blocks, "FRACTAL_CSV", csv_path)

    rows = stale_blocks.load_fractal_stales(min_height=0)

    assert [row["hash"] for row in rows] == ["validhash"]
