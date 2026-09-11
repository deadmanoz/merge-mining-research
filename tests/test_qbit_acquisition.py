"""Acquisition failure gates, independent of proof parsing fixtures."""

import json
import gzip

import pytest

from stale_blocks_analysis import qbit_acquisition as acquisition
from stale_blocks_analysis.qbit import GENESIS

END = "11" * 32


def test_digest_supports_python_310(tmp_path, monkeypatch):
    monkeypatch.delattr(acquisition.hashlib, "file_digest", raising=False)
    data = b"qbit" * 300_000
    path = tmp_path / "capture"
    path.write_bytes(data)
    assert acquisition.digest(path) == acquisition.hashlib.sha256(data).hexdigest()


class Node:
    inventory = []

    def __init__(self, *, missing=False, reorg=False):
        self.missing = missing
        self.reorg = reorg
        self.endpoint_reads = 0

    def batch(self, method, params):
        if method == "getblockchaininfo":
            return [{"chain": "main", "pruned": False, "blocks": 1}]
        if method == "getblockhash":
            if params == [[0], [1]]:
                self.endpoint_reads += 1
                if self.reorg and self.endpoint_reads == 3:
                    return [GENESIS, "22" * 32]
            return [GENESIS if p[0] == 0 else END for p in params]
        if self.missing:
            return ["00"]
        if params[0][1] == 1:
            return [
                {"height": h, "hash": block_hash, "confirmations": 1}
                for h, block_hash in enumerate((GENESIS, END))
            ]
        return ["00", "01"]


@pytest.fixture
def parsed_blocks(monkeypatch):
    def parse(raw, *, height, expected_hash):
        return {
            "header": {"prev_hash": "0" * 64 if height == 0 else GENESIS},
            "mining_class": "direct",
        }

    monkeypatch.setattr(acquisition, "parse_block", parse)


def test_complete_coverage_and_no_fabricated_parent(tmp_path, parsed_blocks):
    result = acquisition.acquire(Node(), tmp_path, height=1, block_hash=END)
    assert result["status"] == "COMPLETE"
    assert result["counts"] == {
        "blocks": 2,
        "direct": 2,
        "auxpow": 0,
        "parent_self_pow": 0,
    }
    assert len((tmp_path / "qbit_auxpow.csv").read_text().splitlines()) == 1
    assert result["unique_parent_headers"] == 0
    with pytest.raises(ValueError, match="fresh"):
        acquisition.acquire(Node(), tmp_path, height=1, block_hash=END)


@pytest.mark.parametrize(
    "node,reason",
    [(Node(missing=True), "missing Qbit heights"), (Node(reorg=True), "reorganised")],
)
def test_missing_height_or_reorg_never_seals(tmp_path, parsed_blocks, node, reason):
    with pytest.raises(ValueError, match=reason):
        acquisition.acquire(node, tmp_path, height=1, block_hash=END)
    assert (
        json.loads((tmp_path / "acquisition.json").read_text())["status"]
        == "INCOMPLETE"
    )


def test_broken_predecessor_never_seals(tmp_path, monkeypatch):
    monkeypatch.setattr(
        acquisition,
        "parse_block",
        lambda *a, **kw: {"header": {"prev_hash": "33" * 32}, "mining_class": "direct"},
    )
    with pytest.raises(ValueError, match="predecessor edge"):
        acquisition.acquire(Node(), tmp_path, height=1, block_hash=END)
    assert (
        json.loads((tmp_path / "acquisition.json").read_text())["status"]
        == "INCOMPLETE"
    )


@pytest.mark.parametrize("ids", [[True], [1], [0, 0], []])
def test_rpc_bad_id_sets_fail_closed_and_retain_responses(tmp_path, monkeypatch, ids):
    cookie = tmp_path / "cookie"
    cookie.write_text("private-user:private-password")
    rpc = acquisition.RecordedRPC("http://unused", cookie, tmp_path / "rpc")
    payload = json.dumps([{"id": i, "result": "value"} for i in ids]).encode()

    class Response:
        content = payload

        def raise_for_status(self):
            pass

    monkeypatch.setattr(rpc.session, "post", lambda *a, **kw: Response())
    monkeypatch.setattr(acquisition.time, "sleep", lambda *_: None)
    with pytest.raises(RuntimeError, match="exhausted retries"):
        rpc.batch("getblockhash", [[0]])
    assert not rpc.inventory
    captures = list((tmp_path / "rpc").glob("*.gz"))
    assert len(captures) == 4
    assert all(gzip.decompress(p.read_bytes()) == payload for p in captures)
    assert "private-password" not in (tmp_path / "rpc/000000-request.json").read_text()


def test_rpc_response_order_is_not_identity(tmp_path, monkeypatch):
    cookie = tmp_path / "cookie"
    cookie.write_text("user:password")
    rpc = acquisition.RecordedRPC("http://unused", cookie, tmp_path / "rpc")

    class Response:
        content = b'[{"id":1,"result":"second"},{"id":0,"result":"first"}]'

        def raise_for_status(self):
            pass

    monkeypatch.setattr(rpc.session, "post", lambda *a, **kw: Response())
    assert rpc.batch("getblockhash", [[0], [1]]) == ["first", "second"]
    entry = rpc.inventory[0]
    assert (
        acquisition.digest(tmp_path / "rpc" / entry["response"])
        == entry["response_sha256"]
    )


@pytest.fixture
def captured_call(tmp_path):
    source = tmp_path / "source"
    rpcdir = source / "rpc"
    rpcdir.mkdir(parents=True)
    request = rpcdir / "request.json"
    request.write_text(
        json.dumps(
            [{"jsonrpc": "2.0", "id": 0, "method": "getblockhash", "params": [0]}]
        )
    )
    payload = json.dumps([{"id": 0, "result": GENESIS, "error": None}]).encode()
    response = rpcdir / "response.json.gz"
    response.write_bytes(gzip.compress(payload, mtime=0))
    (source / "coverage.csv").write_text("retained original")
    entry = {
        "request": request.name,
        "response": response.name,
        "request_sha256": acquisition.digest(request),
        "response_sha256": acquisition.digest(response),
        "decoded_response_sha256": acquisition.hashlib.sha256(payload).hexdigest(),
    }
    receipt = {
        "status": "COMPLETE",
        "source_revision": acquisition.SOURCE_REVISION,
        "genesis": GENESIS,
        "files": {"coverage.csv": acquisition.digest(source / "coverage.csv")},
        "capture_files": {p.name: acquisition.digest(p) for p in rpcdir.iterdir()},
        "rpc_inventory": [entry],
    }
    (source / "acquisition.json").write_text(json.dumps(receipt))
    return source


def test_captured_rpc_authenticates_order_and_preserves_source(tmp_path, captured_call):
    replay = acquisition.CapturedRPC(captured_call, tmp_path / "copy")
    with pytest.raises(ValueError, match="call order"):
        replay.batch("getblockhash", [[1]])
    assert replay.batch("getblockhash", [[0]]) == [GENESIS]
    assert (captured_call / "coverage.csv").read_text() == "retained original"


def test_captured_rpc_rejects_modified_bytes(tmp_path, captured_call):
    (captured_call / "rpc/request.json").write_text("[]")
    with pytest.raises(ValueError, match="digest mismatch"):
        acquisition.CapturedRPC(captured_call, tmp_path / "copy")
    assert not (tmp_path / "copy").exists()
