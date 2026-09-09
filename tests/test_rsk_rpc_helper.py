"""Exercise the RSK shell helper without making network requests."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


HELPER = Path(__file__).resolve().parents[1] / "node-infra/rsk/rsk-rpc.sh"
pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="jq is required")


@pytest.fixture
def run_helper(tmp_path):
    """Capture curl's JSON request and return a caller-selected RPC response."""
    curl = tmp_path / "curl"
    curl.write_text(
        '#!/bin/sh\nset -eu\nwhile [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = --data ]; then\n'
        '    shift\n    printf "%s" "$1" > "$RPC_TEST_REQUEST"\n'
        '  fi\n  shift\ndone\nprintf "%s" "$RPC_TEST_RESPONSE"\n'
    )
    curl.chmod(0o755)
    request = tmp_path / "request.json"

    def invoke(*args, response='{"result":null}'):
        env = {
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "RPC_TEST_REQUEST": str(request),
            "RPC_TEST_RESPONSE": response,
        }
        result = subprocess.run(
            ["sh", str(HELPER), "eth_test", *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return result, json.loads(request.read_text()) if request.exists() else None

    return invoke


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ([], []),
        (["null", "false", "42"], [None, False, 42]),
        (
            ['"space value"', '{"tag":"x value"}', "[1,2]"],
            ["space value", {"tag": "x value"}, [1, 2]],
        ),
        (['"--flag"', '"line\\nvalue"'], ["--flag", "line\nvalue"]),
    ],
)
def test_preserves_one_json_value_per_argument(run_helper, args, expected):
    result, request = run_helper(*args)
    assert result.returncode == 0, result.stderr
    assert request == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_test",
        "params": expected,
    }
    assert result.stdout == "null\n"


@pytest.mark.parametrize("value", ["", " ", "1 2", "null\nfalse", "{", "--flag"])
def test_rejects_invalid_parameter_before_request(run_helper, value):
    result, request = run_helper(value)
    assert result.returncode != 0
    assert request is None


@pytest.mark.parametrize("response", ['{"error":{"code":-1}}', "{}"])
def test_rejects_rpc_error_or_missing_result(run_helper, response):
    result, request = run_helper(response=response)
    assert request is not None
    assert result.returncode != 0
    assert result.stderr
