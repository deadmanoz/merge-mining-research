"""Tests for semantic reconciliation of heterogeneous coinbase outputs."""

from __future__ import annotations

import csv
import importlib.util
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from stale_blocks_analysis.coinbase_output_claims import (
    CoinbaseOutputClaim,
    coinbase_output_claims_refine,
    merge_coinbase_output_claim_sets,
    parse_coinbase_output_claims,
    render_coinbase_output_claims,
    render_coinbase_outputs_column,
)

PAYOUT_SCRIPT = "76a914fb37342f6275b13936799def06f2eb4c0f20151588ac"
NAMECOIN_P2PK_ADDRESS = "~MwSW8YTckP6AkvuSSm9SvaX4grKYJBRtxq"
NAMECOIN_P2PK_SCRIPT = (
    "4104993c2f60c28716a70abce5669f4a76f3b866e4479be7a5bc32116ba03de6"
    "4f659a60aacccb4246ea61920e9897228361c8954696b76ef039f96224332f591d74ac"
)
NAMECOIN_FILTERED_ADDRESSES = ";".join(
    (
        "~NFNFkYitbrBLQh3AdqpBp5bsvxTuiRpDKQ",
        "~NFSAhAtfTZx1Cge8dVaTAiNYMrRydtwWZe",
        "~N55Zkpxqjph3336oVoUxsGxY3q7WELPMHS",
        "~MyGT8f9nq3cZjiH2jhDk2k4JRCgo9ukjji",
        "~N6QyFaz46dapeEqW9gjKnsLdgo6xJjvySh",
        "~MwVtSyYLkQn9xN1Hfyj3pboE2C7rEXGtog",
        "~NF8BVd6rVZZaUZaLDA6AddkpAgBfEr88De",
        "~N5Uppu32TTPwso4eHpL3ibg3TXPb4g3A6p",
        "~NGciQtxGoV1jAKuksqAxeTZKT8AJgxzgge",
        "~N8fxQ5WnM17fWNLuue6e2MRY7BwZkbzuwr",
        "~N8qSzt5fkeG1GUyz8gkW2YP49wpKi5yT2Q",
        "~NHdyLVkB1Br3fojmPRHiPCgrhwgEDyYAs6",
        "~NGiScLNWmc84MnuUq3qs7E3WJYofqimevW",
        "~N7XYuD7RbFqWUW4px3bo33h7paZFRs5HkQ",
        "~MxQCkLt316zUwCe79cRigSmXRKENDCu3Zw",
        "~NAw8AX4PQPsZcjqkNaRqyR4AYiGhqrULdN",
        "~MvpvmxqpgjUS954SYJgVGa4vaDer6B5u7g",
        "~MzsrRRXTuUnDYjGRsTs6ACeHnLVYc8v69c",
        "~N2Y4Y7gtMtNezfVYQtcpE31hiH6pfNHRur",
        "~NHwDuM3RCGpV5F8BbciEyxdnX3SS75Ehqe",
        "~MxLYDXQ7utcjdvTEhdA2snxai71jiLQydB",
        "~NFCXBTqkYkK8mSXc3rMduX4kyjHuBgr2f9",
    )
)
NAMECOIN_EXACT_SCRIPTS = ";".join(
    (
        NAMECOIN_P2PK_SCRIPT,
        "76a914ce2003a0739a284a968e995a9fcc865799eb55ec88ac",
        "76a914cedd74a429273018a836fcc9fd74d1c92563262e88ac",
        "76a9145d46b6f371b8389391ad2cc29adfc2d91824fddc88ac",
        "76a9141d8501a4d186338c7aa7828ac04a458d97055bcb88ac",
        "76a9146bea5b67d6d1da7ef3d7b4231fea4c8e43f6ad8888ac",
        "76a9140a1f4b80a6f6709cc8539e0af61f9b2acfd803c488ac",
        "76a914cb76a309fa97f9b8826376c339c88d82b7caccc588ac",
        "76a91461acdc99dc928d31099f1adc76db005f6d9a5d7788ac",
        "76a914dbd43813e27f3ca6b69cfaf683ffee8238053c6688ac",
        "76a91484b022b0aa0e494e7daac3bb6f48ae52c40315d288ac",
        "76a914867bc0d72ef2405a457a4077c45b14200d3d975a88ac",
        "76a914e7093805e2b766448dabe64d639b6e0118611aae88ac",
        "76a914dce985f850dfedb5ea857cf3cb952ac094ec8c0588ac",
        "76a9147821112dad0a971b58e58125979d882d4a42177488ac",
        "76a91414043357804a8794f5073bdb88c37adcf4c1440b88ac",
        "76a9149d7ec767cea1a4f3d0de81ee223d00d91555138c88ac",
        "76a91402c103e572117d99b6c1d418b16f65f3dee5b1dc88ac",
        "76a9142f2f21afdf4d621983d6ec1a2e605c46141ccc5488ac",
        "76a91441612d65fddff0f2f82af01676f033ebaee9ce1d88ac",
        "76a914ea4c73185fb4c779ab4d869a55863102f19d567a88ac",
        "76a9141352c9ced798caf651546fbfc623d5e57955726e88ac",
        "76a914cc48bc094901e59d9f696b4d8b5c6045006bd33188ac",
    )
)
OP_RETURN_SCRIPTS = (
    "6a2773797307ced0202870aac2a4dd4b5e5a8bfae418d190b60f98b247ccc76e593171d4a374b52100",
    "6a124558534154011508000113021b1a1f120013",
    "6a2d434f52450164db24a662e20bbdf72d1cc6e973dbb2d12897d56a931d9de30a5f313a566775a135cf47d40c0ccd",
    "6a2952534b424c4f434b3af670312307f17ef8ddc2c84642a65fed05a1cdf4b2a1ffe794c71b1700841451",
    "6a24aa21a9ed348c76a1b1bfe3bd1e7ca91f5c3165bc29bffb8a480887742e14e2c0580a6e71",
)


def _coinbase_tx(
    outputs: tuple[tuple[int, str], ...], scriptsig_hex: str = "aabb"
) -> str:
    raw = bytearray.fromhex("01000000")
    raw.extend(b"\x01")
    raw.extend(b"\x00" * 32)
    raw.extend(bytes.fromhex("ffffffff"))
    scriptsig = bytes.fromhex(scriptsig_hex)
    raw.extend(bytes([len(scriptsig)]))
    raw.extend(scriptsig)
    raw.extend(bytes.fromhex("ffffffff"))
    raw.extend(bytes([len(outputs)]))
    for value_sats, script_hex in outputs:
        script = bytes.fromhex(script_hex)
        raw.extend(value_sats.to_bytes(8, "little"))
        raw.extend(bytes([len(script)]))
        raw.extend(script)
    raw.extend(b"\x00" * 4)
    return raw.hex()


def test_941882_sources_merge_amounts_with_exact_scripts() -> None:
    syscoin = parse_coinbase_output_claims(
        "SkCJmd2CqThFWqSx6CHjpgxUe2SbHwkdKj:3.13110129"
        "|OP_RETURN:0.0|OP_RETURN:0.0|OP_RETURN:0.0"
        "|OP_RETURN:0.0|OP_RETURN:0.0"
    )
    exact_scripts = parse_coinbase_output_claims(
        ";".join((PAYOUT_SCRIPT, *OP_RETURN_SCRIPTS))
    )

    merged = merge_coinbase_output_claim_sets(syscoin, exact_scripts)

    assert render_coinbase_output_claims(merged) == "|".join(
        (f"{PAYOUT_SCRIPT}:313110129", *(f"{script}:0" for script in OP_RETURN_SCRIPTS))
    )


def test_parser_accepts_legacy_and_canonical_source_forms() -> None:
    assert parse_coinbase_output_claims("51:5000000000") == (
        CoinbaseOutputClaim(0, 5_000_000_000, script_hex="51"),
    )
    # A Bitcoin address is an exact P2PKH script: the canonical rendering
    # shows P2PK as raw hex, so an address cannot stand for one.
    assert parse_coinbase_output_claims("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa:1e-08") == (
        CoinbaseOutputClaim(
            0,
            1,
            script_hex="76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
            position_exact=True,
        ),
    )
    # A child-chain rendering preserves only the hash160, because the
    # acquisition decoded it through the child node and the template behind
    # it is unknown.
    assert parse_coinbase_output_claims("~NFNFkYitbrBLQh3AdqpBp5bsvxTuiRpDKQ") == (
        CoinbaseOutputClaim(
            0,
            None,
            recipient_hash160="ce2003a0739a284a968e995a9fcc865799eb55ec",
            position_exact=False,
        ),
    )
    assert parse_coinbase_output_claims("nonstandard:0.0") == (
        CoinbaseOutputClaim(0, 0),
    )
    assert parse_coinbase_output_claims("pubkey:2.7e-07") == (
        CoinbaseOutputClaim(0, 27),
    )


def test_p2pkh_destination_claim_refines_to_matching_p2pk_or_p2pkh_script() -> None:
    address_claim = parse_coinbase_output_claims(NAMECOIN_P2PK_ADDRESS)
    exact_p2pk = parse_coinbase_output_claims(NAMECOIN_P2PK_SCRIPT)

    assert address_claim[0].recipient_hash160
    assert coinbase_output_claims_refine(address_claim, exact_p2pk)
    assert (
        render_coinbase_output_claims(
            merge_coinbase_output_claim_sets(address_claim, exact_p2pk)
        )
        == f"{NAMECOIN_P2PK_SCRIPT}:"
    )

    bitcoin_address = parse_coinbase_output_claims("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    exact_p2pkh = parse_coinbase_output_claims(
        "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac"
    )
    assert coinbase_output_claims_refine(bitcoin_address, exact_p2pkh)


def test_filtered_namecoin_addresses_refine_to_an_exact_vector_with_omissions() -> None:
    filtered = parse_coinbase_output_claims(NAMECOIN_FILTERED_ADDRESSES)
    exact_scripts = parse_coinbase_output_claims(NAMECOIN_EXACT_SCRIPTS)

    assert len(filtered) == 22
    assert len(exact_scripts) == 23
    assert all(not claim.position_exact for claim in filtered)
    assert coinbase_output_claims_refine(filtered, exact_scripts)
    assert merge_coinbase_output_claim_sets(filtered, exact_scripts) == exact_scripts

    assert not coinbase_output_claims_refine(filtered, exact_scripts[:-1])
    reordered = list(exact_scripts)
    reordered[1] = replace(exact_scripts[2], position=1)
    reordered[2] = replace(exact_scripts[1], position=2)
    assert not coinbase_output_claims_refine(filtered, tuple(reordered))
    changed_recipient = replace(
        exact_scripts[-1],
        script_hex="76a914" + "11" * 20 + "88ac",
    )
    changed = (*exact_scripts[:-1], changed_recipient)
    assert not coinbase_output_claims_refine(filtered, changed)


def test_p2pkh_destination_claim_rejects_a_different_public_key() -> None:
    address_claim = parse_coinbase_output_claims(NAMECOIN_P2PK_ADDRESS)
    different_p2pk = parse_coinbase_output_claims(NAMECOIN_P2PK_SCRIPT[:-4] + "75ac")

    assert not coinbase_output_claims_refine(address_claim, different_p2pk)
    with pytest.raises(ValueError, match="filtered output claims"):
        merge_coinbase_output_claim_sets(address_claim, different_p2pk)


def test_filtered_alignment_rejects_materially_ambiguous_value_attachment() -> None:
    recipient = "11" * 20
    script = f"76a914{recipient}88ac"
    filtered = parse_coinbase_output_claims(f"~pkh({recipient}):10")
    exact_without_values = parse_coinbase_output_claims(f"{script}:|{script}:")

    with pytest.raises(ValueError, match="materially ambiguous alignments"):
        merge_coinbase_output_claim_sets(filtered, exact_without_values)

    exact_same_values = parse_coinbase_output_claims(f"{script}:10|{script}:10")
    assert merge_coinbase_output_claim_sets(filtered, exact_same_values) == (
        CoinbaseOutputClaim(0, 10, script_hex=script),
        CoinbaseOutputClaim(1, 10, script_hex=script),
    )


def test_parser_decodes_real_syscoin_bech32_adapter_input() -> None:
    claims = parse_coinbase_output_claims(
        "sys1qf274x7penhcd8hsv3jcmwa5xxzjl2a6p44su3f:6.82882226"
    )

    assert claims == (
        CoinbaseOutputClaim(
            0,
            682_882_226,
            script_hex="00144abd5378399df0d3de0c8cb1b7768630a5f57741",
        ),
    )


def test_full_coinbase_refines_partial_output_claims() -> None:
    full_coinbase = _coinbase_tx(((0, "6a01ff"),))

    claims = parse_coinbase_output_claims("OP_RETURN:0.0", full_coinbase)

    assert claims == (CoinbaseOutputClaim(0, 0, script_hex="6a01ff"),)
    assert render_coinbase_output_claims(claims) == "6a01ff:0"


@pytest.mark.parametrize(
    ("left", "right", "message"),
    [
        (
            CoinbaseOutputClaim(0, 1, script_hex="51"),
            CoinbaseOutputClaim(0, 2, script_hex="51"),
            "conflicting values",
        ),
        (
            CoinbaseOutputClaim(0, 1, script_hex="51"),
            CoinbaseOutputClaim(0, 1, script_hex="52"),
            "conflicting scripts",
        ),
        (
            CoinbaseOutputClaim(0, 0, script_prefix_hex="6a"),
            CoinbaseOutputClaim(0, 0, script_prefix_hex="76"),
            "conflicting script prefixes",
        ),
    ],
)
def test_merge_rejects_incompatible_claims(
    left: CoinbaseOutputClaim, right: CoinbaseOutputClaim, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        merge_coinbase_output_claim_sets((left,), (right,))


def test_refinement_preserves_partial_claims_and_rejects_loss() -> None:
    committed = ":313110129|6a*:0"
    staged = f"{PAYOUT_SCRIPT}:313110129|{OP_RETURN_SCRIPTS[0]}:0|51:1"

    assert coinbase_output_claims_refine(committed, staged)
    assert not coinbase_output_claims_refine(staged, committed)
    assert not coinbase_output_claims_refine("6a*:0", "76a91400:0")


def test_canonical_render_round_trips_positions_and_partial_claims() -> None:
    claims = (
        CoinbaseOutputClaim(0, 10),
        CoinbaseOutputClaim(2, script_hex="51"),
        CoinbaseOutputClaim(3, 0, script_prefix_hex="6a"),
        CoinbaseOutputClaim(4, recipient_hash160="11" * 20),
    )

    rendered = render_coinbase_output_claims(claims)

    assert rendered == ":10||51:|6a*:0|pkh(" + "11" * 20 + "):"
    assert parse_coinbase_output_claims(rendered) == claims

    filtered = (
        CoinbaseOutputClaim(0, recipient_hash160="22" * 20, position_exact=False),
    )
    filtered_rendered = render_coinbase_output_claims(filtered)
    assert filtered_rendered == "~pkh(" + "22" * 20 + "):"
    assert parse_coinbase_output_claims(filtered_rendered) == filtered


def _load_prep_script(name: str):
    """Import a scripts/prep module by path (they are not a package)."""
    path = Path(__file__).resolve().parents[1] / "scripts" / "prep" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"{name}_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_committed_coinbase_outputs_are_canonically_rendered() -> None:
    """Every committed `coinbase_outputs` entry follows the one contract.

    The column records BTC parent coinbase payouts, but each acquisition path
    once rendered it differently (raw script hex, Bitcoin addresses, and the
    *child* chain's base58/bech32 for Namecoin and Syscoin). The normalizer
    collapsed those onto a single rendering; this pins it so a new extractor
    or a hand edit cannot reintroduce the drift.
    """
    module = _load_prep_script("normalize_coinbase_outputs")
    offenders: list[str] = []
    for path in module.target_files():
        with path.open(newline="") as handle:
            for row in csv.DictReader(handle):
                cell = row.get("coinbase_outputs") or ""
                offenders.extend(module.cell_problems(path, cell))
    assert offenders[:5] == [], f"{len(offenders)} non-canonical entries"


def test_amountless_script_prefix_round_trips() -> None:
    """The renderer's amount-less prefix form parses back to the same claim.

    ``render_coinbase_outputs_column`` emits a prefix claim without an amount
    as ``6a*`` (no value delimiter, symmetric with bare script hex), so the
    parser must accept that form or legitimate prefix-only evidence would
    fail canonical validation at publication.
    """
    claim = CoinbaseOutputClaim(0, script_prefix_hex="6a")
    rendered = render_coinbase_outputs_column((claim,))
    assert rendered == "6a*"
    [parsed] = parse_coinbase_output_claims(rendered)
    assert parsed == claim
    assert render_coinbase_outputs_column((parsed,)) == rendered


def test_child_decoded_addresses_parse_recipient_only() -> None:
    """The decode flag demotes even version-0 addresses to recipient claims.

    A child node's decode renders a P2PK output as the P2PKH-form address of
    its pubkey's hash160, so an address from such a cell cannot assert the
    exact script; a P2SH address stays exact because only a P2SH script
    derives it, and raw script hex is unaffected by the flag.
    """
    addr_cell = "134vPp664VcocqouZeuSMZaXfquFyRLfQG:15.70929643"
    [exact] = parse_coinbase_output_claims(addr_cell)
    assert exact.script_hex == ("76a91416ae11e7b47ba05a3e495ce47f16b9ab95c3551488ac")
    [demoted] = parse_coinbase_output_claims(addr_cell, child_decoded_addresses=True)
    assert demoted.script_hex == ""
    assert demoted.recipient_hash160 == "16ae11e7b47ba05a3e495ce47f16b9ab95c35514"
    assert demoted.value_sats == 1570929643
    assert demoted.position_exact

    p2sh = "3P14159f73E4gFr7JterCCQh9QjiTjiZrG"
    [p2sh_claim] = parse_coinbase_output_claims(p2sh, child_decoded_addresses=True)
    assert p2sh_claim.script_hex.startswith("a914")

    script = "76a914" + "ab" * 20 + "88ac"
    [raw_claim] = parse_coinbase_output_claims(script, child_decoded_addresses=True)
    assert raw_claim.script_hex == script


def test_legacy_type_labels_parse_as_prefix_or_amount_claims() -> None:
    """Legacy RPC ``type:value`` placeholders keep their slots and evidence.

    Template types imply a script prefix, which carries more than the
    amount; ``multisig`` and ``witness_unknown`` have no fixed prefix and
    establish only the amount. The label text itself survives in the
    archived cell.
    """
    claims = parse_coinbase_output_claims(
        "pubkeyhash:15.70929643|pubkey:1e-08|OP_RETURN:0.0"
    )
    assert [
        (claim.position, claim.value_sats, claim.script_prefix_hex) for claim in claims
    ] == [(0, 1570929643, "76a914"), (1, 1, ""), (2, 0, "6a")]
    [scripthash] = parse_coinbase_output_claims("scripthash:0.0")
    assert scripthash.script_prefix_hex == "a914"
    [multisig] = parse_coinbase_output_claims("multisig:0.0")
    assert (multisig.value_sats, multisig.script_prefix_hex) == (0, "")
    [witness] = parse_coinbase_output_claims("witness_unknown:1e-08")
    assert (witness.value_sats, witness.script_prefix_hex) == (1, "")


def test_normalizer_preserves_leading_output_gaps() -> None:
    """A leading empty slot survives the rewrite and the checker.

    The column renderer emits a leading gap for a vector whose first output
    carries no evidence, so treating it as separator noise would renumber
    every later payout while ``--check`` stayed green.
    """
    module = _load_prep_script("normalize_coinbase_outputs")
    path = Path("terracoin_validated_stales.csv")
    assert module.split_entries(";51:8") == ["", "51:8"]
    assert module.rewrite_cell(";51:8") == ";51:8"
    assert module.cell_problems(path, ";51:8") == []
    [claim] = parse_coinbase_output_claims(";51:8")
    assert claim.position == 1
