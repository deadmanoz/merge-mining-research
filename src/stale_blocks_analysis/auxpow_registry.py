"""Curated AuxPoW child-chain registry.

The registry is intentionally data-only.  It gives the chain-ID inference
helpers a stable set of known child-chain IDs without coupling them to the
stale-block loaders or documentation tables.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SlotEnforcement = Literal["consensus", "advisory", "unknown", "out_of_scope"]


@dataclass(frozen=True)
class AuxPoWChain:
    slug: str
    display_name: str
    chain_id: int
    activation_date: str
    slot_enforcement: SlotEnforcement
    scope_notes: str


CHAINS: tuple[AuxPoWChain, ...] = (
    AuxPoWChain(
        slug="namecoin",
        display_name="Namecoin",
        chain_id=1,
        activation_date="2011-10-08",
        slot_enforcement="consensus",
        scope_notes="Original Namecoin-style AuxPoW chain.",
    ),
    AuxPoWChain(
        slug="geistgeld",
        display_name="GeistGeld",
        chain_id=0,
        activation_date="2011-10-08",
        slot_enforcement="advisory",
        scope_notes="Default/configurable chain ID (-OurChainID, default 0); catalogue date excludes pre-production experimental activity.",
    ),
    AuxPoWChain(
        slug="i0coin",
        display_name="i0coin",
        chain_id=2,
        activation_date="2011-12-20",
        slot_enforcement="consensus",
        scope_notes="Namecoin-family SHA-256d AuxPoW.",
    ),
    AuxPoWChain(
        slug="ixcoin",
        display_name="ixcoin",
        chain_id=3,
        activation_date="2011-12-31",
        slot_enforcement="consensus",
        scope_notes="Namecoin-family SHA-256d AuxPoW.",
    ),
    AuxPoWChain(
        slug="coiledcoin",
        display_name="CoiledCoin",
        chain_id=16,
        activation_date="2012-01-05",
        slot_enforcement="consensus",
        scope_notes="Namecoin-family chain; numeric ID collides with current Syscoin.",
    ),
    AuxPoWChain(
        slug="devcoin",
        display_name="Devcoin",
        chain_id=4,
        activation_date="2012-01-07",
        slot_enforcement="consensus",
        scope_notes="Namecoin-family chain; some legacy material also mentions chain ID 4096.",
    ),
    AuxPoWChain(
        slug="devcoin-legacy",
        display_name="Devcoin legacy",
        chain_id=4096,
        activation_date="2012-01-07",
        slot_enforcement="advisory",
        scope_notes="Legacy ID retained as a candidate filter, not a primary integrated-chain identity.",
    ),
    AuxPoWChain(
        slug="groupcoin",
        display_name="Groupcoin",
        chain_id=5,
        activation_date="2012-02-16",
        slot_enforcement="consensus",
        scope_notes="Chain ID 5 per AuxPoW registry; recovery source is Stifter JSON dump.",
    ),
    AuxPoWChain(
        slug="huntercoin-sha256d",
        display_name="Huntercoin SHA-256d branch",
        chain_id=6,
        activation_date="2014-01-31",
        slot_enforcement="consensus",
        scope_notes="Only SHA-256d/BTC branch; Scrypt branch uses chain ID 2 and is out of scope.",
    ),
    AuxPoWChain(
        slug="fusioncoin",
        display_name="Fusioncoin SHA-256d branch",
        chain_id=0,
        activation_date="2014-03-15",
        slot_enforcement="unknown",
        scope_notes="Unrecovered parent-agnostic SHA-256d branch; parent-header strict chain-ID check was disabled, but slot-check enforcement is not source-audited here.",
    ),
    AuxPoWChain(
        slug="unobtanium",
        display_name="Unobtanium",
        chain_id=117,
        activation_date="2015-05-08",
        slot_enforcement="consensus",
        scope_notes="Chain ID decoded from post-activation child-header versions.",
    ),
    AuxPoWChain(
        slug="myriadcoin-sha256d",
        display_name="Myriadcoin SHA-256d branch",
        chain_id=90,
        activation_date="2015-09-26",
        slot_enforcement="consensus",
        scope_notes="Multi-algo SHA-256d branch; fStrictChainId=false for parent-header version checks.",
    ),
    AuxPoWChain(
        slug="sixeleven",
        display_name="SixEleven",
        chain_id=1,
        activation_date="2015-11-03",
        slot_enforcement="consensus",
        scope_notes="Recovered official chain uses chain ID 1; AuxPoW activates at child height 19,200.",
    ),
    AuxPoWChain(
        slug="argentum-sha256d",
        display_name="Argentum SHA-256d branch",
        chain_id=1187,
        activation_date="2016-04-10",
        slot_enforcement="consensus",
        scope_notes="Multi-algo SHA-256d branch; fStrictChainId=false for parent-header version checks.",
    ),
    AuxPoWChain(
        slug="syscoin-chain1",
        display_name="Syscoin chain 1",
        chain_id=4096,
        activation_date="2016-05-01",
        slot_enforcement="consensus",
        scope_notes="Retired Syscoin chain-1 ID.",
    ),
    AuxPoWChain(
        slug="terracoin",
        display_name="Terracoin",
        chain_id=50,
        activation_date="2016-09-23",
        slot_enforcement="consensus",
        scope_notes="Dash-derived Namecoin-style AuxPoW.",
    ),
    AuxPoWChain(
        slug="emercoin",
        display_name="Emercoin",
        chain_id=666,
        activation_date="2017-03-17",
        slot_enforcement="consensus",
        scope_notes="Strict chain ID enforced by raw consensus conditional.",
    ),
    AuxPoWChain(
        slug="blast-launch",
        display_name="BLAST launch ID",
        chain_id=6464,
        activation_date="2017-12-06",
        slot_enforcement="advisory",
        scope_notes="Both launch and rotated IDs accepted by BLAST; not extracted.",
    ),
    AuxPoWChain(
        slug="blast-rotated",
        display_name="BLAST rotated ID",
        chain_id=164,
        activation_date="2017-12-06",
        slot_enforcement="advisory",
        scope_notes="Alternate BLAST chain ID accepted after rotation; not extracted.",
    ),
    AuxPoWChain(
        slug="jincoin",
        display_name="Jincoin",
        chain_id=186,
        activation_date="2018-03-01",
        slot_enforcement="consensus",
        scope_notes="Code-confirmed dormant chain; activation height still unresolved.",
    ),
    AuxPoWChain(
        slug="doichain",
        display_name="Doichain",
        chain_id=2,
        activation_date="2018-05-23",
        slot_enforcement="consensus",
        scope_notes="Namecoin reimplementation; zero BTC stales in current recovery.",
    ),
    AuxPoWChain(
        slug="bitmark-sha256d",
        display_name="Bitmark SHA-256d branch",
        chain_id=91,
        activation_date="2018-06-07",
        slot_enforcement="consensus",
        scope_notes="Multi-algo SHA-256d branch; fStrictChainId=true.",
    ),
    AuxPoWChain(
        slug="xaya",
        display_name="Xaya",
        chain_id=1829,
        activation_date="2018-07-13",
        slot_enforcement="consensus",
        scope_notes="SHA256D-AuxPoW from genesis (multi-algo; NEOSCRYPT solo branch out of scope). Integrated from an offline blocks.zip snapshot.",
    ),
    AuxPoWChain(
        slug="elastos",
        display_name="Elastos",
        chain_id=1224,
        activation_date="2018-08-26",
        slot_enforcement="consensus",
        scope_notes="Go implementation with Namecoin-byte-identical AuxPoW blob.",
    ),
    AuxPoWChain(
        slug="bitcoin-stash",
        display_name="Bitcoin Stash",
        chain_id=0x0044,
        activation_date="2018-11-15",
        slot_enforcement="unknown",
        scope_notes="Dual-parent BCH fork; parent-chain labels are separate advisory payload values, but child slot-check enforcement is not source-audited here.",
    ),
    AuxPoWChain(
        slug="syscoin-chain2",
        display_name="Syscoin chain 2",
        chain_id=16,
        activation_date="2019-06-03",
        slot_enforcement="consensus",
        scope_notes="Current Syscoin chain; numeric ID collides with CoiledCoin.",
    ),
    AuxPoWChain(
        slug="bitcoin-vault",
        display_name="Bitcoin Vault",
        chain_id=1638,
        activation_date="2020-11-17",
        slot_enforcement="consensus",
        scope_notes="Namecoin-byte-identical AuxPoW with strict chain ID 0x0666.",
    ),
    AuxPoWChain(
        slug="elcash",
        display_name="Electric Cash",
        chain_id=8503,
        activation_date="2020-12-20",
        slot_enforcement="consensus",
        scope_notes="Bitcoin Core 0.20.2 fork with strict chain ID 0x2137; merge-mined from its 2020-12-20 fresh-genesis launch (AuxPoW permitted from height 1).",
    ),
    AuxPoWChain(
        slug="lyncoin",
        display_name="Lyncoin",
        chain_id=2829,
        activation_date="2022-12-30",
        slot_enforcement="consensus",
        scope_notes="Strict chain ID 0x0b0d; pre-Flex AuxPoW ends at child height 260,499.",
    ),
    AuxPoWChain(
        slug="fractal",
        display_name="Fractal Bitcoin",
        chain_id=8228,
        activation_date="2024-09-09",
        slot_enforcement="consensus",
        scope_notes="Modern cadence-mined chain with standard scriptSig AuxPoW.",
    ),
)

CHAINS_BY_SLUG: dict[str, AuxPoWChain] = {chain.slug: chain for chain in CHAINS}


def get_chain(slug: str) -> AuxPoWChain | None:
    """Return the registry entry for ``slug``, or None when unknown."""
    return CHAINS_BY_SLUG.get(slug)
