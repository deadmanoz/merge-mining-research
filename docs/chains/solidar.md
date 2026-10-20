# Solidar (formerly WorldLeadCurrency)

| Field | Value |
|---|---|
| Proposed key | `solidar` |
| Aliases | WorldLeadCurrency, WLC, Solidar, SDR |
| Recovery status | Two complete AuxPoW proofs authenticated 2026-10-02. Block history unrecovered |
| Source-level AuxPoW activation | Child height 1 (`GetAuxPowStartBlock()` returns 1). Source capability, not observed use |
| First reported Bitcoin use | Child 11,418, developer report in the August 2015 [debugging thread](https://bitcointalk.org/index.php?topic=1125701.msg12138626#msg12138626). The block is authenticated. "First" is unproven: blocks 1–11,417 are not recovered |
| First authenticated Bitcoin observation | 2015-06-11, WLC child 11,418 (`04ed00f2…e0edda`). Parent extends canonical BTC 360,468. `near`: the parent fails the Bitcoin target and meets the child target |
| Mainnet genesis | `000000004f7ca0e7345a6c29b19a2d555fe922540adfdd74aeaa2cee98d52d85` (declared identically by both inspected C++ lineages) |
| Network status | No reachable peer, working explorer, or public block archive. Rechecked 2026-10-20: no listener accepted port 55889. A 2016-09-03 Wayback capture of the zpool WLC explorer shows the chain live at child height ~69,250 with every block AuxPoW |
| Coverage and stale yield | Unknown. Explorer index covers child hashes 0–23,508 (gap at 19,860). Checkpoint hashes run through 131,690. Full proofs: children 11,418 and 20,357. The index and checkpoints are not a block archive |
| In Stifter et al. 2018 baseline | No. Not one of the paper's seven measured Bitcoin-parent chains |
| Loader / validated CSV | None. No placeholder validated-stales file and no `CHAIN_SPECS` entry |
| Data wanted | [Research issue 59](https://github.com/deadmanoz/merge-mining-research/issues/59) — full chain history still wanted |

Solidar launched as WorldLeadCurrency (WLC) and was renamed Solidar (SDR) by the same developer ([rebranding discussion](https://bitcointalk.org/index.php?topic=791398.220)).

## 1. Historical claim and authenticated fixtures

The primary contemporary evidence is the developer's 2015 [debugging thread](https://bitcointalk.org/index.php?topic=1125701.0) about getting a namecoinj-derived Java node to accept the chain. On 2026-10-02 the thread page `topic=1125701.msg12138626` was captured in full (HTTP 200, 182,707 bytes; the `;all` rendering remains Cloudflare-blocked). It contains the C++ daemon's own `[hexdbg]` dump of blocks it served to the Java node on 2015-08-13, including two complete raw child blocks with full AuxPoW proofs. Both authenticate end-to-end against the pinned WLC validation rules and Bitcoin Core:

| | WLC child 11,418 | WLC child 20,357 |
|---|---|---|
| Child hash | `04ed00f23c1a65d20a84c26d947200961a2960f45f8adf60330446f718e0edda` | `12ea133dfdbcebb34678b52d53c68e99c4daf36fa9904e83e56ed4b083bd29dc` |
| Child time | 2015-06-11 12:39:02 | 2015-08-06 13:57:26 |
| Child height evidence | coinbase `nRefHeight` = 11,418 (its txid equals the child merkle root); the `getblocks` log serves this block first after height 11,417 | coinbase `nRefHeight` = 20,357 (its txid equals the child merkle root); the explorer index assigns this hash to height 20,357 |
| Chain commitment | `fabe6d6d` + 32-slot tree root, WLC at slot 27 — fold of child hash through the 5-step chain branch matches | same, slot 27 |
| Parent coinbase inclusion | txid folds (0-step branch) to parent header merkle root | folds through 10-step branch |
| Parent template | extends **canonical BTC 360,468**; coinbase BIP34 360,469; nBits `18171a8b` matches canonical; 287 P2PKH payouts totalling exactly 25 BTC; template 12:39:54, canonical winner 12:41:17 | extends **canonical BTC 368,655**; BIP34 368,656; nBits `18150815` matches canonical; 243 payouts totalling 25.12398384 BTC; 14:04:05 vs winner 14:07:44 |
| Parent hash | `00000000015a49d368d55eeb44b61ffdc11d3cf2ff69a1540ee03d0a4f4bcb22` | `000000000000011f4e99fd8855e8d74fca38f71084562899d2375488709bc5c6` |
| Bitcoin verdict | **`near`** — fails its own target while meeting the WLC child target; unknown to Bitcoin Core | **`near`** — same pattern |

Child block continuity anchors recovered from the same thread: hashes for heights 9,817, 10,000 and 11,917, plus the 20 zpool explorer hashes at 69,231–69,250 (2016-09-03). These anchor the lineage but do not by themselves authenticate main-chain placement of the fixtures; native validation needs the chain's block data.

The previously saved header pair (September evidence: parent extends BTC 370,595, observed child chain ID `0x0011`, fails the Bitcoin target) remains header-only context — it is a third, distinct parent candidate from August 2015, and it stays excluded from publication because its complete proof bytes are unavailable.

### Explorer height index

`WorldLeadCurrency/explorer` commit `75d92fa990` (2015-12-15, "first commit") contains `nohup.out`, a 22,710,385-byte Iquidus access log (git blob `1b23e4d4c29325540442947bbfb48d2ffc5ca7a4`, SHA-256 `f0e76f99f9f820c093a19ccf10f9b60a44b36c2e7c3b723c095abce8cfaeec5c`). The same blob is on `Henne123/explorer`. It records `getblockhash?height=` followed by `getblock?hash=` with HTTP 200. The response bodies are not in the file: there is no `fabe6d6d` marker and no block hex. Logged `getblock` responses are about 605 bytes before height 11,418 and about 125–126 KB from 11,418 on, which fits AuxPoW JSON starting at the reported first merge-mined block.

Collapsed to one hash per height, the log covers 0 through 23,508 except **19,860**, plus one stray row at 23,600. Before that collapse, 35 heights were paired with more than one hash. Three hashes each appear at two heights (3,818/15,102, 16,441/17,929, 19,277/19,278); those six rows are log noise. Rows that match independent evidence:

| Height | Hash | Agrees with |
|---|---|---|
| 0 | `000000004f7ca0e7345a6c29b19a2d555fe922540adfdd74aeaa2cee98d52d85` | genesis |
| 2,500 | `000000000361b9183245189f7718cceedba1c73a2d6341ce8613af01a1216360` | `checkpoints.cpp` at `a1ab9063` |
| 9,817 | `00000000041658165ce05600eccf7c0a05b2801b2fd9cca5df3c43bdb5016986` | 2015 crash-report quote |
| 10,000 | `000000000476f76304230b34d074a20822f2250f5c04c4424749a62831837aca` | wallet-log quote and `checkpoints.cpp` |
| 11,417 | `0000000002ad72458528c582c84f829ec2fd82412c46b6d4880a2f768374e373` | previous-hash of the recovered 11,418 header |
| 11,418 | `04ed00f23c1a65d20a84c26d947200961a2960f45f8adf60330446f718e0edda` | recovered AuxPoW block |
| 11,917 | `089e5f2f0ea7e20da7169714203c64a3105b0ea7fcd825790f4430c0445c59c2` | `getblocks` limit hash from the same thread |
| 20,000 | `e2c793013d2b4f9f1a46d97235aafcfe0b65c9397804b6346c03aa5132456800` | `checkpoints.cpp` |
| 20,357 | `12ea133dfdbcebb34678b52d53c68e99c4daf36fa9904e83e56ed4b083bd29dc` | recovered AuxPoW block |

The index can check membership of a future datadir in this range. It has no parent hash, `nBits`, or proof, so it cannot classify Bitcoin parents. The 2016-09-03 zpool tip near height 69,250 is outside the log. Those `getblock` bodies were served by `http://109.73.173.119:81`. Wayback has no capture of that host, and the Common Crawl index refused connections on 2026-10-20.

### December 2016 header fragment

BitcoinTalk topic 791398, post around #239 (2016-12-15 09:23:09), prints a miner log whose coinbase is cut off. It is a header fragment, not a block:

| Field | Value |
|---|---|
| Child hash | `1e39e84c18c74770ef1c8e4f418945692ec89d6d064857ec608d66f2f8b21194` |
| Child previous | `27eb9c61addf372ddffeaa8909fcaa091da526f3051f375644ed078dd6b4c1f0` |
| Bitcoin parent | `0000000000001a7c605f76c932222833cc1ddf7b66c105c6add7597643de6a8a` |
| Merkle | `4f12a572822cb8eba8f60e4ce2ea187685f968e1575032e30527a3560c329910` |
| `nTime` / `nBits` / `nRefHeight` | 1481793106 (2016-12-15 09:11:46Z) / `1a1c5761` / 74,758 |
| Version | 1434976513 = `0x55880101` (chain ID `0x5588`, AuxPoW bit, version 1) |

The log prints `vtx=1`, and that transaction's hash equals the merkle root (`vin.size=1`, `vout.size=2`). `ConnectBlock` requires the coinbase `nRefHeight` to equal the block height, so 74,758 is the block height under the pinned rules. The same thread says the first block of the replacement chain is 74,517 and that 74,516 is the last block the old client accepts. That is the developer's statement. A synced Bitcoin Core node did not have the parent hash in its block index on 2026-10-20. The parent header itself was not recovered, so this fragment is not a `near` or stale verdict.

## 2. Preserved source

Four repositories are preserved and pinned (re-fetched and fast-forward checked 2026-10-02; pins unchanged):

| Lineage | Repository | Pinned revision |
|---|---|---|
| Historical WLC (C++) | [WorldLeadCurrency/WLC](https://github.com/WorldLeadCurrency/WLC) | `f07b4a0d1a3eb831d116885edc237fb306aa1862` |
| Solidar (C++) | [wincev/SOLIDAR](https://github.com/wincev/SOLIDAR) | `a1ab9063f338666f602f0e056960061026ffb0d7` |
| WLC Java | [WorldLeadCurrency/wlcj](https://github.com/WorldLeadCurrency/wlcj) | `cb2de4e12553b67ef96d85f40dfe0f1283768554` |
| WLC namecoinj | [Rikski/namecoinj](https://github.com/Rikski/namecoinj) | `407141d6a82232afccca45642d41ae7cfa64727d` |

Both C++ pins share the genesis above, `GetOurChainID()` `0x5588`, `GetOldChainID()` `0x0011`, and AuxPoW from child height 1. Treat the rename, the branch, and the chain-ID change as one lineage unless recovered blocks show a second deployment. The inherited `0.9` and `freimarkets` branches carry the Freicoin-family genesis.

A byte/object-level inventory of all four repositories (2026-10-02; all refs, all packed objects, deleted files, large blobs, content scans) found **no committed block payload** — no `blk*.dat`, bootstrap, or raw export. That scan's long-hex threshold (160 characters) did not extract the shorter checkpoint hashes. `src/checkpoints.cpp` at `a1ab9063` contains this mainnet map, height and hash only:

| Height | Hash |
|---|---|
| 0 | `000000004f7ca0e7345a6c29b19a2d555fe922540adfdd74aeaa2cee98d52d85` |
| 2,500 | `000000000361b9183245189f7718cceedba1c73a2d6341ce8613af01a1216360` |
| 10,000 | `000000000476f76304230b34d074a20822f2250f5c04c4424749a62831837aca` |
| 20,000 | `e2c793013d2b4f9f1a46d97235aafcfe0b65c9397804b6346c03aa5132456800` |
| 84,980 | `c57387f8920957d2dd944bc41a9606b19e3e2734b70f92eec8dd3605481228a6` |
| 111,320 | `0000000000076c1853d51eb9fc73e6156f066f59e484402427c507e379b73957` |
| 131,690 | `00000000002e6923e0cdeec64a81e72d600f79ef5eea57ce522e9cfb81a05817` |

Heights 0, 2,500, 10,000, and 20,000 match the explorer index above. The same file sets the last-checkpoint time to 1631157394 (2021-09-09 03:16:34Z) and the last-checkpoint transaction count to 131,700. Master history also contains superseded checkpoints at 111,080 (`000000002fcdaf5ae5f471e6ed27ce9b35694050250e3a9ece3c7d0a719a77b0`) and 111,155 (`000000003c8400246a4de521ce5dc8b9d166720a198e74d7dfe86f4b8838812e`). The testnet map is only the known testnet genesis `00000000a52504ffe3420a43bd385ef24f81838921a903460b235d95f37cd65e`. No header or AuxPoW for any checkpoint height is in these repositories.

Known non-chain artifacts: the Java `1checkpoints` files are inherited Bitcoin fixtures (all 281 entries match this repo's committed Bitcoin epoch reference, heights 2,016–296,352); Solidar commit `ca6b885e…` retains an accidental empty datadir (0-peer `peers.dat`, failed init); `solidar/src/root@193.32.223.84` is a compiled 2020 `solidard` ELF, not chain data. The AuxPoW chain-ID change `0x0011`→`0x5588` is exactly commit `f07b4a0d` (wlc-solidar, 2016-12-12) / `460ab9b0` (solidar, 2016-12-16). `wincev/bitcoin-abe` `Abe/Chain/Solidar.py` sets the same magic and `datadir_rpcport` 44889; the pinned daemon's RPC port is 55888, and that module ships no datadir.

## 3. Completed checks

The 2026-09-08 pass covered the filename-level source inventory, 36 public HTTP routes, and four source-derived P2P endpoints on port 55889 (all timed out). Receipts are in the private evidence directory.

On 2026-10-02, 77 routes were re-run: Wayback CDX and availability, archive.org item search, bitcointalk, the heap-dump Drive link (HTTP 401), GitHub releases, forks, and owner repos, DNS for historical seed and explorer hosts, and the live endpoints. New captures were the debugging-thread page, the zpool explorer, the 2016 `winc-ev.org` coinspecs (10-minute targets, port 55889), and a 2015 `worldcurrency.jimdo.com` downloads page with historical addnode IPs. wlc-java has no merge-mining support. wlc-namecoinj carries the devcoinj-derived classes with `MERGED_MINE_CHAIN_ID = 0x0011`. Parent checks used `getblockhash` and `getblockheader`. The fixtures and the source inventory are in §1 and §2.

On 2026-10-20 the unfetched pull refs and the Henne123, faz-bz, and zebbra2014 forks had no `blk` file, bootstrap, or header dump. `Henne123/SOLIDAR` is 29 commits ahead of `a1ab9063` (difficulty filter, `RESTED_BLOCK_HEIGHT`, checkpoint bumps); those checkpoint hashes are already in inventoried master. SOLIDAR pulls 3 and 4 are Freicoin history. `financialautonomouszone/SOLIDAR` returns 404. Topics 791398 and 1125701 are readable page by page; `;all` is Cloudflare 403. The only complete serialized blocks on those pages are the two already recovered. `worldleadcurrency.freeforums.org` has no DNS record and no Wayback capture. A March 2016 Abe log names `/home/rik/.worldleadcurrency/blocks/blk00000.dat` and an import through transactions 68,382–68,394 before an exception. That path was not published. Drive id `0Bzt8Hb4nQtyhQ0FxU3kzT0hkbTQ` has no GitHub, Wayback, or Archive.org copy. `archive.ph` returned HTTP 429. No connection was accepted on 55889. `104.168.155.110` refused the port. `pool.winc-ev.com`, `pool.winc-ev.de`, `solidar.it`, and `slr.sicanet.net` are NXDOMAIN.

Still open: the Drive heap dumps, the `;all` rendering, `solidar.it` and `winc-ev.com` DNS, `explorer.solidar.us` (parked redirect; TLS name mismatch on HTTPS), the old IP explorer (timeout, no archive coverage), and Wayback snapshots for `solidar.it/download/` and `slr.sicanet.net/chain/Solidar`. A Freicoin Alliance page links the sicanet chain URL and contains no block hash.

## 4. Wire format and parser plan (now fixture-backed)

The recovered fixtures pin the chain's exact 2015 wire format, which differs from the production parser's later Namecoin convention:

- **Old Durham commitment format.** The parent coinbase scriptSig carries `fabe6d6d` + 32-byte **chain merkle root** (not the child hash). Validation folds the child hash through `vChainMerkleBranch` at `nChainIndex` and requires the root immediately after a single `fabe6d6d` marker (`CAuxPow::Check` in the pinned source). Both fixtures: 2^5 = 32-slot tree, WLC at slot 27, eight zero bytes trailing inside the 44-byte push.
- **Chain ID in the high 16 version bits** (`BLOCK_VERSION_CHAIN_START = 1 << 16`, AuxPoW flag `1 << 8`); observed 2015 chain ID `0x0011`. The C++ child-ID guard is ineffective (`!(id != OLD || id != NEW)` never rejects), while the remaining checks use the header's actual chain ID. Extensions must retain observed IDs and reproduce revision-specific behaviour, not impose a corrected allowlist.
- **`nRefHeight`.** Child transactions are version 2 (`CTransaction::CURRENT_VERSION = 2`), with a 4-byte `nRefHeight` after `nLockTime`. `ConnectBlock` rejects `pindex->nHeight < tx.nRefHeight` for every transaction, and rejects a coinbase whose `nRefHeight` is not the block height. A non-coinbase `nRefHeight` is only a lower bound. Parent (Bitcoin) coinbases in the fixtures are version 1, so parent-side hashing is unaffected here. A version-2 parent coinbase would be hashed with `nRefHeight` appended by this chain's serializer.
- Child `nBits` is easier than Bitcoin's. The fixture parents meet the child target and fail the Bitcoin target (`near`). Child height and main-chain placement are separate from proof validity (§1).

## 5. Unresolved recovery work

1. **Developer-held archive.** The original developer's (`rik8119`) block archive, or the three Android heap dumps behind the Drive link. A request draft exists. No outreach has been sent.
2. **Node data.** Datadirs, `blk*.dat`, bootstraps, raw exports, or explorer backups. The workspace is [`node-infra/solidar/`](../../node-infra/solidar/). No listener accepted 55889 on 2026-10-03 or 2026-10-20. Do not assume the newest branch validates every historical era.
3. **Block bodies.** The height index places the two full proofs on the 2015 explorer chain and matches the early checkpoints, at hash level only. Linking genesis to the 69,231+ anchors, and reading any Bitcoin parent, still requires the intervening bytes. Checkpoint hashes above 20,000 are the developer's claimed chain through September 2021.

Do not publish an empty validated-stales CSV as coverage.

## 6. Integration history

- **2026-09-08.** [Issue 59](https://github.com/deadmanoz/merge-mining-research/issues/59) opened. No complete proof.
- **2026-10-02.** Pins unchanged. Two AuxPoW proofs recovered (children 11,418 and 20,357).
- **2026-10-03.** No live peer. `node-infra/solidar/` added. Genesis hash verified on the archival host.
- **2026-10-20.** No new block file and no new peer. Height index and checkpoint map recorded. Truncated header whose coinbase `nRefHeight` is 74,758.
