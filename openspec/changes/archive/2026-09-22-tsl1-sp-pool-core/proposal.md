## Why

The TSL1_SP pool now runs end to end on a regtest node at both scales, but only inside a test: `test/pool_chain_fixture.dart` proves every transfer itself, advances headers by hand, keeps the trees in local variables and puts synthetic bytes where the ciphertext bundles go. The coordinator, chain reader and transfer type in `lib/` still drive the legacy state-script pool. Before a standalone coordinator and a CLI wallet can exist (the next two changes, toward BSV testnet), the library needs the three things both of them stand on: a unit a wallet can hand to a coordinator, a ledger either side can rebuild from the chain alone, and a way for a wallet to find its own notes in it.

## What Changes

- **A TSL1_SP transfer**: the spend proof, its publics, the ciphertext bundle of its two output notes, an optional withdrawal, and for a deposit the covenant outpoint it backs. It checks its own consistency without the pool (outHash lanes against the bundle and withdrawal, the bundle's commitments against the publics, the padding and deposit shapes), and has a versioned binary wire format. Measured at production parameters: a 63,512 B spend proof, 224 B of publics and two 1,827 B hybrid bundles, about 67 KB a transfer, inside ricochet's 10 MB frame.
- **A TSL1_SP ledger**: the header, the commitment tree, the nullifier tree, and the chain tip a next round spends (Y_N, round N, witness N). It applies a mined round and its witness and refuses one that does not reach the round's header.
- **A chain reader for TSL1_SP**: rebuilds the ledger from the issuance and every (round, witness) pair since. Nullifiers, amounts, real flags and outHash come from the wide statement at the bottom of V's unlock in round N+1's input 2; commitments come from the bundles in witness N+1, or the padding note's constant for a padding transfer. The rebuilt tree and nullifier set must reach the header's roots, and the balance its balance.
- **Note scanning**: a wallet with its incoming viewing key recovers its notes from a round's bundles, checked against `outHash`, with their tree positions and Merkle paths from the reader's tree.
- **Real bundles and the padding note in the test chain**: the fixture moves from synthetic bytes to `NoteBundle`s and from random padding notes to `paddingNote`, so the reader and scanner are tested on the chain that is mined.
- **The pool's wallet-facing surface is exported** from `lib/tstokenlib.dart` (today only the PP1_SP builders and `ShieldedPoolTool` are).

Not in this change: the coordinator port, the wallet-to-coordinator message schema, the coordinator server and the CLI wallet. The legacy `PoolCoordinator`, `PoolChainReader` and `PoolTransfer` stay as they are until the coordinator change replaces them.

Numbers to hold, each a requirement in the specs with a scenario that measures it: a transfer encodes to under 100 KB at production parameters (about 67 KB expected); a hostile or inconsistent transfer is refused in under 5 ms, before any proof verification; the reader applies a production round (256 transfers, 512 leaves, up to 512 nullifier insertions, a 277 KB V unlock and a 2.2 MB witness) in under 5 s on one core; scanning one production round for one diversifier takes under 5 s; restoring a 1,000-round snapshot takes under 10 s.

The specs also carry the change's non-functional contract: decoding treats every transfer as hostile, a transfer holds no secrets, scanning is local, reading needs no keys and is deterministic, and both encodings are versioned.

## Capabilities

### New Capabilities
- `pool-transfer`: the unit a wallet submits and a coordinator puts in a round: what it carries, the consistency checks it passes on its own, the padding and deposit shapes, and its wire format.
- `pool-ledger`: the TSL1_SP pool state as a wallet or coordinator holds it, rebuilt from the chain alone, and how a wallet finds and proves its own notes in it.

### Modified Capabilities
<!-- None. pool-coordinator's "Chain reader" and "Note data on chain" requirements describe the legacy pool (note-data outputs, slot unlocks); the tsl1-sp-coordinator change rewrites that spec along with the coordinator, so this change does not touch it. -->

## Impact

- New code under `lib/src/shielded_pool/` (transfer, ledger, reader, scanner); `lib/tstokenlib.dart` exports.
- `test/pool_chain_fixture.dart` changes its bundles and padding, which moves the witness sizes the anatomy page quotes by the difference between synthetic and real bundles (production: +0.92 MB a witness, per the 2026-09-21 measurement). The localnet test and `pool_round_v_test` keep passing; the anatomy page is re-measured.
- No script, circuit or parameter changes, so no template re-export and no kernel byte-identity work.
- Consumers: the coordinator port (next change) builds on the ledger and transfer; the CLI wallet on the transfer, reader and scanner.
