## Context

See proposal.md for why. What the code already gives this change, measured or read on 2026-09-22:

- **Where each part of a round is on chain.** Round N+1's input 2 unlock (V's) begins with the root proof's wide statement, one script number per lane in `PoolStatement` order (`StarkVerifierGen.buildUnlock` pushes `air.publicValues` first). Per transfer the statement pins four of the seven 8-lane chunks: both nullifiers, and the chunks holding the public amount, outHash, the two real flags and the asset. It leaves out the anchor and the two output commitments (`PoolStatement.freeChunks`), because pinning a commitment per transfer cost +203 KB of root verifier (design 7.1). Witness N+1's input 1 unlock (PP1's) carries the round's bundles as one push, `PoolOutHash.encodeBundles` (2-byte length per transfer), at a fixed place in `PP1SpUnlockBuilder`'s ROUND layout (the 14th push of 18). The header is in round N+1's PP1 output.
- **So commitments reach a reader only through the bundles.** The design already relies on it: "every commitment is already in plaintext in the note bundles for wallets to build paths from" (design 7.1). Nothing in the circuit ties a bundle's commitment to the transfer's commitment lanes. `outHash` ties the bundle's bytes to the transfer, and the tree root ties the commitments to the round, but a transfer whose bundle names a different commitment than its proof would be accepted by V and would leave every reader unable to reach `rootAfter`. That makes the bundle check at intake (pool-transfer, Self-consistency) a liveness requirement for every wallet, not tidiness.
- **Leaf placement** is `AggregationTree.subtreeLeavesOf(spendLanes, s)`, which reads the commitment chunks out of each transfer's full lanes. A reader that rebuilds full lanes, with commitments from bundles and a zero anchor, gets the builder's placement by calling the same function.
- **Padding** is recognisable from pinned lanes alone (`isPadding`: no real input, public amount 0), so a reader can tell padding without its commitments. `ShieldedPoolLegacyTool.paddingNote` / `paddingCm` define the public padding note. The test fixture does not use it yet: its padding pays random notes, and its bundles are synthetic bytes.
- **Scanning** is `NoteEncryption.scanIncoming(bundle, ivk, diversifiers)`: async (KEM decapsulation), one attempt per diversifier the wallet has handed out, and it discards a plaintext that does not reproduce the commitment.
- **Sizes**: a production spend proof encodes to 63,512 B through `ProofCodec` (`tool/scratch/spend_submission_size.dart`, 1.2 s to prove), publics are 56 lanes (224 B), a hybrid note bundle is 1,827 B.

## Goals / Non-Goals

**Goals:**
- One transfer type that both the coordinator and the wallet use, with the checks that do not need pool state living on the type.
- A ledger whose only inputs are mined transactions, so a wallet trusts nothing the coordinator says about state.
- The test chain, in memory and on localnet, exercises the reader and scanner as mined.

**Non-Goals:**
- Verifying spend proofs inside the reader. A mined round was verified by V; the reader checks consistency, not soundness.
- Chain access. The reader is given transactions; fetching them (ARC, WhatsOnChain, node RPC, BEEF and merkle proofs) belongs to the apps.
- Replacing the legacy `PoolCoordinator`, `PoolChainReader` or `PoolTransfer`. They stay until the coordinator change.
- Fees, funding and change for the coordinator's transactions.

## Decisions

**New names beside the legacy ones: `ShieldedTransfer`, `ShieldedLedger`, `ShieldedChainReader`, `ShieldedNoteScanner`**, in `lib/src/shielded_pool/`. The legacy `PoolTransfer` and `PoolLedger` keep their names and files until the coordinator change deletes them, so no import in the legacy coordinator breaks meanwhile. Alternative: rename the legacy types first. Rejected because it touches the legacy coordinator, its tests and `bin/pool_coordinator.dart` for code that is about to be retired.

**The reader rebuilds full lanes and reuses the aggregation's placement**, rather than reimplementing leaf order. A second implementation of leaf order would drift the first time the plan's tree shape changes; calling `subtreeLeavesOf` with the reader's lanes cannot. It means the reader needs the pool's `AggregationTree` (transfers, subtrees, receipt slots). The reader takes it from the pool's configuration, built without compiling the level programs (the tree shape is plain data; `PoolAggregation(dryRun: true)` is the fallback if extracting it costs more than it saves). The statement layout comes from the same tree via `PoolStatement.of`.

**Statement lanes are parsed from V's unlock by count, not by pattern.** The first `numPublics` chunks of input 2's unlock are the statement, each a minimally encoded script number, so the parser reads exactly that many pushes and refuses a round whose unlock does not start with them. It is the same layout V itself reads, so a round V accepted always parses.

**Bundles are parsed from the witness by `PP1SpUnlockBuilder`'s own layout.** A static reader on the unlock builder returns the ROUND pushes by name, so the index of the bundles push is written once, next to the code that writes it.

**The ledger applies a round in two phases.** It computes everything on copies (the tree and nullifier tree are copied, since `NullifierTree.copy` exists and the commitment tree gains one), then commits only when every check in the spec's list holds. A refused round leaves the ledger as it was without any undo logic.

**A snapshot stores leaves and nullifiers, not tree nodes.** Restore replays the appends and inserts and then checks the roots against the stored header, which doubles as an integrity check on the file. Node maps would restore faster but are larger, carry no check, and tie the format to `MerkleStore`'s internals. The cost is measured (task 5.5); if a 1,000-round replay (512,000 leaves) is over 10 s, store the frontier and node map as well.

**The wire format is a versioned concatenation with explicit lengths**: version byte, flags (withdrawal present, deposit present), the 56 publics as 4-byte lanes, the proof length (4 bytes) and `ProofCodec` bytes, the bundle length and bytes, then the withdrawal record (28 B) and the deposit outpoint (36 B) when flagged. `ProofCodec` needs the AIR, which depends only on column counts, so the decoder builds it from the decoded publics. Alternative: JSON with hex fields, rejected for doubling a 64 KB proof and for leaving the byte-level refusals (truncation, trailing bytes) to a JSON parser.

**Hostile input is bounded before it is read.** The decoder checks the total against 100 KB first, then each length against both the remaining bytes and its field's own bound: the proof length must equal `ProofCodec`'s fixed length for the spend parameters (the shape is known before any byte is read, so a wrong length is refused outright), and the bundle is at most 6,054 B, two hybrid note bundles each with an issuer copy (`NoteBundle.sizeOf(2, issuerKem: 2)` = 3,027 B, `tool/scratch/bundle_size_bounds.dart`). Every failure is caught at the decoder's boundary and returned as a refusal naming the field. The check order is fixed by cost: size, decode, self-consistency (SHA-256 and parsing only), and only then the proof. The coordinator change inherits that order at intake. Alternative: verify first and decode lazily. Rejected because verification is the one expensive step and an open inbox invites cheap garbage.

**Robustness is tested by mutation, not by enumerating cases.** Both the transfer decoder and the ledger's round parser get a mutation test (random strings, single-byte mutations of a valid input) whose only assertion is that every outcome is a value or a named refusal. It is the non-functional requirement that example-based tests miss, and it costs seconds.

**Determinism comes from ordered state.** The snapshot writes leaves and nullifiers in insertion order and the header and tip transactions as bytes, so two ledgers that applied the same rounds write the same file. Nothing is keyed by a hash map's iteration order.

**Scanning takes the wallet's diversifiers explicitly.** `scanIncoming` tries each diversifier, so the scanner cannot guess which addresses a wallet handed out. The scanner reports spends by checking each owned note's nullifier (computed from nk and rho) against each round's inserted nullifiers, which the reader already has.

**The fixture gets real notes and the padding note.** Round 1's deposit note and round 2's 200 change note are addressed to one wallet key (so scanning finds both), the other outputs to other keys, bundles come from `NoteEncryption.encrypt`, and padding transfers pay `paddingNote` twice with an empty bundle. The fixture's rngs stay seeded, so the chain is still reproducible.

## Risks / Trade-offs

- **A transfer can pass V and break every reader.** Its bundle can name a commitment other than its proof's. → The coordinator must refuse such transfers at intake, which is why the check sits on the transfer type where the coordinator change will call it. A reader that fails to reach `rootAfter` stops and reports the round, which makes the fault visible, but does not recover. The remedy lies with the coordinator, per design 8.3: death, not theft.
- **The fixture's witnesses grow.** Real bundles are about 3.65 KB a transfer where the synthetic ones were 40 to 103 B, so a production witness grows by about 0.92 MB, to roughly 3.1 to 3.5 MB. That's still under 10 MB a transaction. The localnet production run goes through node RPC anyway, since ARC's limit is 1,636,802 B unpatched. → Re-measure the anatomy page from the new chain.
- **Scanning cost grows with diversifiers × bundles.** One KEM decapsulation per bundle per diversifier, so 512 × D a production round. The 5 s bound in pool-ledger is set before measuring: the ML-KEM half is native, and the X25519 half is pure Dart from `package:cryptography`. → Task 6.3 measures it. If the bound fails, the options are a native X25519 in `native/stark_kernels` or a cheaper trial decryption ahead of the KEM (a short tag per bundle). Either changes the bundle format, so it would come back as a spec change, not a silent miss.
- **Performance bounds are one machine's.** "One core of the coordinator's machine" is the 12-core laptop the budget is measured on. → The bounds are recorded with the machine in the design doc, and a wallet on slower hardware is expected to be slower in proportion.
- **Legacy and new types coexist.** Two `...Transfer` types in one library for one change. → Only the new ones are exported; the legacy ones stay internal.

## Migration Plan

Additive. The legacy coordinator and reader keep working and keep their tests. The fixture change moves measured witness sizes, so the anatomy page and design doc's measurement sections are updated in this change's last tasks. Rollback is reverting the change; no on-chain format changes.

## Open Questions

- Whether `AggregationTree` can be built without `PoolAggregation` at production shape, and how long it takes if not. It changes only how the reader is constructed, not what it does.
