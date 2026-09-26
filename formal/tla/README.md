# The pool's round state machine, model-checked

`PoolRounds.tla` is a TLA+ model of the TSL1_SP pool at the level of what each covenant enforces: transactions are actions, an output's script is a predicate on the transaction that spends it, and anyone (the coordinator, an outsider, a depositor) may build any transaction the scripts accept. It exists to check the design record's safety argument (design §8 and §9: a dishonest coordinator can freeze the pool, never take from it) mechanically, and to reproduce the attacks the design closed by switching each protection off.

Started 2026-09-26 as the covenant-layer item of `docs/SECURITY_CLAIM.md` (O9 and section 10).

## Run it

```
formal/tla/run.sh                 # every configuration
formal/tla/run.sh AsBuilt.cfg     # one
TRACE=1 formal/tla/run.sh Attack_Burn.cfg   # with the full counterexample
```

Needs Java. The script fetches `tla2tools.jar` beside itself if it is missing. The full run is about six minutes on a laptop; a configuration that holds explores about a quarter of a million states, one that is violated stops at its counterexample.

## What is modelled

| Thing | In the model |
|---|---|
| Y_n, the slot transaction (design 4.1) | `MineSlot`: anyone mines it with any header, any signer and a body that is the pool's verifier or a decoy. One slot per index, and PP3_n pins slot n |
| The issuance (5.1, 11.5) | `Issue`: spends the tokenId's funding outpoint (once, by construction) and Y_0's anchor; the coordinator writes any genesis header |
| Round n (4.2) | `MineRound`: coordinator only (input 1 is the witness output). Spends V_{n-1}, PP3_{n-1}, Y_n's anchor and the deposit covenants naming PP3_{n-1}; writes header, PP3 program and value, receipts, one withdrawal. `VAccepts` and `PP3Accepts` are the scripts |
| Witness n (4.3) | `MineWitness`: PP1's create branch (n = 0) and round branch, reduced to slot certification and the PP3-holds-the-balance check. Lineage and outHash hold by construction |
| The spend proof | `ProofExists`: a proof from header h to h2 with these deposits and this withdrawal exists exactly when the payee owns the notes in h and the balances follow. The STARK is assumed sound; h may have come from anywhere |
| Deposits (7.1) | `MakeDeposit` (a careful depositor checks canonical PP3, empty genesis and lineage), `Refund` |
| Attacks | `SpendVOutsideRound` (11.15 vector 1), `Burn` (5.6), `TakeWeakPP3` (a PP3 running some other program), `Forge` and `TakeForgedDeposits` (design §16: a state output written into a fresh transaction) |

Header = balance plus what the pool owes each note holder. Values are small integers. Not modelled: bytes and parsing (varints, yInput's length, V's fixed-size pushes: the interpreter tests own those), time (a refund may race a round), the mempool (an outsider is assumed to have a copy of any proof it needs), the ciphertext bundles, and the chain reader.

## Protections and invariants

Each protection the design added is a constant, so the attack it closed is one flag away.

| Constant | Design | Off means |
|---|---|---|
| `CertifyGenesisSlot` | 8.2, 11.15 vector 5 | witness 0 accepts any Y_0 |
| `VRequiresSigner` | 5.5 | V takes any spender with a proof |
| `PP3HasBurn` | 5.6 (TRUE is the hole) | the owner's key takes the balance |
| `PP3ForwardCovenant` | 5.4 | a round may write any program into output 3 |
| `VPinsPrograms` | 5.5 "Built" | V does not check PP3's program |
| `AnchorRequired` | 4.1 | a round may pin a Y that was never mined |
| `DepositorChecksLineage` | 5.4, 16 | a depositor pays into whatever names itself the pool |

Invariants: `NoTheft` (nobody takes out more than they paid in), `DepositorNotesExist` (in a pool opened empty, the live header owes the depositor what they paid in and have not withdrawn), `OutsiderCannotFreeze` (a pinned, certified slot's verifier output is spent only by a round or the coordinator), `NoDepositStolen`.

## Results, 2026-09-26

MaxRound 2, one deposit, unit amounts.

| Configuration | Result | Counterexample |
|---|---|---|
| `AsBuilt` (everything on, no burn) | holds, 240,933 states | |
| `Attack_DecoyGenesis` | `DepositorNotesExist` | decoy Y_0, issue, Y_1, witness 0 passes, round 1 writes a header nobody proved |
| `Attack_DecoyGenesis_Theft` | `NoTheft` | as above, but round 1 receives the deposit and pays it to the outsider: with a decoy V there is no proof to constrain the outputs, so the theft needs no fabricated notes at all |
| `Attack_ProofCopy` | `OutsiderCannotFreeze` | the outsider spends the pinned V_0 with a copied proof; PP3_0 can never be spent |
| `Attack_Burn` | `NoTheft` | deposit received in round 1, then the owner burns PP3_1 |
| `Attack_WeakPP3` (forward covenant and V's pin both off) | `NoTheft` | round 1 writes a weak PP3 holding the deposit; anyone takes it |
| `Holds_OnlyForwardCovenant` | holds, 309,321 states | either pin alone suffices |
| `Holds_OnlyVPins` | holds, 240,933 states | |
| `Holds_NoAnchor` | holds, 243,870 states | the anchor is a liveness measure, not a safety one: without it the coordinator can freeze, nobody can take |
| `Attack_CarelessDepositor` | `NoTheft` | a forged state output with a weak PP3; the deposit naming it is taken |

Two things the run said that the design record had not: the decoy-genesis theft is shorter than vector 5 described (one round, no fabricated notes), and removing either program pin alone is safe, so the redundancy in 5.5 step 6 is real.

## Next

- Two depositors and MaxRound 3, to look for cross-round interactions the one-deposit model cannot show.
- A liveness property: with every protection on, an honest coordinator can always reach the next witnessed round. Today only safety is checked.
- Time: refund lock heights against round assembly (design 7.1's `minRefundAfter`).
- The chain reader as a second reader of the same model, so that "a forged round is never applied" can be stated beside "a forged round never advances".
