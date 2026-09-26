------------------------------ MODULE PoolRounds ------------------------------
(***************************************************************************)
(* The TSL1_SP pool's round state machine, at the level of what each        *)
(* covenant enforces, for the safety arguments of the design record        *)
(* (docs/ZK_SHIELDED_POOL_TSL1_DESIGN.md, sections 4, 5, 7, 8, 9, 11.15).  *)
(*                                                                         *)
(* Transactions are actions. An output's script is a predicate on the      *)
(* transaction that spends it. Anyone may build any transaction the        *)
(* scripts accept: the coordinator, an outsider (Att) and a depositor      *)
(* (Dep) each hold one key, and nothing else about them is trusted. The    *)
(* STARK is assumed sound: a proof exists exactly when its statement is    *)
(* true of the header it is proved against (ProofExists), whoever that     *)
(* header came from. Bytes and parsing are below this model; the           *)
(* interpreter tests own them.                                             *)
(*                                                                         *)
(* Each protection the design added is a constant, so removing it here     *)
(* reproduces the attack it closed. Every constant TRUE (except            *)
(* PP3HasBurn, which is the hole) is the design as built on 2026-09-26.    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Coord, Att, Dep,              \* the three keys
  NoSlot, NoRound, NoDep,       \* "not mined yet"
  Forged,                       \* the target of a deposit into a forged state output
  MaxRound,                     \* rounds 1..MaxRound; 0 is the issuance
  MaxDeposits, MaxValue,        \* deposits over the whole run, and per-transfer amount
  CertifyGenesisSlot,           \* PP1_0's create branch certifies Y_0 (8.2, 11.15 vector 5)
  VRequiresSigner,              \* V takes the owner's SIGHASH_ALL signature (5.5, vector 1)
  PP3HasBurn,                   \* PP3 keeps a burn branch (5.6): the hole, FALSE as built
  PP3ForwardCovenant,           \* PP3 requires its successor to run its own program (5.4)
  VPinsPrograms,                \* PP1's and PP3's programs are constants of V's body (5.5)
  AnchorRequired,               \* a round spends the anchor of the slot it pins (4.1)
  DepositorChecksLineage        \* a depositor byte-checks PP1 and follows the chain (5.4, 16)

ASSUME MaxRound \in Nat /\ MaxDeposits \in Nat /\ MaxValue \in Nat \ {0}

VARIABLES
  slots,        \* n -> Y_n as mined, or NoSlot
  vSpentBy,     \* n -> who spent Y_n's output 0: "None", "Round", or a key
  rounds,       \* n -> round n as mined, or NoRound
  forged,       \* a state output written into a fresh transaction (section 16)
  deposits,     \* d -> a deposit covenant, or NoDep
  withdrawn,    \* key -> satoshis paid out of the pool to that key
  depositedBy   \* key -> satoshis that key paid in through receipts

vars == <<slots, vSpentBy, rounds, forged, deposits, withdrawn, depositedBy>>

R            == 0..MaxRound
Deps         == 1..MaxDeposits
Parties      == {Coord, Att, Dep}
NoteHolders  == {Att, Dep}
Builders     == {Coord, Att}
MaxBal       == MaxDeposits * MaxValue
Headers      == [bal: 0..MaxBal, owed: [NoteHolders -> 0..MaxBal]]
Empty        == [bal |-> 0, owed |-> [p \in NoteHolders |-> 0]]
Programs     == {"Canonical", "Weak"}      \* the pool's PP3, or anything else
Bodies       == {"Real", "Decoy"}          \* the pool's verifier, or anything else
Withdrawals  == [payee: NoteHolders, amount: 0..MaxValue]   \* amount 0: none
Targets      == R \cup {Forged}

Slot    == [hdr: Headers, signer: Builders, body: Bodies, anchorSpent: BOOLEAN]
Round   == [hdr: Headers, prog: Programs, bal: 0..MaxBal, witnessed: BOOLEAN, pp3Spent: BOOLEAN]
Deposit == [amount: 1..MaxValue, target: Targets, state: {"Open", "Received", "Refunded", "Stolen"}]

TypeOK ==
  /\ slots \in [R -> Slot \cup {NoSlot}]
  /\ vSpentBy \in [R -> {"None", "Round"} \cup Builders]
  /\ rounds \in [R -> Round \cup {NoRound}]
  /\ forged \in [exists: BOOLEAN, prog: Programs]
  /\ deposits \in [Deps -> Deposit \cup {NoDep}]
  /\ withdrawn \in [Parties -> Nat]
  /\ depositedBy \in [Parties -> Nat]

Live(n) == rounds[n] # NoRound

RECURSIVE SumAmt(_)
SumAmt(S) == IF S = {} THEN 0
             ELSE LET d == CHOOSE x \in S : TRUE IN deposits[d].amount + SumAmt(S \ {d})

OpenDeps(t) == {d \in Deps : deposits[d] # NoDep /\ deposits[d].state = "Open" /\ deposits[d].target = t}

(* The spend statement, abstracted: a proof from header h to header h2 with *)
(* the deposits recv received and the withdrawal w paid exists exactly when *)
(* the payee owns the notes and the balances follow. Deposits are Dep's.    *)
ProofExists(h, h2, recv, w) ==
  /\ w.amount <= h.owed[w.payee]
  /\ h2.bal = h.bal + SumAmt(recv) - w.amount
  /\ h2.owed = [p \in NoteHolders |->
                  h.owed[p] + (IF p = Dep THEN SumAmt(recv) ELSE 0)
                            - (IF p = w.payee THEN w.amount ELSE 0)]

(* PP1's slot certification (5.2 check 2, and the create branch of 11.15): *)
(* the slot round n pins holds this pool's verifier, initialised with        *)
(* header_n, signed for by the owner.                                       *)
SlotCertified(n) ==
  /\ slots[n] # NoSlot
  /\ slots[n].body = "Real"
  /\ slots[n].hdr = rounds[n].hdr
  /\ slots[n].signer = Coord

-----------------------------------------------------------------------------
Init ==
  /\ slots = [n \in R |-> NoSlot]
  /\ vSpentBy = [n \in R |-> "None"]
  /\ rounds = [n \in R |-> NoRound]
  /\ forged = [exists |-> FALSE, prog |-> "Canonical"]
  /\ deposits = [d \in Deps |-> NoDep]
  /\ withdrawn = [p \in Parties |-> 0]
  /\ depositedBy = [p \in Parties |-> 0]

(* Y_n (4.1): anyone mines it, with any header, signer and body. The       *)
(* coordinator decides which one PP3 pins; here that is slot n.             *)
MineSlot(n, h, s, b) ==
  /\ slots[n] = NoSlot
  /\ rounds[n] = NoRound /\ (IF n = 0 THEN TRUE ELSE Live(n-1))   \* just in time; earlier mining changes nothing
  /\ slots' = [slots EXCEPT ![n] = [hdr |-> h, signer |-> s, body |-> b, anchorSpent |-> FALSE]]
  /\ UNCHANGED <<vSpentBy, rounds, forged, deposits, withdrawn, depositedBy>>

(* The issuance (5.1, 11.5): spends the funding outpoint whose txid is the *)
(* tokenId (once, by construction) and, with the anchor, Y_0's output 1.   *)
(* The coordinator writes the genesis header; a depositor reads it.        *)
Issue(h0, prog) ==
  /\ rounds[0] = NoRound
  /\ h0.bal = 0
  /\ AnchorRequired => (slots[0] # NoSlot /\ ~slots[0].anchorSpent)
  /\ rounds' = [rounds EXCEPT ![0] = [hdr |-> h0, prog |-> prog, bal |-> 0, witnessed |-> FALSE, pp3Spent |-> FALSE]]
  /\ slots' = IF AnchorRequired THEN [slots EXCEPT ![0].anchorSpent = TRUE] ELSE slots
  /\ UNCHANGED <<vSpentBy, forged, deposits, withdrawn, depositedBy>>

(* V's checks when round n+1 spends Y_n:0 (5.5). A decoy body accepts      *)
(* anything. The real body verifies the proof against ITS header, checks    *)
(* PP3's value against the new header and, when it pins programs, the       *)
(* successor's program. The signer check is in the round's builder.         *)
VAccepts(v, h, prog, recv, w, bal) ==
  \/ v.body = "Decoy"
  \/ /\ v.body = "Real"
     /\ ProofExists(v.hdr, h, recv, w)
     /\ bal = h.bal
     /\ (VPinsPrograms => prog = "Canonical")

(* PP3_n's checks when round n+1 spends it (5.4): the witness exists and   *)
(* input 2 is the pinned slot (both by construction here), and with the     *)
(* forward covenant output 3 runs PP3's own program. A weak PP3 accepts     *)
(* anything.                                                                *)
PP3Accepts(p, prog) ==
  \/ p.prog = "Weak"
  \/ (PP3ForwardCovenant => prog = "Canonical")

(* Round n (4.2), built by the coordinator: input 1 is witness_{n-1}'s      *)
(* output, so nobody else can build one. It spends V_{n-1}, PP3_{n-1}, the  *)
(* anchor of Y_n and the deposit covenants naming PP3_{n-1}, and writes     *)
(* header h, PP3 with program prog and value bal, receipts (the covenants   *)
(* force them) and the withdrawal w. Consensus: outputs within inputs.      *)
MineRoundWith(n, h, prog, recv, w, bal) ==
  LET p == rounds[n-1]
      v == slots[n-1]
  IN
  /\ Live(n-1) /\ ~Live(n)
  /\ p.witnessed /\ ~p.pp3Spent
  /\ v # NoSlot /\ vSpentBy[n-1] = "None"
  /\ recv \subseteq OpenDeps(n-1)
  /\ AnchorRequired => (slots[n] # NoSlot /\ ~slots[n].anchorSpent)
  /\ bal + w.amount <= p.bal + SumAmt(recv)
  /\ VAccepts(v, h, prog, recv, w, bal)
  /\ PP3Accepts(p, prog)
  /\ rounds' = [rounds EXCEPT ![n] = [hdr |-> h, prog |-> prog, bal |-> bal, witnessed |-> FALSE, pp3Spent |-> FALSE],
                              ![n-1].pp3Spent = TRUE]
  /\ vSpentBy' = [vSpentBy EXCEPT ![n-1] = "Round"]
  /\ slots' = IF AnchorRequired THEN [slots EXCEPT ![n].anchorSpent = TRUE] ELSE slots
  /\ deposits' = [d \in Deps |-> IF d \in recv THEN [deposits[d] EXCEPT !.state = "Received"] ELSE deposits[d]]
  /\ depositedBy' = [depositedBy EXCEPT ![Dep] = @ + SumAmt(recv)]
  /\ withdrawn' = [withdrawn EXCEPT ![w.payee] = @ + w.amount]
  /\ UNCHANGED forged

(* Witness n (4.3): PP1_n runs. The create branch (n = 0) certifies Y_0    *)
(* when built to; the round branch certifies Y_n and checks PP3_n holds    *)
(* header_n's balance. Lineage to the tokenId and the outHash of the        *)
(* bundles hold by construction here.                                       *)
MineWitness(n) ==
  /\ Live(n) /\ ~rounds[n].witnessed
  /\ IF n = 0 THEN (CertifyGenesisSlot => SlotCertified(0))
              ELSE SlotCertified(n) /\ rounds[n].bal = rounds[n].hdr.bal
  /\ rounds' = [rounds EXCEPT ![n].witnessed = TRUE]
  /\ UNCHANGED <<slots, vSpentBy, forged, deposits, withdrawn, depositedBy>>

(* A deposit covenant (7.1) naming a PP3 outpoint. A careful depositor      *)
(* deposits only into the live pool: canonical PP3, empty genesis, and a    *)
(* chain that reaches the tokenId, which a forged output never does.        *)
MakeDeposit(d, amt, t) ==
  /\ deposits[d] = NoDep
  /\ IF t = Forged
       THEN forged.exists /\ ~DepositorChecksLineage
       ELSE /\ Live(t) /\ ~rounds[t].pp3Spent
            /\ (DepositorChecksLineage => (rounds[t].prog = "Canonical" /\ rounds[0].hdr = Empty))
  /\ deposits' = [deposits EXCEPT ![d] = [amount |-> amt, target |-> t, state |-> "Open"]]
  /\ UNCHANGED <<slots, vSpentBy, rounds, forged, withdrawn, depositedBy>>

(* The refund branch, after its lock time (time is not modelled).          *)
Refund(d) ==
  /\ deposits[d] # NoDep /\ deposits[d].state = "Open"
  /\ deposits' = [deposits EXCEPT ![d].state = "Refunded"]
  /\ UNCHANGED <<slots, vSpentBy, rounds, forged, withdrawn, depositedBy>>

(* Spending a pinned Y_n:0 outside a round (11.15 vector 1). A decoy needs  *)
(* nothing.                                                                 *)
(* The real V needs a proof, which an outsider copies from the mempool, and *)
(* the owner's signature when built to. PP3_n is then unspendable: frozen.  *)
SpendVOutsideRound(n, b) ==
  /\ Live(n) /\ slots[n] # NoSlot /\ vSpentBy[n] = "None"
  /\ slots[n].body = "Decoy" \/ ~VRequiresSigner \/ b = Coord
  /\ vSpentBy' = [vSpentBy EXCEPT ![n] = b]
  /\ UNCHANGED <<slots, rounds, forged, deposits, withdrawn, depositedBy>>

(* PP3's burn branch (5.6): the owner's signature takes the balance.        *)
Burn(n) ==
  /\ PP3HasBurn
  /\ Live(n) /\ ~rounds[n].pp3Spent
  /\ rounds' = [rounds EXCEPT ![n].pp3Spent = TRUE]
  /\ withdrawn' = [withdrawn EXCEPT ![Coord] = @ + rounds[n].bal]
  /\ UNCHANGED <<slots, vSpentBy, forged, deposits, depositedBy>>

(* A PP3 that runs some other program holds the balance for whoever can     *)
(* satisfy that program; here, anyone.                                      *)
TakeWeakPP3(n, b) ==
  /\ Live(n) /\ ~rounds[n].pp3Spent /\ rounds[n].prog = "Weak"
  /\ rounds' = [rounds EXCEPT ![n].pp3Spent = TRUE]
  /\ withdrawn' = [withdrawn EXCEPT ![b] = @ + rounds[n].bal]
  /\ UNCHANGED <<slots, vSpentBy, forged, deposits, depositedBy>>

(* Section 16: an outsider writes a state output with the pool's header    *)
(* bytes into a fresh transaction, beside a PP3 of their choosing. With the *)
(* canonical PP3 it can never be spent (its witness needs a parent chain    *)
(* that ends at the tokenId's outpoint, spent once by the issuance); with a *)
(* weak one the forger spends it, and any covenant naming it, at will.      *)
Forge(prog) ==
  /\ ~forged.exists
  /\ forged' = [exists |-> TRUE, prog |-> prog]
  /\ UNCHANGED <<slots, vSpentBy, rounds, deposits, withdrawn, depositedBy>>

TakeForgedDeposits ==
  /\ forged.exists /\ forged.prog = "Weak"
  /\ OpenDeps(Forged) # {}
  /\ deposits' = [d \in Deps |-> IF d \in OpenDeps(Forged) THEN [deposits[d] EXCEPT !.state = "Stolen"] ELSE deposits[d]]
  /\ withdrawn' = [withdrawn EXCEPT ![Att] = @ + SumAmt(OpenDeps(Forged))]
  /\ UNCHANGED <<slots, vSpentBy, rounds, forged, depositedBy>>

MineRound ==
  \E n \in 1..MaxRound, h \in Headers, prog \in Programs, w \in Withdrawals, bal \in 0..MaxBal :
    \E recv \in SUBSET OpenDeps(n-1) : MineRoundWith(n, h, prog, recv, w, bal)

Next ==
  \/ \E n \in R, h \in Headers, s \in Builders, b \in Bodies : MineSlot(n, h, s, b)
  \/ \E h0 \in Headers, prog \in Programs : Issue(h0, prog)
  \/ MineRound
  \/ \E n \in R : MineWitness(n)
  \/ \E d \in Deps, amt \in 1..MaxValue, t \in Targets : MakeDeposit(d, amt, t)
  \/ \E d \in Deps : Refund(d)
  \/ \E n \in R, b \in Builders : SpendVOutsideRound(n, b)
  \/ \E n \in R : Burn(n)
  \/ \E n \in R, b \in Builders : TakeWeakPP3(n, b)
  \/ \E prog \in Programs : Forge(prog)
  \/ TakeForgedDeposits

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Safety. Section 8.3: a dishonest coordinator can freeze, never take.     *)

(* Nobody takes out more than they paid in. Coord and Att never pay in.    *)
NoTheft == \A p \in Parties : withdrawn[p] <= depositedBy[p]

(* In a pool opened on the empty tree (the only kind a depositor uses, 5.1),*)
(* the live header owes the depositor exactly what they have paid in and   *)
(* not yet withdrawn: a receipt is honoured by a note in the tree.          *)
DepositorNotesExist ==
  \A n \in R : (Live(0) /\ rounds[0].hdr = Empty /\ Live(n) /\ ~rounds[n].pp3Spent) =>
    rounds[n].hdr.owed[Dep] = depositedBy[Dep] - withdrawn[Dep]

(* A slot the pool pinned and certified is spent only by a round or by the  *)
(* coordinator: no outsider can freeze the pool. (An unpinned or decoy      *)
(* slot is nobody's to lose; a pinned decoy is the coordinator's own freeze.) *)
OutsiderCannotFreeze == \A n \in R : (Live(n) /\ SlotCertified(n)) => vSpentBy[n] # Att

(* A deposit is received with its receipt or refunded, never taken.        *)
NoDepositStolen == \A d \in Deps : deposits[d] # NoDep => deposits[d].state # "Stolen"

=============================================================================
