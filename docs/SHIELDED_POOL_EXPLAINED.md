# The Shielded Pool, Explained

*A plain-language account of how the pool works: who the parties are, where
money lives, how it moves in and out, how double-spending is prevented, and how
many transfers fit in one transaction. Written for readers who are neither
programmers nor cryptographers. Diagrams are sketched in text and marked
`[Figure]` where a drawing will replace them.*

---

## 1. What the pool is

The shielded pool is a shared account that lives on the BSV blockchain. Money
inside it belongs to individual people, but the blockchain does not show who
owns what, who paid whom, or how much anyone holds. It only shows that the
rules were followed.

Three things make this possible:

- **Notes.** Inside the pool, money is held as *notes*: sealed envelopes that
  say "this amount belongs to whoever holds this key". The blockchain stores
  only a fingerprint of each envelope, never its contents.
- **Proofs.** When someone spends a note, they do not reveal it. They publish a
  small mathematical proof that they *could* have opened it and that the
  amounts add up. Anyone can check the proof; nobody learns which note it was.
- **A covenant.** The pool's money sits in one blockchain output whose spending
  rules are written in script. Nobody has a key to it. It can only move to a
  new version of itself, and only if every rule is satisfied.

`[Figure 1: the pool as a chain of blockchain outputs, one per round, each
holding the vault and a small header.]`

```
   round 1          round 2          round 3
 ┌──────────┐     ┌──────────┐     ┌──────────┐
 │ vault    │ ──► │ vault    │ ──► │ vault    │ ──►  …
 │ header   │     │ header   │     │ header   │
 └──────────┘     └──────────┘     └──────────┘
```

Each arrow is one *round*: a single transaction that spends the previous
version of the pool and creates the next one, carrying many people's transfers
at once.

## 2. The parties

```
  USER WALLETS            COORDINATOR                 BLOCKCHAIN
  hold keys and notes     collects proofs,            holds the pool output,
  build proofs            bundles them into           checks every round
  read the chain          one round transaction       with its own rules
```

- **A user's wallet** holds the user's secret key and the notes they own. It
  reads the blockchain to keep an up-to-date copy of the pool's public state.
  It builds proofs. It never publishes a transaction of its own.
- **The coordinator** is a service that gathers proofs from many wallets,
  bundles them, and publishes one round transaction. It is *untrusted*: it
  cannot take money, redirect a payment, or forge a spend, because the
  blockchain checks everything. The worst it can do is refuse to include
  someone, and in that case a wallet can publish a round by itself.
- **The blockchain** enforces the rules. A round transaction is only accepted
  if the proofs verify and the pool's accounting is exact.

## 3. Where the money lives

The pool's coins sit in one place: the **vault**, which is the value of the
pool's blockchain output. Next to it sits a small **header** with three
records:

```
  ┌────────────────────────────────────────────────────────────┐
  │  VAULT        all the satoshis in the pool                  │
  │  TREE ROOT    fingerprint of every note ever created         │
  │  SPENT LIST   fingerprint of every note ever spent           │
  └────────────────────────────────────────────────────────────┘
```

`[Figure 2: the pool output with its vault and header records.]`

A person's balance is not written anywhere. It is simply the total of the
notes they hold that have not been spent. Only their wallet can add that up,
because only their wallet can read their envelopes.

The pool keeps one invariant at all times: **the vault equals the sum of all
unspent notes.** Every transfer proves that what goes in equals what comes
out, and the covenant applies exactly that difference to the vault.

## 4. Getting money in: a deposit

```
  Alice's ordinary coins ──► round transaction ──► vault grows by the amount
                                                    a new note for Alice is created
```

Alice owns some ordinary BSV. To bring it into the pool she asks her wallet to
deposit. The wallet builds a proof that creates a fresh note for her worth the
deposit amount, and sends the coordinator that proof together with permission
to use her coins. In the next round, her coins become an input of the round
transaction, the vault grows by that amount, and her new note's fingerprint is
added to the tree. From this point on, nobody can tell which note is hers.

## 5. Moving money inside: a transfer

```
  Alice spends note(s) ──► a new note for Bob + a change note for Alice
  the vault does not change
```

To pay Bob, Alice's wallet spends one or two of her notes and creates two new
ones: one sealed to Bob's key, one sealed back to her own key for the change.
The proof shows the amounts balance without revealing any of them. The
blockchain sees two spent-note fingerprints and two new-note fingerprints, and
learns nothing else. Alice tells Bob the contents of his new envelope directly.

## 6. Getting money out: a withdrawal

```
  Alice spends note(s) ──► a change note for Alice
                       ──► an ordinary payment to any address, from the vault
```

A withdrawal is a transfer where part of the value leaves the pool. Alice names
an ordinary BSV address and an amount. The round transaction pays that address
directly, as a normal output anyone can spend with that address's key, and the
vault shrinks by the same amount. The proof binds the payment to the exact
address and amount, so the coordinator cannot redirect it.

Two things to know:

- The destination address and the amount are visible on the blockchain, as in
  every shielded system. What stays hidden is where the money came from.
  Withdrawing to a fresh address keeps the exit clean.
- A round carries as many withdrawals as it carries transfers. Each one gets
  its own payment output.

## 7. Stopping double-spends

Every note has a secret serial number. When a note is spent, its serial number
is published, in a form that cannot be linked back to the note's fingerprint.
The covenant keeps a **spent list** of serial numbers in the header and, before
accepting a spend, checks that the serial number is not already on the list,
then adds it. Spending the same note twice would publish the same serial
number twice, and the second attempt fails.

`[Figure 3: a note being spent; its serial number joins the spent list.]`

This check is done by the blockchain script itself, not by the coordinator,
so no one has to be trusted for it.

## 8. What the coordinator bundles

The coordinator does not bundle transactions. Users never make any. It bundles
**proofs**.

```
  proofs from many wallets     p1   p2   p3   p4   …   pN
                                \  /      \  /
  proofs about proofs           "p1 and p2 verify"   "p3 and p4 verify"   …
                                       \          /
                                    "those verify"
                                          │
                              one proof for the whole round
```

`[Figure 4: the aggregation tree.]`

A proof can vouch for other proofs. The coordinator stacks them into a tree
until one proof remains that vouches, indirectly, for every transfer in the
round. Only that one proof goes on chain, and it is the same size no matter
how many transfers it covers. This has been demonstrated four levels deep with
no growth in proof size or proving time from one level to the next.

## 9. One round on the blockchain

```
  the round transaction
  ┌────────────────────────────────────────────────────────────────────┐
  │ spends:  the previous pool output                                  │
  │          the previous "checker" output                             │
  │          depositors' coins                                         │
  │ creates: the new pool output (vault, header)                       │
  │          a receipt of everything checked                           │
  │          a new "checker" output for the next round                 │
  │          every withdrawal payment and deposit change               │
  └────────────────────────────────────────────────────────────────────┘
```

`[Figure 5: inputs and outputs of a round transaction.]`

The round transaction carries the bundled proof, the public facts of every
transfer (spent serial numbers, new note fingerprints, amounts leaving), and
the payment outputs. The pool output's script applies each transfer to the
vault, the tree and the spent list, and rebuilds every output, so nothing can
be altered on the way.

## 10. Why this is fast

Without bundling, every transfer needs its own on-chain checker, and a round
fits about eleven transfers. With bundling, the on-chain cost is one checker
per round plus a small amount of bookkeeping per transfer, and a round holds
on the order of two hundred transfers in a few megabytes. Rounds chain one
after another, several to a block, so throughput scales with how fast the
coordinator can build proofs, not with what the blockchain can hold.

## 11. What each party can and cannot do

| | Can | Cannot |
|---|---|---|
| A user | deposit, transfer, withdraw; act as their own coordinator | see other people's notes; spend a note twice |
| The coordinator | choose which transfers to include and when | take money, alter a payment, forge a spend, learn note contents |
| The blockchain | reject any round that breaks a rule | see who owns what |

## Glossary

- **Note**: a sealed record of an amount owned by a key. Money inside the pool.
- **Fingerprint (commitment)**: a one-way summary of a note, stored in the tree.
- **Serial number (nullifier)**: a secret per note, revealed when it is spent.
- **Vault**: the pool's satoshis, held in its blockchain output.
- **Tree**: the list of all note fingerprints, summarised by one root value.
- **Spent list**: all revealed serial numbers, summarised by one root value.
- **Proof**: evidence that a rule was followed, checkable without the secrets.
- **Round**: one transaction that advances the pool and carries many transfers.
- **Coordinator**: the untrusted service that bundles proofs into rounds.
- **Checker**: the on-chain output that verifies the round's bundled proof.

---

*Status note for maintainers: sections 1–7 and 9–11 describe what is built and
tested. Section 8's aggregation is built and measured off chain; putting the
bundled proof on chain (one checker per round) is the next engineering step.*
