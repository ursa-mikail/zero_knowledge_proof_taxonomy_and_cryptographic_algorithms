# Commitment schemes & shared primitives

The small building blocks that show up inside almost every other family in
this repo.

## Files

- `hash_based_commitment.py` — the simplest possible commitment: hash a
  value with a random blinding nonce
- `merkle_tree_commitment.py` — commit to a whole *set/list* of values with
  one root hash, and prove membership of any single element in `O(log n)`

(Pedersen commitments, the other major commitment primitive, live in
`01_zero_knowledge_proofs/pedersen_commitment.py` since they're introduced
there alongside the ZK proofs that use them; oblivious transfer lives in
`03_multi_party_computation/oblivious_transfer_1_of_2.py` for the same
reason.)

---

## 1. Hash-based commitment — step by step

**The idea in one sentence:** hide a value behind a one-way function plus
enough randomness that guessing it is infeasible, then later reveal both the
value and the randomness so anyone can check they match.

### Steps

1. **Commit.** To commit to value `v`, generate a large random nonce `r`
   (32 random bytes is standard), and publish `commitment = H(v || r)`
   (concatenate then hash with SHA-256 or similar).
2. **(time passes — other parties commit too, or an event occurs that the
   commitment shouldn't be able to react to)**
3. **Reveal.** Publish `(v, r)`.
4. **Verify.** Anyone recomputes `H(v || r)` and checks it equals the
   originally published `commitment`.

### Why it's hiding

`H` is a one-way function — given only `H(v||r)`, finding *any* `(v', r')`
that hashes to it is computationally infeasible (that's the definition of
preimage resistance). The random `r` additionally defeats a brute-force
*dictionary* attack: without `r`, an attacker could just hash every
plausible value of `v` and compare — with a full 256-bit random `r` mixed
in, there's no small search space to try.

### Why it's binding

Producing two different valid openings `(v1, r1)` and `(v2, r2)` for the
*same* published commitment would require finding a **hash collision**
(`H(v1||r1) = H(v2||r2)` with `v1 ≠ v2`) — believed computationally
infeasible for SHA-256. So once you've published a commitment, you can't
later "change your mind" about what you committed to.

### Worked example (sealed-bid auction, real SHA-256, shown as hex)

Suppose Carol bids `1800`. She picks a random 32-byte nonce, say (shown
truncated) `r = 9f3a...`, and publishes:

```
commitment = SHA256(b"1800" + r)   e.g. a2f1e087...   (32 bytes, looks random)
```

Nobody can tell from `a2f1e087...` whether Carol bid 1800, 1200, or
anything else — every possible bid, paired with *some* nonce, is equally
capable of producing that exact hash output (as far as anyone can tell
without breaking SHA-256). Once bidding closes, Carol reveals
`(1800, r)`; everyone recomputes `SHA256(b"1800" + r)` and checks it equals
`a2f1e087...`. If Carol tries to claim she actually bid `2500`, recomputing
`SHA256(b"2500" + r)` gives a *completely different* hash — it won't match,
and the lie is caught immediately.

Run `hash_based_commitment.py` for the full 3-bidder auction with real
SHA-256 output.

---

## 2. Merkle tree commitment — step by step

**The idea in one sentence:** hash pairs of hashes up a binary tree until
one root hash summarizes the entire list, and prove any single element's
membership by revealing just the handful of "sibling" hashes on the path
from that element to the root.

### Steps (building the tree)

1. **Hash every leaf:** for each item `data_i` in your list, compute
   `leaf_i = H(data_i)`.
2. **Pair up and hash again:** group leaves into pairs, compute
   `parent = H(left || right)` for each pair, forming the next level up. If
   there's an odd one out, duplicate the last leaf to make the pairing work
   (a common convention — see the caveat below).
3. **Repeat** until only one hash remains — the **Merkle root**. Publish
   just this one value (e.g., in a block header).

### Steps (proving membership of one element)

4. To prove leaf `i` is in the committed list, walk from that leaf to the
   root, and at each level record the **sibling** hash (the other node
   needed to compute the parent) plus which side it's on (left/right).
   This is `O(log₂ n)` hashes total — for a list of a million items, just
   ~20 hashes prove membership of any single one.
5. **Verify:** starting from `H(data_i)`, repeatedly combine with each
   sibling hash in the proof, in the recorded left/right order, and check
   the final result equals the published root.

### Why this is efficient AND secure

Efficient: you never need to see or download the other `n-1` items — just
`log₂ n` sibling hashes. Secure: forging a membership proof for an item
*not* actually in the tree would require finding a hash collision at some
level of the tree — again relying on SHA-256's collision resistance, the
same assumption underlying hash commitments above.

### Worked example (4 items, real SHA-256, shown as 8-hex-char prefixes for
readability — the actual hashes are full 32-byte values)

Items: `A, B, C, D`.

1. Leaf hashes: `H(A)=559aead0..., H(B)=df7e70e5..., H(C)=6b23c0d5...,
   H(D)=3f39d5c3...`
2. Level-1 (pair and hash): `H(H(A)+H(B)) = 63956f0c...`,
   `H(H(C)+H(D)) = 98a2fbfd...`
3. Root: `H(63956f0c... + 98a2fbfd...) = 1b3faa3f...` — this single value
   commits to all four items in a fixed order.

**Proving `C` is in the set:** the path from `C` to the root needs two
sibling hashes: `H(D) = 3f39d5c3...` (C's sibling at level 0) and
`63956f0c...` (the A-B pair's hash, C's sibling at level 1).

**Verifying:** start with `H(C) = 6b23c0d5...`. Combine with sibling `H(D)`
on the right: `H(6b23c0d5... + 3f39d5c3...) = 98a2fbfd...` (matches the
level-1 hash computed during construction ✓). Combine that with sibling
`63956f0c...` on the left: `H(63956f0c... + 98a2fbfd...) = 1b3faa3f...` —
matches the published root ✓. Membership confirmed using only 2 hashes,
not all 4 original items.

Run `merkle_tree_commitment.py` for a 5-item version with full (untruncated)
SHA-256 output and a tamper-detection check.

---

## When to use

- **Hash commitment**: sealed-bid auctions, commit-reveal games/voting,
  any "I promise this value now, prove it later" flow where you don't need
  homomorphic properties.
- **Merkle tree**: committing to a large dataset (blockchain transaction
  sets, certificate transparency logs, file integrity) while letting anyone
  cheaply verify a single element is in the set without downloading it all.

## When *not* to use

- Hash commitments aren't *hiding* against a small message space unless you
  add real entropy in `r` — committing to a boolean or a small integer
  without a properly random nonce lets an attacker just brute-force every
  possible value and match hashes.
- Merkle trees prove *membership*, not *non-membership*, efficiently, unless
  you additionally sort the leaves or use a sparse Merkle tree — plain
  Merkle trees are the wrong tool if "prove X is NOT in this set" is your
  actual requirement.
- If you need the commitment itself to support algebraic operations (adding
  two commitments to get a commitment to the sum, as in Bulletproofs range
  proofs or Pedersen-based VSS), hash commitments won't do it — use
  Pedersen commitments instead.

## Caveats in this code

- `hash_based_commitment.py` uses SHA-256 directly with a 32-byte random
  nonce, which is fine, but real commit-reveal protocols also need to bind
  the commitment to a *context* (e.g. round number, participant ID) to stop
  cross-protocol replay of a commitment.
- The Merkle tree implementation pads an odd number of leaves by duplicating
  the last one — a known footgun (CVE-worthy in some historical
  implementations) if not handled consistently between proof generation and
  verification; this demo is consistent internally but don't copy the
  padding rule blindly into a different implementation.

---

## Real-world examples

- **Hash-based commitment**: Ethereum's RANDAO mechanism has validators
  commit to random values ahead of time and reveal them later to jointly
  produce unpredictable, unbiasable randomness for block proposer
  selection. Commit-reveal is also the standard pattern for on-chain
  sealed-bid auctions and simple on-chain games (rock-paper-scissors
  contracts, for instance, are a textbook use case since neither player
  can see the other's move before committing).
- **Merkle trees**: Bitcoin and Ethereum both commit to their entire set of
  transactions in a block via a Merkle root, so light clients can verify a
  single transaction was included without downloading the whole block.
  Certificate Transparency (the public log system browsers rely on to
  detect fraudulently-issued TLS certificates) is built entirely on Merkle
  trees. Git's object model is itself a Merkle DAG — every commit hash
  transitively commits to the entire history beneath it.

## Decision guide: which one do I need?

- **Do you need to commit to a SINGLE value now and reveal it later (a bid,
  a move in a game, a random contribution)?**
  → Hash-based commitment.
- **Do you need to commit to a whole LIST or SET of items, and later prove
  individual items are part of that set without revealing or transmitting
  the rest?**
  → Merkle tree.
- **Do you need the commitment itself to support algebraic combination
  (e.g. adding two commitments together to get a commitment to the sum,
  without opening either one)?**
  → Neither of these — use Pedersen commitments instead (see
  `01_zero_knowledge_proofs/pedersen_commitment.py`).
- **Do you need to prove an item is NOT in a set, efficiently?**
  → Plain Merkle trees don't do this well — look at sparse Merkle trees or
  a sorted/range-proof variant instead.
