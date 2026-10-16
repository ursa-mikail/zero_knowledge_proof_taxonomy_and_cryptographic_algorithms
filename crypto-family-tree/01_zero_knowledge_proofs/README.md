# Zero-knowledge proofs

Prove a statement is true without revealing *why* it's true (the witness).

## Files

- `schnorr_sigma_protocol.py` — interactive 3-move proof of knowledge of a discrete log
- `fiat_shamir_nizk.py` — the same proof made non-interactive via a hash-based challenge
- `pedersen_commitment.py` — the commitment scheme every SNARK/STARK is built on

All three reuse the toy group from the top-level README:
**p = 23, g = 5, secret x = 6, public key y = g^x mod p = 8.**

---

## 1. Schnorr sigma protocol — step by step

**The idea in one sentence:** the prover proves "I know x" by answering a
random challenge in a way that only someone who actually knows x could get
right, without that answer leaking x itself.

**Setup (public):** a group of prime order `q`, generator `g`, and a public
key `y = g^x mod p`. The prover privately holds `x`.

### The three moves

1. **Commit.** The prover picks a fresh random number `r` (the *nonce*,
   never reused) and sends `t = g^r mod p`.
   *Why:* `t` looks like a random group element to the verifier — it carries
   no information about `r` or `x` on its own (this is what makes the whole
   thing zero-knowledge).
2. **Challenge.** The verifier sends back a random `c`.
   *Why random:* if `c` were predictable, a cheating prover could
   precompute a fake `t` and `s` that only work for that one `c` — the
   randomness is what forces the prover to "commit before knowing the
   question."
3. **Response.** The prover computes `s = r + c·x mod q` and sends it.
   *Why this formula:* it mixes the nonce `r` with the secret `x`, weighted
   by the challenge `c`, in a way that's linear — which is exactly what
   makes verification possible without revealing either `r` or `x`
   individually.
4. **Verify.** The verifier checks `g^s == t · y^c mod p`.
   *Why this check works:* substitute the response —
   `g^s = g^(r + c·x) = g^r · g^(c·x) = g^r · (g^x)^c = t · y^c`.
   The equation is just the definition of `s` rewritten in exponent form, so
   it holds **only if** the prover actually used the right `x` when
   computing `s`.

### Why it's zero-knowledge (not just "correct")

A simulator with no knowledge of `x` can produce a transcript
`(t, c, s)` indistinguishable from a real one: pick `s` and `c` first
(both random), then compute `t = g^s · y^(-c) mod p`. This transcript
satisfies the same verification equation, so a verifier can't distinguish
"talked to the real prover" from "watched a simulated transcript" — meaning
the real transcript couldn't have taught the verifier anything about `x`
beyond "the prover knows it."

### Worked example (toy numbers, p=23, g=5, x=6, y=8)

1. Prover picks nonce `r = 3` → commit `t = 5³ mod 23 = 10`.
2. Verifier sends challenge `c = 4`.
3. Prover computes `s = r + c·x mod 22 = 3 + 4·6 = 27 mod 22 = 5`.
   (`mod 22` because that's the order of `g=5` in this toy group.)
4. Verifier checks `g^s =? t · y^c mod 23`:
   - `g^s = 5^5 mod 23 = 20`
   - `y^c = 8^4 mod 23`: `8²=64=18`, `8⁴=18²=324=324-322=2`
   - `t · y^c = 10 · 2 mod 23 = 20`
   - `20 == 20` ✓ — the verifier accepts.

Run `schnorr_sigma_protocol.py` to see the same flow with real (large)
numbers instead of the toy ones above.

---

## 2. Fiat-Shamir NIZK — step by step

**The idea in one sentence:** replace the live verifier's random challenge
with a hash of the transcript so far — a hash function is unpredictable
enough to play the verifier's role, but the prover can compute it alone.

### Steps

1. Prover picks nonce `r`, computes `t = g^r mod p` — same as Schnorr, step 1.
2. **Instead of waiting for a verifier**, the prover computes
   `c = H(g, y, t)` itself, hashing everything the verifier would have seen
   so far.
   *Why this is safe:* the prover has to fix `t` (by choosing `r`) *before*
   it knows what `c` will hash to, because `c` depends on `t`. This is the
   same "commit before knowing the question" property that made the
   interactive version sound.
3. Prover computes `s = r + c·x mod q`, exactly as before.
4. The **entire proof is just the pair `(t, s)`** — no verifier interaction
   ever happened.
5. Anyone can verify later, at any time, without contacting the prover: 
   recompute `c = H(g, y, t)` and check `g^s == t · y^c mod p`.

### Worked example (same toy numbers)

Using `r = 3`, `t = 10` as before: instead of a verifier picking `c`, the
prover computes (conceptually) `c = H(g=5, y=8, t=10) mod 22`. Whatever that
hash evaluates to, say it comes out to `4` again — the rest of the
computation is identical to the Schnorr example above, and the check
`g^s == t·y^c` still passes. The *only* difference is who produced `c` and
when.

### Why this matters

This single substitution — "hash instead of ask" — is the mechanism that
lets zk-SNARKs and zk-STARKs produce one self-contained proof blob that
anyone can check offline, with no back-and-forth. Every non-interactive
proof system in modern cryptography traces back to this trick.

---

## 3. Pedersen commitment — step by step

**The idea in one sentence:** lock in a value now, in a way nobody (not even
you) can later change, while revealing nothing about the value until you
choose to open it.

### Setup

Two generators `g` and `h` of the same group, where **nobody** knows the
discrete log of `h` base `g` (i.e., nobody knows an `a` with `h = g^a`). In
real systems `h` is derived via a verifiable "nothing up my sleeve"
procedure so no party can secretly know this `a`.

### Steps

1. To commit to value `v`, pick a random blinding factor `r`.
2. Compute `c = g^v · h^r mod p` and publish `c`.
   *Why two generators:* if you only used `g^v`, then `c` would take one of
   a small number of fixed values (one per possible `v`) — easy to guess by
   brute force. Multiplying by `h^r` (with `r` random and secret) drowns `v`
   in randomness, so `c` looks like a uniformly random group element no
   matter what `v` was.
3. Later, to **open** the commitment, reveal `(v, r)`. Anyone recomputes
   `g^v · h^r mod p` and checks it equals the original `c`.

### Why it's *hiding* (v stays secret until opened)

For any two different values `v` and `v'`, there's a blinding factor `r'`
that makes `commit(v', r') = commit(v, r)` — specifically
`r' = r + (v - v')·a` where `a = log_g(h)`. Since nobody knows `a`, nobody
can actually compute that `r'`, but *mathematically* every value is equally
consistent with any given commitment — which is exactly why `c` reveals
nothing: it doesn't even statistically favor one `v` over another.

### Why it's *binding* (you can't change your mind later)

Suppose you could open the same `c` as two different values `v ≠ v'` with
blinding factors `r ≠ r'`. Then `g^v·h^r = g^v'·h^r'`, which rearranges to
`h^(r-r') = g^(v'-v)`, i.e. `h = g^((v'-v)/(r-r'))` — you'd have just
computed the discrete log of `h` base `g`, something believed
computationally infeasible. So breaking the binding property is exactly as
hard as breaking discrete log.

### Worked example (toy numbers; for real use, `log_g(h)` must be secret —
here we intentionally use a *known* toy relationship so you can verify the
arithmetic by hand)

With `p = 23, g = 5`, let `h = g² mod 23 = 25 mod 23 = 2` (so here
`a = 2` — fine for illustration, forbidden in real deployments).

1. Commit to `v = 3` with blinding `r = 4`:
   `c = 5³ · 2⁴ mod 23 = 125·16 mod 23 = (125 mod 23)·16 mod 23 = 10·16 mod 23 = 160 mod 23 = 22`.
2. Open by revealing `(3, 4)`. Verifier recomputes `5³·2⁴ mod 23 = 22` and
   confirms it matches the published `c = 22`. ✓

Run `pedersen_commitment.py` for the same idea with real (large,
cryptographically meaningful) numbers.

---

## When to use

- You need to prove possession of a secret (private key, credential, solution)
  without revealing it — authentication, anonymous credentials, voting.
- You need a building block for a larger NIZK/SNARK system.

## When *not* to use

- You need succinct proofs of large computations (e.g. "this program ran
  correctly on this input") — that's SNARKs/STARKs, not raw sigma protocols.
- You need post-quantum security — discrete-log-based ZK breaks under Shor's
  algorithm; look at hash-based (STARK-style) or lattice-based ZK instead.
- Fiat-Shamir is only sound in the random oracle model — a bad hash choice
  can break soundness in theory (rare in practice with SHA-256/3).

## Caveats in this code

- Uses a small (~1536-bit) but *real* safe prime (RFC 3526 group 5), not a
  toy prime — big enough to be a legitimate demo, still far below what you'd
  want for long-term security margins in 2026.
- No constant-time arithmetic — timing side channels are not addressed.
- `secrets` module is used for randomness, which is cryptographically
  appropriate, but nonce reuse detection is not implemented (reusing `r`
  across two proofs leaks `x` — a classic real-world bug: two signatures
  with the same nonce let you solve for `x` directly by subtracting the two
  `s` equations).

---

## Real-world examples

- **Schnorr sigma protocol / Schnorr signatures**: Bitcoin's Taproot upgrade
  (BIP340) switched from ECDSA to Schnorr signatures specifically because
  their linearity enables clean signature aggregation (see
  `06_multisig_aggregate_signatures/musig_schnorr_aggregate.py`). EdDSA
  (used in Signal, SSH, TLS 1.3) is a Schnorr-family construction over
  Edwards curves.
- **Fiat-Shamir NIZK**: the transform underneath essentially every
  practical SNARK/STARK — Zcash's shielded transactions, zk-rollups
  (zkSync, StarkNet, Polygon zkEVM) all use Fiat-Shamir-derived challenges
  internally so a prover can publish one proof blob with no verifier
  round-trip.
- **Pedersen commitments**: Confidential Transactions in Monero and in
  Elements/Liquid (Blockstream's sidechain) hide transaction amounts using
  Pedersen commitments, while still letting the network verify that inputs
  equal outputs (the commitments are additively homomorphic, so summing
  commitments and checking against zero works without revealing amounts).
  Bulletproofs (used for Monero's range proofs) are built directly on top
  of this primitive.

## Decision guide: which one do I need?

- **Do you need an interactive proof, live with a verifier who's actually
  present (an in-person or real-time-session authentication flow)?**
  → Schnorr sigma protocol.
- **Do you need a proof that can be generated once, stored, and verified
  later by anyone, with no verifier needing to be online at proof time?**
  → Fiat-Shamir NIZK.
- **Do you need to hide a specific value (an amount, a vote, a bid) now, and
  reveal or algebraically combine it later — without needing to prove
  anything else about it yet?**
  → Pedersen commitment.
- **Do you need to prove something about a large, complex computation
  (e.g. "this program executed correctly")?**
  → None of these three alone — you need a full SNARK/STARK system (Groth16,
  PLONK, STARKs), which are built from these primitives but are out of
  scope for this repo's hand-checkable demos.
