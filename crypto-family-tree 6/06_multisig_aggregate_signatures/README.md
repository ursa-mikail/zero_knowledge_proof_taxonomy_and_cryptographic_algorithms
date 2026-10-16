# Multisig & aggregate signatures

Multiple signers, one payload — but with very different guarantees and
on-chain footprints depending on the scheme.

## Files

- `naive_nofn_multisig.py` — n independent signatures, all required and all
  visible (e.g. Bitcoin's original `OP_CHECKMULTISIG` model)
- `musig_schnorr_aggregate.py` — MuSig-style key & signature aggregation:
  n signers, ONE compact signature indistinguishable from a single-key one
- `bls_aggregate_signature.py` — BLS: aggregate n signatures on
  (possibly different) messages into one, verified with a pairing check
  (requires `py_ecc`, see requirements.txt)

---

## 1. Naive n-of-n multisig — step by step

**The idea in one sentence:** don't do anything clever — just require `n`
completely independent, ordinary signatures, and check each one on its own.

### Steps

1. Each of the `n` signers generates its own keypair independently — no
   coordination needed at all.
2. Each signer signs the message with an ordinary signature scheme (Schnorr,
   in this repo's demo) — again, completely independently, potentially at
   different times, in any order.
3. The verifier checks **every** signature against its own signer's public
   key, using the exact same verification equation as a single-signer
   signature (see `01_zero_knowledge_proofs/README.md`'s Schnorr write-up
   for the check itself: `g^s == t·y^c mod p`).
4. The policy passes only if **all n** checks succeed.

### Why this is simple but expensive

There's no interaction required between signers — each just signs on their
own time and hands their signature to whoever's collecting them. But the
on-chain (or on-the-wire) footprint is `n` full `(pubkey, signature)` pairs,
growing linearly with the number of signers, and it's *visibly* a multisig
to anyone inspecting it — no privacy about how many people or which keys
were involved.

Since each signature is independently ordinary, there's no worked numeric
example beyond "run the Schnorr verification equation once per signer" —
see the ZKP README for that equation traced by hand.

---

## 2. MuSig (Schnorr key & signature aggregation) — step by step

**The idea in one sentence:** weight each signer's public key by a
per-signer coefficient derived from *everyone's* public key (so no one can
cherry-pick their own key to cancel out others'), and then run one shared
Schnorr signing equation whose result is indistinguishable from a
single-signer's.

### The rogue-key attack this defends against, first

Naively, an "aggregate public key" might just be `Y = y1 · y2 · ... · yn`
(plain product, no weighting). But then a malicious signer who sees
everyone else's public key `y_honest` could publish their own key as
`y_evil = Y_target / y_honest` for whatever *target* aggregate key they
want to forge a signature under — cancelling out the honest signer
entirely and controlling the "aggregate" alone. MuSig's per-signer
coefficients close this hole.

### Steps

1. **Compute a coefficient per signer** that depends on the *entire* set of
   public keys: `L = H(y1, y2, ..., yn)`, then `a_i = H(L, y_i)` for each
   signer `i`. Because `a_i` depends on `y_i` itself (not just the signer's
   identity), a signer can't choose their `y_i` *after* seeing others' keys
   and still control what `a_i` comes out to — the hash scrambles any
   attempted cancellation.
2. **Aggregate the public keys, weighted:** `Y = Π_i y_i^(a_i) mod p`.
3. **Each signer picks a nonce** `r_i`, publishes `R_i = g^(r_i)`; aggregate:
   `R = Π_i R_i`.
4. **Challenge:** `c = H(R, Y, message)` — the same Fiat-Shamir style
   challenge as ordinary Schnorr, but over the *aggregate* key and nonce.
5. **Each signer computes a partial signature using its OWN key and OWN
   coefficient:** `partial_i = r_i + c·a_i·x_i mod q`.
6. **Combine:** `s = Σ_i partial_i mod q`. The pair `(R, s)` is now a
   completely ordinary-looking Schnorr signature.
7. **Verify exactly like single-signer Schnorr**, against the aggregate key
   `Y`: `g^s == R · Y^c mod p`.

### Why the combination checks out (the algebra)

`s = Σ_i r_i + c·Σ_i(a_i·x_i)`. The first part matches `R` in exponent
form. The second part, `Σ_i a_i·x_i`, is exactly the exponent that makes
`g^(Σ a_i x_i) = Π (g^x_i)^a_i = Π y_i^a_i = Y` — so
`s = r_total + c·(the exponent of Y)`, precisely the single-signer Schnorr
equation, computed jointly without anyone learning anyone else's `x_i`.

### Worked example (toy order-11 subgroup, p=23, g=4; 2 signers for brevity)

Alice: `x1=3 → y1 = 4^3 mod23 = 18`. Bob: `x2=5 → y2 = 4^5 mod23 = 12`.

1. Toy "hash" outputs (stand-ins for real SHA-256 outputs, fixed here for a
   hand-checkable example): `a1 = 6, a2 = 9` (both mod 11).
2. Aggregate key: `Y = y1^6 · y2^9 mod 23`.
   `18^6 mod23`: `18²=324mod23=2`, `18³=2·18=36mod23=13`, `18^6=13²=169mod23=8`.
   `12^9 mod23`: `12²=144mod23=6`, `12³=6·12=72mod23=3`, `12⁴=3·12=36mod23=13`,
   `12⁸=13²=169mod23=8`, `12⁹=8·12=96mod23=4`.
   `Y = 8·4 mod23 = 32 mod23 = 9`.
3. Nonces: `r1=5 → R1=4^5mod23=12`; `r2=7 → R2=4^7mod23=8`.
   `R = 12·8 mod23 = 96 mod23 = 4`.
4. Challenge (toy, fixed): `c = 3`.
5. Partial signatures:
   `partial_1 = r1 + c·a1·x1 mod11 = 5 + 3·6·3 = 5+54=59 mod11 = 4`
   `partial_2 = r2 + c·a2·x2 mod11 = 7 + 3·9·5 = 7+135=142 mod11 = 10`
6. Combined: `s = 4+10 = 14 mod11 = 3`.
7. Verify: `g^s = 4^3 mod23 = 18`. `Y^c = 9^3 mod23 = 16`
   (`9²=81mod23=12`, `9³=12·9=108mod23=16`). `R·Y^c = 4·16 mod23 = 64 mod23
   = 18`. `18 == 18` ✓ — the standard single-signer Schnorr check passes on
   a signature that two independent parties jointly produced, with neither
   learning the other's secret key.

Run `musig_schnorr_aggregate.py` for the real 3-signer, 1536-bit version.

---

## 3. BLS aggregate signatures — step by step

**The idea in one sentence:** BLS signatures live in a special kind of
elliptic-curve group that has a *bilinear pairing* — a function `e` that
turns "is this signature valid" into an equation you can check algebraically
even after adding many signatures together, on possibly different messages.

*(Real BLS12-381 arithmetic isn't something you can trace by hand the way
the discrete-log examples above are — the numbers involved are points on a
381-bit elliptic curve with a 12-degree extension field pairing. The
structure below explains exactly what the pairing equation is doing
conceptually; run `bls_aggregate_signature.py`, which uses `py_ecc`'s
reference implementation, to see it actually execute.)*

### Steps

1. **Key generation:** private key `x`, public key `Y = x·G` (elliptic-curve
   scalar multiplication, analogous to `g^x` in the discrete-log schemes
   above, just written additively since EC groups are usually written with
   `+`).
2. **Sign:** hash the message onto a curve point, `H(m)`, then compute
   `Sig = x · H(m)`.
3. **Verify a single signature** using the pairing: check
   `e(Sig, G) == e(H(m), Y)`.
   *Why this works:* `e(Sig, G) = e(x·H(m), G) = e(H(m), G)^x` (pairings are
   bilinear — scalars can move between the two arguments), and
   `e(H(m), Y) = e(H(m), x·G) = e(H(m), G)^x` — both sides are the same
   value, computed two different ways.
4. **Aggregate signatures on the SAME message:** just add the signature
   points, `Sig_agg = Σ_i Sig_i`. Verify with `FastAggregateVerify`:
   `e(Sig_agg, G) == e(H(m), Σ_i Y_i)` — one pairing check covers every
   signer, because addition on the curve mirrors addition of the underlying
   secret keys inside the pairing equation.
5. **Aggregate signatures on DIFFERENT messages:** still just add the
   points. Verify with `AggregateVerify`:
   `e(Sig_agg, G) == Π_i e(H(m_i), Y_i)` — one product of pairings, one
   comparison, regardless of how many distinct messages were involved.
6. **Proof of possession (POP):** before trusting any public key in an
   aggregate scheme, each signer proves it actually knows the matching
   private key by signing its *own* public key. This defeats a rogue-key
   attack analogous to the one MuSig defends against: without POP, a
   malicious party could publish `Y_evil = Y_target - Y_honest` (again
   without knowing a matching private key) to hijack an aggregate
   verification. POP forces the attacker to actually know a discrete log,
   which they can't do without breaking the underlying hard problem.

### Why aggregation works algebraically (the punchline)

Because both signing (`x · H(m)`) and the pairing itself are *linear* in the
secret key, adding signature points is equivalent to "combining" the
underlying signing equations — and the bilinear pairing lets you check the
combined equation with a single evaluation of `e`, no matter how many
individual signatures went into the sum.

Run `bls_aggregate_signature.py` — it exercises key generation, POP,
same-message aggregation (`FastAggregateVerify`), and different-message
aggregation (`AggregateVerify`) with real BLS12-381 arithmetic, plus a
tamper check showing verification correctly fails on a modified message.

---

## When to use

- **Naive multisig**: simplicity and auditability matter more than
  compactness/privacy, or your platform's scripting only supports it
  (legacy Bitcoin scripts, simple governance).
- **MuSig/Schnorr aggregation**: same chain footprint as a single signer,
  privacy (nobody can tell it was a multisig), and you can afford an
  interactive signing ceremony (2-3 rounds).
- **BLS aggregation**: you need to aggregate *many* signatures, possibly on
  different messages, into one constant-size object with one verification
  (validator attestations in PoS chains, e.g. Ethereum's beacon chain).

## When *not* to use

- Naive multisig, if you care about on-chain privacy or fee cost at scale —
  cost grows linearly with signer count.
- MuSig, if signers can't do the required interactive rounds (needs live
  coordination, unlike naive multisig where each signer can sign
  independently and asynchronously). Also: MuSig1's naive version is
  vulnerable to a Wagner's-algorithm nonce attack if signers can bias which
  round they reveal nonces in — use MuSig2 (proper nonce commitment order),
  not the textbook version, in production.
- BLS, if you need post-quantum security (pairing-based, breaks under
  Shor's algorithm) or you're on a platform without efficient pairing
  support.

## Caveats in this code

- `musig_schnorr_aggregate.py` implements the *simplified* single-round
  version for clarity — it omits the nonce-commitment round that MuSig2
  adds to stay safe against adaptive nonce-bias attacks. Do not deploy this
  exact flow.
- `bls_aggregate_signature.py` requires the `py_ecc` package (pure-Python
  BLS12-381) — install via `pip install -r requirements.txt`. It is a
  reference implementation, not a hardened one (no subgroup-check hardening
  against rogue-key attacks beyond basic proof-of-possession, which is
  included but simplified).

---

## Real-world examples

- **Naive n-of-n multisig**: classic Bitcoin P2SH multisig wallets (e.g.
  2-of-3 escrow between a buyer, seller, and arbitrator) used exactly this
  pattern for years before Taproot — each signer's public key and signature
  appear individually in the spending transaction.
- **MuSig / Schnorr aggregation**: Bitcoin wallets built around Taproot
  (e.g. collaborative-custody wallets like Blockstream's Liana, and
  various Lightning Network implementations for cooperative channel
  closes) use MuSig2 so a multi-party spend looks on-chain like an ordinary
  single-signer transaction — smaller, cheaper, and private about how many
  signers were actually involved.
- **BLS aggregate signatures**: Ethereum's proof-of-stake beacon chain
  aggregates tens of thousands of validator attestations per epoch into
  compact BLS aggregate signatures so the network doesn't have to store or
  verify each one individually. Filecoin and the Chia blockchain also use
  BLS signatures for similar aggregation benefits at scale.

## Decision guide: which one do I need?

- **Do you need maximum simplicity/auditability, don't mind the larger
  transaction size, or are constrained to a legacy scripting system that
  only supports independent signature checks?**
  → Naive n-of-n multisig.
- **Do a SMALL, FIXED group of co-signers (a handful of people/devices) need
  to jointly produce ONE compact signature, and they can coordinate live
  (a signing "ceremony") for each signature?**
  → MuSig / Schnorr aggregation.
- **Do you need to aggregate signatures from potentially THOUSANDS of
  independent signers (validators, IoT devices, sensors), possibly signing
  different messages, into one constant-size object?**
  → BLS aggregate signatures.
- **Do you need post-quantum security?**
  → None of these three — all rely on discrete-log-style hardness
  (Schnorr) or pairings (BLS), both broken by a sufficiently large quantum
  computer. Look toward hash-based or lattice-based multisignature schemes
  instead (an active research area, not included in this repo).
