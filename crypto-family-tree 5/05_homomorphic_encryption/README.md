# Homomorphic encryption

Perform computation directly on ciphertexts, producing an encrypted result
that decrypts to the correct answer — without ever decrypting the inputs.

## Files

- `paillier_additive_he.py` — additively homomorphic: `Enc(a) * Enc(b) = Enc(a+b)`
- `elgamal_multiplicative_he.py` — multiplicatively homomorphic:
  `Enc(a) * Enc(b) = Enc(a*b)`

Both are *partially* homomorphic (one operation, unlimited times). Fully
homomorphic encryption (FHE — BGV, BFV, CKKS, TFHE) supports both addition
and multiplication with bounded/unbounded depth, at far higher computational
cost; it's out of scope for a small demo (real FHE needs noise budgeting,
bootstrapping, and lattice libraries like SEAL/OpenFHE/concrete).

---

## 1. Paillier — step by step

**The idea in one sentence:** encode the message in the exponent of a fixed
base `g = n+1` (which has the special property that raising it to a power
just adds a multiple of `n` instead of wrapping unpredictably), then mask
that with a random `n`-th power for security — multiplying two ciphertexts
adds the exponents, i.e. adds the messages.

### Key generation

1. Pick two large primes `p, q`; let `n = p·q` (same shape as RSA).
2. Set `g = n + 1`. This specific choice makes `g^m mod n² = 1 + m·n mod n²`
   — a clean linear relationship in `m` (a consequence of the binomial
   theorem: `(1+n)^m = 1 + m·n + C(m,2)·n² + ...`, and every term from the
   `n²` one onward vanishes mod `n²`).
3. Compute `λ = lcm(p-1, q-1)` (the private key) and
   `μ = λ⁻¹ mod n` (its modular inverse, needed for decryption).

### Encrypt

4. To encrypt `m`, pick a random `r` coprime to `n`, and compute
   `c = g^m · r^n mod n²`.
   *Why the `r^n` factor:* without it, `c` would just be `1 + m·n mod n²` —
   trivially invertible by anyone (just divide by `n`!). Multiplying by a
   random `n`-th power hides `m` behind something that (under the
   Decisional Composite Residuosity assumption) is indistinguishable from a
   uniformly random element of `Z_{n²}^*`.

### Decrypt

5. Compute `x = c^λ mod n²`. Because `r` was raised to the `n`-th power
   during encryption, and `λ` is a multiple of the group order that kills
   off the `r^n` component when raised further, this step **cancels the
   randomness entirely**, leaving `x = 1 + (m·λ mod n)·n mod n²` — the same
   clean linear form as before, but now with `m·λ` instead of `m`.
6. Extract the exponent via `L(x) = (x - 1) / n` (an exact integer division,
   because `x` has exactly this "1 plus a multiple of n" shape), then undo
   the `λ` multiplication: `m = L(x) · μ mod n`.

### The homomorphic property, algebraically

`Enc(a) · Enc(b) = g^a·r1^n · g^b·r2^n = g^(a+b) · (r1·r2)^n mod n²`

— which is *exactly* the formula for `Enc(a+b)` using combined randomness
`r1·r2`. Decrypting the product therefore always yields `a+b mod n`, without
either `a` or `b` ever being decrypted individually.

**Bonus — scaling by a public constant:** `Enc(a)^k = g^(a·k) · r^(nk) mod n²`,
which decrypts to `a·k` — so multiplying a ciphertext by a plaintext
exponent gives an encrypted *scaled* value, useful for weighted sums (e.g.
weighted voting) without ever exposing individual votes.

### Worked example (toy primes p=7, q=11 — far too small for real security,
but big enough to compute by hand with a calculator)

- `n = 77`, `g = 78`, `λ = lcm(6,10) = 30`, `μ = 30⁻¹ mod 77 = 18`
  (check: `30 × 18 = 540 = 7×77 + 1`, so `540 mod 77 = 1` ✓).
- Encrypt `a=5` with `r=4`: `c_a = 78^5 · 4^77 mod 77² = 16` (large
  intermediate numbers — this is why real code just calls `pow(g, m, n*n)`
  rather than computing it by hand; trust the modular exponentiation here).
- Encrypt `b=3` with `r=2`: `c_b = 2020`.
- Multiply ciphertexts: `c_a · c_b mod 77² = 16 × 2020 mod 5929 = 32320 mod
  5929 = 2020`. *(coincidentally equal to c_b here — just an artifact of
  these particular toy numbers, not a general pattern)*
- Decrypt the product: `x = 2020^30 mod 5929`, `L(x) = (x-1)/77`,
  `m = L(x)·18 mod 77 = 8` — matches `a+b = 5+3 = 8` ✓.

Run `paillier_additive_he.py` for the same flow with real 256-bit primes.

---

## 2. ElGamal — step by step

**The idea in one sentence:** encrypt by hiding the message behind
`y^r` (a Diffie-Hellman-style shared secret only the key holder can
remove), and multiplying two such ciphertexts multiplies the hidden
messages together because the group operation is multiplication.

Reuses the toy group from the main README: `p=23, g=5, x=6, y=g^x mod p=8`.

### Encrypt

1. To encrypt `m`, pick a random `r`, and send the pair
   `(c1, c2) = (g^r mod p,  m · y^r mod p)`.
   *Why it hides `m`:* `y^r = (g^x)^r = g^(xr)`, a value that (under the
   Decisional Diffie-Hellman assumption) looks uniformly random to anyone
   without `x` — so `c2 = m · (random-looking value)` reveals nothing about
   `m` on its own.

### Decrypt

2. The key holder computes `s = c1^x mod p = (g^r)^x = g^(rx) = y^r` — the
   *same* masking value used during encryption, recoverable only because
   the key holder (and only the key holder) knows `x`.
3. Recover `m = c2 · s⁻¹ mod p` — dividing out the mask.

### The homomorphic property, algebraically

Given two ciphertexts `(c1,c2) = (g^r1, m1·y^r1)` and
`(c1',c2') = (g^r2, m2·y^r2)`, multiply component-wise:

`(c1·c1', c2·c2') = (g^(r1+r2), m1·m2·y^(r1+r2))`

— which is *exactly* the ciphertext you'd get from encrypting `m1·m2`
directly with combined randomness `r1+r2`. Decrypting it recovers
`m1·m2 mod p`, without ever decrypting `m1` or `m2` individually.

### Worked example (p=23, g=5, x=6, y=8 — same numbers as the main README)

- Encrypt `m1=10` with `r=3`: `c1 = 5^3 mod23 = 10`,
  `c2 = 10 · 8^3 mod23`. `8^3 mod23 = 6` (since `8²=64=18`, `18·8=144=6`),
  so `c2 = 10·6 mod23 = 60 mod23 = 14`. Ciphertext `(10, 14)`.
- Encrypt `m2=3` with `r=5`: `c1' = 5^5 mod23 = 20`,
  `c2' = 3 · 8^5 mod23`. `8^5 = 8^4·8 = 2·8 = 16`, so
  `c2' = 3·16 mod23 = 48 mod23 = 2`. Ciphertext `(20, 2)`.
- Multiply pointwise: `(10·20 mod23, 14·2 mod23) = (200 mod23, 28 mod23) =
  (16, 5)`.
- Decrypt the product: `s = 16^6 mod23`. `16² = 256 mod23 = 3`,
  `16³ = 3·16 mod23 = 2`, `16^6 = (16³)² = 4`. Then
  `m = 5 · 4⁻¹ mod23`. Since `4·6=24=1 mod23`, `4⁻¹=6`, so
  `m = 5·6 mod23 = 30 mod23 = 7`.
- Expected `m1·m2 mod23 = 30 mod23 = 7` ✓ — matches exactly.

Run `elgamal_multiplicative_he.py` for the same flow with real 1536-bit
parameters.

---

## When to use

- Aggregating sensitive data server-side without the server ever seeing
  individual records (encrypted vote tallying, encrypted ad-metric sums,
  private smart-metering aggregation).
- Delegating computation to an untrusted cloud when the operation set you
  need is one of {add-only, multiply-only} — partially homomorphic schemes
  are far cheaper than full FHE.

## When *not* to use

- You need both addition AND multiplication (e.g. evaluating an arbitrary
  polynomial or neural network on encrypted data) — that needs FHE (BGV,
  BFV, CKKS, TFHE), not Paillier or ElGamal.
- Latency/throughput matters a lot — even partially homomorphic ops are
  orders of magnitude slower than plaintext arithmetic; FHE is orders of
  magnitude slower still.
- You need malleability to be a *bug*, not a feature — homomorphic schemes
  are intentionally malleable (that's the point), so they must never be
  used where you actually want a normal IND-CCA-secure encryption scheme.

## Caveats in this code

- Small (demo-scale) key sizes for readable output; production Paillier
  wants 2048+ bit moduli, matching RSA-equivalent security.
- No zero-knowledge range proofs on ciphertexts — a real e-voting/tallying
  system needs a ZK proof that each ciphertext encodes a valid vote (e.g.
  0 or 1), otherwise a malicious voter can encrypt an out-of-range value.
- ElGamal demo shows raw multiplicative homomorphism; the "additive over
  exponent" variant (encrypting `g^m` instead of `m`, needing a final
  discrete-log lookup to recover a sum) is described in concept only, not
  implemented here.

---

## Real-world examples

- **Paillier**: used in academic and pilot electronic-voting systems for
  encrypted tallying (individual ballots stay encrypted; only the summed
  result is ever decrypted), and in some privacy-preserving smart-metering
  proposals where a utility needs a household's total usage without seeing
  individual time-of-day readings.
- **ElGamal**: the Helios open-audit voting system uses (exponential)
  ElGamal so that encrypted votes can be homomorphically combined into an
  encrypted tally before a single decryption reveals only the final count.
  GNU Privacy Guard (GPG) offers ElGamal as one of its public-key
  encryption options (used there for its standard IND-CPA security
  property, not for its homomorphism).

## Decision guide: which one do I need?

- **Do you need to combine encrypted VALUES by adding them (tallying votes,
  summing metered readings, aggregating financial records)?**
  → Paillier (additive).
- **Do you need to combine encrypted values by multiplying them, or you're
  building on an existing ElGamal-based system (e.g. extending a Diffie-
  Hellman-flavored protocol) and only need one homomorphic operation?**
  → ElGamal (multiplicative), or its "exponential ElGamal" variant if you
  actually want additive behavior over small values (encrypt `g^m` instead
  of `m`, then solve a small discrete log at the end to recover the sum).
- **Do you need to combine encrypted values using BOTH addition and
  multiplication (arbitrary polynomial evaluation, ML inference on
  encrypted data)?**
  → Neither — you need full FHE (BGV, BFV, CKKS, or TFHE), which is a much
  heavier piece of machinery not demonstrated in this repo (see this
  folder's "The math" note on why).
