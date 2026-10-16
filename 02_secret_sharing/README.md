# Secret sharing

Split a secret into `n` shares such that any `t` of them reconstruct it, but
`t-1` reveal *nothing* — not even a probabilistic hint.

## Files

- `shamir_secret_sharing.py` — polynomial-based t-of-n sharing + Lagrange reconstruction
- `feldman_vss.py` — Shamir + Pedersen-style commitments so shareholders can
  verify their share is consistent with everyone else's, without a trusted dealer

---

## 1. Shamir secret sharing — step by step

**The idea in one sentence:** hide the secret as the y-intercept of a random
polynomial, and give each party one point on that polynomial — a lone point
tells you nothing about the curve it sits on, but enough points pin it down
exactly.

### Why a polynomial

A single point `(x, y)` is consistent with infinitely many different
curves. But a *degree-(t-1)* polynomial is uniquely determined by any `t`
points on it (this is a basic fact of algebra — two points determine a
line, three points determine a parabola, and so on). Shamir's insight: pick
a random degree-`(t-1)` polynomial whose constant term IS the secret, hand
out points as shares, and threshold reconstruction falls out for free.

### Steps

1. **Choose the field.** Pick a large prime `p` (all arithmetic below is
   mod `p`).
2. **Build the polynomial.** To share secret `s` among `n` parties with
   threshold `t`, pick `t-1` random coefficients `a1, ..., a(t-1)` and form
   `f(x) = s + a1·x + a2·x² + ... + a(t-1)·x^(t-1) mod p`.
   Note `f(0) = s` — the secret is baked in as the constant term.
3. **Distribute shares.** Give party `i` the point `(i, f(i))` for
   `i = 1, ..., n`. (Never use `x=0` as a share — that would just hand out
   the secret directly!)
4. **Reconstruct from any `t` shares via Lagrange interpolation.** Given
   points `(x1,y1), ..., (xt,yt)`, the unique degree-`(t-1)` polynomial
   through them evaluated at 0 is:

   ```
   f(0) = Σ_j  y_j · Π_{m≠j} (0 - x_m) / (x_j - x_m)     (all mod p)
   ```

   Each big fraction is a **Lagrange basis coefficient** `L_j(0)`: it's
   built so that `L_j(x_j) = 1` and `L_j(x_m) = 0` for every other point
   `x_m`. Summing `y_j · L_j(0)` across all `t` points therefore reproduces
   exactly the value the original polynomial takes at 0 — the secret.

### Why `t-1` shares reveal *nothing* (not just "not enough")

With only `t-1` points, there are `p` different degree-`(t-1)` polynomials
passing through them — one for every possible value of the missing
constant term `s`. Each candidate secret is equally likely from the
shareholders' point of view. This is **information-theoretic** security: an
attacker with unlimited computing power, given `t-1` shares, learns
literally zero bits about `s`. Contrast this with computational security
(like RSA), which only holds if some hard math problem stays hard.

### Worked example (toy numbers, prime p = 17)

Share secret `s = 13` with `t = 2, n = 3`. Pick one random coefficient
`a1 = 7`, giving `f(x) = 13 + 7x mod 17`.

- Share 1: `f(1) = 13+7 = 20 mod 17 = 3` → `(1, 3)`
- Share 2: `f(2) = 13+14 = 27 mod 17 = 10` → `(2, 10)`
- Share 3: `f(3) = 13+21 = 34 mod 17 = 0` → `(3, 0)`

**Reconstruct from shares 1 and 2** using the Lagrange formula:

- `L1(0) = (0 - x2)/(x1 - x2) = (0-2)/(1-2) = -2/-1 = 2`
- `L2(0) = (0 - x1)/(x2 - x1) = (0-1)/(2-1) = -1 mod 17 = 16`
- `f(0) = y1·L1 + y2·L2 = 3·2 + 10·16 = 6 + 160 = 166 mod 17 = 166 - 153 = 13` ✓

Matches the original secret. Try it with shares 2 and 3, or 1 and 3 — same
answer every time, because they're all points on the *same* line.

Run `shamir_secret_sharing.py` for the same idea over a real 521-bit prime.

---

## 2. Feldman VSS — step by step

**The idea in one sentence:** publish a "fingerprint" of each polynomial
coefficient (as a group element) so every shareholder can check their own
share is consistent with everyone else's, without trusting the dealer or
seeing anyone else's share.

### Steps

1. Dealer builds the same kind of polynomial as Shamir:
   `f(x) = s + a1·x + ... + a(t-1)·x^(t-1) mod q`.
2. Dealer also publishes **commitments to each coefficient**:
   `C_j = g^(a_j) mod p` for `j = 0, 1, ..., t-1` (where `a_0 = s`). These
   are broadcast once, publicly, to everyone.
3. Dealer sends party `i` its share `f(i)` privately, as usual.
4. **Each party independently verifies** its own share against the public
   commitments:

   ```
   g^f(i)  =?=  Π_j  C_j ^ (i^j)      (mod p)
   ```

   *Why this check works:* expand the right-hand side —
   `Π_j (g^(a_j))^(i^j) = g^(Σ_j a_j·i^j) = g^(f(i))`.
   The right side is literally `g` raised to the polynomial evaluated at
   `i`, computed entirely from public commitments — so it must equal
   `g^f(i)` if and only if the dealer sent the *actual* `f(i)`, not some
   other made-up number.

### What this buys you over plain Shamir

Plain Shamir has a single point of trust: if the dealer is dishonest and
sends inconsistent shares to different parties (say, points that don't lie
on a single polynomial), the parties can reconstruct *different* "secrets"
depending on which subset gets combined — and nobody would notice until it's
too late. Feldman's public commitments let each party catch a cheating
dealer *immediately*, on their own, using only public information — no
trust in the dealer required for this check (though the dealer still learns
the full secret during generation; eliminating even that requires the
distributed key generation protocol in `04_threshold_cryptography/`).

### What it costs you

The commitment `C_0 = g^s` is published, which leaks `g^s` — not `s`
itself (discrete log is still hard), but a specific piece of public
information about the secret that plain Shamir wouldn't reveal.

### Worked example (toy numbers, p = 23, g = 5, prime q = 11 for exponents)

Share `s = 4` with `t = 2`, coefficient `a1 = 3`: `f(x) = 4 + 3x mod 11`.

- Commitments: `C0 = 5^4 mod 23 = 625 mod 23 = 4`, `C1 = 5^3 mod 23 = 125 mod 23 = 10`.
- Share for party 2: `f(2) = 4 + 6 = 10`.
- Party 2 checks: `g^f(2) = 5^10 mod 23`. Compute: `5^5=20` (from the main
  README example scaled up), `5^10=(5^5)^2=20^2=400 mod 23 = 400-391=9`.
  Right-hand side: `C0 · C1^2 = 4 · 10^2 mod 23 = 4·100 mod 23 = 4·8=32 mod23=9`.
  `9 == 9` ✓ — party 2's share is confirmed consistent, using only `C0, C1`
  and its own share, no dealer trust required.

Run `feldman_vss.py` to see this catch an actual injected bad share.

---

## When to use

- Distributing a root/master key across custodians so no single party (or
  server compromise) exposes it.
- As the substrate under threshold signatures (see `04_threshold_cryptography/`)
  and most MPC protocols.
- Backup/recovery schemes (e.g. wallet seed backup across trustees).

## When *not* to use

- You need to *compute* on the shares beyond simple linear reconstruction —
  that's the job of a full MPC protocol (`03_multi_party_computation/`), not
  bare secret sharing.
- Plain Shamir has no way to detect a malicious dealer or a lying
  shareholder — use Feldman/Pedersen VSS, or full PVSS, if any party might
  be adversarial.
- Shares must be refreshed periodically (proactive secret sharing) if the
  threat model includes an adversary that can compromise different parties
  over time and accumulate `t` shares — plain Shamir shares are static.

## Caveats in this code

- Field arithmetic uses a fixed 521-bit prime for simplicity — swap in
  whatever field size your application's secret needs.
- No proactive refresh, no misbehaving-dealer detection in
  `shamir_secret_sharing.py` (that's what `feldman_vss.py` adds).
- Reconstruction here assumes an honest majority of shares presented; it
  does not attempt Reed-Solomon-style error correction to tolerate wrong
  shares mixed in with good ones.

---

## Real-world examples

- **Shamir secret sharing**: HashiCorp Vault uses Shamir's Secret Sharing to
  split its master unseal key among several operators (a default 3-of-5
  scheme), so no single administrator can unlock the vault alone. SLIP-39
  (used by Trezor hardware wallets) is a standardized Shamir-based scheme
  for splitting a cryptocurrency seed phrase across multiple physical
  backup shares.
- **Feldman VSS**: used as a building block inside distributed key
  generation protocols for threshold signature systems and randomness
  beacons (e.g. `drand`, the League of Entropy's distributed randomness
  service) — anywhere a dealer-free setup needs shareholders to catch a
  cheating contributor without a central authority to appeal to.

## Decision guide: which one do I need?

- **Is the party doing the splitting (the "dealer") fully trusted, and you
  just need the storage/recovery properties?**
  → Plain Shamir secret sharing.
- **Might the dealer be malicious, unreliable, or is there no dealer at all
  (parties need to generate shares among themselves)?**
  → Feldman VSS (or, for the dealer-free case specifically, the
  distributed key generation protocol in `04_threshold_cryptography/`).
- **Do you need the shares to also support signing or decrypting
  operations later, not just reconstruction of a static secret?**
  → You want `04_threshold_cryptography/`, not plain secret sharing — these
  two folders are often used together (secret sharing is the substrate,
  threshold crypto is what you build on top of it).
